//! The service runtime: one process serving the proxy, the admin listener and
//! the bus consumers, with config reload, signal handling and graceful
//! shutdown.
//!
//! Start order (each step only once the previous one succeeded): load the
//! config and exceptions → [history] → bus consumers → admin listener → proxy
//! listener. A failed step stops what already started, in reverse. Stop runs
//! the other way: proxy (stop accepting, drain), admin, [history flush],
//! supervised tasks.

use crate::admin::{check_bind, serve_admin, AdminState, Reload};
use crate::metrics::Metrics;
use crate::status::{Health, StatusBoard, StatusRecord};
use crate::supervise::supervise;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use vft_core::config::ConfigError;
use vft_core::{Config, ExceptionClock, Exceptions, Shield};
use vft_proxy::audit::{AuditSink, Format};
use vft_proxy::bus::{BusEvent, EventBus};
use vft_proxy::config_handle::{candidate, Candidate, ConfigHandle};
use vft_proxy::ProxyState;

/// How long [`Runtime::stop`] waits for in-flight requests.
pub const DRAIN: Duration = Duration::from_secs(10);

pub struct RuntimeOptions {
    /// Proxy listener address.
    pub bind: SocketAddr,
    pub upstream: String,
    /// `None` runs (and reloads) the built-in defaults.
    pub config_path: Option<PathBuf>,
    /// Scoped exceptions, loaded at start and on every reload as of that time.
    pub exceptions_path: Option<PathBuf>,
    /// JSONL audit file; `None` writes to stdout.
    pub audit: Option<PathBuf>,
    pub audit_max_bytes: u64,
    /// OCSF JSONL file; `None` is off.
    pub ocsf: Option<PathBuf>,
    /// Stop Block/Challenge (false: monitor only).
    pub enforce: bool,
    /// Loopback admin listener; `None` = off.
    pub admin_bind: Option<SocketAddr>,
    pub state_dir: PathBuf,
    pub history: bool,
}

/// Everything a reload touches; shared with the admin listener.
struct Core {
    config_path: Option<PathBuf>,
    exceptions_path: Option<PathBuf>,
    handle: Arc<ConfigHandle>,
    proxy: Arc<ProxyState>,
    bus: EventBus,
    status: Arc<StatusBoard>,
    metrics: Arc<Metrics>,
    /// Held for a whole reload, so admin POSTs and SIGHUP never interleave.
    reload_lock: Mutex<()>,
}

fn issues_text<T: std::fmt::Display>(v: &[T]) -> Vec<String> {
    v.iter().map(|i| i.to_string()).collect()
}

/// The config at `path` (defaults if `None`), validated; issue strings on failure.
fn read_config(path: Option<&Path>) -> Result<Config, Vec<String>> {
    let cfg = Config::load_or_default(path).map_err(|e| match e {
        ConfigError::Invalid(issues) => issues_text(&issues),
        other => vec![match path {
            Some(p) => format!("{}: {other}", p.display()),
            None => other.to_string(),
        }],
    })?;
    cfg.validate().map_err(|v| issues_text(&v))?;
    Ok(cfg)
}

/// The exceptions at `path` as of now (none if `None`); issue strings on failure.
fn read_exceptions(path: Option<&Path>) -> Result<Option<Exceptions>, Vec<String>> {
    let Some(path) = path else { return Ok(None) };
    let ex = Exceptions::load(path, vft_proxy::now_ms()).map_err(|issues| {
        issues
            .iter()
            .map(|i| format!("{}: {i}", path.display()))
            .collect::<Vec<_>>()
    })?;
    for w in ex.warnings() {
        tracing::warn!("{}: {w}", path.display());
    }
    Ok(Some(ex))
}

fn build_shield(cfg: Config, ex: Option<Exceptions>) -> Shield {
    let shield = Shield::new(cfg);
    match ex {
        Some(ex) => shield.with_exceptions(ex, ExceptionClock::PerRequest),
        None => shield,
    }
}

impl Core {
    /// Read, validate and build the next shield; nothing is swapped here.
    fn prepare(&self, live: &Config) -> Result<(Shield, Candidate), Vec<String>> {
        let next = read_config(self.config_path.as_deref())?;
        let ex = read_exceptions(self.exceptions_path.as_deref())?;
        let cand = candidate(live, next);
        // Restart-only values were copied back from live: validate the merge too.
        cand.config.validate().map_err(|v| issues_text(&v))?;
        Ok((build_shield(cand.config.clone(), ex), cand))
    }

    fn on_hup(&self) {
        tracing::info!("SIGHUP: reloading the config");
        let _ = self.reload();
    }
}

impl Reload for Core {
    /// Read → validate → build → swap → publish, under one lock. On any issue
    /// nothing is swapped and the live config stays.
    fn reload(&self) -> Result<u64, (Vec<String>, u64)> {
        let _serial = self
            .reload_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let live = self.handle.load();
        match self.prepare(live.shield.config()) {
            Ok((shield, cand)) => {
                // `swap`'s precondition holds: the shield is built from `cand.config`.
                let rev = self.handle.swap(shield);
                self.proxy
                    .pipeline
                    .chain()
                    .set_live_config(&cand.config.chain);
                self.status.set("config", Health::Ok, "");
                self.status.set_config(rev, cand.restart_required.clone());
                tracing::info!(rev, changed = ?cand.changed, restart_required = ?cand.restart_required, "config applied");
                self.bus.publish(BusEvent::ConfigApplied {
                    rev,
                    changed: cand.changed,
                    restart_required: cand.restart_required,
                });
                self.metrics.reload(true);
                // Task 7: enqueue a config-revision row when history is on.
                Ok(rev)
            }
            Err(issues) => {
                let joined = issues.join("; ");
                tracing::warn!(rev = live.rev, issues = %joined, "config reload rejected; the live config stays");
                self.status.set("config", Health::Warn, joined);
                self.bus.publish(BusEvent::ConfigRejected {
                    issues: issues.clone(),
                });
                self.metrics.reload(false);
                Err((issues, live.rev))
            }
        }
    }
}

/// A started listener: its stop flag and task.
struct Stage<T> {
    stop: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<T>>,
}

impl<T> Stage<T> {
    async fn stop(self) -> anyhow::Result<T> {
        let _ = self.stop.send(true);
        self.task
            .await
            .map_err(|e| anyhow::anyhow!("task failed: {e}"))?
    }
}

/// Supervised background tasks sharing one stop flag.
struct Tasks {
    stop: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
}

impl Tasks {
    async fn stop(self) {
        let _ = self.stop.send(true);
        for h in self.handles {
            let _ = h.await;
        }
    }
}

/// The metrics consumer: counts every decision and counts a lag as drops for
/// consumer `metrics`. The first receiver is made now, so no decision after
/// `start` returns is missed.
fn start_metrics_consumer(
    bus: &EventBus,
    metrics: Arc<Metrics>,
    status: Arc<StatusBoard>,
    stop: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mut first = Some(bus.subscribe());
    let bus = bus.clone();
    tokio::spawn(supervise("metrics", stop, move || {
        let mut rx = first.take().unwrap_or_else(|| bus.subscribe());
        let (metrics, status) = (metrics.clone(), status.clone());
        async move {
            loop {
                match rx.recv().await {
                    Ok(BusEvent::Decision(d)) => {
                        metrics.observe_decision(d.judgment.verdict, d.latency_us)
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(n)) => status.add_drops("metrics", n),
                    Err(RecvError::Closed) => return Ok(()),
                }
            }
        }
    }))
}

/// The running service. Dropping it without [`Runtime::stop`] also stops every
/// listener and task (their stop senders go away), without waiting for them.
pub struct Runtime {
    core: Arc<Core>,
    proxy_addr: SocketAddr,
    admin_addr: Option<SocketAddr>,
    history: bool,
    proxy: Stage<usize>,
    admin: Option<Stage<()>>,
    tasks: Tasks,
}

impl Runtime {
    /// Ordered start with rollback: load config (+exceptions, PerRequest clock) → [history: open db,
    /// migrate, record config revision "startup", restore active bans] → start bus consumers →
    /// admin listener → proxy listener. On any error, stop what started, in reverse, and return it.
    /// A non-loopback `admin_bind` fails before anything is loaded or bound.
    pub async fn start(opts: RuntimeOptions) -> anyhow::Result<Runtime> {
        Self::start_with(opts, DRAIN).await
    }

    /// [`Runtime::start`] with another drain limit (tests).
    async fn start_with(opts: RuntimeOptions, drain: Duration) -> anyhow::Result<Runtime> {
        if let Some(a) = opts.admin_bind {
            check_bind(a)?;
        }
        let cfg = read_config(opts.config_path.as_deref())
            .map_err(|v| anyhow::anyhow!("loading config: {}", v.join("; ")))?;
        let ex = read_exceptions(opts.exceptions_path.as_deref())
            .map_err(|v| anyhow::anyhow!("loading exceptions:\n{}", v.join("\n")))?;
        let handle = Arc::new(ConfigHandle::new(Arc::new(build_shield(cfg, ex))));
        let status = Arc::new(StatusBoard::new());
        status.set_config(1, Vec::new());
        let metrics = Arc::new(Metrics::new());

        // History: Task 7 replaces this.
        if opts.history {
            tracing::warn!("history not available in this build; running without it");
        }
        status.set("history", Health::Ok, "off");

        let bus = EventBus::new();
        let (tasks_stop, tasks_rx) = watch::channel(false);
        let tasks = Tasks {
            handles: vec![start_metrics_consumer(
                &bus,
                metrics.clone(),
                status.clone(),
                tasks_rx,
            )],
            stop: tasks_stop,
        };

        let audit = AuditSink::new(opts.audit.clone(), opts.audit_max_bytes);
        let ocsf = match &opts.ocsf {
            Some(p) => AuditSink::with_format(Some(p.clone()), opts.audit_max_bytes, Format::Ocsf),
            None => AuditSink::off(),
        };
        let proxy = Arc::new(
            ProxyState::with_handle(
                handle.clone(),
                opts.upstream.clone(),
                audit,
                ocsf,
                opts.enforce,
            )
            .with_bus(bus.clone()),
        );
        let core = Arc::new(Core {
            config_path: opts.config_path.clone(),
            exceptions_path: opts.exceptions_path.clone(),
            handle,
            proxy: proxy.clone(),
            bus,
            status: status.clone(),
            metrics: metrics.clone(),
            reload_lock: Mutex::new(()),
        });

        let (admin, admin_addr) = match opts.admin_bind {
            None => (None, None),
            Some(a) => match TcpListener::bind(a)
                .await
                .and_then(|l| Ok((l.local_addr()?, l)))
            {
                Ok((addr, l)) => {
                    let state = Arc::new(AdminState {
                        status: status.clone(),
                        metrics,
                        reload: core.clone(),
                    });
                    let (stop, rx) = watch::channel(false);
                    (
                        Some(Stage {
                            stop,
                            task: tokio::spawn(serve_admin(l, state, rx)),
                        }),
                        Some(addr),
                    )
                }
                Err(e) => {
                    tasks.stop().await;
                    anyhow::bail!("binding the admin listener on {a}: {e}");
                }
            },
        };

        let (listener, proxy_addr) = match TcpListener::bind(opts.bind)
            .await
            .and_then(|l| Ok((l.local_addr()?, l)))
        {
            Ok((addr, l)) => (l, addr),
            Err(e) => {
                if let Some(a) = admin {
                    let _ = a.stop().await;
                }
                tasks.stop().await;
                anyhow::bail!("binding the proxy listener on {}: {e}", opts.bind);
            }
        };
        let (stop, rx) = watch::channel(false);
        let proxy_stage = Stage {
            stop,
            task: tokio::spawn(vft_proxy::serve_until(proxy, listener, rx, drain)),
        };
        tracing::info!(%proxy_addr, admin = ?admin_addr, "venusflytrap started");
        Ok(Runtime {
            core,
            proxy_addr,
            admin_addr,
            history: false,
            proxy: proxy_stage,
            admin,
            tasks,
        })
    }

    /// Reload the config and exceptions files; see [`Reload::reload`].
    pub fn reload(&self) -> Result<u64, (Vec<String>, u64)> {
        self.core.reload()
    }

    pub fn status(&self) -> StatusRecord {
        self.core.status.snapshot()
    }

    /// The bound proxy address (the real port when `bind` asked for port 0).
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    /// The bound admin address; `None` when the admin listener is off.
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        self.admin_addr
    }

    /// Whether history is being recorded.
    pub fn history(&self) -> bool {
        self.history
    }

    /// The bus decisions, bans and config changes are published on.
    pub fn bus(&self) -> &EventBus {
        &self.core.bus
    }

    /// What SIGHUP does: one reload, logged; the outcome is on the status board.
    pub fn on_hup(&self) {
        self.core.on_hup();
    }

    /// Stop accepting, drain ≤ 10 s, stop admin, flush history, stop supervised tasks.
    pub async fn stop(self) -> anyhow::Result<()> {
        let Runtime {
            core,
            proxy,
            admin,
            tasks,
            ..
        } = self;
        let mut first_err = None;
        match proxy.stop().await {
            Ok(0) => {}
            Ok(open) => tracing::warn!(open, "connections still open after the drain were closed"),
            Err(e) => first_err = Some(e),
        }
        core.status.set("proxy", Health::Critical, "stopped");
        if let Some(a) = admin {
            if let Err(e) = a.stop().await {
                first_err.get_or_insert(e);
            }
        }
        // History flush: Task 7.
        tasks.stop().await;
        tracing::info!("venusflytrap stopped");
        first_err.map_or(Ok(()), Err)
    }

    /// Wait for Ctrl+C (all platforms) or SIGTERM (unix); SIGHUP (unix) calls reload and keeps waiting.
    pub async fn run_until_signal(self) -> anyhow::Result<()> {
        self.wait_for_shutdown().await?;
        tracing::info!("shutdown signal received");
        self.stop().await
    }

    #[cfg(unix)]
    async fn wait_for_shutdown(&self) -> anyhow::Result<()> {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        let mut hup = signal(SignalKind::hangup())?;
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            tokio::select! {
                r = &mut ctrl_c => return r.map_err(Into::into),
                _ = term.recv() => return Ok(()),
                _ = hup.recv() => {
                    // File and parse work: keep it off the async workers.
                    let core = self.core.clone();
                    let _ = tokio::task::spawn_blocking(move || core.on_hup()).await;
                }
            }
        }
    }

    #[cfg(not(unix))]
    async fn wait_for_shutdown(&self) -> anyhow::Result<()> {
        tokio::signal::ctrl_c().await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use vft_proxy::bus::BusEvent;

    const SQLI: &str = "/x?id=1%20union%20select%20a,b";

    /// A fresh empty directory under the system temp dir.
    fn tmpdir() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "vft-runtime-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Upstream stub: `200 ok` after `delay` (never, if `None`).
    async fn stub(delay: Option<Duration>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let _ = s.read(&mut buf).await;
                    match delay {
                        Some(d) => tokio::time::sleep(d).await,
                        None => std::future::pending::<()>().await,
                    }
                    let _ = s
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        addr
    }

    struct Env {
        dir: PathBuf,
        config: PathBuf,
    }

    impl Env {
        /// A temp dir with `shield.yaml` holding `yaml`.
        fn new(yaml: &str) -> Env {
            let dir = tmpdir();
            let config = dir.join("shield.yaml");
            std::fs::write(&config, yaml).unwrap();
            Env { dir, config }
        }

        fn write(&self, yaml: &str) {
            std::fs::write(&self.config, yaml).unwrap();
        }

        fn opts(&self, upstream: SocketAddr) -> RuntimeOptions {
            RuntimeOptions {
                bind: "127.0.0.1:0".parse().unwrap(),
                upstream: format!("http://{upstream}"),
                config_path: Some(self.config.clone()),
                exceptions_path: None,
                audit: Some(self.dir.join("audit.jsonl")),
                audit_max_bytes: 10 * 1024 * 1024,
                ocsf: None,
                enforce: true,
                admin_bind: Some("127.0.0.1:0".parse().unwrap()),
                state_dir: self.dir.join("state"),
                history: false,
            }
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// One request with `Connection: close`; (status, body). Status 0 when the
    /// connection ended without a status line.
    async fn http(
        addr: SocketAddr,
        method: &str,
        target: &str,
        extra: &[(&str, &str)],
    ) -> (u16, String) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut raw = format!("{method} {target} HTTP/1.1\r\nHost: shop.test\r\nConnection: close\r\nContent-Length: 0\r\n");
        for (k, v) in extra {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str("\r\n");
        s.write_all(raw.as_bytes()).await.unwrap();
        read_response(s).await
    }

    async fn read_response(mut s: TcpStream) -> (u16, String) {
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        let text = String::from_utf8_lossy(&out).into_owned();
        let status = text
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    async fn status_json(rt: &Runtime) -> serde_json::Value {
        let (code, body) = http(rt.admin_addr().unwrap(), "GET", "/api/v1/status", &[]).await;
        assert_eq!(code, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    }

    fn config_health(rec: &StatusRecord) -> (Health, String) {
        let c = rec.components.iter().find(|c| c.name == "config").unwrap();
        (c.health, c.reason.clone())
    }

    #[tokio::test]
    async fn start_serves_proxy_and_admin_and_stop_releases_both_ports() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let (proxy, admin) = (rt.proxy_addr(), rt.admin_addr().unwrap());
        assert_ne!(proxy.port(), 0);
        assert_eq!(
            http(proxy, "GET", "/products?page=2", &[]).await,
            (200, "ok".to_string())
        );
        assert_eq!(http(proxy, "GET", SQLI, &[]).await.0, 403);
        let (code, body) = http(admin, "GET", "/api/v1/health", &[]).await;
        assert_eq!((code, body.as_str()), (200, r#"{"ok":true}"#));
        let st = rt.status();
        assert_eq!(st.config_rev, 1);
        assert_eq!(st.health, Health::Ok, "{st:?}");
        assert!(!rt.history());
        rt.stop().await.unwrap();
        TcpListener::bind(proxy).await.expect("proxy port released");
        TcpListener::bind(admin).await.expect("admin port released");
    }

    #[tokio::test]
    async fn the_metrics_consumer_counts_decisions() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        assert_eq!(http(rt.proxy_addr(), "GET", "/", &[]).await.0, 200);
        assert_eq!(http(rt.proxy_addr(), "GET", SQLI, &[]).await.0, 403);
        let admin = rt.admin_addr().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (_, text) = http(admin, "GET", "/metrics", &[]).await;
            if text.contains("vft_requests_total{verdict=\"allow\"} 1")
                && text.contains("vft_requests_total{verdict=\"block\"} 1")
            {
                assert!(text.contains("vft_config_rev 1"), "{text}");
                break;
            }
            assert!(Instant::now() < deadline, "decisions not counted:\n{text}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn admin_bind_none_runs_without_an_admin_listener() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let mut o = env.opts(up);
        o.admin_bind = None;
        let rt = Runtime::start(o).await.unwrap();
        assert!(rt.admin_addr().is_none());
        assert_eq!(http(rt.proxy_addr(), "GET", "/", &[]).await.0, 200);
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn history_requested_is_accepted_but_off_in_this_build() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let mut o = env.opts(up);
        o.history = true;
        let rt = Runtime::start(o).await.unwrap();
        assert!(!rt.history());
        assert_eq!(rt.status().health, Health::Ok);
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn reload_applies_a_changed_file() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let mut rx = rt.bus().subscribe();
        env.write("version: 1\nscoring:\n  block_at: 95\n");
        assert_eq!(rt.reload(), Ok(2));
        assert_eq!(rt.core.handle.load().shield.config().scoring.block_at, 95);
        let st = rt.status();
        assert_eq!(st.config_rev, 2);
        assert_eq!(config_health(&st).0, Health::Ok);
        assert!(st.restart_required.is_empty());
        loop {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                BusEvent::ConfigApplied {
                    rev,
                    changed,
                    restart_required,
                } => {
                    assert_eq!(rev, 2);
                    assert_eq!(changed, vec!["scoring.block_at".to_string()]);
                    assert!(restart_required.is_empty());
                    break;
                }
                BusEvent::Decision(_) | BusEvent::BanChanged { .. } => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(status_json(&rt).await["config_rev"], 2);
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn an_invalid_file_is_rejected_with_422_and_a_later_success_clears_the_warning() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let mut rx = rt.bus().subscribe();
        env.write("version: 1\nscoring:\n  block_at: 500\n");
        let (code, body) = http(rt.admin_addr().unwrap(), "POST", "/api/v1/reload", &[]).await;
        assert_eq!(code, 422, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["rev"], 1);
        assert!(
            v["issues"][0]
                .as_str()
                .unwrap()
                .contains("scoring.block_at"),
            "{body}"
        );
        assert_eq!(rt.core.handle.load().rev, 1, "nothing swapped");
        let st = rt.status();
        assert_eq!(st.config_rev, 1);
        let (health, reason) = config_health(&st);
        assert_eq!(health, Health::Warn);
        assert!(reason.contains("scoring.block_at"), "{reason}");
        match tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            BusEvent::ConfigRejected { issues } => {
                assert!(issues[0].contains("scoring.block_at"), "{issues:?}")
            }
            other => panic!("expected ConfigRejected, got {other:?}"),
        }
        // A file that does not parse is rejected the same way.
        env.write("version: [\n");
        assert_eq!(rt.reload().unwrap_err().1, 1);
        // A later success clears the warning.
        env.write("version: 1\nscoring:\n  block_at: 92\n");
        let (code, body) = http(rt.admin_addr().unwrap(), "POST", "/api/v1/reload", &[]).await;
        assert_eq!((code, body.as_str()), (200, r#"{"rev":2}"#));
        assert_eq!(config_health(&rt.status()), (Health::Ok, String::new()));
        let (_, metrics) = http(rt.admin_addr().unwrap(), "GET", "/metrics", &[]).await;
        assert!(
            metrics.contains("vft_reloads_total{result=\"applied\"} 1"),
            "{metrics}"
        );
        assert!(
            metrics.contains("vft_reloads_total{result=\"rejected\"} 2"),
            "{metrics}"
        );
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn a_restart_only_change_is_reported_and_not_applied() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let live = rt.core.handle.load().shield.config().limits.max_body;
        env.write(&format!(
            "version: 1\nlimits:\n  max_body: {}\nscoring:\n  block_at: 93\n",
            live * 2
        ));
        assert_eq!(rt.reload(), Ok(2));
        let cur = rt.core.handle.load();
        assert_eq!(
            cur.shield.config().limits.max_body,
            live,
            "restart-only value stays live"
        );
        assert_eq!(
            cur.shield.config().scoring.block_at,
            93,
            "the live change applies"
        );
        assert_eq!(
            rt.status().restart_required,
            vec!["limits.max_body".to_string()]
        );
        assert_eq!(
            status_json(&rt).await["restart_required"],
            serde_json::json!(["limits.max_body"])
        );
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn reload_rejects_an_invalid_exceptions_file_and_applies_a_valid_one() {
        let env = Env::new("version: 1\n");
        let exc = env.dir.join("exceptions.yaml");
        std::fs::write(&exc, "version: 1\nexceptions: []\n").unwrap();
        let up = stub(Some(Duration::ZERO)).await;
        let mut o = env.opts(up);
        o.exceptions_path = Some(exc.clone());
        let rt = Runtime::start(o).await.unwrap();
        std::fs::write(&exc, "version: [\n").unwrap();
        let (issues, rev) = rt.reload().unwrap_err();
        assert_eq!(rev, 1);
        assert!(
            issues
                .iter()
                .all(|i| i.starts_with(&exc.display().to_string())),
            "{issues:?}"
        );
        std::fs::write(&exc, "version: 1\nexceptions: []\n").unwrap();
        assert_eq!(rt.reload(), Ok(2));
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn start_fails_on_an_invalid_exceptions_file() {
        let env = Env::new("version: 1\n");
        let exc = env.dir.join("exceptions.yaml");
        std::fs::write(&exc, "version: [\n").unwrap();
        let up = stub(Some(Duration::ZERO)).await;
        let mut o = env.opts(up);
        o.exceptions_path = Some(exc);
        let err = Runtime::start(o)
            .await
            .err()
            .expect("start fails")
            .to_string();
        assert!(err.contains("exceptions"), "{err}");
    }

    #[tokio::test]
    async fn reload_lowering_exploitation_blocks_changes_when_a_source_gets_banned() {
        // Trust the loopback peer so X-Forwarded-For picks the source.
        let base = "version: 1\nproxy:\n  trusted_proxies: [\"127.0.0.1\"]\n";
        let env = Env::new(base);
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let p = rt.proxy_addr();
        let from = |ip: &'static str| [("X-Forwarded-For", ip)];
        // Default policy: one exploitation block does not ban.
        assert_eq!(http(p, "GET", SQLI, &from("198.51.100.1")).await.0, 403);
        assert_eq!(
            http(p, "GET", "/", &from("198.51.100.1")).await.0,
            200,
            "not banned yet"
        );
        env.write(&format!(
            "{base}chain:\n  ban_policy:\n    exploitation_blocks: 1\n"
        ));
        assert_eq!(rt.reload(), Ok(2));
        assert_eq!(http(p, "GET", SQLI, &from("198.51.100.2")).await.0, 403);
        assert_eq!(
            http(p, "GET", "/", &from("198.51.100.2")).await.0,
            403,
            "one block bans after the reload"
        );
        rt.stop().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reloads_under_load_fail_no_request() {
        let base = "version: 1\nproxy:\n  trusted_proxies: [\"127.0.0.1\"]\n";
        let env = Arc::new(Env::new(base));
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let p = rt.proxy_addr();
        let clients: Vec<_> = (0..4u32)
            .map(|c| {
                tokio::spawn(async move {
                    let mut bad = Vec::new();
                    for i in 0..500u32 {
                        let attack = i % 25 == 0;
                        // Every attack from its own source, so no source is ever banned.
                        let ip = if attack {
                            format!("203.0.113.{}", (c * 20 + i / 25) % 250 + 1)
                        } else {
                            format!("198.51.100.{}", c + 1)
                        };
                        let target = if attack { SQLI } else { "/products?page=2" };
                        let (code, _) =
                            http(p, "GET", target, &[("X-Forwarded-For", ip.as_str())]).await;
                        let want = if attack { 403 } else { 200 };
                        if code != want {
                            bad.push(format!("client {c} #{i} {target}: {code}"));
                        }
                    }
                    bad
                })
            })
            .collect();
        let core = rt.core.clone();
        let env2 = env.clone();
        let revs = tokio::task::spawn_blocking(move || {
            let mut revs = Vec::new();
            for n in 0..20u8 {
                env2.write(&format!("{base}scoring:\n  block_at: {}\n", 90 + n % 5));
                revs.push(core.reload().expect("valid file"));
                std::thread::sleep(Duration::from_millis(10));
            }
            revs
        })
        .await
        .unwrap();
        assert_eq!(revs, (2..=21).collect::<Vec<u64>>());
        let mut failed = Vec::new();
        for c in clients {
            failed.extend(c.await.unwrap());
        }
        assert!(
            failed.is_empty(),
            "{} failed:\n{}",
            failed.len(),
            failed.join("\n")
        );
        assert_eq!(rt.status().config_rev, 21);
        rt.stop().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reloads_are_serialized() {
        let env = Env::new("version: 1\nscoring:\n  block_at: 91\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        let mut rx = rt.bus().subscribe();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let core = rt.core.clone();
                std::thread::spawn(move || {
                    (0..10).map(|_| core.reload().unwrap()).collect::<Vec<_>>()
                })
            })
            .collect();
        let mut revs: Vec<u64> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect();
        revs.sort_unstable();
        assert_eq!(revs, (2..=81).collect::<Vec<u64>>());
        // The board always ends at the live revision.
        assert_eq!(rt.status().config_rev, 81);
        assert_eq!(rt.core.handle.load().rev, 81);
        // ConfigApplied events come out in revision order.
        let mut published = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let BusEvent::ConfigApplied { rev, .. } = ev {
                published.push(rev);
            }
        }
        assert_eq!(published, (2..=81).collect::<Vec<u64>>());
        rt.stop().await.unwrap();
    }

    #[tokio::test]
    async fn on_hup_reloads() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let rt = Runtime::start(env.opts(up)).await.unwrap();
        env.write("version: 1\nscoring:\n  block_at: 94\n");
        rt.on_hup();
        assert_eq!(rt.status().config_rev, 2);
        assert_eq!(rt.core.handle.load().shield.config().scoring.block_at, 94);
        // A rejected reload through the signal path keeps the live config.
        env.write("version: 1\nscoring:\n  block_at: 0\n");
        rt.on_hup();
        assert_eq!(rt.status().config_rev, 2);
        assert_eq!(config_health(&rt.status()).0, Health::Warn);
        rt.stop().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_in_flight_request_completes_when_stop_is_called() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::from_millis(300))).await;
        let rt = Runtime::start_with(env.opts(up), Duration::from_millis(500))
            .await
            .unwrap();
        let p = rt.proxy_addr();
        let req = tokio::spawn(async move { http(p, "GET", "/", &[]).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        rt.stop().await.unwrap();
        assert_eq!(req.await.unwrap(), (200, "ok".to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_request_that_never_finishes_is_cut_off_at_the_drain_limit() {
        let env = Env::new("version: 1\n");
        let up = stub(None).await;
        let rt = Runtime::start_with(env.opts(up), Duration::from_millis(500))
            .await
            .unwrap();
        let p = rt.proxy_addr();
        let req = tokio::spawn(async move { http(p, "GET", "/", &[]).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let t = Instant::now();
        rt.stop().await.unwrap();
        let took = t.elapsed();
        assert!(
            took >= Duration::from_millis(450) && took < Duration::from_secs(3),
            "{took:?}"
        );
        let (code, _) = tokio::time::timeout(Duration::from_secs(5), req)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(code, 0, "cut off without a response");
    }

    #[tokio::test]
    async fn a_non_loopback_admin_bind_fails_before_anything_binds() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        // Hold the proxy port: had the proxy bound first, the error would be "in use".
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut o = env.opts(up);
        o.bind = held.local_addr().unwrap();
        o.admin_bind = Some("0.0.0.0:8899".parse().unwrap());
        let err = Runtime::start(o)
            .await
            .err()
            .expect("start fails")
            .to_string();
        assert!(err.contains("loopback"), "{err}");
    }

    #[tokio::test]
    async fn a_failed_proxy_bind_rolls_back_the_admin_listener() {
        let env = Env::new("version: 1\n");
        let up = stub(Some(Duration::ZERO)).await;
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin = {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap()
        };
        let mut o = env.opts(up);
        o.bind = held.local_addr().unwrap();
        o.admin_bind = Some(admin);
        assert!(Runtime::start(o).await.is_err());
        TcpListener::bind(admin)
            .await
            .expect("admin port released by the rollback");
    }
}
