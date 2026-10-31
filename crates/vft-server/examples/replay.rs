//! Replay a raw-request corpus through a full `Runtime` (proxy, bus consumers,
//! optional history) at a fixed rate and print one JSON report.
//!
//! ```text
//! cargo run --release -p vft-server --example replay -- \
//!   --corpus <dir of .white/.black files> --state-dir <fresh dir> \
//!   [--manifest <manifest.tsv> --side dev] [--rate 1000] [--seconds 60] [--clients 32] \
//!   [--history on|off] [--reload-every-ms 3000]
//! ```
//!
//! - The corpus files are raw HTTP/1.1 requests (`*.white` benign, `*.black`
//!   malicious), read recursively and cycled in path order. With `--manifest`
//!   and `--side`, only the rows the split manifest (`eval/split.py`) puts on
//!   that side are used; measurements use `--side dev`, never `heldout`.
//! - Each file is re-framed like `venusflytrap eval --mode tcp` does: its own
//!   `X-Forwarded-For` (a distinct 10.x.y.z per request, so no source is ever
//!   banned by an earlier request), `Connection: close`, an exact
//!   `Content-Length`. Files with `Transfer-Encoding` or `Upgrade` are skipped.
//! - The runtime listens on 127.0.0.1:0 with its admin listener on
//!   127.0.0.1:0, an audit file and the history database in `--state-dir`
//!   (the directory must be fresh: use a new one per run). Its upstream is an
//!   in-process stub that answers every request 200 with an empty body.
//! - `--clients` tasks on their own runtime send request `i` at `i / rate`
//!   seconds after the start (open loop), one connection per request, until
//!   `rate * seconds` requests have been sent. If the clients cannot keep the
//!   schedule the run takes longer than `--seconds`; `achieved_rate` and
//!   `schedule_lag_ms` show it.
//! - `--reload-every-ms N` calls `Runtime::reload` every N ms (the first one at
//!   once), after rewriting the config file so `history.allow_sample_rate`
//!   alternates between 0.01 and 0.02 (a Live option), so every reload swaps in a
//!   different config.
//!
//! Report fields: `sent`, `ok` (status 200 or 403), `rejected` (400, 413, 431 or
//! 501: the proxy refused a malformed corpus request at the HTTP layer, before
//! any decision, as in `venusflytrap eval --mode tcp`'s `proxy_rejected`),
//! `failed` (anything else, including i/o errors and 5xx), client-side latency `p50_ms`/`p95_ms`/`p99_ms`
//! (connect to end of reply), `reloads_applied`, `history_written`,
//! `history_dropped`, and the server's own counters read from `/metrics`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vft_server::runtime::{Runtime, RuntimeOptions};

struct Args {
    corpus: PathBuf,
    manifest: Option<PathBuf>,
    side: Option<String>,
    rate: f64,
    seconds: u64,
    clients: usize,
    history: bool,
    reload_every_ms: Option<u64>,
    state_dir: PathBuf,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut a = Args {
        corpus: PathBuf::new(),
        manifest: None,
        side: None,
        rate: 1000.0,
        seconds: 60,
        clients: 32,
        history: true,
        reload_every_ms: None,
        state_dir: PathBuf::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut val = || {
            it.next()
                .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--corpus" => a.corpus = val()?.into(),
            "--manifest" => a.manifest = Some(val()?.into()),
            "--side" => a.side = Some(val()?),
            "--rate" => a.rate = val()?.parse()?,
            "--seconds" => a.seconds = val()?.parse()?,
            "--clients" => a.clients = val()?.parse()?,
            "--history" => {
                a.history = match val()?.as_str() {
                    "on" => true,
                    "off" => false,
                    other => anyhow::bail!("--history on|off, got {other:?}"),
                }
            }
            "--reload-every-ms" => a.reload_every_ms = Some(val()?.parse()?),
            "--state-dir" => a.state_dir = val()?.into(),
            other => anyhow::bail!("unknown flag {other}"),
        }
    }
    if a.corpus.as_os_str().is_empty() || a.state_dir.as_os_str().is_empty() {
        anyhow::bail!("--corpus and --state-dir are required");
    }
    if a.manifest.is_some() != a.side.is_some() {
        anyhow::bail!("--manifest and --side go together");
    }
    if a.rate <= 0.0 || a.seconds == 0 || a.clients == 0 {
        anyhow::bail!("--rate, --seconds and --clients must be positive");
    }
    Ok(a)
}

/// A request with its framing headers removed; the per-request ones are added at send time.
struct Prepared {
    head: Vec<u8>,
    body: Vec<u8>,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Split a raw request into request line + headers (without the framing
/// headers `eval --mode tcp` replaces) and body. `None` for Transfer-Encoding / Upgrade.
fn prepare(raw: &[u8]) -> Option<Prepared> {
    let (head, body) = if let Some(i) = find(raw, b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = find(raw, b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &raw[raw.len()..])
    };
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let mut out = lines.next()?.to_vec();
    out.extend_from_slice(b"\r\n");
    for line in lines {
        let name = line
            .split(|&b| b == b':')
            .next()
            .unwrap_or(b"")
            .trim_ascii()
            .to_ascii_lowercase();
        match name.as_slice() {
            b"transfer-encoding" | b"upgrade" => return None,
            b"connection" | b"content-length" | b"x-forwarded-for" | b"keep-alive"
            | b"proxy-connection" => continue,
            _ => {}
        }
        if !line.is_empty() {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    Some(Prepared {
        head: out,
        body: body.to_vec(),
    })
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            walk(root, &p, out)?;
        } else if matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("white" | "black")
        ) {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, p));
        }
    }
    Ok(())
}

/// `(files found, files used, skipped as not replayable or unreadable, the prepared requests)`.
fn load(a: &Args) -> anyhow::Result<(usize, Vec<Prepared>, usize)> {
    let mut files = Vec::new();
    walk(&a.corpus, &a.corpus, &mut files)?;
    files.sort();
    let found = files.len();
    if let (Some(m), Some(side)) = (&a.manifest, &a.side) {
        let text = std::fs::read_to_string(m)?;
        let on_side: std::collections::HashSet<&str> = text
            .lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split('\t').collect();
                (c.len() == 4 && c[3] == side).then_some(c[0])
            })
            .collect();
        files.retain(|(rel, _)| on_side.contains(rel.as_str()));
    }
    let mut out = Vec::with_capacity(files.len());
    let mut skipped = 0;
    for (_, p) in &files {
        match std::fs::read(p).ok().and_then(|raw| prepare(&raw)) {
            Some(r) => out.push(r),
            None => skipped += 1,
        }
    }
    if out.is_empty() {
        anyhow::bail!("no replayable request files under {}", a.corpus.display());
    }
    Ok((found, out, skipped))
}

/// The Content-Length of a request head (0 when absent); `None` for
/// `Transfer-Encoding` or a length that does not parse.
fn content_length(head: &[u8]) -> Option<usize> {
    let mut len = 0usize;
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            len = std::str::from_utf8(line[colon + 1..].trim_ascii())
                .ok()?
                .parse()
                .ok()?;
        }
    }
    Some(len)
}

/// Stub upstream: an empty 200 per request, connection kept open.
async fn serve_keepalive(mut s: TcpStream) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let head_end = loop {
            if let Some(i) = find(&buf, b"\r\n\r\n") {
                break i + 4;
            }
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let Some(body_len) = content_length(&buf[..head_end]) else {
            return;
        };
        while buf.len() < head_end + body_len {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf.drain(..head_end + body_len);
        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
    }
}

const IO_LIMIT: Duration = Duration::from_secs(10);

/// Status of the reply to `raw`, or an error text. Zero linger: closing sends
/// RST, so no TIME_WAIT builds up on loopback.
async fn send(addr: SocketAddr, raw: &[u8]) -> Result<u16, String> {
    let mut sock = match tokio::time::timeout(IO_LIMIT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connect: {e}")),
        Err(_) => return Err("connect timeout".into()),
    };
    let _ = sock.set_zero_linger();
    let write_err = match tokio::time::timeout(IO_LIMIT, sock.write_all(raw)).await {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(format!("write: {e}")),
        Err(_) => Some("write timeout".to_string()),
    };
    let mut resp = Vec::new();
    let _ = tokio::time::timeout(IO_LIMIT, sock.read_to_end(&mut resp)).await;
    let status: u16 = std::str::from_utf8(&resp)
        .ok()
        .and_then(|t| t.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    match (status, write_err) {
        (0, Some(e)) => Err(e),
        (0, None) => Err("no parsable status line in reply".into()),
        (code, _) => Ok(code),
    }
}

#[derive(Default)]
struct ClientStats {
    latency_us: Vec<u32>,
    lag_us: Vec<u32>,
    statuses: BTreeMap<String, u64>,
    ok: u64,
    rejected: u64,
    failed: u64,
}

async fn client(
    k: usize,
    n_clients: usize,
    total: u64,
    rate: f64,
    start: Instant,
    proxy: SocketAddr,
    corpus: Arc<Vec<Prepared>>,
) -> ClientStats {
    let mut st = ClientStats::default();
    let mut idx = k as u64;
    while idx < total {
        let due = start + Duration::from_secs_f64(idx as f64 / rate);
        let now = Instant::now();
        if now < due {
            tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
        }
        st.lag_us.push(
            u32::try_from(Instant::now().saturating_duration_since(due).as_micros())
                .unwrap_or(u32::MAX),
        );
        let p = &corpus[usize::try_from(idx).unwrap_or(0) % corpus.len()];
        let ip = Ipv4Addr::new(
            10,
            ((idx >> 16) & 255) as u8,
            ((idx >> 8) & 255) as u8,
            (idx & 255) as u8,
        );
        let mut raw = Vec::with_capacity(p.head.len() + p.body.len() + 96);
        raw.extend_from_slice(&p.head);
        raw.extend_from_slice(
            format!(
                "X-Forwarded-For: {ip}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                p.body.len()
            )
            .as_bytes(),
        );
        raw.extend_from_slice(&p.body);
        let t = Instant::now();
        let r = send(proxy, &raw).await;
        st.latency_us
            .push(u32::try_from(t.elapsed().as_micros()).unwrap_or(u32::MAX));
        match r {
            Ok(code @ (200 | 403)) => {
                st.ok += 1;
                *st.statuses.entry(code.to_string()).or_default() += 1;
            }
            Ok(code @ (400 | 413 | 431 | 501)) => {
                st.rejected += 1;
                *st.statuses.entry(code.to_string()).or_default() += 1;
            }
            Ok(code) => {
                st.failed += 1;
                *st.statuses.entry(code.to_string()).or_default() += 1;
            }
            Err(e) => {
                st.failed += 1;
                *st.statuses.entry(e).or_default() += 1;
            }
        }
        idx += n_clients as u64;
    }
    st
}

/// Nearest-rank percentile of an ascending slice, in ms.
fn pct(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    f64::from(sorted[rank.min(sorted.len()) - 1]) / 1000.0
}

fn dist(mut v: Vec<u32>) -> serde_json::Value {
    v.sort_unstable();
    serde_json::json!({
        "p50_ms": pct(&v, 50.0), "p95_ms": pct(&v, 95.0), "p99_ms": pct(&v, 99.0),
        "max_ms": v.last().map_or(0.0, |m| f64::from(*m) / 1000.0),
    })
}

/// One `GET /metrics` on the admin listener.
async fn scrape(admin: SocketAddr) -> anyhow::Result<BTreeMap<String, f64>> {
    let mut s = TcpStream::connect(admin).await?;
    // The admin listener serves only `Host: <its loopback ip:port>`.
    let req = format!("GET /metrics HTTP/1.1\r\nHost: {admin}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut text = String::new();
    s.read_to_string(&mut text).await?;
    let mut m = BTreeMap::new();
    for line in text.lines().filter(|l| l.starts_with("vft_")) {
        if let Some((k, v)) = line.rsplit_once(' ') {
            if let Ok(v) = v.parse::<f64>() {
                m.insert(k.to_string(), v);
            }
        }
    }
    Ok(m)
}

fn config_text(sample_rate: f64) -> String {
    format!(
        "proxy:\n  trusted_proxies: [\"127.0.0.1\"]\nhistory:\n  allow_sample_rate: {sample_rate}\n"
    )
}

async fn run(
    a: Args,
    corpus: Arc<Vec<Prepared>>,
    client_rt: tokio::runtime::Handle,
) -> anyhow::Result<serde_json::Value> {
    std::fs::create_dir_all(&a.state_dir)?;
    let stub = TcpListener::bind("127.0.0.1:0").await?;
    let stub_addr = stub.local_addr()?;
    tokio::spawn(async move {
        while let Ok((s, _)) = stub.accept().await {
            tokio::spawn(serve_keepalive(s));
        }
    });
    let config_path = a.state_dir.join("replay-config.yaml");
    std::fs::write(&config_path, config_text(0.01))?;
    let runtime = Arc::new(
        Runtime::start(RuntimeOptions {
            bind: "127.0.0.1:0".parse()?,
            upstream: format!("http://{stub_addr}"),
            config_path: Some(config_path.clone()),
            exceptions_path: None,
            audit: Some(a.state_dir.join("audit.jsonl")),
            audit_max_bytes: 100 * 1024 * 1024,
            ocsf: None,
            enforce: true,
            admin_bind: Some("127.0.0.1:0".parse()?),
            state_dir: a.state_dir.clone(),
            history: a.history,
        })
        .await?,
    );
    let proxy = runtime.proxy_addr();
    let admin = runtime
        .admin_addr()
        .ok_or_else(|| anyhow::anyhow!("no admin listener"))?;

    let total = (a.rate * a.seconds as f64).round() as u64;
    let start = Instant::now() + Duration::from_millis(200);
    let end = start + Duration::from_secs(a.seconds);

    // Reloads: the first at once, then every N ms, until the run's nominal end.
    let reloader = a.reload_every_ms.map(|every| {
        let rt = runtime.clone();
        let path = config_path.clone();
        tokio::spawn(async move {
            let (mut applied, mut rejected) = (0u64, 0u64);
            let mut iv = tokio::time::interval_at(
                tokio::time::Instant::from_std(start),
                Duration::from_millis(every),
            );
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut flip = false;
            loop {
                iv.tick().await;
                if Instant::now() >= end {
                    break;
                }
                flip = !flip;
                let _ = std::fs::write(&path, config_text(if flip { 0.02 } else { 0.01 }));
                let rt2 = rt.clone();
                match tokio::task::spawn_blocking(move || rt2.reload()).await {
                    Ok(Ok(_)) => applied += 1,
                    _ => rejected += 1,
                }
            }
            (applied, rejected)
        })
    });

    let mut handles = Vec::new();
    for k in 0..a.clients {
        handles.push(client_rt.spawn(client(
            k,
            a.clients,
            total,
            a.rate,
            start,
            proxy,
            corpus.clone(),
        )));
    }
    let mut all = ClientStats::default();
    for h in handles {
        let s = h.await?;
        all.latency_us.extend(s.latency_us);
        all.lag_us.extend(s.lag_us);
        all.ok += s.ok;
        all.rejected += s.rejected;
        all.failed += s.failed;
        for (k, v) in s.statuses {
            *all.statuses.entry(k).or_default() += v;
        }
    }
    let finished = Instant::now();
    let (reloads_applied, reloads_rejected) = match reloader {
        Some(h) => h.await?,
        None => (0, 0),
    };

    // Let the history writer drain (the queue is empty and nothing more is written).
    let mut metrics = scrape(admin).await?;
    if a.history {
        let mut stable = 0;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let next = scrape(admin).await?;
            let same = next.get("vft_history_rows_written_total")
                == metrics.get("vft_history_rows_written_total")
                && next.get("vft_history_queue_depth") == Some(&0.0);
            metrics = next;
            stable = if same { stable + 1 } else { 0 };
            if stable >= 2 {
                break;
            }
        }
    }
    let get = |k: &str| metrics.get(k).copied().unwrap_or(0.0);
    let requests_total: f64 = metrics
        .iter()
        .filter(|(k, _)| k.starts_with("vft_requests_total{"))
        .map(|(_, v)| *v)
        .sum();
    let server = serde_json::json!({
        "requests_total": requests_total,
        "reloads_applied": get("vft_reloads_total{result=\"applied\"}"),
        "reloads_rejected": get("vft_reloads_total{result=\"rejected\"}"),
        "bus_dropped_history": get("vft_bus_dropped_total{consumer=\"history\"}"),
        "bus_dropped_metrics": get("vft_bus_dropped_total{consumer=\"metrics\"}"),
        "config_rev": get("vft_config_rev"),
    });
    let (written, dropped) = (
        get("vft_history_rows_written_total"),
        get("vft_history_rows_dropped_total"),
    );

    Arc::try_unwrap(runtime)
        .map_err(|_| anyhow::anyhow!("the runtime is still shared"))?
        .stop()
        .await?;

    // What the store holds after the clean stop.
    let db = if a.history {
        let conn = vft_server::history::read::open_read_only(&a.state_dir)?;
        let q = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
        serde_json::json!({
            "rollup_decisions": q("SELECT COALESCE(SUM(count), 0) FROM rollup_minute")?,
            "requests_rows": q("SELECT COUNT(*) FROM requests")?,
            "config_revisions": q("SELECT COUNT(*) FROM config_revisions")?,
        })
    } else {
        serde_json::Value::Null
    };

    let sent = all.ok + all.rejected + all.failed;
    let elapsed = finished.saturating_duration_since(start).as_secs_f64();
    Ok(serde_json::json!({
        "history": a.history,
        "target_rate": a.rate,
        "seconds": a.seconds,
        "clients": a.clients,
        "corpus_requests": corpus.len(),
        "sent": sent,
        "ok": all.ok,
        "rejected": all.rejected,
        "failed": all.failed,
        "statuses": all.statuses,
        "elapsed_s": elapsed,
        "achieved_rate": sent as f64 / elapsed,
        "latency": dist(all.latency_us),
        "schedule_lag_ms": dist(all.lag_us),
        "reloads_applied": reloads_applied,
        "reloads_rejected": reloads_rejected,
        "history_written": written,
        "history_dropped": dropped,
        "server": server,
        "db": db,
    }))
}

fn main() -> anyhow::Result<()> {
    let a = parse_args()?;
    let (found, corpus, skipped) = load(&a)?;
    eprintln!(
        "replay: {} files found, {} used, {} not replayable or unreadable",
        found,
        corpus.len(),
        skipped
    );
    let corpus = Arc::new(corpus);
    let server_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()?;
    let client_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let report = server_rt.block_on(run(a, corpus, client_rt.handle().clone()))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
