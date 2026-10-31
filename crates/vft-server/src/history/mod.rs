//! The SQLite history store: every decision as a per-minute rollup, the
//! decisions worth keeping as rows (see [`keep`]), kill-chain events, bans and
//! config revisions.
//!
//! One writer thread owns the only write connection. Producers hand it
//! [`WriteMsg`]s through bounded queues with `try_send`, so recording history
//! never blocks the proxy: a full queue drops the message and counts it.
//! Bans and config revisions have their own small control queue, which the
//! writer always drains before the decision queue, so a decision flood cannot
//! crowd them out.

pub mod query;
pub mod read;
mod retention;
mod schema;
mod writer;

use crate::metrics::Metrics;
use crate::sha256::sha256_hex;
use crate::status::StatusBoard;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use vft_core::config::HistoryConfig;
use vft_core::{BanRecord, Judgment, Verdict};
use vft_proxy::bus::DecisionEvent;

pub use retention::{active_bans, sweep};
pub use schema::USER_VERSION;

/// One unit of work for the writer thread.
#[derive(Debug)]
pub enum WriteMsg {
    Decision(Arc<DecisionEvent>),
    Ban {
        key: String,
        ban: Option<BanRecord>,
        lifted: bool,
        ts_ms: u64,
    },
    ConfigRevision {
        rev: u64,
        ts_ms: u64,
        source: &'static str,
        config_sha256: String,
        exceptions_sha256: String,
        changed_keys: Vec<String>,
    },
    /// Delete what retention no longer keeps ([`sweep`]): commit the pending batch, then
    /// delete in transactions of at most 5,000 rows on the writer's connection.
    Sweep {
        now_ms: u64,
        retention_days: u32,
    },
    /// Upsert every (key, ban) as a `bans` row, as `Ban` with `lifted` false
    /// does; [`HistoryQueue::snapshot_bans`] sends it at stop.
    BanSnapshot(Vec<(String, BanRecord)>),
    /// Commit everything before this message, then send `()` (the sender may block).
    Flush(SyncSender<()>),
}

impl WriteMsg {
    /// Bans, config revisions and ban snapshots go on the control queue.
    fn is_control(&self) -> bool {
        matches!(
            self,
            WriteMsg::Ban { .. } | WriteMsg::ConfigRevision { .. } | WriteMsg::BanSnapshot(_)
        )
    }
}

/// State shared by every queue clone and the writer thread.
#[derive(Debug, Default)]
struct Shared {
    dropped: AtomicU64,
    written: AtomicU64,
    /// Messages sent (on either queue) and not yet taken by the writer.
    depth: AtomicU64,
    /// `allow_sample_rate` per config revision, ascending by revision (a
    /// Live option): a decision is sampled with the rate of the config that
    /// decided it, whenever the writer gets to it.
    rates: Mutex<Vec<(u64, f64)>>,
    /// Set by `close`: the writer exits after the next flush.
    stop: AtomicBool,
}

/// Revisions of sample rates kept; older revisions use the oldest kept rate.
const RATES_KEPT: usize = 16;

impl Shared {
    /// Count `n` dropped messages (a full decision queue, or the rows of a
    /// failed batch) under consumer `history-writer`.
    fn drop_n(&self, metrics: &Metrics, status: &StatusBoard, n: u64) {
        self.dropped.fetch_add(n, Relaxed);
        metrics.history_dropped(n);
        status.add_drops("history-writer", n);
    }

    fn rates(&self) -> std::sync::MutexGuard<'_, Vec<(u64, f64)>> {
        self.rates.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The rate in effect at `rev`: the entry with the highest revision not above
/// it, else the oldest entry, else 0.
fn rate_at(rates: &[(u64, f64)], rev: u64) -> f64 {
    rates
        .iter()
        .rev()
        .find(|(r, _)| *r <= rev)
        .or(rates.first())
        .map_or(0.0, |(_, rate)| *rate)
}

/// A cloneable producer side of the writer queues (for the bus consumer and reloads).
#[derive(Clone)]
pub struct HistoryQueue {
    tx: SyncSender<WriteMsg>,
    /// Bans and config revisions ([`WriteMsg::is_control`]).
    control: SyncSender<WriteMsg>,
    shared: Arc<Shared>,
    metrics: Arc<Metrics>,
    status: Arc<StatusBoard>,
}

/// `try_send` on `tx` until it is taken or `deadline` passes, counting depth
/// as `enqueue` does. False on timeout or when the writer is gone.
fn send_until(
    tx: &SyncSender<WriteMsg>,
    shared: &Shared,
    mut msg: WriteMsg,
    deadline: Instant,
) -> bool {
    loop {
        shared.depth.fetch_add(1, Relaxed);
        match tx.try_send(msg) {
            Ok(()) => return true,
            Err(e) => {
                shared.depth.fetch_sub(1, Relaxed);
                match e {
                    TrySendError::Disconnected(_) => return false,
                    TrySendError::Full(m) => {
                        if Instant::now() >= deadline {
                            return false;
                        }
                        msg = m;
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
            }
        }
    }
}

impl HistoryQueue {
    /// `try_send`; returns false (and counts a drop) when the queue is full or
    /// the writer is gone. Never blocks. Bans and config revisions go on the
    /// control queue; a drop there is logged and counted under consumer
    /// `history-control`, every other drop under `history-writer`.
    pub fn enqueue(&self, msg: WriteMsg) -> bool {
        let control = msg.is_control();
        let tx = if control { &self.control } else { &self.tx };
        // Count before sending, so the writer's decrement never underflows.
        self.shared.depth.fetch_add(1, Relaxed);
        match tx.try_send(msg) {
            Ok(()) => true,
            Err(e) => {
                self.shared.depth.fetch_sub(1, Relaxed);
                if control {
                    let (TrySendError::Full(m) | TrySendError::Disconnected(m)) = e;
                    self.control_dropped(&m);
                } else {
                    self.shared.drop_n(&self.metrics, &self.status, 1);
                }
                false
            }
        }
    }

    /// Count a control message that was not queued, and log what it was.
    fn control_dropped(&self, msg: &WriteMsg) {
        self.shared.dropped.fetch_add(1, Relaxed);
        self.metrics.history_dropped(1);
        self.status.add_drops("history-control", 1);
        match msg {
            WriteMsg::Ban { key, lifted, .. } => {
                tracing::warn!(%key, lifted, "history: control queue full; ban record dropped")
            }
            WriteMsg::ConfigRevision { rev, .. } => {
                tracing::warn!(rev, "history: control queue full; config revision dropped")
            }
            WriteMsg::BanSnapshot(bans) => {
                tracing::warn!(
                    bans = bans.len(),
                    "history: control queue full; ban snapshot dropped"
                )
            }
            _ => {}
        }
    }

    /// Queue an upsert of every (key, ban) in `bans` on the control queue,
    /// waiting at most `timeout` for room (used at stop, never on the request
    /// path). False, logged and counted like a control drop, when it could
    /// not be queued.
    pub fn snapshot_bans(&self, bans: Vec<(String, BanRecord)>, timeout: Duration) -> bool {
        let n = bans.len();
        let deadline = Instant::now() + timeout;
        if send_until(
            &self.control,
            &self.shared,
            WriteMsg::BanSnapshot(bans),
            deadline,
        ) {
            return true;
        }
        self.shared.dropped.fetch_add(1, Relaxed);
        self.metrics.history_dropped(1);
        self.status.add_drops("history-control", 1);
        tracing::warn!(bans = n, "history: the ban snapshot could not be queued");
        false
    }

    /// Queue a config-revision row with the SHA-256 of the raw file bytes. An
    /// empty slice (no file given) is recorded as the empty string.
    pub fn config_revision(
        &self,
        rev: u64,
        source: &'static str,
        config: &[u8],
        exceptions: &[u8],
        changed: Vec<String>,
    ) {
        self.enqueue(WriteMsg::ConfigRevision {
            rev,
            ts_ms: vft_proxy::now_ms(),
            source,
            config_sha256: digest(config),
            exceptions_sha256: digest(exceptions),
            changed_keys: changed,
        });
    }

    /// Apply the Live `history.*` options of config revision `rev` to the
    /// decisions that revision makes (the sample rate; snippets are the
    /// proxy's). Revisions are expected in ascending order.
    pub fn set_config(&self, rev: u64, cfg: &HistoryConfig) {
        let mut rates = self.shared.rates();
        rates.retain(|(r, _)| *r < rev);
        rates.push((rev, cfg.allow_sample_rate));
        let excess = rates.len().saturating_sub(RATES_KEPT);
        rates.drain(..excess);
    }

    /// Wait until the writer committed everything queued before this call.
    /// False on timeout or when the writer is gone. Never counts a drop.
    pub fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (ack, done) = sync_channel(1);
        // The writer drains the control queue before every decision-queue
        // message, so this also covers bans and revisions queued before it.
        if !send_until(&self.tx, &self.shared, WriteMsg::Flush(ack), deadline) {
            return false;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        done.recv_timeout(left).is_ok()
    }

    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Relaxed)
    }

    pub fn written(&self) -> u64 {
        self.shared.written.load(Relaxed)
    }
}

/// The history store: the writer thread and its queue.
pub struct HistoryHandle {
    queue: HistoryQueue,
    join: Option<JoinHandle<()>>,
    path: PathBuf,
}

impl HistoryHandle {
    /// Decision-queue capacity.
    pub const QUEUE: usize = 16384;
    /// Control-queue capacity (bans and config revisions).
    pub const CONTROL_QUEUE: usize = 1024;
    /// Messages per transaction at most.
    pub const BATCH: usize = 2000;
    /// The longest a message waits in a batch before the batch is committed.
    pub const BATCH_WAIT: Duration = Duration::from_millis(250);

    /// Opens/creates `<dir>/history.db`, runs migrations, starts the writer
    /// thread. `cfg` applies from config revision 1 (see [`HistoryQueue::set_config`]).
    pub fn open(
        dir: &Path,
        cfg: HistoryConfig,
        metrics: Arc<Metrics>,
    ) -> anyhow::Result<HistoryHandle> {
        Self::open_with_status(dir, cfg, metrics, Arc::new(StatusBoard::new()))
    }

    /// [`HistoryHandle::open`], reporting write errors as `history` on `status`.
    pub fn open_with_status(
        dir: &Path,
        cfg: HistoryConfig,
        metrics: Arc<Metrics>,
        status: Arc<StatusBoard>,
    ) -> anyhow::Result<HistoryHandle> {
        create_state_dir(dir).map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
        let path = dir.join("history.db");
        let conn = schema::open(&path)
            .and_then(|c| {
                writer::tune(&c)?;
                Ok(c)
            })
            .map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?;
        let (tx, rx) = sync_channel(Self::QUEUE);
        let (control, control_rx) = sync_channel(Self::CONTROL_QUEUE);
        let shared = Arc::new(Shared::default());
        let queue = HistoryQueue {
            tx,
            control,
            shared: shared.clone(),
            metrics: metrics.clone(),
            status: status.clone(),
        };
        queue.set_config(1, &cfg);
        let join = std::thread::Builder::new()
            .name("vft-history".into())
            .spawn(move || writer::run(conn, rx, control_rx, shared, metrics, status))
            .map_err(|e| anyhow::anyhow!("starting the history writer: {e}"))?;
        Ok(HistoryHandle {
            queue,
            join: Some(join),
            path,
        })
    }

    /// A producer handle on the same queue.
    pub fn queue(&self) -> HistoryQueue {
        self.queue.clone()
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// try_send; returns false (and counts a drop) when the queue is full.
    pub fn enqueue(&self, msg: WriteMsg) -> bool {
        self.queue.enqueue(msg)
    }

    pub fn config_revision(
        &self,
        rev: u64,
        source: &'static str,
        config: &[u8],
        exceptions: &[u8],
        changed: Vec<String>,
    ) {
        self.queue
            .config_revision(rev, source, config, exceptions, changed)
    }

    /// Waits for the writer to commit everything queued so far.
    pub fn flush(&self, timeout: Duration) -> bool {
        self.queue.flush(timeout)
    }

    /// Flush, stop the thread. Waits at most `timeout` in all; a writer still
    /// busy after that is left to finish on its own (and logged).
    pub fn close(mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        self.queue.shared.stop.store(true, Relaxed);
        if !self.queue.flush(timeout) {
            tracing::warn!("history: the final flush did not finish in time");
        }
        let Some(join) = self.join.take() else { return };
        while !join.is_finished() {
            if Instant::now() >= deadline {
                tracing::warn!("history: the writer is still busy; not waiting for it");
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if join.join().is_err() {
            tracing::error!("history: the writer thread panicked");
        }
    }

    pub fn dropped(&self) -> u64 {
        self.queue.dropped()
    }

    pub fn written(&self) -> u64 {
        self.queue.written()
    }
}

/// Create the state directory (and its parents). On Unix a directory this
/// creates gets mode 0700: the database holds request metadata.
fn create_state_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// Lower-case hex SHA-256, or `""` for no bytes (no file given).
fn digest(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        String::new()
    } else {
        sha256_hex(bytes)
    }
}

/// Deterministic sample point of an event in `[0, 1)`: the first 8 hex digits
/// of `sha256_hex(event_id)` as a `u32` over 2^32.
pub fn sample(event_id: &str) -> f64 {
    let h = sha256_hex(event_id.as_bytes());
    let top = u32::from_str_radix(&h[..8], 16).unwrap_or(0);
    f64::from(top) / 4_294_967_296.0
}

/// Whether a decision gets a `requests` row: `Some(false)` always (not
/// Allow, or an exception touched it), `Some(true)` when sampled in, `None`
/// otherwise (it still counts in the rollup).
pub fn keep(j: &Judgment, event_id: &str, allow_sample_rate: f64) -> Option<bool> {
    if j.verdict != Verdict::Allow || !j.exceptions.is_empty() || !j.skipped.is_empty() {
        Some(false)
    } else if sample(event_id) < allow_sample_rate {
        Some(true)
    } else {
        None
    }
}

/// Bit `n` set for every non-shadow contribution of the `n`-th `Family`
/// (declaration order: bit 0 Sqli … bit 9 Anomaly).
pub fn families(j: &Judgment) -> i64 {
    j.contributions
        .iter()
        .filter(|c| !c.shadow)
        .filter_map(|c| c.family)
        .fold(0, |acc, f| acc | (1i64 << (f as u32)))
}

#[cfg(test)]
mod tests;
