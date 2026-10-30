//! FR10 — JSONL audit sink. The request path only does a non-blocking
//! `try_send`; a dedicated thread owns the file, batches writes, rotates at a
//! size cap and counts drops and write errors (L2).

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Serialize;
use vft_core::{FieldRef, Judgment, Request};

#[derive(Serialize)]
struct ContribLine<'a> {
    construct: Option<&'a str>,
    field: Option<String>,
    value: String,
    points: f32,
    shadow: bool,
}

#[derive(Serialize)]
struct AttackLine<'a> {
    tactic_id: &'a str,
    id: &'a str,
}

#[derive(Serialize)]
struct AuditLine<'a> {
    event_id: &'a str,
    group_id: Option<&'a str>,
    confidence: Option<u8>,
    exceptions: &'a [String],
    skipped: Vec<String>,
    attack: Vec<AttackLine<'a>>,
    ts_ms: u64,
    request_id: u64,
    method: &'a str,
    path: &'a str,
    src_ip: Option<String>,
    verdict: String,
    score: u8,
    stage: Option<String>,
    banned: bool,
    layers: u8,
    contributions: Vec<ContribLine<'a>>,
    reason: &'a str,
    cause: String,
    option_key: &'a str,
}

/// What the proxy knows about one event beyond the request and its judgment;
/// every sink receives the same values.
#[derive(Debug, Clone, Copy)]
pub struct EventMeta<'a> {
    pub ts_ms: u64,
    pub request_id: u64,
    pub event_id: &'a str,
    /// The episode group ID from the decision's source key (`Decision::group_id`).
    pub group_id: Option<&'a str>,
    /// Whether Challenge and Block were enforced (false under `serve --monitor-only`,
    /// where they are forwarded).
    pub enforced: bool,
}

impl<'a> EventMeta<'a> {
    /// An enforced event without a group ID.
    pub fn new(ts_ms: u64, request_id: u64, event_id: &'a str) -> Self {
        EventMeta { ts_ms, request_id, event_id, group_id: None, enforced: true }
    }
}

/// What a sink writes per judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One venusflytrap audit line.
    Jsonl,
    /// One line per OCSF 1.9.0 record (`ocsf::encode`).
    Ocsf,
}

pub struct AuditSink {
    tx: Option<SyncSender<String>>,
    worker: Option<JoinHandle<()>>,
    dropped: Arc<AtomicU64>,
    write_errors: Arc<AtomicU64>,
    enabled: bool,
    format: Format,
}

impl AuditSink {
    /// A JSONL audit sink; `None` writes to stdout.
    pub fn new(path: Option<PathBuf>, max_bytes: u64) -> Self {
        Self::with_format(path, max_bytes, Format::Jsonl)
    }

    /// `None` writes to stdout.
    pub fn with_format(path: Option<PathBuf>, max_bytes: u64, format: Format) -> Self {
        let (tx, rx) = sync_channel::<String>(4096);
        let write_errors = Arc::new(AtomicU64::new(0));
        let errs = write_errors.clone();
        let worker = std::thread::spawn(move || {
            // `failed` is true while the file could not be opened: `out` is a
            // writer that errors on every write (so each lost line is counted
            // as a write error) and the idle tick retries the open.
            let (mut out, mut failed): (Box<dyn Write>, bool) = match &path {
                Some(p) => open_out(p, &errs),
                None => (Box::new(BufWriter::new(std::io::stdout())), false),
            };
            let mut size = path
                .as_ref()
                .and_then(|p| std::fs::metadata(p).ok())
                .map_or(0, |m| m.len());
            loop {
                match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(line) => {
                        if writeln!(out, "{line}").is_err() {
                            errs.fetch_add(1, Ordering::Relaxed);
                        }
                        size += line.len() as u64 + 1;
                        if let Some(p) = path.as_ref().filter(|_| !failed && size >= max_bytes) {
                            let _ = out.flush();
                            drop(out);
                            if std::fs::rename(p, p.with_extension("1")).is_err() {
                                errs.fetch_add(1, Ordering::Relaxed);
                            }
                            (out, failed) = open_out(p, &errs);
                            size = 0;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if failed {
                            if let Some(f) = path.as_ref().and_then(|p| open(p)) {
                                out = Box::new(BufWriter::new(f));
                                failed = false;
                                size = path
                                    .as_ref()
                                    .and_then(|p| std::fs::metadata(p).ok())
                                    .map_or(0, |m| m.len());
                            }
                        } else if out.flush().is_err() {
                            errs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        let _ = out.flush();
                        return;
                    }
                }
            }
        });
        AuditSink {
            tx: Some(tx),
            worker: Some(worker),
            dropped: Arc::new(AtomicU64::new(0)),
            write_errors,
            enabled: true,
            format,
        }
    }

    /// A sink that records nothing.
    pub fn off() -> Self {
        AuditSink {
            tx: None,
            worker: None,
            dropped: Arc::new(AtomicU64::new(0)),
            write_errors: Arc::new(AtomicU64::new(0)),
            enabled: false,
            format: Format::Jsonl,
        }
    }

    pub fn record(&self, req: &Request, j: &Judgment, m: &EventMeta) {
        let Some(tx) = self.tx.as_ref().filter(|_| self.enabled) else {
            return;
        };
        match self.format {
            Format::Jsonl => {
                if let Some(json) = jsonl_line(req, j, m) {
                    self.send(tx, json);
                }
            }
            Format::Ocsf => {
                for rec in crate::ocsf::encode(req, j, m.ts_ms, m.event_id, m.group_id, m.enforced) {
                    match serde_json::to_string(&rec) {
                        Ok(json) => self.send(tx, json),
                        // An encoding failure is a write error on this sink only.
                        Err(_) => {
                            self.write_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    fn send(&self, tx: &SyncSender<String>, line: String) {
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(line) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// Flush and stop the writer thread.
    pub fn close(mut self) {
        self.tx.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

/// The JSONL audit line for one judgment; `None` if it does not serialize.
fn jsonl_line(req: &Request, j: &Judgment, m: &EventMeta) -> Option<String> {
    let line = AuditLine {
        event_id: m.event_id,
        group_id: m.group_id,
        confidence: j.confidence,
        exceptions: &j.exceptions,
        skipped: j.skipped.iter().map(FieldRef::label).collect(),
        attack: j
            .attack
            .iter()
            .map(|a| AttackLine { tactic_id: &a.tactic_id, id: &a.id })
            .collect(),
        ts_ms: m.ts_ms,
        request_id: m.request_id,
        method: &req.method,
        path: &req.path,
        src_ip: req.src_ip.map(|i| i.to_string()),
        verdict: format!("{:?}", j.verdict),
        score: j.score,
        stage: j.stage().map(|s| format!("{s:?}")),
        banned: j.banned(),
        layers: j.normalized_layers,
        contributions: j
            .contributions
            .iter()
            .map(|c| ContribLine {
                construct: c.construct.as_deref(),
                field: c.field.as_ref().map(|f| format!("{:?}:{}", f.loc, f.name)),
                value: format!("{:?}", c.value),
                points: c.points,
                shadow: c.shadow,
            })
            .collect(),
        reason: &j.decided_by.msg,
        cause: format!("{:?}", j.decided_by.kind),
        option_key: j.decided_by.option_key,
    };
    serde_json::to_string(&line).ok()
}

fn open(p: &std::path::Path) -> Option<File> {
    OpenOptions::new().create(true).append(true).open(p).ok()
}

/// Open the audit file; on failure count one write error and return a writer
/// that fails every write so each lost line is counted too.
fn open_out(p: &std::path::Path, errs: &AtomicU64) -> (Box<dyn Write>, bool) {
    match open(p) {
        Some(f) => (Box::new(BufWriter::new(f)), false),
        None => {
            errs.fetch_add(1, Ordering::Relaxed);
            (Box::new(FailedWriter), true)
        }
    }
}

/// Stand-in for an unopened file: every write and flush errors.
struct FailedWriter;

impl Write for FailedWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("audit file unavailable"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("audit file unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vft_core::{Config, Shield};

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vft-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("1"));
        p
    }

    #[test]
    fn lines_carry_timestamp_and_request_id() {
        let p = tmp("ts.jsonl");
        let sink = AuditSink::new(Some(p.clone()), 10 * 1024 * 1024);
        let mut req = Request::get("/x");
        req.query.push(("id".into(), "1 union select a".into()));
        let j = Shield::new(Config::default()).inspect(&req);
        sink.record(&req, &j, &EventMeta::new(1_700_000_000_000, 7, "019000000000-7000-8000-000000000001"));
        sink.close();
        let line = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(v["ts_ms"], 1_700_000_000_000u64);
        assert_eq!(v["request_id"], 7);
        assert!(v["contributions"].as_array().unwrap().iter().any(|c| c["construct"] == "sqli.union-select"));
        assert!(v["cause"].is_string() && v["option_key"].is_string(), "{v}");
        assert!(v["contributions"][0]["points"].is_number(), "{v}");
        assert_eq!(v["contributions"][0]["shadow"], false, "{v}");
        assert_eq!(v["event_id"], "019000000000-7000-8000-000000000001", "{v}");
        assert!(v.get("confidence").is_some(), "{v}");
        assert!(v["attack"].is_array(), "{v}");
        assert!(v.get("group_id").is_some() && v["group_id"].is_null(), "{v}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn lines_carry_exceptions_and_skipped_fields() {
        let req = Request::get("/x");
        let mut j = Judgment::allow();
        j.exceptions = vec!["referer-sql".into()];
        j.skipped = vec![vft_core::FieldRef::header("X-Sig")];
        let line = jsonl_line(&req, &j, &EventMeta::new(1, 1, "e")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["exceptions"], serde_json::json!(["referer-sql"]), "{v}");
        assert_eq!(v["skipped"], serde_json::json!(["header:x-sig"]), "{v}");
        let plain: serde_json::Value = serde_json::from_str(&jsonl_line(&req, &Judgment::allow(), &EventMeta::new(1, 1, "e")).unwrap()).unwrap();
        assert_eq!(plain["exceptions"], serde_json::json!([]), "{plain}");
        assert_eq!(plain["skipped"], serde_json::json!([]), "{plain}");
    }

    #[test]
    fn ocsf_sink_writes_one_line_per_record() {
        let p = tmp("ocsf.jsonl");
        let sink = AuditSink::with_format(Some(p.clone()), 10 * 1024 * 1024, Format::Ocsf);
        let mut req = Request::get("/x");
        req.query.push(("id".into(), "1 union select a,b".into()));
        let mut j = Shield::new(Config::default()).inspect(&req);
        j.verdict = vft_core::Verdict::Block;
        sink.record(&req, &j, &EventMeta::new(1_700_000_000_000, 7, "e"));
        sink.close();
        let text = std::fs::read_to_string(&p).unwrap();
        let classes: Vec<u64> = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["class_uid"].as_u64().unwrap())
            .collect();
        assert_eq!(classes, vec![4002, 2004], "{text}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn both_sinks_write_the_group_id_they_are_given() {
        let (pj, po) = (tmp("gid.jsonl"), tmp("gid.ocsf.jsonl"));
        let jsonl = AuditSink::new(Some(pj.clone()), 10 * 1024 * 1024);
        let ocsf = AuditSink::with_format(Some(po.clone()), 10 * 1024 * 1024, Format::Ocsf);
        let mut req = Request::get("/x");
        req.src_ip = Some("2001:db8:1:2::9".parse().unwrap());
        let j = Shield::new(Config::default()).inspect(&req);
        let m = EventMeta { group_id: Some("2001:db8:1:2::@5"), ..EventMeta::new(1, 1, "e") };
        jsonl.record(&req, &j, &m);
        ocsf.record(&req, &j, &m);
        jsonl.close();
        ocsf.close();
        let line: serde_json::Value = serde_json::from_str(std::fs::read_to_string(&pj).unwrap().trim()).unwrap();
        assert_eq!(line["group_id"], "2001:db8:1:2::@5", "{line}");
        // The JSONL line keeps the client address; only the group ID uses the key.
        assert_eq!(line["src_ip"], "2001:db8:1:2::9", "{line}");
        let rec: serde_json::Value = serde_json::from_str(std::fs::read_to_string(&po).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(rec["metadata"]["correlation_uid"], "2001:db8:1:2::@5", "{rec}");
        let _ = std::fs::remove_file(&pj);
        let _ = std::fs::remove_file(&po);
    }

    #[test]
    fn rotates_at_max_bytes() {
        let p = tmp("rot.jsonl");
        let sink = AuditSink::new(Some(p.clone()), 300);
        let req = Request::get("/rotate");
        let j = Shield::new(Config::default()).inspect(&req);
        for i in 0..20 {
            sink.record(&req, &j, &EventMeta::new(i, i, "e"));
        }
        sink.close();
        assert!(p.with_extension("1").exists(), "rotated file missing");
        let current = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        assert!(current < 300 + 400, "current file should have been restarted, len {current}");
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("1"));
    }

    #[test]
    fn off_sink_records_nothing_and_counts_nothing() {
        let sink = AuditSink::off();
        let req = Request::get("/x");
        let j = Shield::new(Config::default()).inspect(&req);
        sink.record(&req, &j, &EventMeta::new(1, 1, "e"));
        assert_eq!(sink.dropped(), 0);
        assert_eq!(sink.write_errors(), 0);
        sink.close();
    }

    #[test]
    fn unopenable_path_counts_every_lost_line() {
        let p = std::env::temp_dir()
            .join(format!("vft-audit-{}-nodir", std::process::id()))
            .join("a")
            .join("b.jsonl");
        let sink = AuditSink::new(Some(p), 1024);
        let req = Request::get("/x");
        let j = Shield::new(Config::default()).inspect(&req);
        for i in 0..10 {
            sink.record(&req, &j, &EventMeta::new(i, i, "e"));
        }
        assert_eq!(sink.dropped(), 0);
        let errs = sink.write_errors.clone();
        sink.close();
        assert!(errs.load(Ordering::Relaxed) >= 10, "got {}", errs.load(Ordering::Relaxed));
    }

    #[test]
    fn reopens_after_transient_open_failure() {
        let dir = std::env::temp_dir().join(format!("vft-audit-{}-late", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("late.jsonl");
        let sink = AuditSink::new(Some(p.clone()), 1024 * 1024);
        let req = Request::get("/x");
        let j = Shield::new(Config::default()).inspect(&req);
        sink.record(&req, &j, &EventMeta::new(1, 1, "e")); // lost: directory missing
        std::thread::sleep(Duration::from_millis(100));
        std::fs::create_dir_all(&dir).unwrap();
        std::thread::sleep(Duration::from_millis(600)); // let the idle tick retry
        sink.record(&req, &j, &EventMeta::new(2, 2, "e"));
        let errs = sink.write_errors.clone();
        sink.close();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 1, "only the post-recovery line is written");
        assert!(text.contains("\"request_id\":2"));
        assert!(errs.load(Ordering::Relaxed) >= 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
