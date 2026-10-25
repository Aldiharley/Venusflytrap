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
use vft_core::{Judgment, Request};

#[derive(Serialize)]
struct ContribLine<'a> {
    construct: Option<&'a str>,
    field: Option<String>,
    value: String,
}

#[derive(Serialize)]
struct AuditLine<'a> {
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
}

pub struct AuditSink {
    tx: Option<SyncSender<String>>,
    worker: Option<JoinHandle<()>>,
    dropped: Arc<AtomicU64>,
    write_errors: Arc<AtomicU64>,
    enabled: bool,
}

impl AuditSink {
    /// `None` writes to stdout.
    pub fn new(path: Option<PathBuf>, max_bytes: u64) -> Self {
        let (tx, rx) = sync_channel::<String>(4096);
        let write_errors = Arc::new(AtomicU64::new(0));
        let errs = write_errors.clone();
        let worker = std::thread::spawn(move || {
            let mut out: Box<dyn Write> = match &path {
                Some(p) => match open(p) {
                    Some(f) => Box::new(BufWriter::new(f)),
                    None => {
                        errs.fetch_add(1, Ordering::Relaxed);
                        Box::new(std::io::sink())
                    }
                },
                None => Box::new(BufWriter::new(std::io::stdout())),
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
                        if let Some(p) = path.as_ref().filter(|_| size >= max_bytes) {
                            let _ = out.flush();
                            drop(out);
                            if std::fs::rename(p, p.with_extension("1")).is_err() {
                                errs.fetch_add(1, Ordering::Relaxed);
                            }
                            out = match open(p) {
                                Some(f) => Box::new(BufWriter::new(f)),
                                None => {
                                    errs.fetch_add(1, Ordering::Relaxed);
                                    Box::new(std::io::sink())
                                }
                            };
                            size = 0;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if out.flush().is_err() {
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
        }
    }

    pub fn record(&self, req: &Request, j: &Judgment, ts_ms: u64, request_id: u64) {
        let Some(tx) = self.tx.as_ref().filter(|_| self.enabled) else {
            return;
        };
        let line = AuditLine {
            ts_ms,
            request_id,
            method: &req.method,
            path: &req.path,
            src_ip: req.src_ip.map(|i| i.to_string()),
            verdict: format!("{:?}", j.verdict),
            score: j.score,
            stage: j.chain_stage.map(|s| format!("{s:?}")),
            banned: j.banned_source,
            layers: j.normalized_layers,
            contributions: j
                .contributions
                .iter()
                .map(|c| ContribLine {
                    construct: c.construct.as_deref(),
                    field: c.field.as_ref().map(|f| format!("{:?}:{}", f.loc, f.name)),
                    value: format!("{:?}", c.value),
                })
                .collect(),
            reason: &j.reason,
        };
        let Ok(json) = serde_json::to_string(&line) else {
            return;
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(json) {
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

fn open(p: &std::path::Path) -> Option<File> {
    OpenOptions::new().create(true).append(true).open(p).ok()
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
        sink.record(&req, &j, 1_700_000_000_000, 7);
        sink.close();
        let line = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(v["ts_ms"], 1_700_000_000_000u64);
        assert_eq!(v["request_id"], 7);
        assert!(v["contributions"].as_array().unwrap().iter().any(|c| c["construct"] == "union-select"));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rotates_at_max_bytes() {
        let p = tmp("rot.jsonl");
        let sink = AuditSink::new(Some(p.clone()), 300);
        let req = Request::get("/rotate");
        let j = Shield::new(Config::default()).inspect(&req);
        for i in 0..20 {
            sink.record(&req, &j, i, i);
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
        sink.record(&req, &j, 1, 1);
        assert_eq!(sink.dropped(), 0);
        assert_eq!(sink.write_errors(), 0);
        sink.close();
    }

    #[test]
    fn unopenable_path_counts_write_error_and_never_blocks() {
        let p = std::env::temp_dir().join(format!("vft-audit-{}-nodir", std::process::id())).join("a").join("b.jsonl");
        let sink = AuditSink::new(Some(p), 1024);
        let req = Request::get("/x");
        let j = Shield::new(Config::default()).inspect(&req);
        sink.record(&req, &j, 1, 1);
        assert_eq!(sink.dropped(), 0);
        let errs = sink.write_errors.clone();
        sink.close();
        assert!(errs.load(Ordering::Relaxed) >= 1);
    }
}
