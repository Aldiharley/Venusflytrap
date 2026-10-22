//! FR10 — JSONL audit log, mirroring the article's "battle log" format.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use serde::Serialize;
use vft_core::{Judgment, Request};

#[derive(Serialize)]
struct AuditLine<'a> {
    method: &'a str,
    path: &'a str,
    src_ip: Option<String>,
    verdict: String,
    score: u8,
    stage: Option<String>,
    banned: bool,
    layers: u8,
    matched: Vec<String>,
    reason: &'a str,
}

pub struct AuditLog {
    path: Option<String>,
    // Serialize writes to avoid interleaving across tasks.
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: Option<String>) -> Self {
        AuditLog {
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn record(&self, req: &Request, j: &Judgment) {
        let line = AuditLine {
            method: &req.method,
            path: &req.path,
            src_ip: req.src_ip.map(|i| i.to_string()),
            verdict: format!("{:?}", j.verdict),
            score: j.score,
            stage: j.chain_stage.map(|s| format!("{s:?}")),
            banned: j.banned_source,
            layers: j.normalized_layers,
            matched: j
                .matched
                .iter()
                .map(|p| format!("{:?}:{}", p.family, p.name))
                .collect(),
            reason: &j.reason,
        };
        let json = match serde_json::to_string(&line) {
            Ok(s) => s,
            Err(_) => return,
        };
        match &self.path {
            Some(p) => {
                let _guard = self.lock.lock();
                if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                    let _ = writeln!(f, "{json}");
                }
            }
            None => {
                let _guard = self.lock.lock();
                println!("{json}");
            }
        }
    }
}
