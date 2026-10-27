//! Real-corpus evaluation harness. Reads a JSONL of parsed HTTP requests, runs
//! the full engine over each, and writes a per-sample CSV plus FP/FN diagnostics.
//! Usage: cargo run --release -p vft-cli --example bench_http -- <in.jsonl> <out.csv>

use std::io::{BufRead, BufWriter, Write};
use std::time::Instant;

use serde::Deserialize;
use vft_core::{Config, Request, Shield, Verdict};

#[derive(Deserialize)]
struct Rec {
    label: u8,
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let inp = &args[1];
    let outp = &args[2];
    let shield = Shield::new(Config::default());

    let f = std::fs::File::open(inp).expect("open jsonl");
    let rdr = std::io::BufReader::new(f);
    let out = std::fs::File::create(outp).expect("create csv");
    let mut w = BufWriter::new(out);
    writeln!(w, "label,pred,score,latency_us").unwrap();
    let dbg = std::fs::File::create(format!("{outp}.miss.csv")).expect("create miss csv");
    let mut dw = BufWriter::new(dbg);
    writeln!(dw, "kind\tscore\tlayers\tmatched\treason").unwrap();

    let (mut tp, mut fp, mut tn, mut fn_) = (0u64, 0u64, 0u64, 0u64);
    let mut lat: Vec<u64> = Vec::new();

    for line in rdr.lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let r: Rec = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let req = Request {
            method: r.method,
            path: r.path,
            query: r.query,
            headers: r.headers,
            cookies: r.cookies,
            body: r.body.into_bytes(),
            src_ip: None,
            non_utf8_headers: Vec::new(),
        };
        let t = Instant::now();
        let j = shield.inspect(&req);
        let us = t.elapsed().as_micros() as u64;
        lat.push(us);
        let pred = matches!(j.verdict, Verdict::Block | Verdict::Challenge) as u8;
        let kind = match (pred, r.label) {
            (1, 1) => { tp += 1; None }
            (1, 0) => { fp += 1; Some("FP") }
            (0, 0) => { tn += 1; None }
            (0, 1) => { fn_ += 1; Some("FN") }
            _ => None,
        };
        if let Some(k) = kind {
            let mut fams: Vec<String> = Vec::new();
            for c in &j.contributions {
                if let (Some(f), Some(n)) = (c.family, c.construct.as_deref()) {
                    let s = format!("{f:?}:{n}");
                    if !fams.contains(&s) {
                        fams.push(s);
                    }
                }
            }
            writeln!(
                dw,
                "{}\t{}\t{}\t{}\t{}",
                k,
                j.score,
                j.normalized_layers,
                fams.join("|"),
                j.decided_by.msg.replace(['\t', '\n'], " ")
            )
            .unwrap();
        }
        writeln!(w, "{},{},{},{}", r.label, pred, j.score, us).unwrap();
    }
    w.flush().unwrap();
    dw.flush().unwrap();

    lat.sort_unstable();
    let pct = |p: f64| -> u64 {
        if lat.is_empty() {
            0
        } else {
            lat[(((lat.len() - 1) as f64) * p).round() as usize]
        }
    };
    let recall = tp as f64 / (tp + fn_).max(1) as f64;
    let prec = tp as f64 / (tp + fp).max(1) as f64;
    let f1 = if prec + recall > 0.0 {
        2.0 * prec * recall / (prec + recall)
    } else {
        0.0
    };
    let fpr = fp as f64 / (fp + tn).max(1) as f64;
    eprintln!(
        "engine=venusflytrap tp={tp} fp={fp} tn={tn} fn={fn_} recall={:.4} precision={:.4} f1={:.4} fp_rate={:.4} p50={}us p95={}us p99={}us",
        recall, prec, f1, fpr, pct(0.5), pct(0.95), pct(0.99)
    );
}
