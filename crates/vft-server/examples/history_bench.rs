//! Measure the history store on its own: write throughput and query latency.
//!
//! ```text
//! history_bench write --state-dir <fresh dir> [--rate 5000] [--seconds 60] [--sample-rate 0.01] [--events N]
//! history_bench query --state-dir <fresh dir> [--rows 1000000] [--days 7] [--queries 200] [--no-fill]
//! ```
//!
//! Both print one JSON report. The synthetic events are the same in both
//! modes: 95 % Allow, 5 % non-Allow (half Block, 30 % Monitor, 20 % Challenge,
//! with a construct and family each), from a pool of 5,000 source addresses
//! (the non-Allow ones from the first 300 of them), each with a unique event id.
//!
//! `write` sends events through `HistoryHandle::enqueue` and reports what the
//! writer thread committed. With `--rate R` (R > 0) a producer paces R events/s
//! for `--seconds` and `events_per_s` is `written / elapsed` including the final
//! flush, `dropped` the queue's drop count. With `--rate 0` it sends `--events`
//! events in chunks of 2,000, flushing after each chunk (so nothing is dropped),
//! which measures the writer's ceiling. `--sample-rate` is `history.allow_sample_rate`
//! (1.0 stores a `requests` row for every event, the worst case).
//!
//! `query` fills a database with `--rows` events (sample rate 1.0, so one
//! `requests` row each) spread evenly over the last `--days` days, then runs
//! `--queries` queries of each 24-hour form over random 24-hour windows:
//! `verdict:block`, `construct:sqli.*`, `src:<random source>`, `-verdict:allow`,
//! the empty query grouped by `construct` (every row of the window), and
//! `-verdict:allow` grouped by `construct`. `--no-fill` queries a database
//! that is already there (window bounds are read from it).

use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vft_core::config::HistoryConfig;
use vft_core::{
    Cause, CauseKind, Contribution, Family, FieldRef, FourValued, Judgment, Location, Verdict,
};
use vft_proxy::bus::DecisionEvent;
use vft_server::history::query::{GroupBy, Request};
use vft_server::history::read::{open_read_only, run};
use vft_server::history::{HistoryHandle, WriteMsg};
use vft_server::metrics::Metrics;

const WAIT: Duration = Duration::from_secs(600);
const DAY_MS: u64 = 86_400_000;
const POOL: u64 = 5000;
const ATTACKERS: u64 = 300;

/// xorshift64*: deterministic and dependency free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn ip_of(k: u64) -> String {
    format!("10.{}.{}.{}", (k >> 16) & 255, (k >> 8) & 255, k & 255)
}

const KINDS: [(&str, Family); 6] = [
    ("sqli.union-select", Family::Sqli),
    ("sqli.boolean-tautology", Family::Sqli),
    ("xss.script-tag", Family::Xss),
    ("cmd.shell-meta", Family::CommandInjection),
    ("path.traversal", Family::PathTraversal),
    ("recon.scanner-ua", Family::Recon),
];

fn judgment(rng: &mut Rng) -> Judgment {
    let mut j = Judgment::allow();
    let (construct, family) = KINDS[rng.below(KINDS.len() as u64) as usize];
    let (verdict, score) = match rng.below(10) {
        0..=4 => (Verdict::Block, 95),
        5..=7 => (Verdict::Monitor, 45),
        _ => (Verdict::Challenge, 70),
    };
    let field = FieldRef {
        loc: Location::Query,
        name: "id".into(),
    };
    j.verdict = verdict;
    j.score = score;
    j.contributions = vec![Contribution {
        engine: "graph-taint",
        field: Some(field.clone()),
        construct: Some(construct.into()),
        family: Some(family),
        value: FourValued::Dangerous,
        weight: 1.0,
        points: f32::from(score),
        shadow: false,
        exception: None,
    }];
    j.decided_by = Cause {
        kind: CauseKind::Detection,
        option_key: "scoring.block_at",
        construct: Some(construct.into()),
        field: Some(field),
        msg: "synthetic".into(),
    };
    j.confidence = Some(90);
    j
}

/// Event number `i` at `ts_ms`.
fn event(i: u64, ts_ms: u64, rng: &mut Rng) -> WriteMsg {
    let attack = rng.below(100) < 5;
    let (src, j) = if attack {
        (ip_of(rng.below(ATTACKERS)), judgment(rng))
    } else {
        (ip_of(rng.below(POOL)), Judgment::allow())
    };
    WriteMsg::Decision(Arc::new(DecisionEvent {
        event_id: format!("e{i:010}"),
        group_id: None,
        ts_ms,
        src_key: Some(src.clone()),
        ip: src.parse().ok(),
        method: "GET".into(),
        host: "shop.test".into(),
        path: format!("/p/{}", rng.below(200)),
        judgment: j,
        latency_us: 120,
        upstream_status: Some(200),
        config_rev: 1,
        snippets: Vec::new(),
    }))
}

fn now_ms() -> u64 {
    vft_proxy::now_ms()
}

struct Args {
    mode: String,
    state_dir: PathBuf,
    rate: f64,
    seconds: u64,
    events: u64,
    sample_rate: f64,
    rows: u64,
    days: u64,
    queries: usize,
    no_fill: bool,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut it = std::env::args().skip(1);
    let mut a = Args {
        mode: it.next().ok_or_else(|| {
            anyhow::anyhow!("usage: history_bench write|query --state-dir DIR ...")
        })?,
        state_dir: PathBuf::new(),
        rate: 5000.0,
        seconds: 60,
        events: 300_000,
        sample_rate: 0.01,
        rows: 1_000_000,
        days: 7,
        queries: 200,
        no_fill: false,
    };
    while let Some(flag) = it.next() {
        if flag == "--no-fill" {
            a.no_fill = true;
            continue;
        }
        let v = it
            .next()
            .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))?;
        match flag.as_str() {
            "--state-dir" => a.state_dir = v.into(),
            "--rate" => a.rate = v.parse()?,
            "--seconds" => a.seconds = v.parse()?,
            "--events" => a.events = v.parse()?,
            "--sample-rate" => a.sample_rate = v.parse()?,
            "--rows" => a.rows = v.parse()?,
            "--days" => a.days = v.parse()?,
            "--queries" => a.queries = v.parse()?,
            other => anyhow::bail!("unknown flag {other}"),
        }
    }
    if a.state_dir.as_os_str().is_empty() {
        anyhow::bail!("--state-dir is required");
    }
    Ok(a)
}

fn open(a: &Args, sample_rate: f64) -> anyhow::Result<(HistoryHandle, Arc<Metrics>)> {
    let metrics = Arc::new(Metrics::new());
    let cfg = HistoryConfig {
        allow_sample_rate: sample_rate,
        ..HistoryConfig::default()
    };
    Ok((
        HistoryHandle::open(&a.state_dir, cfg, metrics.clone())?,
        metrics,
    ))
}

fn write_mode(a: &Args) -> anyhow::Result<serde_json::Value> {
    let (h, _m) = open(a, a.sample_rate)?;
    let mut rng = Rng(1);
    let start = Instant::now();
    let mut sent = 0u64;
    if a.rate > 0.0 {
        let total = (a.rate * a.seconds as f64).round() as u64;
        while sent < total {
            let due = ((start.elapsed().as_secs_f64() * a.rate) as u64 + 1).min(total);
            while sent < due {
                h.enqueue(event(sent, now_ms(), &mut rng));
                sent += 1;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    } else {
        while sent < a.events {
            for _ in 0..2000.min(a.events - sent) {
                h.enqueue(event(sent, now_ms(), &mut rng));
                sent += 1;
            }
            if !h.flush(WAIT) {
                anyhow::bail!("flush timed out");
            }
        }
    }
    let sent_s = start.elapsed().as_secs_f64();
    if !h.flush(WAIT) {
        anyhow::bail!("final flush timed out");
    }
    let elapsed = start.elapsed().as_secs_f64();
    let (written, dropped) = (h.written(), h.dropped());
    h.close(WAIT);
    let conn = open_read_only(&a.state_dir)?;
    let q = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
    Ok(serde_json::json!({
        "mode": "write",
        "target_rate": a.rate,
        "sample_rate": a.sample_rate,
        "sent": sent,
        "written": written,
        "dropped": dropped,
        "send_s": sent_s,
        "elapsed_s": elapsed,
        "events_per_s": written as f64 / elapsed,
        "rollup_decisions": q("SELECT COALESCE(SUM(count), 0) FROM rollup_minute")?,
        "requests_rows": q("SELECT COUNT(*) FROM requests")?,
    }))
}

fn fill(a: &Args) -> anyhow::Result<serde_json::Value> {
    let (h, _m) = open(a, 1.0)?;
    let mut rng = Rng(1);
    let span = a.days * DAY_MS;
    let t0 = now_ms() - span;
    let start = Instant::now();
    let mut i = 0u64;
    while i < a.rows {
        for _ in 0..2000.min(a.rows - i) {
            let ts = t0 + (u128::from(i) * u128::from(span) / u128::from(a.rows)) as u64;
            h.enqueue(event(i, ts, &mut rng));
            i += 1;
        }
        if !h.flush(WAIT) {
            anyhow::bail!("flush timed out");
        }
    }
    let (written, dropped) = (h.written(), h.dropped());
    h.close(WAIT);
    let elapsed = start.elapsed().as_secs_f64();
    Ok(serde_json::json!({
        "rows": a.rows, "written": written, "dropped": dropped,
        "fill_s": elapsed, "fill_events_per_s": written as f64 / elapsed,
    }))
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

fn query_mode(a: &Args) -> anyhow::Result<serde_json::Value> {
    let fill_report = if a.no_fill {
        serde_json::Value::Null
    } else {
        fill(a)?
    };
    let conn: Connection = open_read_only(&a.state_dir)?;
    let (lo, hi): (i64, i64) =
        conn.query_row("SELECT MIN(ts_ms), MAX(ts_ms) FROM requests", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let rows: i64 = conn.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))?;
    let non_allow: i64 = conn.query_row(
        "SELECT COUNT(*) FROM requests WHERE verdict != 'Allow'",
        [],
        |r| r.get(0),
    )?;
    let (lo, hi) = (lo as u64, hi as u64);
    anyhow::ensure!(hi - lo > DAY_MS, "the database spans less than 24 hours");
    let db_bytes = std::fs::metadata(a.state_dir.join("history.db"))?.len();

    // (name, q, group_by); `src:<random>` is filled in per query.
    let forms: [(&str, &str, Option<GroupBy>); 6] = [
        ("verdict:block", "verdict:block", None),
        ("construct:sqli.*", "construct:sqli.*", None),
        ("src:<ip>", "", None),
        ("-verdict:allow", "-verdict:allow", None),
        ("group-by construct", "", Some(GroupBy::Construct)),
        (
            "group-by construct -verdict:allow",
            "-verdict:allow",
            Some(GroupBy::Construct),
        ),
    ];
    let mut rng = Rng(7);
    let mut out = Vec::new();
    for (name, q, group_by) in forms {
        let mut ms = Vec::with_capacity(a.queries);
        let mut returned = 0usize;
        for _ in 0..a.queries {
            let from = lo + rng.below(hi - lo - DAY_MS);
            let q = if name == "src:<ip>" {
                format!("src:{}", ip_of(rng.below(POOL)))
            } else {
                q.to_string()
            };
            let req = Request {
                q,
                from_ms: from,
                to_ms: from + DAY_MS,
                group_by,
                limit: 100,
                cursor: None,
            };
            let t = Instant::now();
            let page = run(&conn, &req).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            ms.push(t.elapsed().as_secs_f64() * 1000.0);
            returned += page.rows.len() + page.groups.as_ref().map_or(0, Vec::len);
        }
        let first = ms[0];
        ms.sort_by(f64::total_cmp);
        out.push(serde_json::json!({
            "form": name, "queries": a.queries,
            "p50_ms": pct(&ms, 50.0), "p95_ms": pct(&ms, 95.0), "max_ms": ms[ms.len() - 1],
            "first_ms": first, "mean_returned": returned as f64 / a.queries as f64,
        }));
    }
    Ok(serde_json::json!({
        "mode": "query", "fill": fill_report, "requests_rows": rows, "non_allow_rows": non_allow,
        "span_h": (hi - lo) as f64 / 3_600_000.0, "db_bytes": db_bytes, "forms": out,
    }))
}

fn main() -> anyhow::Result<()> {
    let a = parse_args()?;
    let report = match a.mode.as_str() {
        "write" => write_mode(&a)?,
        "query" => query_mode(&a)?,
        other => anyhow::bail!("mode must be write or query, got {other:?}"),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
