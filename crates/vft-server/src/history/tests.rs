use super::*;
use crate::status::Health;
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};
use std::sync::atomic::AtomicU64 as Counter;
use vft_core::chain::{BanCause, ChainOutcome};
use vft_core::{
    AttackTag, Cause, CauseKind, Contribution, Family, FieldRef, FourValued, Location, Stage,
};

const WAIT: Duration = Duration::from_secs(10);

/// A fresh empty directory under the system temp dir, removed on drop.
struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        static N: Counter = Counter::new(0);
        let d = std::env::temp_dir().join(format!(
            "vft-history-{}-{}",
            std::process::id(),
            N.fetch_add(1, Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cfg(rate: f64) -> HistoryConfig {
    HistoryConfig {
        allow_sample_rate: rate,
        ..HistoryConfig::default()
    }
}

fn open(dir: &Path, rate: f64) -> HistoryHandle {
    HistoryHandle::open(dir, cfg(rate), Arc::new(Metrics::new())).unwrap()
}

/// A read-only connection on the store in `dir`.
fn read(dir: &Path) -> Connection {
    Connection::open_with_flags(dir.join("history.db"), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
}

fn count(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

fn contribution(family: Family, shadow: bool) -> Contribution {
    Contribution {
        engine: "graph-taint",
        field: Some(FieldRef {
            loc: Location::Query,
            name: "id".into(),
        }),
        construct: Some(
            if shadow {
                "xss.script-tag"
            } else {
                "sqli.union-select"
            }
            .into(),
        ),
        family: Some(family),
        value: FourValued::Dangerous,
        weight: 1.0,
        points: if shadow { 0.0 } else { 95.0 },
        shadow,
        exception: None,
    }
}

fn block() -> Judgment {
    let mut j = Judgment::allow();
    j.verdict = Verdict::Block;
    j.score = 95;
    j.contributions = vec![
        contribution(Family::Sqli, false),
        contribution(Family::Xss, true),
    ];
    j.decided_by = Cause {
        kind: CauseKind::Detection,
        option_key: "scoring.block_at",
        construct: Some("sqli.union-select".into()),
        field: Some(FieldRef {
            loc: Location::Query,
            name: "id".into(),
        }),
        msg: "blocked".into(),
    };
    j.attack = vec![AttackTag {
        tactic_id: "TA0001".into(),
        tactic: "Initial Access".into(),
        id: "T1190".into(),
        name: "Exploit Public-Facing Application".into(),
    }];
    j.confidence = Some(97);
    j
}

fn event(id: &str, ts_ms: u64, judgment: Judgment) -> WriteMsg {
    WriteMsg::Decision(Arc::new(DecisionEvent {
        event_id: id.into(),
        group_id: Some("192.0.2.7@1000".into()),
        ts_ms,
        src_key: Some("192.0.2.7".into()),
        ip: Some("192.0.2.7".parse().unwrap()),
        method: "GET".into(),
        host: "shop.test".into(),
        path: "/x".into(),
        judgment,
        latency_us: 120,
        upstream_status: Some(200),
        config_rev: 1,
        snippets: Vec::new(),
    }))
}

fn with_rev(msg: WriteMsg, rev: u64) -> WriteMsg {
    let WriteMsg::Decision(d) = msg else {
        unreachable!()
    };
    let mut d = (*d).clone();
    d.config_rev = rev;
    WriteMsg::Decision(Arc::new(d))
}

#[test]
fn open_twice_runs_migrations_once_with_wal_on() {
    let tmp = Tmp::new();
    open(&tmp.0, 0.01).close(WAIT);
    let h = open(&tmp.0, 0.01);
    assert!(h.path().ends_with("history.db"));
    h.close(WAIT);
    let c = read(&tmp.0);
    let v: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
    assert_eq!(USER_VERSION, 1);
    let mode: String = c
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    for t in [
        "requests",
        "rollup_minute",
        "chain_events",
        "bans",
        "config_revisions",
    ] {
        let n = count(
            &c,
            &format!("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '{t}'"),
        );
        assert_eq!(n, 1, "{t}");
    }
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name LIKE 'requests_%'"
        ),
        5
    );
}

#[test]
fn sampling_keeps_every_non_allow_and_touched_allow_and_a_sample_of_the_rest() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.01);
    let t0 = 1_700_000_000_000u64;
    assert!(h.enqueue(event("blk", t0, block())));
    let mut touched = Judgment::allow();
    touched.exceptions = vec!["ex-1".into(), "ex-2".into()];
    assert!(h.enqueue(event("touched", t0 + 1, touched)));
    let ids: Vec<String> = (0..1000).map(|i| format!("allow-{i}")).collect();
    for (i, id) in ids.iter().enumerate() {
        // Spread over three minutes.
        assert!(h.enqueue(event(id, t0 + i as u64 * 150, Judgment::allow())));
    }
    assert!(h.flush(WAIT));
    assert_eq!(h.written(), 1002);
    assert_eq!(h.dropped(), 0);

    let c = read(&tmp.0);
    let blk = |col: &str| -> Value {
        c.query_row(
            &format!("SELECT {col} FROM requests WHERE event_id = 'blk'"),
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    let text = |s: &str| Value::Text(s.into());
    assert_eq!(blk("ts_ms"), Value::Integer(t0 as i64));
    assert_eq!(blk("src_key"), text("192.0.2.7"));
    assert_eq!(blk("ip"), text("192.0.2.7"));
    assert_eq!(
        (blk("method"), blk("host"), blk("path")),
        (text("GET"), text("shop.test"), text("/x"))
    );
    assert_eq!(blk("verdict"), text("Block"));
    assert_eq!(blk("score"), Value::Integer(95));
    assert_eq!(blk("stage"), Value::Null, "no chain observation");
    assert_eq!(
        blk("families"),
        Value::Integer(1),
        "Sqli only: the shadow Xss is not counted"
    );
    assert_eq!(blk("construct"), text("sqli.union-select"));
    assert_eq!(blk("technique"), text("T1190"));
    assert_eq!(blk("confidence"), Value::Integer(97));
    assert_eq!(blk("group_id"), text("192.0.2.7@1000"));
    assert_eq!(blk("cause_kind"), text("Detection"));
    assert_eq!(blk("decided_option"), text("scoring.block_at"));
    assert_eq!(blk("config_rev"), Value::Integer(1));
    assert_eq!(blk("latency_us"), Value::Integer(120));
    assert_eq!(blk("upstream_status"), Value::Integer(200));
    assert_eq!(blk("sampled"), Value::Integer(0));
    assert_eq!(blk("exceptions"), text(""));
    let Value::Text(extra) = blk("extra") else {
        panic!("extra is text")
    };
    let extra: serde_json::Value = serde_json::from_str(&extra).unwrap();
    assert_eq!(
        extra,
        serde_json::json!({
            "contributions": [
                {"construct": "sqli.union-select", "field": "query:id", "points": 95.0, "shadow": false, "exception": null},
                {"construct": "xss.script-tag", "field": "query:id", "points": 0.0, "shadow": true, "exception": null},
            ],
            "skipped": [],
            "snippets": [],
        })
    );
    let (sampled, exceptions): (i64, String) = c
        .query_row(
            "SELECT sampled, exceptions FROM requests WHERE event_id = 'touched'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((sampled, exceptions.as_str()), (0, "ex-1,ex-2"));

    let stored = count(
        &c,
        "SELECT count(*) FROM requests WHERE event_id LIKE 'allow-%'",
    );
    assert!((0..=30).contains(&stored), "{stored}");
    let expect = ids.iter().filter(|id| sample(id) < 0.01).count() as i64;
    assert_eq!(stored, expect, "deterministic");
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM requests WHERE event_id LIKE 'allow-%' AND sampled = 1"
        ),
        stored
    );
    assert_eq!(count(&c, "SELECT sum(count) FROM rollup_minute"), 1002);
    assert_eq!(
        count(
            &c,
            "SELECT sum(count) FROM rollup_minute WHERE verdict = 'Allow' AND families = 0"
        ),
        1001
    );
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM rollup_minute WHERE minute_ms % 60000 != 0"
        ),
        0
    );
    h.close(WAIT);
}

#[test]
fn sample_is_deterministic_and_in_range() {
    assert_eq!(sample("abc"), sample("abc"));
    // sha256("abc") = ba7816bf...
    assert_eq!(sample("abc"), f64::from(0xba78_16bfu32) / 4_294_967_296.0);
    for i in 0..100 {
        let s = sample(&format!("e{i}"));
        assert!((0.0..1.0).contains(&s));
    }
}

#[test]
fn a_rate_of_zero_stores_no_untouched_allow_and_one_stores_them_all() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    for i in 0..50 {
        h.enqueue(event(&format!("z-{i}"), 1_000 + i, Judgment::allow()));
    }
    assert!(h.flush(WAIT));
    h.queue().set_config(2, &cfg(1.0));
    for i in 0..50 {
        h.enqueue(with_rev(
            event(&format!("o-{i}"), 1_000 + i, Judgment::allow()),
            2,
        ));
    }
    // Decided by revision 1, written after revision 2 applied: still rate 0.
    h.enqueue(event("late-1", 1_000, Judgment::allow()));
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM requests WHERE event_id LIKE 'z-%'"
        ),
        0
    );
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM requests WHERE event_id LIKE 'o-%' AND sampled = 1"
        ),
        50
    );
    assert_eq!(
        count(
            &c,
            "SELECT count(*) FROM requests WHERE event_id = 'late-1'"
        ),
        0
    );
    assert_eq!(count(&c, "SELECT sum(count) FROM rollup_minute"), 101);
    h.close(WAIT);
}

#[test]
fn the_rate_in_effect_is_the_one_of_the_deciding_revision() {
    let rates = [(1, 0.1), (3, 0.3), (7, 0.7)];
    assert_eq!(rate_at(&rates, 1), 0.1);
    assert_eq!(rate_at(&rates, 2), 0.1);
    assert_eq!(rate_at(&rates, 3), 0.3);
    assert_eq!(rate_at(&rates, 99), 0.7);
    assert_eq!(rate_at(&rates, 0), 0.1, "older than kept: the oldest");
    assert_eq!(rate_at(&[], 5), 0.0);
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.5);
    for rev in 2..40 {
        h.queue().set_config(rev, &cfg(rev as f64 / 100.0));
    }
    let rates = h.queue.shared.rates().clone();
    assert_eq!(rates.len(), RATES_KEPT);
    assert_eq!(rates.last(), Some(&(39, 0.39)));
    h.close(WAIT);
}

#[test]
fn stage_advances_and_bans_become_chain_events_and_ban_rows() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    let ban = BanRecord {
        since_ms: 5_000,
        until_ms: 65_000,
        cause: BanCause::RepeatedExploitation,
        offences: 2,
    };
    let mut j = block();
    j.chain = Some(ChainOutcome {
        stage_before: Some(Stage::Recon),
        stage_after: Some(Stage::Exploitation),
        advanced: true,
        new_ban: Some(ban),
        episode_start_ms: Some(1_000),
    });
    h.enqueue(event("adv", 5_000, j));
    // No advance, no ban: no chain event.
    let mut quiet = block();
    quiet.chain = Some(ChainOutcome {
        stage_after: Some(Stage::Exploitation),
        ..ChainOutcome::default()
    });
    h.enqueue(event("same", 5_001, quiet));
    h.enqueue(WriteMsg::Ban {
        key: "192.0.2.7".into(),
        ban: Some(ban),
        lifted: false,
        ts_ms: 5_000,
    });
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    let rows: Vec<(i64, String, String, Option<String>, String)> = c
        .prepare("SELECT ts_ms, src_key, kind, stage, detail FROM chain_events ORDER BY kind DESC")
        .unwrap()
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        (
            rows[0].0,
            rows[0].1.as_str(),
            rows[0].2.as_str(),
            rows[0].3.as_deref()
        ),
        (5_000, "192.0.2.7", "stage", Some("Exploitation"))
    );
    assert_eq!(
        (rows[1].2.as_str(), rows[1].3.as_deref()),
        ("ban", Some("Exploitation"))
    );
    let detail: serde_json::Value = serde_json::from_str(&rows[1].4).unwrap();
    assert_eq!(detail, serde_json::to_value(ban).unwrap());
    let stage_detail: serde_json::Value = serde_json::from_str(&rows[0].4).unwrap();
    assert_eq!(stage_detail["from"], "Recon");
    assert_eq!(stage_detail["to"], "Exploitation");
    assert_eq!(
        c.query_row(
            "SELECT stage FROM requests WHERE event_id = 'adv'",
            [],
            |r| r.get::<_, Option<String>>(0)
        )
        .unwrap()
        .as_deref(),
        Some("Exploitation")
    );

    let b: (String, i64, i64, i64, Option<i64>) = c
        .query_row("SELECT cause, since_ms, until_ms, offences, lifted_ms FROM bans WHERE key = '192.0.2.7'", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap();
    assert_eq!(
        b,
        ("RepeatedExploitation".to_string(), 5_000, 65_000, 2, None)
    );
    drop(c);

    h.enqueue(WriteMsg::Ban {
        key: "192.0.2.7".into(),
        ban: Some(ban),
        lifted: true,
        ts_ms: 9_000,
    });
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    assert_eq!(count(&c, "SELECT count(*) FROM bans"), 1);
    assert_eq!(
        count(&c, "SELECT lifted_ms FROM bans WHERE key = '192.0.2.7'"),
        9_000
    );
    h.close(WAIT);
}

#[test]
fn a_config_revision_row_carries_the_sha256_of_the_given_bytes() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.01);
    h.config_revision(1, "startup", b"version: 1\n", b"", Vec::new());
    h.config_revision(
        2,
        "reload",
        b"version: 1\nscoring:\n  block_at: 95\n",
        b"version: 1\nexceptions: []\n",
        vec![
            "scoring.block_at".into(),
            "history.allow_sample_rate".into(),
        ],
    );
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    let rows: Vec<(i64, i64, String, String, String, String)> = c
        .prepare("SELECT rev, ts_ms, source, config_sha256, exceptions_sha256, changed_keys FROM config_revisions ORDER BY rev")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[0].0, rows[0].2.as_str()), (1, "startup"));
    assert!(rows[0].1 > 0);
    assert_eq!(rows[0].3, sha256_hex(b"version: 1\n"));
    assert_eq!(rows[0].4, "", "no exceptions file");
    assert_eq!(rows[0].5, "");
    assert_eq!((rows[1].0, rows[1].2.as_str()), (2, "reload"));
    assert_eq!(rows[1].4, sha256_hex(b"version: 1\nexceptions: []\n"));
    assert_eq!(rows[1].5, "scoring.block_at,history.allow_sample_rate");
    h.close(WAIT);
}

/// Block the writer: it waits acknowledging a flush until the returned
/// receiver is read. Returns once the writer has taken it.
fn stall(h: &HistoryHandle) -> std::sync::mpsc::Receiver<()> {
    let (barrier, release) = sync_channel(0);
    assert!(h.enqueue(WriteMsg::Flush(barrier)));
    let t = Instant::now();
    while h.queue.shared.depth.load(Relaxed) != 0 {
        assert!(t.elapsed() < WAIT, "the writer never took the barrier");
        std::thread::sleep(Duration::from_millis(1));
    }
    release
}

#[test]
fn a_full_queue_drops_and_counts_without_blocking() {
    let tmp = Tmp::new();
    let metrics = Arc::new(Metrics::new());
    let status = Arc::new(StatusBoard::new());
    let h = HistoryHandle::open_with_status(&tmp.0, cfg(0.01), metrics.clone(), status.clone())
        .unwrap();
    let release = stall(&h);
    let t = Instant::now();
    let refused = (0..HistoryHandle::QUEUE + 10)
        .filter(|i| !h.enqueue(event(&format!("q-{i}"), 1_000, block())))
        .count();
    assert!(t.elapsed() < Duration::from_secs(5), "enqueue never blocks");
    assert_eq!(refused, 10);
    assert_eq!(h.dropped(), 10);
    assert_eq!(status.snapshot().drops.get("history-writer"), Some(&10));
    release.recv().unwrap();
    assert!(h.flush(WAIT));
    assert_eq!(h.written(), HistoryHandle::QUEUE as u64);
    let text = metrics.render(&status.snapshot());
    assert!(text.contains("vft_history_rows_dropped_total 10"), "{text}");
    assert!(
        text.contains("vft_bus_dropped_total{consumer=\"history-writer\"} 10"),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "vft_history_rows_written_total {}",
            HistoryHandle::QUEUE
        )),
        "{text}"
    );
    assert!(text.contains("vft_history_queue_depth 0"), "{text}");
    h.close(WAIT);
}

fn ban_msg(key: &str, since_ms: u64) -> WriteMsg {
    WriteMsg::Ban {
        key: key.into(),
        ban: Some(BanRecord {
            since_ms,
            until_ms: since_ms + 60_000,
            cause: BanCause::RepeatedExploitation,
            offences: 1,
        }),
        lifted: false,
        ts_ms: since_ms,
    }
}

#[test]
fn bans_and_revisions_are_written_while_the_decision_queue_is_full() {
    let tmp = Tmp::new();
    let status = Arc::new(StatusBoard::new());
    let h =
        HistoryHandle::open_with_status(&tmp.0, cfg(0.0), Arc::new(Metrics::new()), status.clone())
            .unwrap();
    let release = stall(&h);
    for i in 0..HistoryHandle::QUEUE {
        assert!(h.enqueue(event(&format!("f-{i}"), 1_000, block())));
    }
    assert!(
        !h.enqueue(event("over", 1_000, block())),
        "the decision queue is full"
    );
    assert!(
        h.enqueue(ban_msg("192.0.2.7", 5_000)),
        "a ban still goes in"
    );
    h.config_revision(2, "reload", b"version: 1\n", b"", Vec::new());
    assert_eq!(h.dropped(), 1);
    release.recv().unwrap();
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    assert_eq!(
        count(&c, "SELECT count(*) FROM bans WHERE key = '192.0.2.7'"),
        1
    );
    assert_eq!(count(&c, "SELECT count(*) FROM config_revisions"), 1);
    assert_eq!(
        count(&c, "SELECT count(*) FROM requests"),
        HistoryHandle::QUEUE as i64
    );
    let drops = status.snapshot().drops;
    assert_eq!(drops.get("history-writer"), Some(&1));
    assert_eq!(drops.get("history-control"), None);
    h.close(WAIT);
}

#[test]
fn a_full_control_queue_drops_counts_and_never_blocks() {
    let tmp = Tmp::new();
    let status = Arc::new(StatusBoard::new());
    let h =
        HistoryHandle::open_with_status(&tmp.0, cfg(0.0), Arc::new(Metrics::new()), status.clone())
            .unwrap();
    let release = stall(&h);
    let t = Instant::now();
    let refused = (0..HistoryHandle::CONTROL_QUEUE as u64 + 3)
        .filter(|i| !h.enqueue(ban_msg(&format!("192.0.2.{}", i % 250), 1_000 + i)))
        .count();
    assert!(t.elapsed() < Duration::from_secs(5), "enqueue never blocks");
    assert_eq!(refused, 3);
    assert_eq!(status.snapshot().drops.get("history-control"), Some(&3));
    assert_eq!(h.dropped(), 3);
    release.recv().unwrap();
    assert!(h.flush(WAIT));
    assert_eq!(
        count(&read(&tmp.0), "SELECT count(*) FROM bans"),
        HistoryHandle::CONTROL_QUEUE as i64
    );
    h.close(WAIT);
}

#[test]
fn a_ban_snapshot_upserts_every_ban_and_keeps_rows_already_there() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    h.enqueue(ban_msg("192.0.2.7", 5_000));
    assert!(h.flush(WAIT));
    let rec = |since_ms| BanRecord {
        since_ms,
        until_ms: since_ms + 60_000,
        cause: BanCause::RepeatedExploitation,
        offences: 1,
    };
    assert!(h.queue().snapshot_bans(
        vec![
            ("192.0.2.7".into(), rec(5_000)),
            ("2001:db8:1:2::".into(), rec(6_000)),
        ],
        WAIT
    ));
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    assert_eq!(count(&c, "SELECT count(*) FROM bans"), 2);
    assert_eq!(
        count(
            &c,
            "SELECT until_ms FROM bans WHERE key = '2001:db8:1:2::' AND since_ms = 6000 AND lifted_ms IS NULL"
        ),
        66_000
    );
    h.close(WAIT);
}

#[test]
fn the_writer_connection_has_a_large_cache_and_rare_checkpoints() {
    let tmp = Tmp::new();
    let c = schema::open(&tmp.0.join("history.db")).unwrap();
    writer::tune(&c).unwrap();
    let cache: i64 = c
        .pragma_query_value(None, "cache_size", |r| r.get(0))
        .unwrap();
    let ckpt: i64 = c
        .pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))
        .unwrap();
    assert_eq!((cache, ckpt), (-65536, 10000));
}

/// The `EXPLAIN QUERY PLAN` details of the compiled `q` grouped by `group_by`.
fn plan(c: &Connection, q: &str, group_by: Option<query::GroupBy>) -> Vec<String> {
    let compiled = query::compile(&query::Request {
        q: q.into(),
        from_ms: 1_000,
        to_ms: 2_000,
        group_by,
        limit: 100,
        cursor: None,
    })
    .unwrap();
    c.prepare(&format!("EXPLAIN QUERY PLAN {}", compiled.sql))
        .unwrap()
        .query_map(rusqlite::params_from_iter(compiled.params.iter()), |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn a_construct_grouping_over_a_window_reads_only_the_covering_ts_index() {
    let tmp = Tmp::new();
    let c = schema::open(&tmp.0.join("history.db")).unwrap();
    for q in ["", "-verdict:allow"] {
        let p = plan(&c, q, Some(query::GroupBy::Construct));
        assert!(
            p.iter()
                .any(|d| d.contains("USING COVERING INDEX requests_ts")),
            "{q:?}: {p:?}"
        );
    }
}

#[test]
fn snippets_are_stored_in_extra_as_given() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    h.enqueue(event("none", 1_000, block()));
    let WriteMsg::Decision(d) = event("some", 1_001, block()) else {
        unreachable!()
    };
    let mut d = (*d).clone();
    d.snippets = vec![(
        FieldRef {
            loc: Location::Query,
            name: "id".into(),
        },
        "1 union select a,b".into(),
    )];
    d.judgment.skipped = vec![FieldRef {
        loc: Location::Header,
        name: "X-Sig".into(),
    }];
    h.enqueue(WriteMsg::Decision(Arc::new(d)));
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    let extra = |id: &str| -> serde_json::Value {
        let s: String = c
            .query_row(
                "SELECT extra FROM requests WHERE event_id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        serde_json::from_str(&s).unwrap()
    };
    assert_eq!(extra("none")["snippets"], serde_json::json!([]));
    assert_eq!(
        extra("some")["snippets"],
        serde_json::json!([["query:id", "1 union select a,b"]])
    );
    assert_eq!(
        extra("some")["skipped"],
        serde_json::json!(["header:X-Sig"])
    );
    h.close(WAIT);
}

#[test]
fn a_write_error_drops_the_batch_marks_history_degraded_and_the_writer_keeps_going() {
    let tmp = Tmp::new();
    let status = Arc::new(StatusBoard::new());
    let h =
        HistoryHandle::open_with_status(&tmp.0, cfg(0.0), Arc::new(Metrics::new()), status.clone())
            .unwrap();
    {
        let c = Connection::open(tmp.0.join("history.db")).unwrap();
        c.execute_batch("DROP TABLE config_revisions").unwrap();
    }
    h.config_revision(1, "startup", b"x", b"", Vec::new());
    h.enqueue(event("lost", 1_000, block()));
    assert!(h.flush(WAIT));
    assert_eq!(h.dropped(), 2, "the whole batch");
    let rec = status.snapshot();
    let hist = rec.components.iter().find(|c| c.name == "history").unwrap();
    assert_eq!(hist.health, Health::Degraded);
    assert!(hist.reason.contains("config_revisions"), "{}", hist.reason);
    // The writer is still running.
    h.enqueue(event("kept", 2_000, block()));
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    assert_eq!(count(&c, "SELECT count(*) FROM requests"), 1);
    assert_eq!(
        count(&c, "SELECT count(*) FROM requests WHERE event_id = 'kept'"),
        1
    );
    let rec = status.snapshot();
    let hist = rec.components.iter().find(|c| c.name == "history").unwrap();
    assert_eq!(
        (hist.health, hist.reason.as_str()),
        (Health::Ok, "on"),
        "a good commit clears it"
    );
    h.close(WAIT);
}

#[test]
fn close_writes_what_was_queued_and_later_enqueues_are_refused() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    let q = h.queue();
    for i in 0..10 {
        q.enqueue(event(&format!("c-{i}"), 1_000, block()));
    }
    h.close(WAIT);
    assert!(!q.enqueue(event("late", 1_000, block())));
    assert_eq!(q.dropped(), 1);
    assert!(!q.flush(Duration::from_millis(100)));
    let c = read(&tmp.0);
    assert_eq!(count(&c, "SELECT count(*) FROM requests"), 10);
}

const DAY_MS: u64 = 86_400_000;

#[test]
fn a_sweep_message_deletes_old_rows_on_the_writer_connection() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    let now = 100 * DAY_MS;
    h.enqueue(event("old", now - 20 * DAY_MS, block()));
    h.enqueue(event("new", now - DAY_MS, block()));
    h.enqueue(WriteMsg::Sweep {
        now_ms: now,
        retention_days: 14,
    });
    // A decision queued behind the sweep is still written.
    h.enqueue(event("later", now, block()));
    assert!(h.flush(WAIT));
    // The sweep works between queue turns; a flush does not wait for it.
    let deadline = Instant::now() + WAIT;
    while count(
        &read(&tmp.0),
        "SELECT count(*) FROM requests WHERE event_id = 'old'",
    ) > 0
    {
        assert!(Instant::now() < deadline, "the sweep did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    let c = read(&tmp.0);
    assert_eq!(count(&c, "SELECT count(*) FROM requests"), 2);
    // Both rollup minutes are far younger than 90 days.
    assert_eq!(count(&c, "SELECT count(*) FROM rollup_minute"), 3);
    h.close(WAIT);
}

#[test]
fn a_failing_sweep_marks_history_degraded_and_the_next_good_write_clears_it() {
    let tmp = Tmp::new();
    let status = Arc::new(StatusBoard::new());
    let h =
        HistoryHandle::open_with_status(&tmp.0, cfg(0.0), Arc::new(Metrics::new()), status.clone())
            .unwrap();
    {
        let c = Connection::open(tmp.0.join("history.db")).unwrap();
        c.execute_batch("ALTER TABLE chain_events RENAME TO chain_events_gone")
            .unwrap();
    }
    h.enqueue(WriteMsg::Sweep {
        now_ms: 100 * DAY_MS,
        retention_days: 14,
    });
    assert!(h.flush(WAIT));
    let health = || {
        let rec = status.snapshot();
        let c = rec.components.iter().find(|c| c.name == "history").unwrap();
        (c.health, c.reason.clone())
    };
    // The sweep runs between queue turns; a flush does not wait for it.
    let until = |want: Health| {
        let deadline = Instant::now() + WAIT;
        while health().0 != want {
            assert!(Instant::now() < deadline, "history never became {want:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    until(Health::Degraded);
    let (_, reason) = health();
    assert!(reason.contains("chain_events"), "{reason}");
    {
        let c = Connection::open(tmp.0.join("history.db")).unwrap();
        c.execute_batch("ALTER TABLE chain_events_gone RENAME TO chain_events")
            .unwrap();
    }
    h.enqueue(WriteMsg::Sweep {
        now_ms: 100 * DAY_MS,
        retention_days: 14,
    });
    assert!(h.flush(WAIT));
    until(Health::Ok);
    h.close(WAIT);
}

/// `n` expired `requests` rows (ts 1 .. n), inserted behind the writer's back.
fn old_backlog(dir: &Path, n: u64) {
    let c = Connection::open(dir.join("history.db")).unwrap();
    c.execute(
        "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < ?1)
         INSERT INTO requests (event_id, ts_ms, method, host, path, verdict, score, families,
           cause_kind, decided_option, config_rev, latency_us, sampled, exceptions, extra)
         SELECT 'old' || i, i, 'GET', 'h', '/', 'Block', 1, 0, 'Detection', 'o', 1, 1, 0, '', '{}' FROM c",
        [n as i64],
    )
    .unwrap();
}

#[test]
fn a_long_sweep_lets_the_queue_through_between_its_batches() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    assert!(h.flush(WAIT));
    let backlog = 100_000;
    old_backlog(&tmp.0, backlog);
    let now = 100 * DAY_MS;
    h.enqueue(WriteMsg::Sweep {
        now_ms: now,
        retention_days: 14,
    });
    h.enqueue(event("fresh", now, block()));
    assert!(h.flush(WAIT));
    let c = read(&tmp.0);
    assert_eq!(
        count(&c, "SELECT count(*) FROM requests WHERE event_id = 'fresh'"),
        1,
        "the decision queued behind the sweep is committed"
    );
    assert!(
        count(
            &c,
            "SELECT count(*) FROM requests WHERE event_id LIKE 'old%'"
        ) > 0,
        "before the sweep finished: it works in batches between queue turns"
    );
    // The sweep carries on and completes.
    let deadline = Instant::now() + WAIT;
    while count(
        &read(&tmp.0),
        "SELECT count(*) FROM requests WHERE event_id LIKE 'old%'",
    ) > 0
    {
        assert!(Instant::now() < deadline, "the sweep did not finish");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(h.dropped(), 0);
    h.close(WAIT);
    assert_eq!(count(&read(&tmp.0), "SELECT count(*) FROM requests"), 1);
}

#[test]
fn close_stops_a_sweep_in_progress_within_its_timeout() {
    let tmp = Tmp::new();
    let h = open(&tmp.0, 0.0);
    assert!(h.flush(WAIT));
    old_backlog(&tmp.0, 300_000);
    h.enqueue(WriteMsg::Sweep {
        now_ms: 100 * DAY_MS,
        retention_days: 14,
    });
    let started = Instant::now();
    h.close(Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(5));
    let left = count(&read(&tmp.0), "SELECT count(*) FROM requests");
    assert!(
        left > 0,
        "the rest of the sweep waits for the next hourly one ({left} left)"
    );
}
