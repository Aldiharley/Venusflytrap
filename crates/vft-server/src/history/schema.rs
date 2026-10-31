//! The history schema and its migrations.

use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

/// `PRAGMA user_version` after the last migration.
pub const USER_VERSION: i64 = 1;

/// Migration `n` (1-based) takes the database from `user_version` `n - 1` to `n`.
const MIGRATIONS: &[&str] = &[r"
CREATE TABLE requests (
  event_id TEXT PRIMARY KEY, ts_ms INTEGER NOT NULL, src_key TEXT, ip TEXT,
  method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL,
  verdict TEXT NOT NULL, score INTEGER NOT NULL, stage TEXT, families INTEGER NOT NULL,
  construct TEXT, technique TEXT, confidence INTEGER, group_id TEXT,
  cause_kind TEXT NOT NULL, decided_option TEXT NOT NULL, config_rev INTEGER NOT NULL,
  latency_us INTEGER NOT NULL, upstream_status INTEGER, sampled INTEGER NOT NULL,
  exceptions TEXT NOT NULL, extra TEXT NOT NULL
);
CREATE INDEX requests_ts ON requests(ts_ms, construct, verdict);
CREATE INDEX requests_verdict_ts ON requests(verdict, ts_ms);
CREATE INDEX requests_src_ts ON requests(src_key, ts_ms);
CREATE INDEX requests_construct_ts ON requests(construct, ts_ms);
CREATE INDEX requests_group ON requests(group_id);
CREATE TABLE rollup_minute (
  minute_ms INTEGER NOT NULL, verdict TEXT NOT NULL, families INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (minute_ms, verdict, families)
);
CREATE TABLE chain_events (ts_ms INTEGER NOT NULL, src_key TEXT NOT NULL, kind TEXT NOT NULL, stage TEXT, detail TEXT NOT NULL);
CREATE INDEX chain_events_src_ts ON chain_events(src_key, ts_ms);
CREATE INDEX chain_events_ts ON chain_events(ts_ms);
CREATE TABLE bans (
  key TEXT NOT NULL, cause TEXT NOT NULL, since_ms INTEGER NOT NULL, until_ms INTEGER NOT NULL,
  offences INTEGER NOT NULL, lifted_ms INTEGER, PRIMARY KEY (key, since_ms)
);
CREATE TABLE config_revisions (
  rev INTEGER NOT NULL, ts_ms INTEGER NOT NULL, source TEXT NOT NULL,
  config_sha256 TEXT NOT NULL, exceptions_sha256 TEXT NOT NULL, changed_keys TEXT NOT NULL
);
"];

/// Open (or create) the database, set the connection pragmas and migrate.
/// Each pending migration runs in its own transaction together with its
/// `user_version` bump, so a crash never leaves a half-applied step.
/// A database a newer build migrated past [`USER_VERSION`] is refused.
pub(super) fn open(path: &Path) -> anyhow::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        tracing::warn!(mode, "history: WAL journal mode not available");
    }
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&mut conn)?;
    Ok(conn)
}

fn migrate(conn: &mut Connection) -> anyhow::Result<()> {
    let have: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if have > USER_VERSION {
        anyhow::bail!("schema version {have} is newer than this build supports ({USER_VERSION})");
    }
    for (n, sql) in MIGRATIONS.iter().enumerate() {
        let version = n as i64 + 1;
        if version <= have {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
    }
    Ok(())
}
