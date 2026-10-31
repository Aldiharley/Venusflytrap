//! Retention (the hourly sweep) and the ban query used to restore bans at boot.

use rusqlite::{params, Connection};
use vft_core::chain::BanCause;
use vft_core::BanRecord;

/// Rows deleted per transaction at most, so the sweep never holds the write
/// connection for long.
pub const SWEEP_BATCH: usize = 5_000;

const DAY_MS: u64 = 86_400_000;

/// Days of rollups kept, whatever `history.retention_days` says.
pub const ROLLUP_DAYS: u32 = 90;

/// Delete requests and chain_events older than now - retention_days, rollups older than now - 90 days,
/// in batches of at most 5,000 rows per transaction. Returns rows deleted per table
/// as `(requests, chain_events, rollup_minute)`.
pub fn sweep(
    conn: &Connection,
    now_ms: u64,
    retention_days: u32,
) -> rusqlite::Result<(u64, u64, u64)> {
    sweep_batched(conn, now_ms, retention_days, SWEEP_BATCH).map(|(rows, _txs)| rows)
}

/// [`sweep`] with another batch size; also returns how many transactions
/// deleted anything (the test hook for the batching).
fn sweep_batched(
    conn: &Connection,
    now_ms: u64,
    retention_days: u32,
    batch: usize,
) -> rusqlite::Result<((u64, u64, u64), u64)> {
    let mut sweeper = Sweeper::new(now_ms, retention_days, batch);
    let mut txs = 0;
    loop {
        let (deleted, done) = sweeper.step(conn)?;
        if deleted > 0 {
            txs += 1;
        }
        if let Some(rows) = done {
            return Ok((rows, txs));
        }
    }
}

const SWEEP_SQL: [&str; 3] = [
    "DELETE FROM requests WHERE rowid IN (SELECT rowid FROM requests WHERE ts_ms < ?1 LIMIT ?2)",
    "DELETE FROM chain_events WHERE rowid IN (SELECT rowid FROM chain_events WHERE ts_ms < ?1 LIMIT ?2)",
    "DELETE FROM rollup_minute WHERE rowid IN (SELECT rowid FROM rollup_minute WHERE minute_ms < ?1 LIMIT ?2)",
];

/// Rows deleted per table: `(requests, chain_events, rollup_minute)`.
pub(super) type Swept = (u64, u64, u64);

/// A sweep in progress, advanced one transaction at a time, so the writer can
/// serve its queue (and `close`) between batches.
pub(super) struct Sweeper {
    /// Cutoffs per table, in `SWEEP_SQL` order.
    cutoffs: [i64; 3],
    limit: i64,
    /// The table being swept.
    table: usize,
    deleted: [u64; 3],
}

impl Sweeper {
    pub(super) fn new(now_ms: u64, retention_days: u32, batch: usize) -> Sweeper {
        let keep_ms = |days: u32| u64::from(days).saturating_mul(DAY_MS);
        let cutoff =
            |days: u32| i64::try_from(now_ms.saturating_sub(keep_ms(days))).unwrap_or(i64::MAX);
        let requests = cutoff(retention_days);
        Sweeper {
            cutoffs: [requests, requests, cutoff(ROLLUP_DAYS)],
            limit: i64::try_from(batch.max(1)).unwrap_or(i64::MAX),
            table: 0,
            deleted: [0; 3],
        }
    }

    /// One transaction of at most `batch` rows. Returns the rows it deleted
    /// and, once every table is swept, the totals `(requests, chain_events,
    /// rollup_minute)`.
    pub(super) fn step(&mut self, conn: &Connection) -> rusqlite::Result<(u64, Option<Swept>)> {
        let tx = conn.unchecked_transaction()?;
        let n = tx.execute(
            SWEEP_SQL[self.table],
            params![self.cutoffs[self.table], self.limit],
        )? as u64;
        tx.commit()?;
        self.deleted[self.table] += n;
        if n < self.limit as u64 {
            self.table += 1;
        }
        let done = (self.table == SWEEP_SQL.len())
            .then(|| (self.deleted[0], self.deleted[1], self.deleted[2]));
        Ok((n, done))
    }
}

/// Active bans: until_ms > now and lifted_ms IS NULL, newest row per key.
/// Ascending by `until_ms`, so restoring them in order keeps the longest bans
/// when the tracker is over capacity.
pub fn active_bans(conn: &Connection, now_ms: u64) -> rusqlite::Result<Vec<(String, BanRecord)>> {
    let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
    let mut stmt = conn.prepare(
        "SELECT key, cause, since_ms, until_ms, offences FROM bans b
         WHERE since_ms = (SELECT MAX(since_ms) FROM bans WHERE key = b.key)
           AND lifted_ms IS NULL AND until_ms > ?1
         ORDER BY until_ms ASC, key ASC",
    )?;
    let rows = stmt.query_map(params![now], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, u32>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (key, cause, since, until, offences) = row?;
        let Some(cause) = parse_cause(&cause) else {
            tracing::warn!(%key, %cause, "history: a stored ban has an unknown cause; not restored");
            continue;
        };
        out.push((
            key,
            BanRecord {
                since_ms: u64::try_from(since).unwrap_or(0),
                until_ms: u64::try_from(until).unwrap_or(0),
                cause,
                offences,
            },
        ));
    }
    Ok(out)
}

/// The inverse of how the writer stores a cause (`format!("{:?}")`).
fn parse_cause(s: &str) -> Option<BanCause> {
    Some(match s {
        "Honeypot" => BanCause::Honeypot,
        "Exfiltration" => BanCause::Exfiltration,
        "RepeatedExploitation" => BanCause::RepeatedExploitation,
        "Manual" => BanCause::Manual,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = DAY_MS;
    const NOW: u64 = 200 * DAY;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE requests (event_id TEXT PRIMARY KEY, ts_ms INTEGER NOT NULL);
             CREATE INDEX requests_ts ON requests(ts_ms);
             CREATE TABLE chain_events (ts_ms INTEGER NOT NULL, src_key TEXT NOT NULL, kind TEXT NOT NULL, stage TEXT, detail TEXT NOT NULL);
             CREATE INDEX chain_events_ts ON chain_events(ts_ms);
             CREATE TABLE rollup_minute (minute_ms INTEGER NOT NULL, verdict TEXT NOT NULL, families INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (minute_ms, verdict, families));
             CREATE TABLE bans (key TEXT NOT NULL, cause TEXT NOT NULL, since_ms INTEGER NOT NULL, until_ms INTEGER NOT NULL, offences INTEGER NOT NULL, lifted_ms INTEGER, PRIMARY KEY (key, since_ms));",
        )
        .unwrap();
        c
    }

    fn n(c: &Connection, table: &str) -> i64 {
        c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    fn req(c: &Connection, id: &str, ts: u64) {
        c.execute(
            "INSERT INTO requests VALUES (?1, ?2)",
            params![id, ts as i64],
        )
        .unwrap();
    }

    fn event(c: &Connection, ts: u64) {
        c.execute(
            "INSERT INTO chain_events VALUES (?1, '192.0.2.7', 'stage', NULL, '{}')",
            params![ts as i64],
        )
        .unwrap();
    }

    fn rollup(c: &Connection, minute: u64) {
        c.execute(
            "INSERT INTO rollup_minute VALUES (?1, 'Allow', 0, 1)",
            params![minute as i64],
        )
        .unwrap();
    }

    fn old_requests(c: &Connection, count: u64, from: u64) {
        let tx = c.unchecked_transaction().unwrap();
        for i in 0..count {
            tx.execute(
                "INSERT INTO requests VALUES (?1, ?2)",
                params![format!("e{i}"), (from + i) as i64],
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }

    #[test]
    fn sweep_deletes_exactly_the_rows_before_the_cutoff() {
        let c = db();
        let cutoff = NOW - 14 * DAY;
        for (id, ts) in [("a", cutoff - 1), ("b", cutoff), ("c", cutoff + 1)] {
            req(&c, id, ts);
        }
        for ts in [cutoff - 1, cutoff, cutoff + 1] {
            event(&c, ts);
        }
        assert_eq!(sweep(&c, NOW, 14).unwrap(), (1, 1, 0));
        let left: Vec<i64> = c
            .prepare("SELECT ts_ms FROM requests ORDER BY ts_ms")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(left, vec![cutoff as i64, cutoff as i64 + 1]);
        assert_eq!(n(&c, "chain_events"), 2);
    }

    #[test]
    fn rollups_use_the_90_day_cutoff_whatever_the_retention() {
        let c = db();
        let cutoff = NOW - 90 * DAY;
        for m in [cutoff - 60_000, cutoff, cutoff + 60_000] {
            rollup(&c, m);
        }
        // 14-day retention leaves a rollup 30 days old alone.
        rollup(&c, NOW - 30 * DAY);
        assert_eq!(sweep(&c, NOW, 14).unwrap(), (0, 0, 1));
        assert_eq!(n(&c, "rollup_minute"), 3);
        // A longer retention does not extend the rollups either.
        assert_eq!(sweep(&c, NOW, 365).unwrap(), (0, 0, 0));
        assert_eq!(n(&c, "rollup_minute"), 3);
    }

    #[test]
    fn a_young_clock_deletes_nothing() {
        let c = db();
        req(&c, "a", 5);
        event(&c, 5);
        rollup(&c, 0);
        assert_eq!(sweep(&c, 1_000, 14).unwrap(), (0, 0, 0));
        assert_eq!(n(&c, "requests"), 1);
    }

    #[test]
    fn a_big_sweep_runs_in_batches_of_at_most_the_limit() {
        let old = NOW - 20 * DAY;
        let c = db();
        old_requests(&c, 12_000, old);
        req(&c, "young", NOW);
        let (rows, txs) = sweep_batched(&c, NOW, 14, SWEEP_BATCH).unwrap();
        assert_eq!(rows, (12_000, 0, 0));
        assert_eq!(txs, 3, "5,000 + 5,000 + 2,000");
        assert_eq!(n(&c, "requests"), 1);
        // The public entry point deletes the same.
        let c = db();
        old_requests(&c, 12_000, old);
        assert_eq!(sweep(&c, NOW, 14).unwrap(), (12_000, 0, 0));
    }

    fn ban(c: &Connection, key: &str, cause: &str, since: u64, until: u64, lifted: Option<u64>) {
        c.execute(
            "INSERT INTO bans VALUES (?1, ?2, ?3, ?4, 2, ?5)",
            params![
                key,
                cause,
                since as i64,
                until as i64,
                lifted.map(|l| l as i64)
            ],
        )
        .unwrap();
    }

    #[test]
    fn active_bans_excludes_expired_and_lifted_and_picks_the_newest_per_key() {
        let c = db();
        ban(&c, "198.51.100.1", "Honeypot", 100, NOW + 5_000, None); // active
        ban(&c, "198.51.100.2", "Manual", 100, NOW, None); // expires exactly now
        ban(
            &c,
            "198.51.100.3",
            "Exfiltration",
            100,
            NOW + 9_000,
            Some(NOW - 1),
        ); // lifted
           // Two rows for one key: the newest decides.
        ban(&c, "198.51.100.4", "Honeypot", 100, NOW + 50_000, None);
        ban(
            &c,
            "198.51.100.4",
            "RepeatedExploitation",
            200,
            NOW + 70_000,
            None,
        );
        // The newest row of this key is lifted; the older unlifted one is superseded.
        ban(&c, "198.51.100.5", "Honeypot", 100, NOW + 80_000, None);
        ban(
            &c,
            "198.51.100.5",
            "Honeypot",
            200,
            NOW + 90_000,
            Some(NOW - 5),
        );
        // The newest row is expired though an older one would still run.
        ban(&c, "198.51.100.6", "Honeypot", 100, NOW + 80_000, None);
        ban(&c, "198.51.100.6", "Honeypot", 200, NOW - 1, None);

        let got = active_bans(&c, NOW).unwrap();
        assert_eq!(
            got,
            vec![
                (
                    "198.51.100.1".to_string(),
                    BanRecord {
                        since_ms: 100,
                        until_ms: NOW + 5_000,
                        cause: BanCause::Honeypot,
                        offences: 2
                    }
                ),
                (
                    "198.51.100.4".to_string(),
                    BanRecord {
                        since_ms: 200,
                        until_ms: NOW + 70_000,
                        cause: BanCause::RepeatedExploitation,
                        offences: 2
                    }
                ),
            ],
            "ascending by until_ms"
        );
    }

    #[test]
    fn active_bans_skips_a_cause_it_does_not_know() {
        let c = db();
        ban(&c, "198.51.100.1", "Sorcery", 100, NOW + 5_000, None);
        ban(&c, "198.51.100.2", "Manual", 100, NOW + 6_000, None);
        let got = active_bans(&c, NOW).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "198.51.100.2");
    }
}
