//! The writer thread: owns the only write connection and commits queued
//! messages in batches (one transaction per [`HistoryHandle::BATCH`] messages
//! or [`HistoryHandle::BATCH_WAIT`], whichever comes first, and on every flush).

use super::retention::{Sweeper, SWEEP_BATCH};
use super::{families, keep, rate_at, HistoryHandle, Shared, WriteMsg};
use crate::metrics::Metrics;
use crate::status::{Health, StatusBoard};
use rusqlite::{params, Connection, Transaction};
use serde_json::json;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::sync::Arc;
use std::time::Instant;
use vft_core::FieldRef;
use vft_proxy::bus::DecisionEvent;

struct Writer {
    conn: Connection,
    shared: Arc<Shared>,
    metrics: Arc<Metrics>,
    status: Arc<StatusBoard>,
    batch: Vec<WriteMsg>,
    /// The last commit failed (status shows `Degraded`).
    failing: bool,
    /// A retention sweep in progress: one batch runs whenever the queue is
    /// empty, so it never keeps decisions (or `close`) waiting for long.
    sweep: Option<Sweeper>,
}

/// The writer loop. Returns when every sender is gone, or after the flush that
/// follows `close` (writing whatever is still queued first).
pub(super) fn run(
    conn: Connection,
    rx: Receiver<WriteMsg>,
    shared: Arc<Shared>,
    metrics: Arc<Metrics>,
    status: Arc<StatusBoard>,
) {
    let mut w = Writer {
        conn,
        shared,
        metrics,
        status,
        batch: Vec::with_capacity(HistoryHandle::BATCH),
        failing: false,
        sweep: None,
    };
    // When the oldest message of the open batch must be committed.
    let mut due: Option<Instant> = None;
    loop {
        let next = if w.sweep.is_some() {
            // Queue first; with nothing waiting, one more sweep batch.
            match rx.try_recv() {
                Ok(msg) => Ok(msg),
                Err(TryRecvError::Empty) => {
                    w.sweep_step();
                    if due.is_some_and(|t| Instant::now() >= t) {
                        w.commit();
                        due = None;
                    }
                    continue;
                }
                Err(TryRecvError::Disconnected) => Err(RecvTimeoutError::Disconnected),
            }
        } else {
            match due {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(t) => rx.recv_timeout(t.saturating_duration_since(Instant::now())),
            }
        };
        match next {
            Ok(msg) => {
                w.shared.depth.fetch_sub(1, Relaxed);
                let flush = matches!(msg, WriteMsg::Flush(_));
                if w.take(msg) {
                    due = None;
                } else if due.is_none() {
                    due = Some(Instant::now() + HistoryHandle::BATCH_WAIT);
                }
                if flush && w.shared.stop.load(Relaxed) {
                    // `close` was called and a flush just went through: write
                    // what is still queued, then stop. A sweep in progress
                    // is left for the next hourly one.
                    w.sweep = None;
                    while let Ok(msg) = rx.try_recv() {
                        w.shared.depth.fetch_sub(1, Relaxed);
                        // Retention can wait for the next start.
                        if !matches!(msg, WriteMsg::Sweep { .. }) {
                            w.take(msg);
                        }
                    }
                    w.commit();
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                w.commit();
                due = None;
            }
            Err(RecvTimeoutError::Disconnected) => {
                w.commit();
                return;
            }
        }
    }
}

impl Writer {
    /// Add `msg` to the batch; returns true when the batch was committed (a
    /// flush, or the batch is full).
    fn take(&mut self, msg: WriteMsg) -> bool {
        match msg {
            WriteMsg::Flush(ack) => {
                self.commit();
                let _ = ack.send(());
                true
            }
            WriteMsg::Sweep {
                now_ms,
                retention_days,
            } => {
                self.commit();
                // A newer sweep replaces one still running.
                self.sweep = Some(Sweeper::new(now_ms, retention_days, SWEEP_BATCH));
                true
            }
            other => {
                self.batch.push(other);
                if self.batch.len() >= HistoryHandle::BATCH {
                    self.commit();
                    true
                } else {
                    false
                }
            }
        }
    }

    /// One batch of the retention sweep on the write connection. A SQLite
    /// error ends the sweep and turns `history` Degraded like a failed commit;
    /// the next good write or sweep clears it.
    fn sweep_step(&mut self) {
        let Some(sweeper) = self.sweep.as_mut() else {
            return;
        };
        match sweeper.step(&self.conn) {
            Ok((_, None)) => {}
            Ok((_, Some((requests, chain_events, rollups)))) => {
                self.sweep = None;
                if requests + chain_events + rollups > 0 {
                    tracing::info!(requests, chain_events, rollups, "history: retention sweep");
                }
                self.recovered();
            }
            Err(e) => {
                self.sweep = None;
                tracing::error!(error = %e, "history: retention sweep failed");
                self.status
                    .set("history", Health::Degraded, format!("sweep failed: {e}"));
                self.failing = true;
            }
        }
    }

    fn recovered(&mut self) {
        if self.failing {
            self.failing = false;
            self.status.set("history", Health::Ok, "on");
            tracing::info!("history: writes succeed again");
        }
    }

    /// One transaction for the whole batch. On a SQLite error the batch is
    /// rolled back and counted as dropped, `history` turns Degraded with the
    /// error text, and the writer carries on; the next good commit clears it.
    fn commit(&mut self) {
        if !self.batch.is_empty() {
            let n = self.batch.len() as u64;
            let rates = self.shared.rates().clone();
            match write_batch(&mut self.conn, &self.batch, &rates) {
                Ok(()) => {
                    self.shared.written.fetch_add(n, Relaxed);
                    self.metrics.history_written(n);
                    self.recovered();
                }
                Err(e) => {
                    self.shared.drop_n(&self.metrics, n);
                    tracing::error!(error = %e, dropped = n, "history: write failed; batch dropped");
                    self.status
                        .set("history", Health::Degraded, format!("write failed: {e}"));
                    self.failing = true;
                }
            }
            self.batch.clear();
        }
        self.metrics
            .set_history_queue(self.shared.depth.load(Relaxed));
    }
}

fn write_batch(
    conn: &mut Connection,
    batch: &[WriteMsg],
    rates: &[(u64, f64)],
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for msg in batch {
        write(&tx, msg, rates)?;
    }
    tx.commit()
}

/// SQLite integers are signed; nothing we store comes near `i64::MAX`.
fn int(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn json_text<T: serde::Serialize>(v: &T) -> rusqlite::Result<String> {
    serde_json::to_string(v).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn write(tx: &Transaction<'_>, msg: &WriteMsg, rates: &[(u64, f64)]) -> rusqlite::Result<()> {
    match msg {
        WriteMsg::Decision(d) => decision(tx, d, rate_at(rates, d.config_rev)),
        WriteMsg::Ban {
            key,
            ban,
            lifted,
            ts_ms,
        } => {
            if let Some(b) = ban {
                tx.prepare_cached(
                    "INSERT INTO bans (key, cause, since_ms, until_ms, offences) VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (key, since_ms) DO UPDATE SET
                       cause = excluded.cause, until_ms = excluded.until_ms, offences = excluded.offences",
                )?
                .execute(params![
                    key,
                    format!("{:?}", b.cause),
                    int(b.since_ms),
                    int(b.until_ms),
                    b.offences
                ])?;
            }
            if *lifted {
                match ban {
                    Some(b) => tx
                        .prepare_cached(
                            "UPDATE bans SET lifted_ms = ?1 WHERE key = ?2 AND since_ms = ?3 AND lifted_ms IS NULL",
                        )?
                        .execute(params![int(*ts_ms), key, int(b.since_ms)])?,
                    None => tx
                        .prepare_cached(
                            "UPDATE bans SET lifted_ms = ?1 WHERE key = ?2 AND lifted_ms IS NULL",
                        )?
                        .execute(params![int(*ts_ms), key])?,
                };
            }
            Ok(())
        }
        WriteMsg::ConfigRevision {
            rev,
            ts_ms,
            source,
            config_sha256,
            exceptions_sha256,
            changed_keys,
        } => {
            tx.prepare_cached(
                "INSERT INTO config_revisions (rev, ts_ms, source, config_sha256, exceptions_sha256, changed_keys)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(params![
                int(*rev),
                int(*ts_ms),
                source,
                config_sha256,
                exceptions_sha256,
                changed_keys.join(",")
            ])?;
            Ok(())
        }
        // Handled by the loop; never batched.
        WriteMsg::Flush(_) | WriteMsg::Sweep { .. } => Ok(()),
    }
}

/// The rollup (always), the `requests` row (when kept) and the chain events.
fn decision(tx: &Transaction<'_>, d: &DecisionEvent, rate: f64) -> rusqlite::Result<()> {
    let j = &d.judgment;
    let verdict = format!("{:?}", j.verdict);
    let fam = families(j);
    tx.prepare_cached(
        "INSERT INTO rollup_minute (minute_ms, verdict, families, count) VALUES (?1, ?2, ?3, 1)
         ON CONFLICT (minute_ms, verdict, families) DO UPDATE SET count = count + 1",
    )?
    .execute(params![int(d.ts_ms - d.ts_ms % 60_000), verdict, fam])?;

    let stage = j.stage().map(|s| format!("{s:?}"));
    if let Some(sampled) = keep(j, &d.event_id, rate) {
        let extra = json!({
            "contributions": j.contributions.iter().map(|c| json!({
                "construct": c.construct,
                "field": c.field.as_ref().map(FieldRef::label),
                "points": c.points,
                "shadow": c.shadow,
                "exception": c.exception,
            })).collect::<Vec<_>>(),
            "skipped": j.skipped.iter().map(FieldRef::label).collect::<Vec<_>>(),
            "snippets": d.snippets.iter().map(|(f, v)| json!([f.label(), v])).collect::<Vec<_>>(),
        });
        tx.prepare_cached(
            "INSERT OR IGNORE INTO requests (
               event_id, ts_ms, src_key, ip, method, host, path, verdict, score, stage, families,
               construct, technique, confidence, group_id, cause_kind, decided_option, config_rev,
               latency_us, upstream_status, sampled, exceptions, extra
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        )?
        .execute(params![
            d.event_id,
            int(d.ts_ms),
            d.src_key,
            d.ip.map(|ip| ip.to_string()),
            d.method,
            d.host,
            d.path,
            verdict,
            j.score,
            stage,
            fam,
            j.decided_by.construct,
            j.attack.first().map(|t| t.id.as_str()),
            j.confidence,
            d.group_id,
            format!("{:?}", j.decided_by.kind),
            j.decided_by.option_key,
            int(d.config_rev),
            int(d.latency_us),
            d.upstream_status,
            sampled,
            j.exceptions.join(","),
            extra.to_string(),
        ])?;
    }

    // Chain events need a source to belong to.
    if let (Some(src), Some(c)) = (&d.src_key, &j.chain) {
        let event = |kind: &str, detail: String| -> rusqlite::Result<()> {
            tx.prepare_cached(
                "INSERT INTO chain_events (ts_ms, src_key, kind, stage, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![int(d.ts_ms), src, kind, stage, detail])?;
            Ok(())
        };
        if c.advanced {
            event(
                "stage",
                json_text(&json!({
                    "from": c.stage_before,
                    "to": c.stage_after,
                    "event_id": d.event_id,
                }))?,
            )?;
        }
        if let Some(ban) = &c.new_ban {
            event("ban", json_text(ban)?)?;
        }
    }
    Ok(())
}
