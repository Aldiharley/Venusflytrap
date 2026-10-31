# B1+B2 (service runtime and SQLite history): measurements

B1 turns `venusflytrap serve` into a service (runtime with reload, signals and graceful shutdown, an admin
listener, metrics). B2 adds a SQLite history store behind it (rollups, rows for non-Allow and sampled Allow
decisions, kill-chain events, bans, config revisions) and `venusflytrap history query`. This note records the
six measurements the work was held to. Every number below was copied from a run made for this note on
2026-10-31.

The first round of runs missed two targets (history writes at sample rate 1.0, and the unfiltered
`group-by construct` query). A fix wave after the final review changed the history writer (a separate
control queue for bans and revisions, a 64 MiB page cache, `wal_autocheckpoint` 10,000, transactions of up
to 2,000 messages, a 16,384-message queue) and the `requests_ts` index (now covering
`(ts_ms, construct, verdict)`), and added the unfiltered `group-by src` and `group-by path` forms to the query
benchmark. Sections 1, 2, 4 and 5 were re-run on the fix-wave build; the first round's numbers stay in each
section as **before** rows. After the fix wave both original misses are met; the two newly measured forms,
unfiltered `group-by src` and `group-by path`, miss the query target and are marked **MISSED**.

## Summary

| # | Measurement | Target | Result | Status |
|---|---|---|---|---|
| 1 | No change to decisions | 0 changed cells (dev A/B), 0 changed decisions (full-corpus serve diff, `distinct` and `pooled:100`) | 0 changed cells on the 16,938 dev rows; 0 changed decisions and 0 score-only changes on all 33,875 rows, in both source models. After the fix wave: dev A/B again 0 changed cells (CSVs byte-identical) | met |
| 2 | Latency overhead of history | p99 with history within 5 % of without (median of 3 runs each, 1,000 rps, 60 s) | after the fix wave: median p99 5.649 ms with, 6.156 ms without (-8.2 %). Before: 5.135 ms with, 5.717 ms without (-10.2 %) | met |
| 3 | Reload under load | `failed` = 0, 20 reloads applied (2,000 rps, 60 s, reload every 3 s) | `failed` 0 (8 malformed corpus requests were rejected by the proxy with 400 before any decision and `replay` counts them as `rejected`; counted as anything other than 200/403 they would be 8), 20 applied, 0 reloads rejected | met |
| 4 | History write throughput | at least 5,000 events/s sustained over 60 s, 0 drops | after the fix wave: sample rate 1.0 (a `requests` row for every event) 300,000 of 300,000 written, 0 drops, in both runs (4,997.8 and 4,996.1 events/s); default 0.01 also 0 drops. Before: 3.7 % dropped at 1.0 | met at both sample rates (was **MISSED** at 1.0); see the flood caveat in section 4 |
| 5 | Query p95 over 1,000,000 rows | every 24-hour form p95 under 100 ms | after the fix wave: the unfiltered `group-by construct` p95 56.3 ms (run 1) and 93.3 ms (run 2), was 122.3 and 120.2 ms; 5 other forms 0.8 to 26.7 ms; the newly measured unfiltered `group-by src` 151.1 and 196.2 ms, `group-by path` 180.9 and 181.5 ms | met for `group-by construct` (was **MISSED**); **MISSED** for the unfiltered `group-by src` and `group-by path` |
| 6 | Stalled consumer | the proxy never waits for a slow consumer | covered by two unit tests, both passing (see below) | met by tests |

## Setup

- **Machine:** AMD Ryzen 9 5900X (12 cores, 24 threads), 64 GB RAM (65,448 MB reported), Windows 11 Pro
  10.0.26300.
- **Toolchain:** rustc 1.96.0 (ac68faa20 2026-05-25), `cargo build --release -p vft-cli -p vft-server --examples`.
- **Commit:** branch `b12-runtime-history`. The library code measured is `2dfcbd5` ("history query language and
  `venusflytrap history query`"). The two tools (`crates/vft-server/examples/replay.rs`,
  `history_bench.rs`) were uncommitted files in the working tree during the runs and were committed as
  `4a6cb3a` after them; `cargo fmt` changed only an import line between the runs and that commit, and the
  release binaries were rebuilt from the committed tree once more with the same source.
- **Fix-wave runs:** branch `b12-runtime-history` at `ec3dc39` (the fix wave's code commits), release build
  `cargo build --release -p vft-cli --bin venusflytrap` and `cargo build --release -p vft-server --examples`,
  same machine, same day. Their outputs are the `fix-*` and `b12-final-*` files in the runs directory.
- **Baseline binary (measurement 1):** `main-d6eec01.exe`, built from main `d6eec01`.
- **Corpus:** the blazehttp corpus (33,875 request files found) with the dev/held-out split manifest
  (`eval/split.py`). Every scored run and every load run used the dev half only; nothing was scored on the
  held-out half. The one run over all 33,875 rows is the serve diff of section 1, which compares two builds'
  decisions and scores nothing. The tools read the manifest and keep the dev rows: 16,938 files, of which 16,849 are replayable by
  `replay` (89 use `Transfer-Encoding` or `Upgrade` or could not be read, the same exclusion as
  `eval --mode tcp`).
- **Paths:** `$VFT_CORPUS` is the corpus `testcases` directory, `$VFT_MANIFEST` the split manifest, `$VFT_RUNS`
  the runs directory (all outputs, databases and state directories were written there, none in the repository)
  and `$MAINBIN` the baseline binary.
- **Load generator limits:** on Windows the client's timer wakes about every 15 ms, so requests are released in
  small bursts: the 99th-percentile lateness of a request against its schedule is 14.0 to 14.6 ms in the
  1,000 rps runs (`schedule_lag_ms` in the tables). It is the same for the runs with and without history. The
  generator is open loop: a request is due at `i / rate` whether or not the one before it has finished.

### The tools

- `replay` (`cargo run --release -p vft-server --example replay`) starts a `Runtime` (history on or off) with
  its audit file and history database in a fresh `--state-dir`, an admin listener on port 0 and an in-process
  stub upstream that answers 200 with an empty body. 32 client tasks on their own runtime replay the corpus
  files over TCP, cycling in path order, one connection per request, each with a distinct
  `X-Forwarded-For` (so no source is banned by an earlier request) and `Connection: close`. It prints one JSON
  report: `sent`, `ok` (status 200 or 403), `rejected`, `failed`, client-side `p50`/`p95`/`p99`, `reloads_applied`,
  `history_written`, `history_dropped`, the server's own counters read from `/metrics`, and, after a clean stop,
  what the database holds.
- `rejected` counts statuses 400, 413, 431 and 501: the proxy's HTTP layer refusing a malformed corpus request
  before any decision, which `eval --mode tcp` reports as `proxy_rejected`. `failed` counts everything else
  (5xx, connect, write or read errors). Four requests per 60,000 (8 per 120,000) were rejected with status 400, in
  every run, with and without history; the server's `requests_total` (decisions) is `sent - rejected` in
  every run. If those were counted as failures, `failed` would be 4 (or 8) in every run, on both sides of the
  comparison. This classification was chosen before any measurement was run.
- `history_bench` has two modes. `write` pushes synthetic decisions through `HistoryHandle::enqueue` (5 % non-Allow,
  95 % Allow, 5,000 source addresses) either paced at a rate for a number of seconds or, with `--rate 0`, in
  chunks of 2,000 with a flush after each (the writer's ceiling; nothing can be dropped). `query` fills a
  database with the same events spread evenly over 7 days (sample rate 1.0, so one row per event), then runs
  200 queries of each form over random 24-hour windows with `limit` 100.

## 1. No change to decisions

Dev A/B in library mode on the dev rows, then a serve-mode diff on the full corpus and on the dev rows, baseline binary against the branch binary. A serve diff compares the decisions of two builds and scores nothing, so it is run on all 33,875 rows; only its decision-diff counts are quoted here, no recall or false-positive figure from the full-corpus runs.

```
bash eval/ab_dev.sh b12-nochange "" "" "$MAINBIN" ./target/release/venusflytrap.exe
```

```
ab: 16938 shared rows, 0 only in a, 0 only in b
delta: tp=+0 fp=+0
mcnemar lib_verdict malicious: b=0 c=0 p=1
mcnemar lib_verdict benign: b=0 c=0 p=1
a: tp=150 fp=100 tn=16510 fn=178 recall=45.73% [40.42%, 51.14%] fp_rate=0.602% [0.495%, 0.732%]
b: tp=150 fp=100 tn=16510 fn=178 recall=45.73% [40.42%, 51.14%] fp_rate=0.602% [0.495%, 0.732%]
fallen: 0 malicious rows from Challenge/Block to Allow/Monitor
```

For each of `distinct` and `pooled:100`, with each binary, on the full corpus (no `--manifest`, no `--side`) and,
earlier in the task, on the dev rows:

```
<binary> eval --corpus "$VFT_CORPUS" --mode serve --sources <distinct|pooled:100> --out <csv> > <json>
<binary> eval --corpus "$VFT_CORPUS" --mode serve --sources <distinct|pooled:100> \
  --manifest "$VFT_MANIFEST" --side dev --out <csv> > <json>
py -I -X utf8 eval/compare_runs.py <main.csv> <new.csv>
py -I -X utf8 eval/changes.py gate --tag <tag> <main.csv> <new.csv> <new.json>
```

| Rows | Sources | Rows compared | Changed decisions | Score-only changes | Only in one run | bans_from_allowed | invariant_violations |
|---|---|---|---|---|---|---|---|
| full corpus | `distinct` | 33,875 | 0 | 0 | 0 | 0 | 0 |
| full corpus | `pooled:100` | 33,875 | 0 | 0 | 0 | 0 | 0 |
| dev rows | `distinct` | 16,938 | 0 | 0 | 0 | 0 | 0 |
| dev rows | `pooled:100` | 16,938 | 0 | 0 | 0 | 0 | 0 |

`compare_runs.py` printed `decision diffs: 0` for all four comparisons. The two CSVs of each comparison
(full corpus: 33,876 lines each; dev rows and the dev A/B: 16,939 lines each, header included) are
byte-for-byte identical (`cmp`), so 0 cells differ in any column.

**After the fix wave.** The fix wave changes `vft-proxy`'s handler (a new ban's `BanChanged` is published
right after the decision instead of after the upstream answers) and adds a read-only ban listing to
`vft-core`'s chain tracker. The dev A/B was re-run against the same baseline binary:

```
bash eval/ab_dev.sh b12-final "" "" "$MAINBIN" ./target/release/venusflytrap.exe
```

```
ab: 16938 shared rows, 0 only in a, 0 only in b
delta: tp=+0 fp=+0
mcnemar lib_verdict malicious: b=0 c=0 p=1
mcnemar lib_verdict benign: b=0 c=0 p=1
a: tp=150 fp=100 tn=16510 fn=178 recall=45.73% [40.42%, 51.14%] fp_rate=0.602% [0.495%, 0.732%]
b: tp=150 fp=100 tn=16510 fn=178 recall=45.73% [40.42%, 51.14%] fp_rate=0.602% [0.495%, 0.732%]
fallen: 0 malicious rows from Challenge/Block to Allow/Monitor
```

The two CSVs (16,939 lines each) are byte-for-byte identical (`cmp`): 0 changed cells. The full-corpus serve
diff was not re-run in the fix wave.

The branch changes `vft-core` (chain, config, options) and `vft-proxy` (event bus, config handle, pipeline).
The diffs above show that those changes leave every decision, score and ban of the corpus identical to
main's, in both source models.

## 2. Latency: history off against history on

```
replay --corpus "$VFT_CORPUS" --manifest "$VFT_MANIFEST" --side dev --rate 1000 --seconds 60 \
  --clients 32 --history <off|on> --state-dir "$VFT_RUNS/lat-<i>-<off|on>"
```

Run alternately (off, on, off, on, off, on) so drift in the machine affects both. Each run is 60,000
requests. The 1,000 rps rate was sustained by the client in all twelve runs.

**After the fix wave** (state dirs `fix-lat-<i>-<off|on>`):

| Run | History | Sent | OK | Rejected | Failed | Achieved rps | p50 ms | p95 ms | p99 ms | max ms | Schedule lag p99 ms |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | off | 60,000 | 59,996 | 4 | 0 | 999.7 | 1.573 | 3.937 | 6.225 | 92.9 | 15.2 |
| 1 | on | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.622 | 3.700 | 5.521 | 120.7 | 13.9 |
| 2 | off | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.606 | 4.088 | 6.156 | 79.1 | 15.5 |
| 2 | on | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.588 | 3.810 | 5.649 | 83.4 | 14.3 |
| 3 | off | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.636 | 3.933 | 5.611 | 81.0 | 14.9 |
| 3 | on | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.570 | 3.766 | 5.717 | 89.3 | 14.3 |

| | History off | History on | Change |
|---|---|---|---|
| p99 of the three runs (ms) | 6.225, 6.156, 5.611 | 5.521, 5.649, 5.717 | |
| **Median p99 (ms)** | **6.156** | **5.649** | **-8.2 %** |
| Median p95 (ms) | 3.937 | 3.766 | -4.3 % |
| Median p50 (ms) | 1.606 | 1.588 | -1.1 % |

With history on, every fix-wave run wrote all 59,997 messages and dropped none (history and metrics bus
drops 0); the databases held 59,996 rollup decisions and 4,259, 4,267 and 4,265 `requests` rows. The target
is met again. As before, the spread between runs is larger than the difference between the sides.

**Before** (first round, library code `2dfcbd5`):

| Run | History | Sent | OK | Rejected | Failed | Achieved rps | p50 ms | p95 ms | p99 ms | max ms | Schedule lag p99 ms |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | off | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.732 | 3.856 | 5.586 | 75.5 | 14.5 |
| 1 | on | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.731 | 3.529 | 4.788 | 90.2 | 14.0 |
| 2 | off | 60,000 | 59,996 | 4 | 0 | 999.8 | 1.795 | 3.999 | 14.029 | 143.6 | 14.6 |
| 2 | on | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.704 | 3.700 | 5.135 | 73.4 | 14.4 |
| 3 | off | 60,000 | 59,996 | 4 | 0 | 1000.0 | 1.676 | 3.972 | 5.717 | 96.3 | 14.6 |
| 3 | on | 60,000 | 59,996 | 4 | 0 | 999.8 | 1.761 | 3.664 | 5.220 | 74.5 | 14.2 |

| | History off | History on | Change |
|---|---|---|---|
| p99 of the three runs (ms) | 5.586, 14.029, 5.717 | 4.788, 5.135, 5.220 | |
| **Median p99 (ms)** | **5.717** | **5.135** | **-10.2 %** |
| Median p95 (ms) | 3.972 | 3.664 | -7.8 % |
| Median p50 (ms) | 1.732 | 1.731 | -0.1 % |

In the first round the target (median p99 with history within 5 % of without) was met: with history on, the median p99 is lower
than without, not higher. Read this as "no overhead measurable at 1,000 rps with three runs", not as history
making the proxy faster: the run-to-run spread is larger than the difference (one history-off run has a p99 of
14.029 ms against 5.6 ms and 5.7 ms in the other two; the median is robust to it).

With history on, every run wrote all 59,997 messages (59,996 decisions and the startup revision) and dropped
none. The database held 59,996 rollup decisions and 4,260, 4,297 and 4,250 `requests` rows (non-Allow
decisions plus about 1 % of Allow).

## 3. Reload under load

```
replay --corpus "$VFT_CORPUS" --manifest "$VFT_MANIFEST" --side dev --rate 2000 --seconds 60 \
  --clients 32 --history on --reload-every-ms 3000 --state-dir "$VFT_RUNS/reload-1"
```

The first reload runs at the start and then one every 3 s while the load is offered (the last at 57 s), 20 in
all. Before each, the config file is rewritten so that `history.allow_sample_rate` alternates between 0.01 and
0.02 (a Live option), so every reload swaps in a different config.

| Field | Value |
|---|---|
| Sent / OK / rejected / **failed** | 120,000 / 119,992 / 8 / **0** |
| Statuses | 200: 118,229; 403: 1,763; 400: 8 |
| Achieved rate | 1,999.98 rps over 60.0007 s |
| Client latency p50 / p95 / p99 / max | 1.334 / 4.990 / 7.235 / 93.66 ms |
| **Reloads applied** (client count and `vft_reloads_total{result="applied"}`) | **20** (and 0 rejected) |
| Config revision at the end | 21 (the startup revision and 20 reloads); 21 rows in `config_revisions` |
| History messages written / dropped | 120,013 (119,992 decisions and 21 revisions) / 0 |
| Bus drops (history, metrics consumers) | 0 / 0 |

Both targets are met: `failed` = 0 and 20 reloads applied. The 8 `rejected` are the same malformed corpus
requests as in section 2 (see "The tools"); no reload produced an error status, a failed connection or a
dropped message.

## 4. History write throughput

`history_bench write` sends 5 % non-Allow, 95 % Allow synthetic decisions. In paced mode a producer offers
5,000 events/s for 60 s (300,000 events); `events_per_s` is the events written divided by the time until the
writer had committed the last one. Two sample rates: the default 0.01, and 1.0, which stores a `requests` row
for every event (the worst case the option allows).

```
history_bench write --state-dir "$VFT_RUNS/hbw-paced-<rate>" --rate 5000 --seconds 60 --sample-rate <0.01|1.0>
history_bench write --state-dir "$VFT_RUNS/hbw-ceiling-<rate>" --rate 0 --events 300000 --sample-rate <0.01|1.0>
```

| Run | Sample rate | Sent | Written | Dropped | Elapsed s | Events/s | `requests` rows |
|---|---|---|---|---|---|---|---|
| **after:** paced 5,000/s | 1.0 | 300,000 | 300,000 | **0** | 60.027 | 4,997.8 | 300,000 |
| **after:** paced 5,000/s, second run | 1.0 | 300,000 | 300,000 | **0** | 60.047 | 4,996.1 | 300,000 |
| **after:** paced 5,000/s | 0.01 | 300,000 | 300,000 | **0** | 60.005 | 4,999.6 | 17,822 |
| **after:** ceiling (chunks of 2,000 with a flush) | 0.01 | 300,000 | 300,000 | 0 | 1.297 | 231,285.9 | 17,822 |
| **after:** ceiling (chunks of 2,000 with a flush) | 1.0 | 300,000 | 300,000 | 0 | 12.514 | 23,972.6 | 300,000 |
| before: paced 5,000/s | 0.01 | 300,000 | 300,000 | **0** | 60.004 | 4,999.65 | 17,822 |
| before: paced 5,000/s | 1.0 | 300,000 | 288,788 | **11,212 (3.74 %)** | 60.955 | 4,737.7 | 288,788 |
| before: paced 5,000/s, second run | 1.0 | 300,000 | 289,006 | **10,994 (3.66 %)** | 60.895 | 4,746.0 | 289,006 |
| before: ceiling (chunks of 2,000 with a flush) | 0.01 | 300,000 | 300,000 | 0 | 3.458 | 86,754.7 | 17,822 |
| before: ceiling (chunks of 2,000 with a flush) | 1.0 | 300,000 | 300,000 | 0 | 45.565 | 6,584.0 | 300,000 |

- **After the fix wave the target is met at both sample rates:** at 1.0 the writer took the 5,000 events/s
  offered for 60 s with 0 drops in both runs (300,000 of 300,000), and at 0.01 again with 0 drops. The
  ceiling at 1.0 rose from 6,584.0 to 23,972.6 events/s (3.6 times; 4.8 times the target). The ceiling runs
  are not directly comparable with the first round's: they flush every 2,000 events, which was 4 transactions
  per chunk at the old batch size of 500 and is 1 at the new 2,000, so part of the ceiling gain is fewer
  commits per flush, not only the cache and checkpoint pragmas. The paced runs, which do not flush until the
  end, are the target's measurement.
- **Flood caveat:** "met at 1.0" is for an offered 5,000 events/s on this machine. A sustained flood above the
  writer's rate at sample rate 1.0 (or a Block flood, which stores every row at any sample rate) still fills
  the queue, now 16,384 messages (about 3.3 s at 5,000/s), and then drops decisions, counted in
  `vft_history_rows_dropped_total` and under consumer `history-writer`. Bans and config revisions no longer
  share that queue: they have their own 1,024-message control queue that the writer drains first, and at stop
  every active ban is written from the chain store, so a decision flood no longer loses them.

First round:

- **At the default sample rate (0.01) the target is met:** the writer took the 5,000 events/s offered for 60 s
  with 0 drops (300,000 of 300,000 written; the computed 4,999.65 events/s is 300,000 over the 60.004 s that
  include the final flush), and its ceiling is 86,754.7 events/s, about 17 times the target.
- **With `history.allow_sample_rate` at 1.0 the target is MISSED:** the writer drops 3.7 % of an offered
  5,000 events/s (11,212 and 10,994 of 300,000 in two runs) and its ceiling is 6,584.0 events/s, only 32 %
  above the target, and the paced producer, which sends in bursts, overflowed the 4,096-message
  queue (the cause was not investigated). Nothing was tuned: the queue size, batch size and pragmas are as shipped. With every Allow stored,
  history does not take 5,000 events/s on this machine; the proxy is not slowed in that case (a full queue
  drops and counts, see section 6), the history just loses rows and `vft_history_rows_dropped_total` shows it.

## 5. Query latency over 1,000,000 rows

`history_bench query` fills `history.db` with 1,000,000 rows over 7 days (168.0 h; 50,163 non-Allow rows, 5.0 %;
database file 304,283,648 bytes) and runs 200 queries per form over random 24-hour windows. A window holds
about 143,000 rows.

```
history_bench query --state-dir "$VFT_RUNS/hbq-1m" --rows 1000000 --days 7 --queries 200          # run 1: fill and query
history_bench query --state-dir "$VFT_RUNS/hbq-1m" --no-fill --queries 200                         # run 2: a new process on the same database
```

**After the fix wave** (`$VFT_RUNS/fix-hbq-1m`, same commands and seeds; the same 1,000,000 rows and 50,163
non-Allow rows over 168.0 h; database file 313,208,832 bytes, 8.9 MB more for the wider index; the fill took
87.17 s, 11,471.7 events/s, 0 dropped). Two forms were added: the empty query grouped by `src` and by `path`.

| Form | Run | p50 ms | p95 ms | max ms | Rows or groups returned (mean) | Target p95 < 100 ms |
|---|---|---|---|---|---|---|
| `verdict:block` | 1 | 1.252 | 1.878 | 3.149 | 100.0 | met |
| `verdict:block` | 2 | 1.320 | 1.730 | 2.200 | 100.0 | met |
| `construct:sqli.*` | 1 | 2.225 | 3.170 | 5.648 | 100.0 | met |
| `construct:sqli.*` | 2 | 2.006 | 2.900 | 6.850 | 100.0 | met |
| `src:<random source>` | 1 | 0.548 | 0.909 | 1.135 | 28.6 | met |
| `src:<random source>` | 2 | 0.491 | 0.806 | 1.404 | 28.6 | met |
| `-verdict:allow` | 1 | 1.420 | 1.715 | 2.426 | 100.0 | met |
| `-verdict:allow` | 2 | 1.244 | 1.588 | 2.094 | 100.0 | met |
| `group-by construct` (empty query) | 1 | 46.926 | **56.251** | 63.954 | 7.0 | met |
| `group-by construct` (empty query) | 2 | 71.515 | **93.347** | 164.669 | 7.0 | met |
| `group-by construct` with `-verdict:allow` | 1 | 15.406 | 19.330 | 21.056 | 6.0 | met |
| `group-by construct` with `-verdict:allow` | 2 | 22.191 | 26.706 | 32.610 | 6.0 | met |
| `group-by src` (empty query, new) | 1 | 116.766 | **151.121** | 184.862 | 100.0 | **MISSED** |
| `group-by src` (empty query, new) | 2 | 169.742 | **196.204** | 246.639 | 100.0 | **MISSED** |
| `group-by path` (empty query, new) | 1 | 140.949 | **180.875** | 248.999 | 100.0 | **MISSED** |
| `group-by path` (empty query, new) | 2 | 155.482 | **181.514** | 205.113 | 100.0 | **MISSED** |

`EXPLAIN QUERY PLAN` of each form (from the report, identical in both runs):

| Form | Plan |
|---|---|
| `verdict:block` | `SEARCH requests USING INDEX requests_verdict_ts (verdict=? AND ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR LAST TERM OF ORDER BY` |
| `construct:sqli.*` | `SEARCH requests USING INDEX requests_ts (ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR LAST TERM OF ORDER BY` |
| `src:<ip>` | `SEARCH requests USING INDEX requests_src_ts (src_key=? AND ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR LAST TERM OF ORDER BY` |
| `-verdict:allow` | `SEARCH requests USING INDEX requests_ts (ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR LAST TERM OF ORDER BY` |
| `group-by construct` | `SEARCH requests USING COVERING INDEX requests_ts (ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR GROUP BY`; `USE TEMP B-TREE FOR ORDER BY` |
| `group-by construct -verdict:allow` | `SEARCH requests USING COVERING INDEX requests_ts (ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR GROUP BY`; `USE TEMP B-TREE FOR ORDER BY` |
| `group-by src` | `SEARCH requests USING INDEX requests_ts (ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR GROUP BY`; `USE TEMP B-TREE FOR ORDER BY` |
| `group-by path` | `SEARCH requests USING INDEX requests_ts (ts_ms>? AND ts_ms<?)`; `USE TEMP B-TREE FOR GROUP BY`; `USE TEMP B-TREE FOR ORDER BY` |

- **The unfiltered `group-by construct` now meets the target:** p95 56.3 ms and 93.3 ms (was 122.3 and
  120.2 ms). It reads only the covering `requests_ts (ts_ms, construct, verdict)` index for the window; the
  first round's plan was `SEARCH requests USING INDEX requests_ts` with a table lookup per row. Run 2 is the
  slower of the two for every grouping (93.3 ms is close to the limit); the cause was not investigated.
- **The unfiltered `group-by src` and `group-by path` miss the target:** p95 151.1 / 196.2 ms and 180.9 /
  181.5 ms. They group about 143,000 rows of the window by a column the index does not hold, so every row is a
  table lookup, and they produce 100 groups from about 5,000 sources and 200 paths. They were not measured in
  the first round. No further index was added in the fix wave (the brief allowed only the one covering `ts`
  index); this is a known limit. With a filter (for example `-verdict:allow`) the window shrinks to about
  5 % of the rows.

**Before** (first round; the fill took 134.16 s, 7,453.6 events/s with a flush every 2,000 events, 0 dropped):

| Form | Run | p50 ms | p95 ms | max ms | Rows or groups returned (mean) | Target p95 < 100 ms |
|---|---|---|---|---|---|---|
| `verdict:block` | 1 | 1.269 | 2.001 | 2.692 | 100.0 | met |
| `verdict:block` | 2 | 1.57 | 2.44 | 3.33 | 100.0 | met |
| `construct:sqli.*` | 1 | 4.371 | 6.390 | 7.055 | 100.0 | met |
| `construct:sqli.*` | 2 | 3.87 | 5.59 | 8.54 | 100.0 | met |
| `src:<random source>` | 1 | 0.482 | 0.889 | 1.277 | 28.6 | met |
| `src:<random source>` | 2 | 0.54 | 1.00 | 1.78 | 28.6 | met |
| `-verdict:allow` | 1 | 2.077 | 2.757 | 3.609 | 100.0 | met |
| `-verdict:allow` | 2 | 1.73 | 2.14 | 3.02 | 100.0 | met |
| `group-by construct` (empty query: every row in the window) | 1 | 98.239 | **122.325** | 148.895 | 7.0 | **MISSED** |
| `group-by construct` (empty query: every row in the window) | 2 | 99.16 | **120.19** | 145.04 | 7.0 | **MISSED** |
| `group-by construct` with `-verdict:allow` (added in run 2) | 2 | 59.55 | 74.87 | 91.35 | 6.0 | met |

- **In the first round the target was missed for `group-by construct` over every row of the window:** p95 122.3 ms and 120.2 ms
  (p50 about 99 ms) against 100 ms. The grouping reads and counts all of a window's ~143,000 rows; the four
  row forms return in 0.9 to 6.4 ms at p95.
- The brief names the form "group-by `construct`" without a filter, so the empty query is the primary result;
  because the question is usually asked about attacks, run 2 added the same grouping over `-verdict:allow`, which
  is 74.9 ms at p95 and meets the target. Run 1 did not have that form. It is shown as a second reading, not as
  a replacement for the miss.
- The first row of each form (cold, before any caching of that form) is in the JSON (`first_ms`); the largest is
  the unfiltered grouping at 89.2 ms in run 1 and 81.2 ms in run 2. Both runs had a warm operating-system file
  cache; a cold cache was not measured.

## 6. Stalled consumer

Not measured here; covered by tests, all passing in this tree (`cargo test --workspace` after the fix wave:
516 passed, 0 failed, over the workspace's test binaries; 507 in the first round):

- `vft-proxy` `bus::tests::a_full_channel_neither_blocks_nor_panics_and_the_slow_subscriber_lags`: a subscriber
  that never reads while 9,000 events are published does not block or slow the publisher, and finds the
  oldest events replaced by a `Lagged` count of 9,000 minus the 8,192 capacity.
- `vft-server` `history::tests::a_full_queue_drops_and_counts_without_blocking`: with the writer stalled, the
  queue takes 16,384 messages (4,096 in the first round), refuses the next 10 at once (no call blocks for more
  than the test's 5 s bound), counts exactly 10 drops in `dropped()`, `vft_history_rows_dropped_total` and
  `vft_bus_dropped_total{consumer="history-writer"}`, and writes the 16,384 it accepted when the writer
  resumes.
- `vft-server` `history::tests::bans_and_revisions_are_written_while_the_decision_queue_is_full` and
  `a_full_control_queue_drops_counts_and_never_blocks` (fix wave): with the decision queue full, a ban and a
  config revision still go in and are written; a full control queue refuses without blocking and counts under
  `history-control`.

In the replay runs above, `vft_bus_dropped_total` was 0 for both consumers, so the lagging path was not
exercised by any load here.

## Deviations from the spec

- **No read-connection pool** (spec §5.1 "Reads use a pool of 4 read-only connections"): deferred to B3. In
  B1+B2 the CLI (`venusflytrap history query`) is the only reader and opens one read-only connection per run.
- **No `Loaded.files: FileStamps`** (spec §4.1): deferred to B3. `Loaded` is `{ rev, shield }`; nothing reads
  file stamps before B3.
- **Queue and batch sizes** (spec §5.1 said `sync_channel(4096)` and transactions of 500 rows): raised to
  16,384 and 2,000 in the fix wave, with a separate 1,024-message control queue for bans and revisions; the
  spec was updated to match.

## Limits of these measurements

- One machine, one run configuration, three runs per side for latency, two for the two sample-rate-1.0 write runs
  and the two query runs. No significance test: the latency result is "within the target", not "history has no
  cost".
- The client, the proxy, the stub upstream and the history writer share one machine and one CPU package. The
  client is open loop, but its timer resolution (about 15 ms) makes the offered load bursty. CPU use was not
  recorded.
- The replay mix is the corpus's (875 of 59,996 requests were blocked in a section 2 run, 1.5 %); it is not
  production traffic.
- History's disk cost is shown only by the database sizes above (about 5.5 MB for 60,000 requests at sample
  rate 0.01, 290 MiB for 1,000,000 rows at 1.0); no retention sweep ran during the measurements.
- The tools were not checked against any other implementation; they are small and documented in their file
  headers.

## Files and commands

- `crates/vft-server/examples/replay.rs`, `crates/vft-server/examples/history_bench.rs` (commit `4a6cb3a`).
- `cargo build --release -p vft-cli -p vft-server --examples`.
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` were green when the
  tools were committed.
- Raw outputs are in the runs directory: `b12-nochange-*` (section 1), `lat-<i>-<off|on>.json` (section 2),
  `reload-1.json` (section 3), `hbw-*.json` (section 4), `hbq-1m.json` and `hbq-1m-nofill.json` (section 5).
  Fix wave: `b12-final-*` (dev A/B), `fix-lat-<i>-<off|on>.json`, `fix-hbw-*.json`, `fix-hbq-1m.json`,
  `fix-hbq-1m-nofill.json`, and `fix-progress.log` (the order and exit status of every run).
