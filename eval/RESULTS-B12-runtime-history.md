# B1+B2 (service runtime and SQLite history): measurements

B1 turns `venusflytrap serve` into a service (runtime with reload, signals and graceful shutdown, an admin
listener, metrics). B2 adds a SQLite history store behind it (rollups, rows for non-Allow and sampled Allow
decisions, kill-chain events, bans, config revisions) and `venusflytrap history query`. This note records the
six measurements the work was held to. Every number below was copied from a run made for this note on
2026-10-31. Two targets are missed and one is met only in part; they are marked **MISSED** and stated with
their numbers in the summary and in each section.

## Summary

| # | Measurement | Target | Result | Status |
|---|---|---|---|---|
| 1 | No change to decisions | 0 changed cells (dev A/B), 0 changed decisions (full-corpus serve diff, `distinct` and `pooled:100`) | 0 changed cells on the 16,938 dev rows; 0 changed decisions and 0 score-only changes on all 33,875 rows, in both source models | met |
| 2 | Latency overhead of history | p99 with history within 5 % of without (median of 3 runs each, 1,000 rps, 60 s) | median p99 5.135 ms with, 5.717 ms without (-10.2 %) | met |
| 3 | Reload under load | `failed` = 0, 20 reloads applied (2,000 rps, 60 s, reload every 3 s) | `failed` 0 (8 malformed corpus requests were rejected by the proxy with 400 before any decision and `replay` counts them as `rejected`; counted as anything other than 200/403 they would be 8), 20 applied, 0 reloads rejected | met |
| 4 | History write throughput | at least 5,000 events/s sustained over 60 s, 0 drops | default sample rate 0.01: 300,000 of 300,000 written in 60.004 s, 0 drops. Sample rate 1.0 (a `requests` row for every event): 3.7 % dropped, 4,737.7 and 4,746.0 events/s | met at the default sample rate, **MISSED** at 1.0 |
| 5 | Query p95 over 1,000,000 rows | every 24-hour form p95 under 100 ms | 4 forms 0.9 to 6.4 ms; the unfiltered `group-by construct` p95 122.3 ms (run 1) and 120.2 ms (run 2); the same grouping over non-Allow rows 74.9 ms | **MISSED** for the unfiltered grouping |
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

The branch changes `vft-core` (chain, config, options) and `vft-proxy` (event bus, config handle, pipeline).
The diffs above show that those changes leave every decision, score and ban of the corpus identical to
main's, in both source models.

## 2. Latency: history off against history on

```
replay --corpus "$VFT_CORPUS" --manifest "$VFT_MANIFEST" --side dev --rate 1000 --seconds 60 \
  --clients 32 --history <off|on> --state-dir "$VFT_RUNS/lat-<i>-<off|on>"
```

Run alternately (off, on, off, on, off, on) so drift in the machine affects both. Each run is 60,000
requests. The 1,000 rps rate was sustained by the client in all six runs.

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

The target (median p99 with history within 5 % of without) is met: with history on, the median p99 is lower
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
| paced 5,000/s | 0.01 | 300,000 | 300,000 | **0** | 60.004 | 4,999.65 | 17,822 |
| paced 5,000/s | 1.0 | 300,000 | 288,788 | **11,212 (3.74 %)** | 60.955 | 4,737.7 | 288,788 |
| paced 5,000/s, second run | 1.0 | 300,000 | 289,006 | **10,994 (3.66 %)** | 60.895 | 4,746.0 | 289,006 |
| ceiling (chunks of 2,000 with a flush) | 0.01 | 300,000 | 300,000 | 0 | 3.458 | 86,754.7 | 17,822 |
| ceiling (chunks of 2,000 with a flush) | 1.0 | 300,000 | 300,000 | 0 | 45.565 | 6,584.0 | 300,000 |

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

The fill took 134.16 s (7,453.6 events/s with a flush every 2,000 events, 0 dropped).

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

- **The target is missed for `group-by construct` over every row of the window:** p95 122.3 ms and 120.2 ms
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

Not measured here; covered by two tests, both passing in this tree (`cargo test --workspace`: 507 passed,
0 failed, over the workspace's test binaries):

- `vft-proxy` `bus::tests::a_full_channel_neither_blocks_nor_panics_and_the_slow_subscriber_lags`: a subscriber
  that never reads while 9,000 events are published does not block or slow the publisher, and finds the
  oldest events replaced by a `Lagged` count of 9,000 minus the 8,192 capacity.
- `vft-server` `history::tests::a_full_queue_drops_and_counts_without_blocking`: with the writer stalled, the
  queue takes 4,096 messages, refuses the next 10 at once (no call blocks for more than the test's 5 s bound),
  counts exactly 10 drops in `dropped()` and `vft_history_rows_dropped_total`, and writes the 4,096 it
  accepted when the writer resumes.

In the replay runs above, `vft_bus_dropped_total` was 0 for both consumers, so the lagging path was not
exercised by any load here.

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
