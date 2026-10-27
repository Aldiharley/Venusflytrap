# DQ1 (measurement foundation): measured results

DQ1 changes no detection. It adds Wilson 95 % intervals to the eval report, a paired McNemar comparison
and `--intersect` in `compare_runs.py`, FP and miss clusters (`eval/clusters.py`), shadow constructs with
promotion counters, a clean keep-alive TCP replay, and a request dump (`--dump-requests`) so the
libinjection and regex baselines score the same requests the engine scored. This file records the
acceptance run. Every number below was copied from the run outputs named next to it; nothing is
estimated.

- **Baseline:** code of main `69d0e32` (captured in Task 1 with `eval/decision_gate.sh capture`).
- **Measured tree:** branch `dq1-measurement` at `c3ee2fa`.
- **Machine and corpus:** the same Windows 11 host as [`RESULTS-SP2.md`](RESULTS-SP2.md); the corpus is
  the directory described in [`docs/BENCHMARK.md`](../docs/BENCHMARK.md) section 1.
- **Samples and read failures** (JSON of each run): `library` 33,875 / 0, `serve, distinct` 33,875 / 0,
  `serve, pooled:100` 33,875 / 0, dev-only `library` 16,939 / 0. The gate's own re-run
  (`now-serve-*.json`) was 33,875 / 0 for both source models. Every run had `parse_failures` 0 and
  `invariant_violations` 0, and the explain counters (`unknown_option_key`, `detection_without_construct`,
  `points_mismatch`) were 0.

## Decision gate

`bash eval/decision_gate.sh check <baseline-dir>` printed `decision gate: identical` (exit 0); both
`compare_runs.py` runs reported `decision diffs: 0`. The row sets matched: no corpus file was absent
between the baseline capture and this run, so the host-antivirus procedure (`--intersect`) was not
needed and there are no absent-file rows to list. Output: `.superpowers/dq1/runs/gate-task9.txt`.

## Recall and FP rate with Wilson 95 % intervals

| Run | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|---|---|
| `library` | 288 | 278 | 32,941 | 368 | 43.90 % [40.15, 47.72] | 0.84 % [0.74, 0.94] |
| `serve, distinct` | 288 | 278 | 32,941 | 368 | 43.90 % [40.15, 47.72] | 0.84 % [0.74, 0.94] |
| `serve, pooled:100` | 288 | 278 | 32,941 | 368 | 43.90 % [40.15, 47.72] | 0.84 % [0.74, 0.94] |

Sources: `library.json` (`library`), `serve-distinct.json` and `serve-pooled100.json` (`serve.metrics`),
with `recall_ci95` and `fp_rate_ci95` from the same files. The three rows are identical because the
shield decides per request and no benign source was banned (`benign_sources_banned` 0, `collateral_fp` 0,
`bans_from_allowed` 0 in both serve runs). The recall interval is about 7.6 points wide because the
malicious class is small (656 attacks: 288 + 368, not the 33,875 rows); the FP rate interval is about
0.2 points wide because the benign class has 33,219 rows.

## Baselines on identical inputs

Input: `requests.jsonl` from `--dump-requests` of the library run, 33,875 lines (`wc -l`), which equals
`tp + fn + fp + tn` for every row below. These are the same requests the engine scored; the path is in
the URI form the engine receives (raw `<`, `>` kept, spaces percent-encoded). Commands:
`py -I -X utf8 eval/baselines.py requests.jsonl baselines.json <libinjection.dll>` (the DLL loaded
without error), then the Wilson helper from the plan's Task 9 Step 3 for the intervals (output saved as `baselines-wilson.txt`).

| Engine | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|---|---|
| libinjection | 215 | 93 | 33,126 | 441 | 32.77 % [29.29, 36.46] | 0.28 % [0.23, 0.34] |
| regex baseline | 127 | 126 | 33,093 | 529 | 19.36 % [16.52, 22.56] | 0.38 % [0.32, 0.45] |
| Venusflytrap `library` (section 3) | 288 | 278 | 32,941 | 368 | 43.90 % [40.15, 47.72] | 0.84 % [0.74, 0.94] |

Sources: `baselines.json` and `baselines-wilson.txt`. The earlier Python-parsed baseline numbers in
`docs/BENCHMARK.md` (libinjection 214 TP / 93 FP, regex 127 TP / 126 FP) stay in the history as those
runs; this table replaces them as the like-for-like comparison. libinjection moved by one TP (215 vs
214) and the regex baseline did not move in TP or FP. The libinjection interval [29.29, 36.46] and
the engine's [40.15, 47.72] do not overlap on recall; the engine's FP rate is higher than both baselines.

## TCP replay

`venusflytrap eval --mode tcp --limit 40000` was run five times on this branch. Each run saved its JSON report and a status file with exit code, wall time and the `netstat -an | grep -c TIME_WAIT` count taken right after the run. All of them are under `.superpowers/dq1/runs/`.

| Run | Head | Exit | Wall | TIME_WAIT | proxy_rejected | io | upstream_5xx | mismatched | Files |
|---|---|---|---|---|---|---|---|---|---|
| Task 7 | `8aef23d` | 0 | 91 s | 32 | 5 | 0 | 0 | 0 | `tcp-full-task7.{json,status}` |
| Task 9 | `c3ee2fa` | 0 | (not saved) | (not saved) | 5 | 0 | 0 | 0 | `tcp-full.json` |
| final 1 | `18733a1` | 3 | 88 s | 36 | 4 | **1** | 0 | 1 | `tcp-final.{json,status}` |
| final 2 | `18733a1` | 0 | 89 s | 33 | 5 | 0 | 0 | 0 | `tcp-final-2.{json,status}` |
| final 3 | `18733a1` | 0 | 88 s | 40 | 5 | 0 | 0 | 0 | `tcp-final-3.{json,status}` |

In final 1, the one `io` mismatch is `78/70/f847412e4801ad7b16af575916d0.white`, with no parsable status line in the reply. In every other run, that same request is `proxy_rejected` with status 413 (body over the proxy limit). It is a timing race on that single sample. The proxy answers 413 and closes while the client is still writing the oversized body. The zero-linger close then resets the connection, and in this run the reset arrived before the client read the reply. No request was decided differently. `upstream_5xx` was 0 in all five runs, and no other bucket was ever non-zero. The breakdown below is from `tcp-full.json` (Task 9, the measured tree).

| Run | replayed | matched_block | matched_allow | proxy_rejected | not_replayable | block_vs_proxy_allow | allow_vs_proxy_403 | upstream_5xx | io | other | mismatched |
|---|---|---|---|---|---|---|---|---|---|---|---|
| full corpus (`--limit 40000`, exit 0) | 33,711 | 563 | 33,143 | 5 | 164 | 0 | 0 | 0 | 0 | 0 | 0 |

SP1's full run had `upstream_5xx` 767 and `io` 9 (776 mismatched, exit 3). With the keep-alive upstream
and zero-linger clients, `upstream_5xx` is 0 in every run, and `io` is 0 except for the one 413 race above. The 5
`proxy_rejected` rows are requests the proxy's HTTP layer refuses before the engine sees them (status in
the example line), listed as in SP1:

- `00/06/005a52981dd324c40488a1a588f9.white` status=400, in-process Block, score 100
- `78/70/f847412e4801ad7b16af575916d0.white` status=413, in-process Block, score 100
- `bd/40/8bdebf8443eecd343739e7fbdf2b.black` status=400, in-process Allow, score 33
- `ec/98/75af1332f120a05581069320ad6f.black` status=400, in-process Block, score 100
- `ff/67/62b331a3e94507a5759d1f9bcb8a.black` status=400, in-process Allow, score 33

`not_replayable` is 164 here (166 in SP1).

## Top false-positive and miss clusters (dev only)

Dev rows only (`--side dev`; the dev library run had 16,939 samples: TP 149, FP 147, TN 16,463, FN 180).
Held-out rows were not read. Examples are rel paths; their payloads were not opened for this file.
Source: `clusters-dev.txt` from `eval/clusters.py library-dev.csv --manifest <manifest> --side dev --top 10`.
Groups are cause, top construct (the contribution with the most points), and field location and name;
`-` means no field was recorded.

**False positives (label 0, Challenge/Block): 147 rows in 30 groups** (the top 10 below cover 118).

| Count | Cause | Top construct | Loc | Name | Example |
|---|---|---|---|---|---|
| 25 | `Detection:scoring.block_at` | `cmd.chained-command` | query | `data` | `04/fe/600f6557dfafd64f62475bb9e12e.white` |
| 25 | `Detection:scoring.block_at` | `sqli.union-select` | header | `referer` | `07/1f/5efaaec9cb9a1c05d01bee6644cf.white` |
| 18 | `Detection:scoring.block_at` | `sqli.boolean-tautology` | header | `referer` | `10/f1/7354f6010c03a758650986dc8102.white` |
| 10 | `Detection:scoring.block_at` | `sqli.quote-breakout` | body | `<body>` | `04/01/b6df95c01984fd44ad58c134cce3.white` |
| 9 | `Detection:scoring.block_at` | `sqli.stacked-query` | body | `<body>` | `2c/ee/9c81dbe36b6365347a11c2005709.white` |
| 8 | `Detection:scoring.block_at` | `cmd.chained-command` | body | `<body>` | `03/76/94174ae092b60dea02a84084c95c.white` |
| 7 | `Detection:scoring.block_at` | `sqli.union-select` | query | `bq` | `23/f3/604f8ab9055a963dca47925f2831.white` |
| 7 | `Detection:scoring.block_at` | `xss.dangerous-proto` | body | `<body>` | `21/85/bde3866f2ae21a1ecbf14a825d23.white` |
| 5 | `Detection:scoring.block_at` | `sqli.boolean-tautology` | body | `<body>` | `75/92/43aab0a7fb477ce030ded2fce907.white` |
| 4 | `Detection:scoring.block_at` | `cmd.chained-command` | header | `referer` | `0e/d4/cfc57364dee9ff7304cf1e277e46.white` |

**Misses (label 1, Allow/Monitor): 180 rows in 9 groups** (all 9 groups are listed).

| Count | Cause | Top construct | Loc | Name | Example |
|---|---|---|---|---|---|
| 148 | `NoEvidence:scoring.monitor_at` | `cmd.shell-meta` | - | - | `02/08/4380fc75422b36e3dda1117e80e8.black` |
| 12 | `NoEvidence:scoring.monitor_at` | `xss.html-tag` | - | - | `0c/ab/6c0d68f61a13a45e5d40bbbc5f9b.black` |
| 8 | `NoEvidence:scoring.monitor_at` | `sqli.sql-keyword` | - | - | `0f/f2/c48aa7a8c26e6a8db09d36b90eb4.black` |
| 5 | `NoEvidence:scoring.monitor_at` | `sqli.fn-sleep` | - | - | `0f/86/52fbed57af5f50033986a9365d4e.black` |
| 2 | `NoEvidence:scoring.monitor_at` | `path.dotdot-segment` | - | - | `29/72/24a2ebf765a5de288ed981cc6d5e.black` |
| 2 | `NoEvidence:scoring.monitor_at` | `sqli.fn-extractvalue` | - | - | `86/bf/4c7ba37fabf025ec46e402f3af2a.black` |
| 1 | `Detection:scoring.monitor_at` | `sqli.sql-keyword` | query | `id` | `22/8a/a904b637da933d7a86928334f05f.black` |
| 1 | `NoEvidence:scoring.monitor_at` | `-` | - | - | `1e/34/d8d5bbd8197013e97808a5214ee4.black` |
| 1 | `NoEvidence:scoring.monitor_at` | `sqli.fn-benchmark` | - | - | `eb/82/88e894f0866ec16ed2f73e49b038.black` |

Reading: on dev, 148 of 180 misses (82 %) have `cmd.shell-meta` as their top contribution, scored below
the monitor threshold with no field recorded (`NoEvidence` rows carry no `decided_by.field`). This is
incidental, not the attack class that was missed: `cmd.shell-meta` fires on the `;` of almost every
User-Agent header (the C1 regression test `browser_is_never_staged_or_banned` in `crates/vft-core/src/shield.rs` covers it; in `library-dev.csv` it appears on all 16,610 benign dev rows), so for a sub-threshold row `top` names the
highest background scorer. Classifying these misses by attack family needs the payload, which this file
does not open. The largest false-positive groups are
`cmd.chained-command` in the `data` query parameter, and SQL constructs in the `Referer` header
(`sqli.union-select`, `sqli.boolean-tautology`): 68 of the 118 top-10 FP rows are in those three groups.
No detection change is made or proposed here.

## Promotion mechanics check

`--shadow intel.scanner-ua --promotion` on the dev library run (`promotion-dev.json`, `promotion` field;
the same table is printed to stderr):

| construct | would_tp | would_fp | already | promote |
|---|---|---|---|---|
| `intel.scanner-ua` | 0 | 0 | 0 | false |

This only checks that the counters run on real data; it is not a promotion decision. No new construct
exists in DQ1, and `intel.scanner-ua` is an existing construct whose three counters are all 0 on the dev rows
(the dev run's metrics are unchanged by the shadow setting, as the design requires).

## UI check

Not run: `ui/node_modules` is absent in this worktree, so `npm run check` and `npm test` were skipped
(Task 5 Step 9 and Task 9 Step 1). The owner runs `npm ci` in `ui/`, then `npm run check` and
`npm test`. `cargo test -p vft-core --features ts --test ts_bindings` passed (the generated types match
the committed bindings), and `ui/src/lib/api/types.ts` was edited as plain text.

## Other checks run in Task 9

`cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` green (exit 0, 0 warnings);
`py -I -X utf8 -m unittest discover -s eval -p "test_*.py"`: 33 tests OK.
