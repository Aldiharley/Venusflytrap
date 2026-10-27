# SP2 (explainable judgments): measured results

SP2 changes no detection. It adds `decided_by` (a cause that names the config option behind every
decision), real per-contribution points, stable construct ids, the option registry and generated
TypeScript types. This file records the acceptance run on the blazehttp corpus. Every number below was
copied from the run output; nothing is estimated.

- **Baseline:** main `b2f82ff` (captured with `eval/decision_gate.sh capture`).
- **Measured tree:** branch `sp2-explainable-judgments` at `db156ee`.
- **Machine and corpus:** the same Windows 11 host and blazehttp commit `afc88a94` as
  [`RESULTS-SP1.md`](RESULTS-SP1.md).

## Decision gate

`bash eval/decision_gate.sh check <baseline-dir>` printed `decision gate: identical` for both source
models. `compare_runs.py` compares `label, lib_verdict, serve_verdict, score, banned` per file and
reported `decision diffs: 0` each time.

| Sources | TP | FP | TN | FN | Recall | FP rate | Decision diffs |
|---|---|---|---|---|---|---|---|
| `distinct` | 288 | 278 | 32,941 | 368 | 0.4390 | 0.0084 | 0 |
| `pooled:100` | 288 | 278 | 32,941 | 368 | 0.4390 | 0.0084 | 0 |

TP, FP, TN, FN, recall and FP rate are the same in the baseline and in the new run, and in the library
run (`--mode library`). The `distinct` and `pooled:100` rows are identical because they measured the
same values, not because one row was copied for both; each comes from its own JSON report.

Scored samples: **33,875**, `read_failures` 0, `parse_failures` 0 in the new run. The `distinct`
baseline counted 33,877 samples with `read_failures` 2; the `pooled:100` baseline counted 33,876
samples with `read_failures` 1 (most likely one of the two files was already gone from the directory
when that baseline ran; the antivirus on this host deletes corpus files). On this host the two files named in
[`BENCHMARK.md`](../docs/BENCHMARK.md) section 1 are now absent from the corpus directory (they are not
reported as unreadable), so the new run does not list them at all. Unreadable files are never written
to the CSV, so both runs score the same 33,875 rows and the gate row sets match.

## Explain counters

From `now-serve-distinct.json`, `now-serve-pooled100.json` and the library run `now-library.json`.
Each counter must be 0 (the CLI exits 3 otherwise).

| Run | `unknown_option_key` | `detection_without_construct` | `points_mismatch` | examples |
|---|---|---|---|---|
| library (`--mode library`) | 0 | 0 | 0 | none |
| serve, `distinct`: library judgments | 0 | 0 | 0 | none |
| serve, `distinct`: serve judgments | 0 | 0 | 0 | none |
| serve, `pooled:100`: library judgments | 0 | 0 | 0 | none |
| serve, `pooled:100`: serve judgments | 0 | 0 | 0 | none |

## Cause tally

Library judgments over the 33,875 scored samples, from the `cause` column
(`kind:option_key`) of `now-library.csv`:

| Count | `kind:option_key` |
|---|---|
| 31,644 | `NoEvidence:scoring.monitor_at` |
| 1,665 | `Detection:scoring.monitor_at` |
| 555 | `Detection:scoring.block_at` |
| 10 | `Detection:scoring.challenge_at` |
| 1 | `Limit:shield.max_inspect_bytes` |

The five counts add up to 33,875.

## What this means

SP2 changes no detection, so the published recall and FP numbers in
[`BENCHMARK.md`](../docs/BENCHMARK.md) and [`RESULTS-SP1.md`](RESULTS-SP1.md) stand. The synthetic
`bench` command is a smoke test and is not quoted here.
