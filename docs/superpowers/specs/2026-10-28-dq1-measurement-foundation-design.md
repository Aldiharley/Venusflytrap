# DQ1 — Measurement foundation (design)

*Date: 2026-10-28 · Status: owner-delegated (the owner accepted all recommendations for the detection-quality programme on 2026-10-27) · Builds on: SP2 (merged to main in 69d0e32: `decided_by`, points, options registry) · Research: `reports/Raising WAF recall and baselines.md` (local, not committed) phase 1.*

## 1. Goal

Make every later detection change, baseline and corpus measurable with uncertainty and with paired comparisons, and let new constructs be evaluated in production-shaped runs without affecting verdicts. No detection change in DQ1: with the shadow list empty, the SP2 decision gate must report identical decisions.

## 2. Non-goals

New constructs or parsers (DQ2, DQ3); external baselines (DQ4); new corpora (DQ5); guided evasion (DQ6); changing the existing dev/held-out manifest.

## 3. Components

### 3.1 Uncertainty in eval reports
- `Metrics` (vft-cli `eval.rs`) gains `recall_ci95: [f64; 2]` and `fp_rate_ci95: [f64; 2]`, computed with the Wilson score interval at z = 1.96 in a pure helper `wilson(k, n) -> (lo, hi)` (returns (0, 0) for n = 0).
- Reports keep existing fields unchanged so `compare_runs.py` and older JSON readers still work.

### 3.2 Paired comparison
- `eval/compare_runs.py` gains a McNemar exact test (two-sided binomial on the discordant pairs) between two eval CSVs, computed separately for malicious rows (detection) and benign rows (false positives), using `lib_verdict` (and `serve_verdict` when both CSVs have it). Output: discordant counts b, c and the p-value per class. Existing exit-code semantics (0 identical / 1 differences / 2 invalid) are unchanged; the test is printed only when decisions differ.
- Unit tests in `eval/test_compare_runs.py` cover b = c = 0, a one-sided split, and the exact p-value for a small hand-computed case.

### 3.3 Miss and false-positive clustering
- The eval CSV gains a `field` column: `decided_by.field` as `loc:name` (empty when none). Column order: existing columns, then `cause`, then `field`.
- New `eval/clusters.py <csv> [--manifest M --side dev|heldout] [--top N]` prints two ranked tables — false positives (label 0, lib verdict Challenge/Block) and misses (label 1, Allow/Monitor) — grouped by (`cause`, top construct, field location, field name normalised to lower case), with counts and up to 3 example rel paths per group. It reads only the CSV, never raw corpus files, and honours `--side` so held-out rows are not opened during development.
- Tests: a tiny CSV fixture with known groups.

### 3.4 Shadow constructs

*As built: the plan's D1 and D2 replace the removal mechanism below. A shadowed id is judged exactly as if it were disabled, and a second pass records its hits. Decoder ids are rejected.*

- New config leaf `shield.shadow: Vec<String>` (registry kind `ConstructIds`, section shield, Advanced, Live): construct ids that are detected and recorded but never score.
- Engine behaviour (vft-core, pure):
  - A pattern whose construct id is in `shield.shadow` is removed from the evidence before scoring. If an evidence item keeps no patterns and had a threat value, it is not scored at all.
  - Every removed pattern is recorded as a `Contribution` with a new field `shadow: true`, `points: 0`.
  - Shadow contributions never influence `score`, `verdict`, `decided_by`, `event_for` or bans; `top_contribution` ignores them.
  - Validation: an id may not be in both `shield.disabled` and `shield.shadow` (cross-field issue on `shield.shadow`).
- `Contribution` gains `pub shadow: bool` (serialised; default false). The TypeScript bindings are regenerated (`ui/src/gen`) and `ui/src/lib/api/types.ts` mirrors the field.
- Eval: the CSV gains a `shadow` column (`|`-joined shadow construct ids that fired), and a new `venusflytrap eval --promotion` mode prints, per shadow construct, `would_tp` (fires on a malicious row the live verdict misses), `would_fp` (fires on a benign row the live verdict allows) and `already` (fires on rows already decided the same way). This is the promotion rule of the recall-lift design in numbers: a construct is promoted only when `would_tp > would_fp` on dev.

### 3.5 Replay harness fix (TCP mode)

*As built: the plan's D5 uses `TcpStream::set_zero_linger()`, because `set_linger` is deprecated in tokio 1.54.1. Measured results are in `eval/RESULTS-DQ1.md`, including one 413 timing race in five full runs.*

- The test upstream in `run_tcp` serves keep-alive (loop: read a request, reply `HTTP/1.1 200 OK`, `Content-Length: 0`, no `Connection: close`) so the proxy's pooled client reuses connections.
- Client sockets in `send_and_read` set `SO_LINGER` to zero before closing (tokio `set_linger(Some(Duration::ZERO))`), so they do not sit in TIME_WAIT.
- Acceptance: a full-corpus `eval --mode tcp --limit 40000` on this Windows host reports `mismatch_upstream_5xx = 0` and `mismatch_io = 0`; any remaining mismatches are listed with examples and explained in the results file.

### 3.6 Identical inputs for the libinjection and regex baselines
- `venusflytrap eval --dump-requests <jsonl>` writes, for every scored sample, the request exactly as `adapt::from_parts` built it, in the JSONL schema `eval/parse_corpus.py` already produces (label, method, path, query, headers, cookies, body as latin-1), plus `rel`.
- `eval/baselines.py` runs unchanged on that file. The libinjection and regex baselines are re-measured on the Rust-parsed corpus, so all three engines see the same fields; the old Python-parser numbers stay in the history as such.

### 3.7 Line endings for scripts and generated files
- A new `.gitattributes` sets `*.sh text eol=lf` and `ui/src/gen/** text eol=lf`, so `eval/decision_gate.sh` runs on Linux, WSL and CI, and the ts drift test compares the same bytes on every platform. Files are renormalised in the same commit.

## 4. Data flow

corpus files → `venusflytrap eval` (library/serve/tcp) → JSON report (now with Wilson CIs) + CSV (cause, field, shadow) → `compare_runs.py` (identity + McNemar) / `clusters.py` (ranked FP/miss groups) / `--promotion` (shadow construct gains) ; `--dump-requests` → `baselines.py`.

## 5. Error handling

- `wilson` with n = 0 returns (0, 0); McNemar with b + c = 0 prints p = 1.
- `clusters.py` rejects CSVs without the `cause`/`field` columns with exit 2 and a message naming the missing column.
- `--dump-requests` writes nothing for unreadable or unparseable samples (they are already counted in the report).

## 6. Testing and acceptance

- `cargo test --workspace`, `cargo clippy --all-targets -- -D warnings`, `py -I -X utf8 -m unittest` for eval/*.py, the UI `npm test`/`npm run check` after the binding regeneration.
- Decision gate (SP2's `eval/decision_gate.sh check`) identical with `shield.shadow` empty.
- A unit test proving a shadowed construct changes no score/verdict/decided_by and appears as a shadow contribution.
- Full-corpus TCP replay with upstream_5xx = 0 and io = 0.
- `eval/RESULTS-DQ1.md`: the recall/FP numbers with Wilson CIs for library, serve distinct and serve pooled:100; the re-measured libinjection and regex baselines on identical inputs; the TCP replay table; the top FP and miss clusters on dev only.
