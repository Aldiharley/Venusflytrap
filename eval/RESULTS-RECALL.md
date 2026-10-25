# Recall-lift results

All numbers measured on this machine, release build. Library mode = `Shield::inspect`
(stateless); serve mode = `Pipeline::decide` (stateful, raw Cookie). Split: `eval/split.py`
(SHA-256 of raw files, label-stratified 50/50). Held-out is scored once per milestone.

## M0 — baseline on SP1's tip (commit 4310582)

| Run | Samples | TP | FP | TN | FN | Recall | Precision | F1 | FP rate | p50/p95/p99 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| library, full | 33877 | 283 | 269 | 32950 | 373 | 0.4314 | 0.5127 | 0.4685 | 0.0081 | 73/209/734 |
| serve, full | 33877 | 283 | 269 | 32950 | 373 | 0.4314 | 0.5127 | 0.4685 | 0.0081 | 73/219/748 |
| library, dev | 16939 | 147 | 142 | 16468 | 182 | 0.4468 | 0.5087 | 0.4757 | 0.0085 | 73/212/751 |
| library, held-out | 16938 | 136 | 127 | 16482 | 191 | 0.4159 | 0.5171 | 0.4610 | 0.0076 | 73/220/798 |

Scored-malicious denominators (TP+FN): full 656, dev 329, held-out 327. Recall above is as reported by
`venusflytrap eval`, over those scored files. Serve mode (distinct sources): benign_sources 33219,
benign_sources_banned 72, collateral_fp 0, bans_from_allowed 0; invariant_violations 0 in all four runs.

| Baseline (per half) | TP | FP | FN | Recall | Precision | FP rate |
|---|---|---|---|---|---|---|
| libinjection, dev | 113 | 36 | 216 | 0.3435 | 0.7584 | 0.0022 |
| libinjection, held-out | 101 | 57 | 228 | 0.3070 | 0.6392 | 0.0034 |
| regex, dev | 68 | 58 | 261 | 0.2067 | 0.5397 | 0.0035 |
| regex, held-out | 59 | 68 | 270 | 0.1793 | 0.4646 | 0.0041 |

Baseline denominators (TP+FN): 329 malicious in each half (the Python-parsed JSONL holds all 658).

Robustness (bench_http, mutate.py seed 1337): seeds recall 0.8636 (19/22), mutants recall 0.8303 (548/660), retained 96.1% (0.8303 / 0.8636 = 0.9614).

Contamination log: before the split existed (2026-10-25), about 30 example payloads from the
full corpus were read while sizing the misses; some are in the held-out half.

Held-out was also scored once during Task 3's CLI check (2026-10-25), before any detection change: library tp=136 fp=127 fn=191 with 2 unreadable files; the same measurement as M0's held-out row, totals only, no misses opened.

Input notes: `venusflytrap eval` cannot read 2 malicious files on this host (access denied), so its
recall is over the malicious files it scores (656 on the full corpus; per-half counts from the JSON
`read_failures`: dev 0 read failures, 329 scored; held-out 2 read failures, 327 scored). The libinjection
and regex baselines read the Python-parsed JSONL, which still holds those 2 requests (an input-fairness gap SP1 also records).

## M1 — registry refactor

Decision diffs vs M0 build: library 0, serve 0, seeds 0, mutants 0 (33,877 + 33,877 + 22 + 660 requests).
