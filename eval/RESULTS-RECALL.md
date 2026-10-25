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

## M1 — existing constructs, leave-one-out on dev

These constructs predate recall-lift: reported only, nothing is dropped (spec §4.3). `d_tp`/`d_fp` are the true/false positives each construct contributes on the dev half (library mode, baseline TP 147, FP 142); `net` = `d_tp` - `d_fp`.

| id | kind | tp | fp | d_tp | d_fp | net |
|---|---|---|---|---|---|---|
| sqli.union-select | Sink | 144 | 102 | 3 | 40 | -37 |
| sqli.boolean-tautology | Sink | 134 | 117 | 13 | 25 | -12 |
| sqli.quote-breakout | Sink | 136 | 135 | 11 | 7 | 4 |
| sqli.stacked-query | Sink | 144 | 134 | 3 | 8 | -5 |
| sqli.sql-keyword | Latent | 147 | 142 | 0 | 0 | 0 |
| sqli.fn-sleep | Latent | 147 | 142 | 0 | 0 | 0 |
| sqli.fn-benchmark | Latent | 147 | 142 | 0 | 0 | 0 |
| sqli.fn-updatexml | Latent | 147 | 142 | 0 | 0 | 0 |
| sqli.fn-extractvalue | Latent | 147 | 142 | 0 | 0 | 0 |
| sqli.fn-load-file | Latent | 147 | 142 | 0 | 0 | 0 |
| sqli.fn-pg-sleep | Latent | 147 | 142 | 0 | 0 | 0 |
| xss.script-tag | Sink | 137 | 134 | 10 | 8 | 2 |
| xss.event-handler | Sink | 141 | 138 | 6 | 4 | 2 |
| xss.dangerous-proto | Sink | 117 | 134 | 30 | 8 | 22 |
| xss.tag-with-handler | Sink | 147 | 142 | 0 | 0 | 0 |
| xss.html-tag | Latent | 147 | 142 | 0 | 0 | 0 |
| cmd.cmd-substitution | Sink | 144 | 142 | 3 | 0 | 3 |
| cmd.chained-command | Sink | 141 | 105 | 6 | 37 | -31 |
| cmd.shell-meta | Latent | 147 | 142 | 0 | 0 | 0 |
| path.directory-traversal | Sink | 143 | 141 | 4 | 1 | 3 |
| path.dotdot-segment | Latent | 147 | 142 | 0 | 0 | 0 |
| sig.union-all-select | Signature | 147 | 142 | 0 | 0 | 0 |
| sig.classic-or | Signature | 147 | 142 | 0 | 0 | 0 |
| sig.schema-enum | Signature | 146 | 142 | 1 | 0 | 1 |
| sig.alert-script | Signature | 147 | 142 | 0 | 0 | 0 |
| sig.onerror | Signature | 147 | 142 | 0 | 0 | 0 |
| sig.etc-passwd | Signature | 144 | 142 | 3 | 0 | 3 |
| sig.cat-subst | Signature | 147 | 142 | 0 | 0 | 0 |
| api.type-violation | Signature | 147 | 142 | 0 | 0 | 0 |
| recon.sensitive-path-probe | Signature | 147 | 142 | 0 | 0 | 0 |
| honeypot.decoy-hit | Signature | 147 | 142 | 0 | 0 | 0 |
| intel.scanner-ua | Signature | 147 | 142 | 0 | 0 | 0 |
| limit.header-non-utf8 | Limit | 147 | 142 | 0 | 0 | 0 |

## M2a — fail-closed and decoder fixes (dev A/B per change)

### H1 — decode.percent-lossy

Fixed decoder: gate is delta TP > delta FP (spec §4.4). Dev half, library mode, `compare_runs.py pre-h1_dev.csv h1_dev.csv`.

```
a: tp=147 fp=142 tn=16468 fn=182 recall=0.4468 fp_rate=0.0085
b: tp=147 fp=142 tn=16468 fn=182 recall=0.4468 fp_rate=0.0085
delta: tp=+0 fp=+0
```

One decision diff: `61/81/472215d2fca9ef868561906345b2.white` (a white-side request) went Monitor to Allow, score 40 to 39; the score fell below the Monitor threshold, no Block/Allow decision changed.

Gate: FAIL (+0 TP is not greater than +0 FP). The dev corpus has no request where a stray invalid `%XX` hid an otherwise-blocked payload, so the fix has no measurable recall effect here. Code and unit tests are kept (they pin the H1 bypass); the controller decides whether the strict rule applies to a change with no corpus footprint. No tuning was done.

Owner ruling (2026-10-25): kept. H1 closes a confirmed bypass (a single invalid `%XX` disabled URL decoding for the whole field) that the dev half never exercises, so it is judged like the C2/C3 fail-closed fixes: 0 added dev FPs (here +0) and its probe regression tests block (`one_bad_byte_does_not_disable_url_decoding`, `sqli_survives_an_invalid_utf8_escape_in_the_same_field`). Gate under the amended rule: PASS.
