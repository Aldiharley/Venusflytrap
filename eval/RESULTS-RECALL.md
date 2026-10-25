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

### L5 — decode.b64-whole before '+' (and decoder ids)

Fixed decoder: gate is delta TP > delta FP (spec §4.4). Whole-field base64 is now tried before the URL step turns `+` into a space; `decode.entity`, `decode.esc-hex` and `decode.b64-whole` are registered ids and can be disabled. Dev half, library mode, `compare_runs.py pre-l5_dev.csv l5_dev.csv`.

```
a: tp=147 fp=142 tn=16468 fn=182 recall=0.4468 fp_rate=0.0085
b: tp=148 fp=142 tn=16468 fn=181 recall=0.4498 fp_rate=0.0085
delta: tp=+1 fp=+0
```

Decision diffs: 1. `09/51/70d77d502fc1f4de9e24b71dd19e.black` went Allow to Block, score 30 to 100.

Gate: PASS (+1 TP is greater than +0 FP).

Note: `parse_corpus.py`/`parse_qsl` and many adapters already turn `+` into a space in query values before the engine sees them, so L5 can only act on bodies, headers and cookies. A small delta is therefore expected and is reported as measured.

### C2 — token windows and limit.graph-truncated

Fail-closed fix: gate is delta FP = 0 on dev plus the regression tests (spec §4.4). Fields now run through overlapping 4096-token windows (64 tokens overlap, up to `shield.max_graph_windows`, default 32), and a field that runs out of windows emits Suspicious `limit.graph-truncated`. Dev half, library mode, `compare_runs.py pre-c2_dev.csv c2_dev.csv`.

```
a: tp=148 fp=142 tn=16468 fn=181 recall=0.4498 fp_rate=0.0085
b: tp=148 fp=146 tn=16464 fn=181 recall=0.4498 fp_rate=0.0088
delta: tp=+0 fp=+4
```

Decision diffs: 17. Four are benign requests that went Allow to Block, score 39 to 100: `c4/63/80b89d9d122c492af6b7077c9fdc.white`, `d0/3f/1709f660a201daf320d310c6c495.white`, `f9/24/0af6ebe0471f3515ad97f7d8de64.white`, `ff/f2/a21259580b9a671c4e5ef35f9519.white`. They are 27-79 KB telemetry POST bodies (`aegis.qq.com`, `insight.cloud.tencent.com`); a later window now reports `sqli.boolean-tautology` (3) or `sqli.stacked-query` (1) next to repeated `cmd.shell-meta`. The other 13 diffs are score-only shifts of 3 to 4 points (33 to 36/37, 36 to 39) with no verdict change. No `limit.graph-truncated` contribution appears in any dev row, so the new FPs come from tokens that were previously cut off at 4096 and are now inspected, not from the limit.

Gate: FAIL (delta FP is +4, required 0). The regression tests pass (`comma_padding_does_not_hide_sqli`, `exhausted_windows_emit_a_limit`, `attack_after_padding_is_found_in_a_later_window`, `running_out_of_windows_is_reported`, `graph_windows_bounds`). Code kept and committed; the controller and owner decide. No tuning was done.

Owner ruling (2026-10-25): kept. The 4 new dev FPs are existing SQL constructs (`sqli.boolean-tautology` ×3, `sqli.stacked-query` ×1) firing on the tails of large benign telemetry bodies that truncation at 4,096 tokens used to hide; `limit.graph-truncated` itself fired on no dev request. For fail-closed fixes, FPs from newly inspected text count against the dev 1.0% FP ceiling instead of a 0-FP rule: dev FP rate is 146 / 16,610 = 0.88%, within the ceiling, and the regression tests block. Gate under the amended rule: PASS. Plan B's body structuring targets these bodies.

### C3 — chunked inspection and limit.payload-truncated

Fail-closed fix, judged under the owner's amended rule (2026-10-25): the regression tests must block and FPs from newly inspected text count against the dev 1.0% FP ceiling (166 of 16,610 benign requests). Fields longer than `shield.max_payload` are inspected in overlapping chunks (256 chars overlap) under a per-request byte budget, `shield.max_inspect_bytes` (default 4 MiB, each field charged once). Dev half, library mode, `compare_runs.py pre-c3_dev.csv c3e_dev.csv`.

Owner rulings after review (2026-10-26): (R1) lossless recursive splitting. Whenever normalizing a piece of raw text is cut, that raw piece is re-inspected as two halves overlapping by 256 raw chars, recursively, until each piece normalizes uncut (depth bound 6; a piece of at most 512 chars cannot be split). This replaces two earlier exemption rules, a folded-overflow comparison and a head-verification check, both of which review showed could be bypassed (decoding shrinks text and NFKC expands it, so the exempted seam could hide an attack). It applies to every field chunk and to the path; sub-pieces are not charged to the budget. (R2) `limit.payload-truncated` now hard-blocks (Dangerous, weight 1.0, pins the verdict to Block like the honeypot does). It fires only on real loss: budget exhaustion, or a piece still cut at the depth bound or too short to split.

Normalization work cap (C3 re-review): every split node used to re-run a full normalization, so a request of NFKC-expanding chars cost seconds of CPU (release, default config: 1 MiB U+FDFA body 1,319 ms, 4 MiB single U+FDFA field 5,684 ms; before C3 the 1 MiB body took 23 ms because everything past 64 KiB was dropped). Two changes bound it. (1) Unicode folding stops at `max_payload + 1` chars, so a cut piece costs O(max_payload) instead of O(18 x raw); uncut text normalizes byte-identically, and a piece that is split skips canonicalization. (2) A per-request counter adds up the folded chars of every normalization (field chunks, split pieces, path) against `shield.max_normalize_work` (new, default 8,388,608 chars = 2 x `max_inspect_bytes`, validated >= `max_payload`). A normalization whose worst case (18 x its input, at most `max_payload`) would pass the cap is not run: inspection stops and `limit.payload-truncated` hard-blocks the request. No clock is involved. A 1 MiB U+FDFA body needs 17,677,824 folded chars to inspect losslessly (measured with the cap lifted), so it reaches the cap (work 8,376,720) and hard-blocks; one 64 KiB-char U+FDFA field needs 3,354,118 and is inspected in full.

```
a: tp=148 fp=146 tn=16464 fn=181 recall=0.4498 fp_rate=0.0088
b: tp=148 fp=146 tn=16464 fn=181 recall=0.4498 fp_rate=0.0088
delta: tp=+0 fp=+0
```

Decision diffs: 7, all benign (label 0) dev rows, all Allow to Monitor, none a Block. Two (`09/8a/171355d4b76706b9e4be0a80519a.white`, `11/27/9e27efe2a7cf63decdd16ed80f7c.white`) go from score 37 to 42 and gain `cmd.shell-meta`, `xss.html-tag` and `cmd.cmd-substitution` firings from text past the first 64 KiB (including re-inspected halves). Five (`66/57/9ea1675a0c2393318bb4e64333e5.white`, `92/f6/e825501ce0567d1b48285015ddd1.white`, `ac/b8/5784291dfc61d9dbcffb451ba393.white`, `c8/51/6e8acba2047ff63b8086b18d557f.white`, `ea/b0/3738d8ed30e1cb95967b389313cb.white`) go from 39 to 41 on one extra `cmd.shell-meta`. `limit.payload-truncated` fires on no dev row, so the hard block cost no dev FP. Dev FP rate: 146 / 16,610 = 0.88%, unchanged from the pre-change run and within the 1.0% ceiling (166).

Worst cases (release build, default config, best of 3 after a warm-up, `cargo test --release -p vft-core --test fuzz_props -- --ignored --nocapture normalization_work_timings`; not part of the dev eval):

| Request | Time | Verdict |
|---|---|---|
| 1 MiB body of U+FDFA | 327 ms | Block (work cap, `limit.payload-truncated`) |
| one query field of 65,536 x U+FDFA | 132 ms | Allow (inspected in full, no evidence) |
| one query field of 300,000 x U+FDFA | 327 ms | Block (work cap) |
| one query field of 4 MiB of U+FDFA | 372 ms | Block (work cap) |
| 64 query fields of 65,536 x U+FDFA | 354 ms | Block (work cap) |
| 4 MiB ASCII body | 99 ms | Allow (inspected in full, no evidence) |

The same harness on the previous commit (44d91ec, no work cap) gave 1,151 ms (Allow), 231 ms (Allow), 1,079 ms (Allow), 5,240 ms (Allow), 5,177 ms (Block, byte budget) and 102 ms (Allow). The worst case is now 372 ms, about 3.8 x the 4 MiB plain-text request.

Gate under the amended rule: PASS (regression tests pass; dev FP 0.88% <= 1.0%). Dev latency p50/p95/p99 in us: 102/287/987 before, 78/219/786 after; earlier runs of near-identical builds gave 67/196/735 to 124/344/1183, so the spread is run-to-run noise and no change is claimed.
