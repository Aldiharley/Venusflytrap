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

Owner rulings after review (2026-10-26): (R1) lossless recursive splitting. Whenever normalizing a piece of raw text is cut, that raw piece is re-inspected as two halves overlapping by 256 raw chars, recursively, until each piece normalizes uncut (depth bound 6; a piece of at most 512 chars cannot be split). (Amended by the final review's C-1 ruling, below: the split now happens on the decoded text.) Lossless here means every char of text reaches an uncut piece; it does not cover constructs. A construct whose span is longer than the 256-char overlap (e.g. `1 union` + 400 spaces + `select …`, `%20` x 150 or `/*x400*/` filler, `<svg` + 400 spaces + `onload=`) placed across a seam is still missed (Allow, score 28 in review). That is not a regression (before C3 everything past 64 KiB was dropped); stitching seams in normalized-token space is a Plan B item. This replaces two earlier exemption rules, a folded-overflow comparison and a head-verification check, both of which review showed could be bypassed (decoding shrinks text and NFKC expands it, so the exempted seam could hide an attack). It applies to every field chunk and to the path; sub-pieces are not charged to the budget. (R2) `limit.payload-truncated` now hard-blocks (Dangerous, weight 1.0, pins the verdict to Block like the honeypot does). It fires only on real loss: budget exhaustion, or a piece still cut at the depth bound or too short to split.

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

The same harness on the previous commit (44d91ec, no work cap) gave 1,151 ms (Allow), 231 ms (Allow), 1,079 ms (Allow), 5,240 ms (Allow), 5,177 ms (Block, byte budget) and 102 ms (Allow). These six cases are not the worst case. The final whole-branch review measured slower requests at the same 4 MiB budget: a 4 MiB query mixing decode-heavy and U+FDFA text (531 ms, Block), a benign 4 MiB body of pure "…" (545 ms, Block on the work cap), a benign 2 MiB body of pure "㌕" (572 ms, Allow) and token-dense text with sparse U+FDFA (422-439 ms); and a 1 MiB U+FDFA body costs 327 ms against 23 ms before C3. The honest worst case is about 0.55-0.6 s of CPU per request at the default 4 MiB budget (re-measured after the C-1 fix: see "M2a — final review fixes" below). The proxy inspects synchronously on its tokio worker threads (`vft-proxy/src/lib.rs:207` → `pipeline.rs:138/152`), so moving inspection to `spawn_blocking` with a time budget (an SP1 item) is a prerequisite before an enforcing proxy ships with this engine.

Gate under the amended rule: PASS (regression tests pass; dev FP 0.88% <= 1.0%). Dev latency p50/p95/p99 in us: 102/287/987 before, 78/219/786 after; earlier runs of near-identical builds gave 67/196/735 to 124/344/1183, so the spread is run-to-run noise and no change is claimed.

## M2a — milestone summary (commit 485ce08)

Plan A close: H1, L5, C2 and C3 on top of the M1 registry. Same commands, corpus and split as M0 (`venusflytrap eval`, release build, distinct sources); run outputs sit in `m2a/` next to `m0/`. Held-out is scored here once for this milestone; only its totals and aggregate decision-diff counts were looked at, no held-out request or construct.

| Run | Samples | TP | FP | TN | FN | Recall | Precision | F1 | FP rate | p50/p95/p99 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| library, full | 33877 | 287 | 276 | 32943 | 369 | 0.4375 | 0.5098 | 0.4709 | 0.0083 | 75/216/736 |
| serve, full | 33877 | 287 | 276 | 32943 | 369 | 0.4375 | 0.5098 | 0.4709 | 0.0083 | 76/223/755 |
| library, dev | 16939 | 148 | 146 | 16464 | 181 | 0.4498 | 0.5034 | 0.4751 | 0.0088 | 83/237/809 |
| library, held-out | 16938 | 139 | 130 | 16479 | 188 | 0.4251 | 0.5167 | 0.4664 | 0.0078 | 74/222/746 |

Change vs M0:

| Run | ΔTP | ΔFP | ΔFN | Recall | Precision | F1 | FP rate |
|---|---|---|---|---|---|---|---|
| library, full | +4 | +7 | -4 | 0.4314 → 0.4375 (+0.0061) | 0.5127 → 0.5098 (-0.0029) | 0.4685 → 0.4709 (+0.0023) | 0.0081 → 0.0083 (+0.0002) |
| library, dev | +1 | +4 | -1 | 0.4468 → 0.4498 (+0.0030) | 0.5087 → 0.5034 (-0.0052) | 0.4757 → 0.4751 (-0.0006) | 0.0085 → 0.0088 (+0.0002) |
| library, held-out | +3 | +3 | -3 | 0.4159 → 0.4251 (+0.0092) | 0.5171 → 0.5167 (-0.0004) | 0.4610 → 0.4664 (+0.0054) | 0.0076 → 0.0078 (+0.0002) |

Deltas are computed from the unrounded values in the run JSON and then rounded, so a delta can differ by 0.0001 from the difference of the two rounded values shown.

Denominators: scored malicious (TP+FN) full 656, dev 329, held-out 327; benign (TN+FP) full 33,219, dev 16,610, held-out 16,609. `venusflytrap eval` still cannot read 2 held-out `.black` files on this host (access denied; `read_failures` is 2 in the full, serve and held-out JSON and 0 in dev), so held-out recall is over 327 attacks, not 329. Dev FP rate 146 / 16,610 = 0.88%; held-out 130 / 16,609 = 0.78%. Parse failures and invariant violations are 0 in all four runs. Dev plus held-out equals full (148 + 139 = 287 TP, 146 + 130 = 276 FP).

Serve mode, full corpus (distinct sources): benign_sources 33219, benign_sources_banned 72, collateral_fp 0, bans_from_allowed 0, the same as M0. The serve and library confusion matrices are identical, as at M0.

Decision diffs vs M0 (library mode, counts only):

| Half | Malicious Allow→Block | Benign Allow→Block | Benign Monitor→Block | Benign Allow→Monitor | Benign Monitor→Allow | Score-only | Total |
|---|---|---|---|---|---|---|---|
| dev | 1 | 4 | 0 | 7 | 1 | 11 | 24 |
| held-out | 3 | 2 | 1 | 5 | 1 | 16 | 28 |
| full | 4 | 6 | 1 | 12 | 2 | 27 | 52 |

The dev diffs match the per-change A/B sections above: L5's 1 new TP, C2's 4 new FPs, C3's 7 Allow→Monitor and H1's 1 Monitor→Allow. Two of C2's 13 score-shift rows (`09/8a/171355d4b76706b9e4be0a80519a.white`, `11/27/9e27efe2a7cf63decdd16ed80f7c.white`) are also among C3's 7 Allow→Monitor rows, so the per-change diffs (1 + 17 + 7 + 1 = 26) net to 24 distinct rows. Held-out gained 3 TPs where dev gained 1. Which change produced them is unknown, because held-out rows are not opened. No verdict moved away from Block in either half.

Robustness (bench_http on M0's `seeds.jsonl` / `mutants.jsonl`, mutate.py seed 1337): seeds recall 0.8636 (19/22), mutants recall 0.8303 (548/660), retained 96.1% (0.8303 / 0.8636 = 0.9614). These are identical to M0, with 0 decision diffs and 0 score diffs over the 22 + 660 requests. p50/p95/p99 µs: seeds 9/15/111, mutants 8/13/16.

### Gates (spec §4.4 as amended by the owner rulings of 2026-10-25)

| Gate | Evidence | Result |
|---|---|---|
| `cargo test --workspace`, `cargo clippy --all-targets -- -D warnings` | 178 passed, 0 failed, 2 ignored; clippy exit 0 | PASS |
| Dev FP rate ≤ 1.0% | 146 / 16,610 = 0.88% | PASS |
| H1 `decode.percent-lossy` (bypass fix): 0 added dev FPs, probe tests block | A/B +0 TP / +0 FP; `one_bad_byte_does_not_disable_url_decoding` and `sqli_survives_an_invalid_utf8_escape_in_the_same_field` pass. The strict ΔTP > ΔFP rule fails (+0 is not greater than +0); the owner ruling judges H1 as a bypass fix | PASS (amended rule); strict rule FAIL, recorded |
| L5 `decode.b64-whole` (fixed decoder): ΔTP > ΔFP | A/B +1 TP / +0 FP | PASS |
| C2 windowing (fail-closed fix): probe tests block, dev FP within 1.0% | A/B +0 TP / +4 FP; `comma_padding_does_not_hide_sqli`, `exhausted_windows_emit_a_limit`, `attack_after_padding_is_found_in_a_later_window`, `running_out_of_windows_is_reported` and `graph_windows_bounds` pass; dev FP 0.88%. The original ΔFP = 0 rule fails (+4) | PASS (amended rule); original rule FAIL, recorded |
| C3 chunking (fail-closed fix): probe tests block, dev FP within 1.0% | A/B +0 TP / +0 FP; the chunk, split and budget tests pass (`seam_attacks_after_a_cut_chunk_are_found`, `exceeding_the_inspection_budget_blocks_with_a_limit`, `a_piece_that_cannot_be_split_further_is_a_real_loss` and others); dev FP 0.88% | PASS |
| Mutation robustness: retained ≥ 96% and mutant recall ≥ 83.0% | retained 96.14%, mutant recall 83.03% (the same as M0) | PASS (margins 0.14 and 0.03 points) |
| Full-corpus latency p95 < 1,000 µs | library p95 216 µs (M0 209); serve 223 µs | PASS |
| Held-out scored once, never tuned on | recall 0.4251, FP rate 0.0078 (M0 0.4159 / 0.0076) | Reported |

Latency: dev p95 went from 212 to 237 µs and full p95 from 209 to 216 µs. The C3 section records a p95 spread of 196-344 µs across dev runs of near-identical builds, so no latency change is claimed.

### Dev ablation (leave-one-out, library mode, baseline TP 148, FP 146)

`venusflytrap ablate --manifest … --side dev` makes one run per registered id, in `constructs()` order, with only that id in `shield.disabled`. `d_tp`/`d_fp` = what the id contributes (the baseline minus the run without it); `net` = `d_tp` - `d_fp`. The drop rule applies only to new or changed constructs. In Plan A those are the decoders and limits marked below, and their gates are the change-alone A/B and fail-closed rows in the gate table above, not this leave-one-out. Every other row predates recall-lift and is report-only.

| id | kind | tp | fp | d_tp | d_fp | net | Plan A status |
|---|---|---|---|---|---|---|---|
| sqli.union-select | Sink | 145 | 106 | 3 | 40 | -37 | existing, report-only |
| sqli.boolean-tautology | Sink | 135 | 118 | 13 | 28 | -15 | existing, report-only |
| sqli.quote-breakout | Sink | 137 | 139 | 11 | 7 | 4 | existing, report-only |
| sqli.stacked-query | Sink | 145 | 137 | 3 | 9 | -6 | existing, report-only |
| sqli.sql-keyword | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sqli.fn-sleep | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sqli.fn-benchmark | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sqli.fn-updatexml | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sqli.fn-extractvalue | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sqli.fn-load-file | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sqli.fn-pg-sleep | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| xss.script-tag | Sink | 137 | 138 | 11 | 8 | 3 | existing, report-only |
| xss.event-handler | Sink | 142 | 142 | 6 | 4 | 2 | existing, report-only |
| xss.dangerous-proto | Sink | 118 | 138 | 30 | 8 | 22 | existing, report-only |
| xss.tag-with-handler | Sink | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| xss.html-tag | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| cmd.cmd-substitution | Sink | 145 | 146 | 3 | 0 | 3 | existing, report-only |
| cmd.chained-command | Sink | 142 | 109 | 6 | 37 | -31 | existing, report-only |
| cmd.shell-meta | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| path.directory-traversal | Sink | 144 | 145 | 4 | 1 | 3 | existing, report-only |
| path.dotdot-segment | Latent | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sig.union-all-select | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sig.classic-or | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sig.schema-enum | Signature | 147 | 146 | 1 | 0 | 1 | existing, report-only |
| sig.alert-script | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sig.onerror | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| sig.etc-passwd | Signature | 145 | 146 | 3 | 0 | 3 | existing, report-only |
| sig.cat-subst | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| api.type-violation | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| recon.sensitive-path-probe | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| honeypot.decoy-hit | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| intel.scanner-ua | Signature | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| limit.header-non-utf8 | Limit | 148 | 146 | 0 | 0 | 0 | existing, report-only |
| limit.graph-truncated | Limit | 148 | 146 | 0 | 0 | 0 | new (C2); fail-closed gate PASS |
| limit.payload-truncated | Limit | 148 | 146 | 0 | 0 | 0 | new (C3); fail-closed gate PASS |
| decode.percent-lossy | Decoder | 99 | 93 | 49 | 53 | -4 | fixed (H1); bypass-fix gate PASS |
| decode.entity | Decoder | 133 | 146 | 15 | 0 | 15 | existing, id registered in L5; report-only |
| decode.esc-hex | Decoder | 145 | 146 | 3 | 0 | 3 | existing, id registered in L5; report-only |
| decode.b64-whole | Decoder | 141 | 146 | 7 | 0 | 7 | fixed (L5); ΔTP > ΔFP gate PASS |

Notes on the ablation:

- Disabling `decode.percent-lossy` turns off the whole URL percent-decoding step, not only the H1 change. With it off, dev loses 49 TPs and 53 FPs (net -4), so on dev, URL decoding as a whole enables slightly more false positives than true positives. H1's own change was +0 / +0. Leave-one-out of a pre-existing decoder is report-only, so nothing is dropped; turning URL decoding off would also reopen every percent-encoding evasion. This is recorded for the owner.
- `limit.graph-truncated` and `limit.payload-truncated` fire on no dev request (0 / 0). C2's 4 FPs come from text that windowing newly inspects and the existing SQL constructs then match: against the M1 leave-one-out, `sqli.boolean-tautology` d_fp went from 25 to 28 and `sqli.stacked-query` from 8 to 9.
- The other change against the M1 leave-one-out is `xss.script-tag` d_tp 10 → 11, which is L5's new dev TP (it fires `xss.script-tag` after the whole-field base64 decode). The baseline moved from 147/142 to 148/146.

## M2a — final review fixes (2026-10-26)

The final whole-branch review (range 3ae8a6a..f3d94cf, verdict "ready to merge with fixes") found one critical regression and a set of documentation issues. Owner ruling: fix C-1 and the documentation now; the other findings go to Plan B or SP1 (listed at the end).

C-1 (critical, regression against 3ae8a6a): R1 split the RAW text of a piece whose normalization was cut. That ignores base64's 4-char groups and the whole-field base64 decoder's need for the whole value. A field that is the base64 of `<script>alert(1)</script> 1 union select password from users` + two spaces + 4,000 U+FDFA (16,084 chars) decodes to text whose fold passes 64 Ki chars; its raw halves no longer decoded, normalized uncut as plain base64 text, and the request was allowed with score 0 and no `limit.*`, in a query field, a header and a body. 3ae8a6a blocked it.

Owner ruling (amends R1's mechanism, keeps its intent of lossless inspection): split the DECODED text, not the raw text. Each field or path chunk is now decoded once, whole (URL, entity, escape and base64 decoders to a fixpoint; decoding never adds chars), then folded (NFKC + skeleton, capped) and canonicalized. If the fold is cut, the decoded text is re-inspected as two halves overlapping by 256 chars, recursively, re-running only fold and canonicalization (and graph and detectors at the leaves). Unchanged: the depth bound 6, the unsplittable rule (at most 512 chars, now decoded chars), the per-field once-charged byte budget, the `shield.max_normalize_work` cap (the first fold's charge covers the decode pass, since decoded text is never longer than the raw chunk; each further fold of a half is admitted and charged), the hard-blocking `limit.payload-truncated` on genuine loss and the early NFKC cut. An uncut chunk reaches the detectors exactly as `normalize()` returns it (unit test `an_uncut_piece_reaches_the_detectors_exactly_as_normalize_returns_it`). The path goes through the same routine; a path longer than `max_payload` is now chunked like a field (not charged to the byte budget) instead of being split as one raw piece.

Regression test `whole_field_base64_survives_a_cut_fold`: the probe with 3,700, 4,000 and 10,000 U+FDFA, each in a query field, a header and a body, must Block with an XSS or SQLi construct. On f3d94cf all 9 cases were Allow (score 0, or 10 in the header) with no evidence; now all 9 Block. The earlier seam and bypass tests still pass, and the reviewer's sweeps run against the fix found 0 bypasses (systematic seam sweep 400,170 cases, default-config seam sweep 1,900, random fuzz 300), with the same counts as f3d94cf except as noted below.

Dev A/B (library mode, `compare_runs.py m2a/lib_dev.csv fr_dev.csv`):

```
a: tp=148 fp=146 tn=16464 fn=181 recall=0.4498 fp_rate=0.0088
b: tp=148 fp=146 tn=16464 fn=181 recall=0.4498 fp_rate=0.0088
delta: tp=+0 fp=+0
decision diffs: 0
```

No dev row changed in any column (verdict, score or constructs); `limit.payload-truncated` fires on no dev row. Dev FP 146 / 16,610 = 0.88% (≤ 166). Gate: PASS (regression test blocks, dev FP within the ceiling). Robustness (bench_http on M0's `seeds.jsonl` / `mutants.jsonl`): 0 decision diffs and 0 score diffs against `m2a/seeds.csv` and `m2a/mutants.csv` (seeds recall 0.8636, mutants 0.8303, retained 96.1%, unchanged). Held-out is not re-scored: it stays at its M2a measurement above (recall 0.4251, FP rate 0.0078).

One behaviour change outside dev: at the minimum `max_payload` of 1024 (not the default), text that decodes to NFKC-expanding chars (`%EF%B7%BA`, `&#xFDFA;`) reaches the unsplittable rule sooner, because the rule now counts decoded chars, which are denser than raw ones. In the reviewer's random fuzz at that setting, 42 of 150 cases hard-block on `limit.payload-truncated` instead of being inspected in full (13 of 150 on f3d94cf); none is a bypass. At the default 64 KiB this cannot happen: a part of at most 512 decoded chars folds to at most 9,216 chars, and a part at depth 6 (at most about 1,276 chars) to at most about 23,000, both under 65,536.

Worst-case timings after the fix (release, default config, best of 3 after a warm-up; `normalization_work_timings` and the reviewer's harness; f3d94cf measured alternately on the same machine, ranges over 2-6 runs):

| Request | f3d94cf | After C-1 fix | Verdict |
|---|---|---|---|
| 1 MiB body of U+FDFA | 331-340 ms | 320-333 ms | Block (work cap) |
| one query field of 65,536 x U+FDFA | 130-134 ms | 128-132 ms | Allow (inspected in full) |
| one query field of 300,000 x U+FDFA | 325-326 ms | 316-332 ms | Block (work cap) |
| one query field of 4 MiB of U+FDFA | 367-399 ms | 363-414 ms | Block (work cap) |
| 64 query fields of 65,536 x U+FDFA | 367-389 ms | 354-414 ms | Block (work cap) |
| 4 MiB ASCII body | 107-111 ms | 109-115 ms | Allow |
| 4 MiB query of five-layer `%25…41` and U+FDFA runs (the review's mixed case) | 550-568 ms | 503-529 ms | Block (work cap) |
| 4 MiB body of pure "…" | 590 ms | 556-578 ms | Block (work cap) |
| 2 MiB body of pure "㌕" | 570-594 ms | 601-634 ms | Allow |
| 4 MiB token-dense body with U+FDFA every 200 chars | 441-458 ms | 445-481 ms | Block (work cap) |

The fix does not change the cost beyond run-to-run spread (about ±10%); the mixed case is a little faster because a chunk is decoded once instead of at every split node. The worst case stays at about 0.55-0.65 s of CPU per request at the 4 MiB budget, reached by benign NFKC-expanding text. As stated in C3, the proxy runs inspection synchronously on tokio workers, so SP1's `spawn_blocking` with a time budget must land before an enforcing proxy ships with this engine.

Documentation and minor fixes from the same review: "lossless" is qualified as covering text, not constructs (C3 above, spec §7.3, `CHUNK_OVERLAP` and the shield comments); the M2a change-vs-M0 deltas are recomputed from unrounded values; the M2a reconciliation sentence accounts for the 2 rows shared by C2 and C3; the sink registry no longer claims an alias mechanism; the `decode_once` stage order is corrected; `chain.ban` is documented as a deliberate non-registry construct; the unused `percent-encoding` dependency is removed; `chunk_ranges(s, 0)` no longer panics; and `max_inspect_bytes` / `max_normalize_work` document that they must scale with the proxy's `limits.max_body`. After both commits: `cargo test --workspace` 182 passed, 0 failed, 2 ignored; `cargo clippy --all-targets -- -D warnings` clean.

Recorded for later, not fixed here: whole-field base64 longer than 64 KiB can still be lost at a chunk seam when a multi-byte char straddles the chunk edge (I-1, Plan B); seam stitching in normalized-token space (I-2, Plan B); `canonicalize_ws_comments` applies SQL comment rules to every field, so `x--><script>alert(1)</script>` is allowed (I-4, P0, first item of Plan B); `spawn_blocking` and an inspection time budget in the proxy (I-3, SP1).

## Merge with SP1's final tip (c157149) — 2026-10-26

`recall-lift` (6005bc0) merged with `origin/sp1-serve-hardening` (c157149: six commits after the branch point 3ae8a6a, incl. a28351f, which inspects query keys, cookie names and Accept-Encoding). One textual conflict (`request.rs`: SP1's private `percent_decode_lossy` stand-in dropped in favour of `normalize::percent_decode_lossy`; SP1's cookie helpers kept). One semantic conflict: `overlap_is_charged_once` set the byte budget to exactly one 3,000-byte query value, but the query key `q` is now inspected as its own field first, so the budget became 3,000 + 1 (the test still separates once-charging, which needs 3,001, from double-charging, ~3,768). `cargo test --workspace`: 195 passed, 0 failed, 2 ignored; clippy clean.

Same corpus, split and commands as M2a (release build). Held-out not scored separately (full minus dev gives its totals).

| Run | TP | FP | TN | FN | Recall | Precision | FP rate | p50/p95/p99 µs |
|---|---|---|---|---|---|---|---|---|
| library, full | 288 | 278 | 32941 | 368 | 0.4390 | 0.5088 | 0.0084 | 97/289/830 |
| serve, full | 288 | 278 | 32941 | 368 | 0.4390 | 0.5088 | 0.0084 | 89/270/783 |
| library, dev | 149 | 147 | 16463 | 180 | 0.4529 | 0.5034 | 0.0089 | 104/311/917 |

Recall is over 656 scored attacks on the full corpus (2 unreadable held-out `.black` files). Serve mode: benign_sources_banned 72, collateral_fp 0, bans_from_allowed 0 (unchanged). Robustness: seeds 19/22, mutants 548/660, retained 96.1% — 0 decision diffs vs M2a.

The two branches' effects are additive. Full corpus vs recall-lift M2a (287 / 276): +1 TP, +2 FP, which is SP1's query-key change as SP1 measured it; vs SP1's tip alone (284 / 271, SP1's RESULTS): +4 TP, +7 FP, which is recall-lift's M2a delta vs M0. Decision diffs vs M2a on the full corpus: 735 — 3 attack-verdict flips (1 malicious Allow→Block, 2 benign Allow→Block), 61 benign Allow→Monitor, 671 score-only (666 benign, 5 malicious); few rows gain a construct, so most shifts come from the extra evidence the newly inspected fields (query keys, Accept-Encoding) add. Dev FP rate 147 / 16,610 = 0.89%, within the 1.0% ceiling. p95 is higher than M2a's 216 µs on this run (289 µs); SP1 measured ~10% p50 cost for the extra fields, and this run was not repeated, so no latency claim is made beyond p95 < 1 ms.
