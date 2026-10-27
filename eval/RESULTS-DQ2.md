# DQ2a (false-positive budget, first part): measured results

DQ2a (this plan) ships three changes: the shell command-position rule (`gate.cmd-position`), body
classification (JSON bodies split into leaves with `parse.body-json`, plus `limit.body-non-utf8`,
`limit.body-unparsed` and the API-safety last-segment rule), and corroboration de-duplication. The SQL
grammar gate (spec section 4.3) and per-context canonicalisation (section 4.5) are deferred for the
owner's decision (section 13). Every number below was copied from the run file named next to it; all
files are under `.superpowers/dq2/runs/` (`baseline/` for the serve baseline) unless a path says otherwise.
Nothing is estimated and nothing was tuned.

- **Baseline:** code of main `a990f26`, built in a temporary worktree (`bin-a990f26.exe`), scored on dev as `base-dev.json`.
- **Measured tree:** branch `dq2-fp-budget` at `882ed67` (`final-build-head.txt`). No code changed after the final checks (`final-checks.txt`): the tree was clean apart from `eval/__pycache__/`.
- **Machine and corpus:** the Windows 11 host of [`RESULTS-DQ1.md`](RESULTS-DQ1.md); the corpus is the directory described in [`docs/BENCHMARK.md`](../docs/BENCHMARK.md) section 1.
- **Samples and read failures** (JSON of each run): dev `base-dev.json` 16,939 / 0 and `final-dev.json` 16,939 / 0; held-out `heldout.json` 16,936 / 0; full-corpus library `final-library.json` 33,875 / 0; serve diff 33,875 shared rows in both source models. `parse_failures` and `invariant_violations` are 0 in all four library JSONs.
- **Absent files (Host facts procedure):** none on dev (`heldout-absent.txt`: manifest 16,939, scored 16,939). Two held-out rows of the manifest (16,938) are absent from the corpus directory and were never scored: `3e/f0/ba59dd0840009f5b678663dbb1bd.black` and `d5/65/2dcdd89317f10d43500014509120.black`. They were already absent in DQ1 (33,875 of the 33,877 manifest rows scored), so every comparison here is over the same rows.
- **Final checks** (`final-checks.txt`): `cargo test --workspace` all ok (vft-core lib 204 passed), `cargo clippy --all-targets -- -D warnings` clean, `ts_bindings` 1 passed (no regeneration), eval Python tests OK. `ui/node_modules` is absent, so the UI check was not run.

## 1. Header summary

| Item | Value | Source |
|---|---|---|
| Dev FP, main to DQ2a | 147 to 100 | `base-dev.json`, `final-dev.json` |
| Dev TP, main to DQ2a | 149 to 149 | same |
| Held-out (scored once) | TP 139, FP 88, FN 188 | `heldout.json` |
| Dev FP exit target (at most 99 rows) | **not met**, 100 rows | section 2 |
| Merge rule | holds | section 2 |
| `bench_http` thresholds | both met | section 7 |
| Library p95 | 280 us (budget 1,000 us) | `final-library.json` |
| Serve diff | exit 0, no unattributed change | section 10 |
| TCP replay | exit 0, all mismatch buckets 0 | section 11 |

## 2. Dev result and exit

Dev rows only (`--side dev`).

| Run | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|---|---|
| main `a990f26` (`base-dev.json`) | 149 | 147 | 16,463 | 180 | 45.29 % [40.00, 50.69] | 0.89 % [0.75, 1.04] |
| DQ2a final (`final-dev.json`) | 149 | 100 | 16,510 | 180 | 45.29 % [40.00, 50.69] | 0.60 % [0.50, 0.73] |

`base-dev.json` matches the expected main counts (TP 149, FP 147, TN 16,463, FN 180), so the baseline is main.

Paired comparison (`final-vs-base.txt`, `compare_runs.py --intersect`, 0 rows only in either run; `compare exit 1`, as expected because decisions changed; 637 rows differ in some decision column or score):

- McNemar `lib_verdict`, malicious: b=0 c=0 p=1
- McNemar `lib_verdict`, benign: b=51 c=4 p=2.047e-11 (b = blocked on main only, c = blocked in DQ2a only)
- delta: TP +0, FP -47

Exit lines, as measured:

- **Dev FP rows against the spec target of at most 99 (about 0.6 %): reached 100 (0.60 %). Target not met**, by one row. Nothing was tuned to close it.
- **Dev delta TP** = 149 - 149 = 0. Net of the justification rows of section 4 (none on dev): 0 + 0 = 0.
- **Fallen malicious dev rows** (`final-fallen.txt`): none. 0 rows go from Challenge/Block on main to Allow/Monitor in the final build; `final-fallen-steps.txt` is empty for that reason.
- **Merge rule** (every shipped step has dev delta FP at most 0 and loses no TP outside the justification list): **holds**. Cmd-position -37, body-total -10, corroboration 0 (section 3); no malicious dev row fell, so the justification list is empty on dev. The three deltas add up: 147 - 37 - 10 + 0 = 100.

## 3. Per-step table (dev)

Each shipped step is one A/B on the dev rows, run when the step was finished, through `eval/ab_dev.sh` (A without the step, B with it). Sources are the `-ab.txt` files. The "after" columns are the B arm of that file.

**Shipped steps**

| Step | Task | dTP | dFP | McNemar malicious b/c/p | McNemar benign b/c/p | Recall after [95 % CI] | FP rate after [95 % CI] | Source |
|---|---|---|---|---|---|---|---|---|
| `cmdpos` (`gate.cmd-position`) | 2 | +0 | -37 | 0 / 0 / 1 | 37 / 0 / 1.455e-11 | 45.29 % [40.00, 50.69] | 0.66 % [0.55, 0.80] | `cmdpos-ab.txt` (A = `--disable gate.cmd-position`) |
| `body-total` (JSON split, as shipped; A is today's single `<body>`) | 3 | +0 | -10 | 0 / 0 / 1 | 14 / 4 / 0.03088 | 45.29 % [40.00, 50.69] | 0.60 % [0.50, 0.73] | `body-total-ab.txt` (round 4's; A = `--disable parse.body-json`) |
| `corroboration` | 4 | +0 | +0 | 0 / 0 / 1 | 0 / 0 / 1 | 45.29 % [40.00, 50.69] | 0.56 % [0.46, 0.69] | `corroboration-ab.txt` (A = `bin-before-corroboration.exe`) |

The `corroboration` row was measured on the tree of Task 4's commit `30c5c79`, when body classification still had its earlier shape (dev FP 93 on both arms). Its delta is a step delta and does not depend on the body rounds that followed. All three rows have 0 fallen malicious rows and 0 rows only in one arm.

**Task 3 design history (per-id and per-round A/Bs; not additive, and not all shipped)**

Task 3 went through five rounds (round 0 uncommitted; commits `c4bc632`, `395aba4`, `7d1dbb9`, `bf8f716`, `882ed67`). The ids `parse.body-binary`, `parse.body-form` and `parse.body-multipart` existed in the earlier rounds and are gone from the shipped build, so their A/Bs cannot be re-run; the files below are the numbers recorded then. Where a name was reused, the older file was renamed first (`r0-*`, `r3-*`, `stop1-*`, per the Task 3 report). `body-ab.txt` and the four `body-<class>-ab.txt` files hold round 1's numbers because round 0's were renamed to `r0-*`. I found no file whose numbers I had to reconstruct.

| File | Round | What changed in the step | dTP | dFP | McNemar malicious b/c/p | McNemar benign b/c/p | FP rate after | Fallen |
|---|---|---|---|---|---|---|---|---|
| `r0-body-ab.txt` | 0 (stopped, uncommitted) | binary, JSON, form and multipart classes together vs single `<body>` | -3 | -13 | 4 / 1 / 0.375 | 22 / 9 / 0.02945 | 0.58 % [0.48, 0.71] | 4 |
| `r0-body-binary-ab.txt` | 0 | binary class alone | +0 | -5 | 0 / 0 / 1 | 5 / 0 / 0.0625 | 0.58 % | 0 |
| `r0-body-json-ab.txt` | 0 | JSON leaves alone | +0 | -12 | 0 / 0 / 1 | 16 / 4 / 0.01182 | 0.58 % | 0 |
| `r0-body-form-ab.txt` | 0 | form splitting alone (this is where the 4 fallen rows came from) | -3 | +4 | 4 / 1 / 0.375 | 1 / 5 / 0.2188 | 0.58 % | 4 |
| `r0-body-multipart-ab.txt` | 0 | multipart parts alone | +0 | -2 | 0 / 0 / 1 | 2 / 0 / 0.5 | 0.58 % | 0 |
| `r0-body-nonutf8-ab.txt` | 0 | `limit.body-non-utf8` alone | +0 | +0 | 0 / 0 / 1 | 0 / 0 / 1 | 0.58 % | 0 |
| `body-ab.txt` | 1 (`c4bc632`) | form class removed; binary, JSON and multipart vs single `<body>` | +0 | -17 | 0 / 0 / 1 | 21 / 4 / 0.0009105 | 0.56 % [0.46, 0.69] | 0 |
| `body-binary-ab.txt` | 1 | binary class alone | +0 | -5 | 0 / 0 / 1 | 5 / 0 / 0.0625 | 0.56 % | 0 |
| `body-json-ab.txt` | 1 | JSON leaves alone | +0 | -12 | 0 / 0 / 1 | 16 / 4 / 0.01182 | 0.56 % | 0 |
| `body-multipart-ab.txt` | 1 | multipart parts alone | +0 | -2 | 0 / 0 / 1 | 2 / 0 / 0.5 | 0.56 % | 0 |
| `body-nonutf8-ab.txt` | 1 | `limit.body-non-utf8` alone | +0 | +0 | 0 / 0 / 1 | 0 / 0 / 1 | 0.56 % | 0 |
| `bodyfix-ab.txt` | 2 (`395aba4`) | review fixes: magic bytes hide text only without a declared text type, multipart framing inspected, duplicate JSON keys kept; A = build at `30c5c79` | +0 | +0 | 0 / 0 / 1 | 0 / 0 / 1 | 0.56 % | 0 |
| `bodyfix2-ab.txt` | 2 (`7d1dbb9`) | an untyped multipart part is text (RFC 7578); A = build at `30c5c79` | +0 | +0 | 0 / 0 / 1 | 0 / 0 / 1 | 0.56 % | 0 |
| `stop1-bodyfix3-ab.txt` | 3, stopped | binary class removed, every part one text field; A = round 2 | +0 | +7 | 0 / 0 / 1 | 0 / 7 / 0.01562 | 0.60 % | 0 |
| `stop1-body-total-ab.txt` | 3, stopped | same state against single `<body>` | +0 | -10 | 0 / 0 / 1 | 14 / 4 / 0.03088 | 0.60 % | 0 |
| `bodyfix3-ab.txt` | 3 (`bf8f716`) | no hiding; JSON parts inside multipart split again; A = round 2 | +0 | +5 | 0 / 0 / 1 | 0 / 5 / 0.0625 | 0.59 % [0.48, 0.72] | 0 |
| `r3-body-total-ab.txt` | 3 (`bf8f716`) | JSON and multipart vs single `<body>` | +0 | -12 | 0 / 0 / 1 | 16 / 4 / 0.01182 | 0.59 % | 0 |
| `bodyfix4-ab.txt` | 4 (`882ed67`) | multipart back to one `<body>` (deferred to DQ3), JSON-only split; A = round 3 | +0 | +2 | 0 / 0 / 1 | 0 / 2 / 0.5 | 0.60 % [0.50, 0.73] | 0 |
| `body-total-ab.txt` | 4 (`882ed67`) | shipped state against single `<body>` (the shipped row above) | +0 | -10 | 0 / 0 / 1 | 14 / 4 / 0.03088 | 0.60 % | 0 |

Where each file's rows are explained: the 4 round-0 fallen rows (a construct that formed only across two form pieces) and 5 new benign Blocks from form splitting are why the form class was removed in round 1; the +5 of round 3 is the 5 benign rows that the binary class used to hide; the +2 of round 4 is the 2 JSON parts of multipart bodies that multipart deferral gives back. Details are in the Task 3 report, not copied here.

## 4. Justification table

| rel | construct (main's top) | step it fell in | reason | recovered in |
|---|---|---|---|---|
| none | | | No malicious dev row fell from Challenge/Block to Allow/Monitor between main and the final build (`final-fallen.txt`). No `bench_http` seed family lost a mutant against M0 (`final-mutant-families.txt`: total lost 0, gained 0). | |

Two held-out rows were recorded during Task 3 as justification candidates. Both are, in the final build, back at the decision main gave them (checked in the `now-serve-distinct.csv` and baseline `serve-distinct.csv` verdict columns; no held-out file was opened):

| rel | label / side | main | final | note |
|---|---|---|---|---|
| `5b/06/b33273adabbcb06926720e04cc1f.black` | malicious / held-out | Block, score 100, top `sqli.stacked-query` | Block, score 100, top `sqli.stacked-query` | Block to Allow in Task 3 rounds 1 to 3; back to Block in round 4. No justification is needed. |
| `78/70/f847412e4801ad7b16af575916d0.white` | benign / held-out | Block, score 100, top `limit.payload-truncated` | Block, score 100, top `limit.payload-truncated` | Block to Allow in rounds 1 to 3; back to Block in round 4. |

## 5. Corroboration

Source: `corroboration-hist.txt` (dev rows; A is the build before Task 4, B is with corroboration de-duplication).

| Label | Arm | 0-9 | 10-19 | 20-29 | 30-39 | 40-49 | 50-59 | 60-69 | 70-79 | 80-89 | 90-100 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| benign | A | 0 | 0 | 3 | 15,254 | 1,260 | 0 | 0 | 0 | 0 | 93 |
| benign | B | 0 | 0 | 3 | 15,254 | 1,260 | 0 | 0 | 0 | 0 | 93 |
| malicious | A | 1 | 0 | 4 | 174 | 1 | 0 | 0 | 0 | 4 | 145 |
| malicious | B | 1 | 0 | 4 | 174 | 1 | 0 | 0 | 0 | 4 | 145 |

Verdicts, both arms: Allow 15,436, Block 238, Challenge 4, Monitor 1,261. Monitor count 1,261 before and after.

As measured, no benign mass moved between score bands or verdicts on dev; the histograms are identical. The step's only measured effect is a 1 to 3 point score reduction on 14 malicious serve rows, with no decision change (Task 4 report). Corroboration buys no false-positive budget on this corpus; it is a guard against the extra latent score that field splitting adds.

## 6. Leave-one-out (dev)

Source: `ablate-dev.tsv` (`venusflytrap ablate --side dev`, exit 0, `ablate-dev.status`; 46 ids). Each row disables one id on the final build. `d_tp` and `d_fp` are the final build minus the disabled build, and `net` = `d_tp` - `d_fp`: a positive `net` means the id adds more true positives than false positives.

The four DQ2a ids (`parse.body-binary`, `parse.body-form` and `parse.body-multipart` are not registered in the shipped build):

| id | kind | d_tp | d_fp | net |
|---|---|---|---|---|
| `gate.cmd-position` | Gate | 0 | -37 | 37 |
| `parse.body-json` | Decoder | 0 | -10 | 10 |
| `limit.body-non-utf8` | Limit | 0 | 0 | 0 |
| `limit.body-unparsed` | Limit | 0 | 0 | 0 |

`limit.body-unparsed` is worth 0 points, so its zero row is expected. `limit.body-non-utf8` fires on no dev row that changes a decision.

The ten rows with the largest `net` (the tenth place is a four-way tie at 3, all four shown):

| id | kind | d_tp | d_fp | net |
|---|---|---|---|---|
| `gate.cmd-position` | Gate | 0 | -37 | 37 |
| `xss.dangerous-proto` | Sink | 30 | 8 | 22 |
| `decode.entity` | Decoder | 15 | 0 | 15 |
| `parse.body-json` | Decoder | 0 | -10 | 10 |
| `sqli.quote-breakout` | Sink | 11 | 2 | 9 |
| `decode.b64-whole` | Decoder | 7 | 0 | 7 |
| `cmd.chained-command` | Sink | 6 | 0 | 6 |
| `cmd.cmd-substitution` | Sink | 3 | 0 | 3 |
| `path.directory-traversal` | Sink | 4 | 1 | 3 |
| `sig.etc-passwd` | Signature | 3 | 0 | 3 |
| `decode.esc-hex` | Decoder | 3 | 0 | 3 |

The most negative rows are `sqli.union-select` (d_tp 3, d_fp 40, net -37) and `sqli.boolean-tautology` (13, 29, net -16). Those are the SQL sinks the deferred grammar gate targets (section 13).

## 7. Robustness (`bench_http`)

Sources: `final-seeds.txt`, `final-mutants.txt` (this build) and `M:/Projects/venusflytrap-recall-runs/m0/seeds.txt`, `mutants.txt` (M0). `bench_http` is the mutation-retention harness, run on the 22 seeds and their 660 mutants; the synthetic `venusflytrap bench` command is not a result and is not quoted.

| Set | Run | TP | FN | Recall | p50 / p95 / p99 (us) |
|---|---|---|---|---|---|
| seeds | DQ2a | 19 | 3 | 0.8636 | 12 / 21 / 135 |
| seeds | M0 | 19 | 3 | 0.8636 | 12 / 18 / 117 |
| mutants | DQ2a | 548 | 112 | 0.8303 | 10 / 13 / 19 |
| mutants | M0 | 548 | 112 | 0.8303 | 8 / 10 / 15 |

- **Retained** (mutants recall / seeds recall) = 0.8303 / 0.8636 = 96.14 % (548/660 over 19/22). Threshold at least 96 %: **met**.
- **Mutant recall** 83.03 % against the threshold of at least 83.0 %: **met**, by 0.03 points (the same 548 of 660 as M0).
- `final-mutant-families.txt` (the 660 per-mutant predictions of this build against M0's `mutants.csv`): `total lost 0, gained 0`. No seed family lost or gained a mutant, so no justification row is needed.
- The timing columns are one run each, taken with no other job of this session running; the small differences from M0 are not analysed.

## 8. Latency

Source: `final-library.json`, full corpus, `--mode library` (33,875 samples, 0 read failures), `latency_us_p50_p95_p99`.

| p50 | p95 | p99 | Budget |
|---|---|---|---|
| 83 us | 280 us | 1,094 us | p95 under 1 ms: **met** |

For reference, main on dev: `base-dev.json` 101 / 311 / 975 us; DQ2a on dev: `final-dev.json` 80 / 274 / 1,110 us; held-out `heldout.json` 81 / 292 / 1,134 us.

## 9. Held-out, scored once

Source: `heldout.json` (`library`), run with `--side heldout` from the frozen tree `882ed67` after the last step, once. It was never used for tuning: no cluster listing and no fallen-row listing was produced for it, and no held-out request was opened by hand. (The full-corpus library, serve and TCP runs that followed score every row, including held-out ones, as the earlier milestones did; they change no decision.)

| TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI] |
|---|---|---|---|---|---|
| 139 | 88 | 16,521 | 188 | 42.51 % [37.27, 47.92] | 0.53 % [0.43, 0.65] |

Samples 16,936, read failures 0 (the two absent manifest rows are listed in the header). For the earlier code, `eval/RESULTS-RECALL.md` (M2a) has held-out recall 0.4251 and FP rate 0.0078 (TP 139, FP 130, FN 188). That row is from earlier code and is not a paired comparison; it is quoted only for orientation. Dev recall is 45.29 % [40.00, 50.69] and held-out 42.51 % [37.27, 47.92]: the intervals overlap.

Held-out rows that lost a malicious decision in the serve regression check (`NON-DEV-LOSS` lines of `serve-attribution.txt`): **0**. The attribution file has no `NON-DEV-LOSS`, `UNJUSTIFIED-DEV-LOSS` or `OTHER` line.

## 10. Serve regression check

- `serve-diff-final.txt` (`bash eval/decision_gate.sh diff "$VFT_BASELINE"`, status `serve-diff-final.status`): **exit 0**; `bans_from_allowed` 0 and `invariant_violations` 0 in both source models.
- Both models (distinct and pooled:100) list the same changes: 33,875 shared rows, 921 changed decisions, 318 score-only changes, 0 rows only in old, 0 only in new.
- Attribution (`serve-attribution.txt`, spec section 6.3 item 1), per source model: `{'body': 37, 'score-only': 819, 'sink': 65}`. That is 921 rows, and there is no `OTHER` line.
- Composition (`serve-breakdown.txt`, verdict columns only): all 921 changed rows are **benign**; no malicious row changed its library or serve verdict.
  - `sink` 65 rows, all benign Block to Allow (19) or Block to Monitor (46): the cmd-position gate.
  - `body` 37 rows, all benign: Block to Allow 19, Block to Monitor 12, Allow to Block 6. The 6 Allow to Block rows are new Blocks on a body field (4 dev, 2 held-out).
  - `score-only` 819 rows, all benign Allow to Monitor, and all 819 have `cmd.shell-meta` as the top construct both before and after (checked in the baseline and `now-serve-distinct.csv` `top` columns). The mechanism (extra latent score from the split body fields) is the one the Task 3 report found; it was not diagnosed row by row here. A Monitor is not a false positive in the library metrics.
- Conclusion: **no unattributed change.**

## 11. TCP replay

Source: `tcp-full.json`; status file `tcp-full.status`: head `882ed67`, **exit 0**, wall **88 s**, `netstat -an | grep -c TIME_WAIT` = **34** (taken right after the run). `venusflytrap eval --mode tcp --limit 40000`.

| Run | replayed | matched_block | matched_allow | proxy_rejected | not_replayable | block_vs_proxy_allow | allow_vs_proxy_403 | upstream_5xx | io | other | mismatched |
|---|---|---|---|---|---|---|---|---|---|---|---|
| DQ2a full corpus (`tcp-full.json`) | 33,711 | 473 | 33,233 | 5 | 164 | 0 | 0 | 0 | 0 | 0 | 0 |
| DQ1 (`RESULTS-DQ1.md` section 5) | 33,711 | 563 | 33,143 | 5 | 164 | 0 | 0 | 0 | 0 | 0 | 0 |

`mismatch_block_vs_proxy_allow`, `mismatch_upstream_5xx` and `mismatch_io` are all 0, at DQ1's level. `matched_block` fell by 90 and `matched_allow` rose by 90, equal to the full-corpus FP change (278 to 188) and to `final-library.json`. The five `proxy_rejected` rows are the same five rel paths as DQ1 (`00/06/005a…`, `78/70/f847…`, `bd/40/8bde…`, `ec/98/75af…`, `ff/67/62b3…`), with the same statuses (400, 413, 400, 400, 400). TIME_WAIT 34 sits inside DQ1's 32 to 40 range, wall time 88 s inside its 88 to 91 s.

## 12. Remaining dev FP clusters

Source: `clusters-final.txt` (`eval/clusters.py final-dev.csv --manifest <manifest> --side dev --top 15`). Dev rows only; held-out was not read. The listing reports **100 FP rows in 34 groups** (the top 15 below cover 81 rows) and 180 misses in 24 groups. Rel paths only.

| Count | Top construct | Loc | Name | Example |
|---|---|---|---|---|
| 25 | `sqli.union-select` | header | `referer` | `07/1f/5efaaec9cb9a1c05d01bee6644cf.white` |
| 18 | `sqli.boolean-tautology` | header | `referer` | `10/f1/7354f6010c03a758650986dc8102.white` |
| 7 | `sqli.union-select` | query | `bq` | `23/f3/604f8ab9055a963dca47925f2831.white` |
| 6 | `xss.dangerous-proto` | body | `json:/events/0/mapvalue/attributes/href` | `21/85/bde3866f2ae21a1ecbf14a825d23.white` |
| 5 | `sqli.boolean-tautology` | body | `<body>` | `75/92/43aab0a7fb477ce030ded2fce907.white` |
| 4 | `sqli.quote-breakout` | body | `<body>` | `2b/8c/78ada4928a945a524d27755e1ebc.white` |
| 3 | `xss.event-handler` | body | `<body>` | `0b/45/e23693894dfc3308b84c3b58e735.white` |
| 2 | `sqli.boolean-tautology` | query | `data` | `87/f5/c2b9fd3b741be8782a2ece2b9b55.white` |
| 2 | `sqli.union-select` | body | `<body>` | `45/cb/8d8e29a3135e0e8f67ea65b41359.white` |
| 2 | `sqli.union-select` | query | `q` | `a2/e3/4ddc588a76e762d29811bff842fb.white` |
| 2 | `xss.script-tag` | body | `<body>` | `38/6e/b4972015fb0ba3e838b5e3753b8f.white` |
| 2 | `xss.script-tag` | query | `param` | `6c/91/b17738858cb2bcd824f5590735a2.white` |
| 1 | `path.directory-traversal` | body | `json:/code` | `7e/ac/a54c85a827388378627dc1e0daa2.white` |
| 1 | `sqli.boolean-tautology` | body | `json:/replaycontent` | `e0/eb/92829ce625536567fec80f184c71.white` |
| 1 | `sqli.boolean-tautology` | query | `bq` | `bc/ae/d6d6252d25a720745dab65f3b78e.white` |

All FP groups have cause `Detection:scoring.block_at`. No `cmd.chained-command` group remains (main had 25 in `query:data`, 8 in `body` and 4 in `header:referer`; `cmdpos-ab.txt`, clusters a). 43 of the 100 rows are SQL constructs in the `Referer` header, and 9 more are `sqli.union-select` in the `bq` and `q` query parameters. The misses are unchanged from DQ1's: 148 of 180 have `cmd.shell-meta` as the top contribution below the monitor threshold.

## 13. Deferred, and what remains

Dev FP reached **100 rows against the at most 99 target**, so the exit target is not met by one row. The gap is not closed because nothing is tuned to the corpus. The following work is deferred and is listed for DQ3 and for the owner's decision:

- **SQL grammar gate** (spec section 4.3; D4 to D7, D9) for `sqli.union-select`, `sqli.boolean-tautology` and `sqli.stacked-query`. The spec's D4 sizes it at the prose, search and telemetry classes behind 77 dev FPs. It is the largest remaining cluster family (section 12). The plan work for it was stopped twice by a safety classifier before the plan could be written, so it was dropped from DQ2a rather than shipped untested; it needs the owner's decision on how to proceed.
- **Per-context canonicalisation (P0)** (spec section 4.5, D11). It was dropped for the same reason, plan writing having been stopped twice.
- **Form splitting.** A form body is one `<body>` field. Splitting it lost constructs that form across two values (4 malicious dev rows in round 0, `r0-body-form-ab.txt`) and added benign Blocks.
- **Multipart splitting.** A multipart body is one `<body>` field. Splitting needs strict RFC 2046 framing with fallback to the whole body on any ambiguity (review finding N-1: lenient matching can split one backend value across fields). The round 0 to 3 files in section 3 show what it bought (about 2 dev FP).
- **The per-header grammar matrix** (spec section 4.1, D15). It decides no dev FP (`cmd.shell-meta` has d_fp 0) and is a guard for header-borne constructs once DQ3 adds them.
- **JSON non-string values and identifier keys** (review minor m-1). Numbers, booleans, null and identifier-only keys are not inspected. They matter once a NoSQL or prototype-pollution detector exists.
- **Earlier recall work** (`eval/RESULTS-RECALL.md`), and the clusters of section 12 that fall outside DQ2a's sinks (spec section 8): the `Referer` and query-parameter SQL groups, and the 148 `cmd.shell-meta` misses scored below the monitor threshold. Dev recall is unchanged at 45.29 % through this plan.
