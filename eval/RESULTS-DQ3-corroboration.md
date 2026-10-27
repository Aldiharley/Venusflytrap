# DQ3 rule C (JSON-leaf latents do not corroborate other fields): measured results

DQ2a split JSON bodies into leaves. Each leaf is its own origin under D10, so a latent (Suspicious) hit on a leaf corroborated a top on another field. Most often that was a `cmd.shell-meta` latent backing up a `cmd.shell-meta` top on a header such as `sec-ch-ua`, which pushed scores from 39 to 41 or 43, across `monitor_at` (40). That raised dev Monitor from 867 to 1,270 rows ([`RESULTS-DQ2.md`](RESULTS-DQ2.md), "Monitor cost"). This change decides that question, which `RESULTS-DQ2.md` left to the owner.

**Rule C** (`crates/vft-core/src/score.rs`, `leaf_latent` and `corroborates`): a Suspicious item on a JSON body leaf (`body:json:…`) corroborates only a top on its own leaf. Everything else is unchanged:

- Dangerous leaf items corroborate any top.
- A leaf latent can still be the top.
- Latents on every other field, including a non-JSON `<body>`, corroborate as before DQ2a.
- No construct, threshold or weight changes.

Every number below was copied from a run file under `.superpowers/dq3/` in the worktree (`runs/`, `baseline/`). Each comparison is measured against main `9842319` (`bin-main.exe`). Tuning and the decision used dev rows only (`--manifest …/split/manifest.tsv --side dev`).

## 1. The options measured (dev, 16,939 rows)

| Option | Benign Monitor | TP / FP | Malicious verdicts changed | Malicious scores lowered | Source |
|---|---|---|---|---|---|
| main (`9842319`) | 1,269 | 149 / 100 | — | — | `optB-a.csv` |
| B: all leaves of a JSON body share one origin | 947 | 149 / 100 | 0 | 0 | `optB-ab.txt`, `optB-b.csv` |
| **C: JSON-leaf latents back up only their own leaf** | **793** | 149 / 100 | 0 | 1 (33 → 30, Allow both) | `optC-ab.txt`, `optC-b.csv` |
| C′: latents on any body field back up only their own field | 547 | 149 / 100 | 0 | 26 (each −2 to −4, all Allow both, top `cmd.shell-meta`) | `optC2-ab.txt`, `optC2-b.csv` |

For reference, dev Monitor was 820 before DQ2a and 867 just before the JSON split (`RESULTS-DQ2.md`).

- **Why C.** It removes the noise the split created, and does so completely: Monitor ends below its pre-split level. It costs nothing measurable on dev. It keeps real multi-field corroboration, because Dangerous leaf items still count.
- **Why not B.** B still lets one latent per body push a header top over `monitor_at`.
- **Why not C′.** C′ also changes how form and whole-body latents have scored since before DQ2a. It lowers 26 missed attacks that sit at 30 to 39, moving them further from the threshold that DQ3 recall work has to cross. That is a separate policy question, left open.

## 2. Rule C as built (dev A/B)

`bash eval/ab_dev.sh ruleC "" "" bin-main.exe bin-ruleC.exe` gives `runs/ruleC-ab.txt`:

| | TP | FP | Recall [95 % CI] | FP rate [95 % CI] | Benign Monitor |
|---|---|---|---|---|---|
| main | 149 | 100 | 45.29 % [40.00, 50.69] | 0.602 % [0.495, 0.732] | 1,269 |
| rule C | 149 | 100 | 45.29 % [40.00, 50.69] | 0.602 % [0.495, 0.732] | 793 |

- McNemar on malicious rows: b=0, c=0, p=1. On benign rows: b=0, c=0, p=1.
- No malicious row fell. The only moves are 476 benign rows going from Monitor to Allow.
- The rule-C CSV is byte-identical to the `optC` experiment CSV (`cmp`).

## 3. Serve regression check (full corpus, both source models)

`bash eval/decision_gate.sh diff baseline` (baseline captured from main) gives `runs/serve-diff-ruleC.txt`. It exits 0, with `bans_from_allowed` 0 and `invariant_violations` 0.

| Source model | Shared rows | Changed decisions | Of which | Malicious decisions changed |
|---|---|---|---|---|
| `distinct` | 33,875 | 938 | 938 benign, Monitor → Allow (library and serve verdict) | 0 |
| `pooled:100` | 33,875 | 938 | 938 benign, Monitor → Allow | 0 |

- Full-corpus benign Monitor goes from 2,541 to 1,603. Malicious Monitor stays at 1.
- Five malicious rows score lower: one from 33 to 30, four from 36 to 33. All five are Allow both before and after. No ban changed.
- Held-out rows are part of this regression check, but they played no part in choosing the rule. The choice was made on dev, in section 1.

## 4. Checks

- `cargo test --workspace`: 294 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `ts_bindings`: 1 passed, with no wire-type change.
- `py -I -X utf8 -m unittest discover -s eval -p "test_*.py"`: 45 OK.
- New and changed unit tests in `score.rs`:
  - `latent_json_leaves_do_not_corroborate_each_other`: replaces `body_leaves_are_separate_origins`, whose 27.5 + 2.75 expectation rule C deliberately removes.
  - `a_json_leaf_latent_does_not_back_up_a_header_top`.
  - `rule_c_keeps_other_corroboration`: non-JSON body latents, Dangerous leaf items, own-leaf corroboration, and a leaf latent as top.

## 5. Still open

- C′, which extends the rule to latents on form and whole-body fields (section 1).
- Whether `limit.body-non-utf8` should keep scoring. It is net 0 on dev and costs 22 Monitor rows (`RESULTS-DQ2.md`).
- The deferred DQ2 items listed in `RESULTS-DQ2.md`.
