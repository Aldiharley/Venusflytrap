# DQ2 — Buy Back the False-Positive Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lower the dev false-positive rate from 147 / 16,610 (0.885 %) toward the spec's **≤ ~0.6 % (≤ 99 rows) with dev ΔTP ≥ 0**, net of the justification rows the owner rules on. The engine does this by reading each field under the grammar its consumer uses. This plan covers the measurement tooling, the shell command-position rule, body classification and corroboration de-duplication. Each change is measured as its own dev-only A/B.

**Architecture:** Every detection change is pure `vft-core`. Each changed construct sits behind a registry id: `gate.cmd-position` (new `ConstructKind::Gate`) and `parse.body-binary` / `-json` / `-form` / `-multipart`. `--disable <id>` restores today's behaviour, so one build gives both sides of the A/B in `eval/ab_dev.sh`. Corroboration has no id, so its A/B runs against a pre-change binary saved before the edit. Task 1 adds the measurement: a `top_field` CSV column, the dev A/B helper and a serve `diff` mode. From Task 2 on, `decision_gate.sh diff` replaces the identity gate: it lists every changed serve decision, each one must be attributable to a DQ2 id, and `bans_from_allowed` and `invariant_violations` must stay 0. Held-out rows are scored once, in the results task.

**Tech Stack:** Rust 2021 workspace (vft-core, vft-proxy, vft-cli), serde / serde_json (already a vft-core dependency), proptest 1.5 (`crates/vft-core/tests/fuzz_props.rs`), Python 3.13 standard library (`csv`, `json`, `math`, `argparse`, `unittest`), Git Bash for the eval scripts.

**Spec:** `docs/superpowers/specs/2026-10-28-dq2-fp-budget-design.md` (commit `0cf9a8f`), sections 4.2, 4.3 (the `cmd.chained-command` bullets), 4.4, 5, 6 and 7. Section 4.1 (per-header grammars) is deferred to DQ3 (D15) and nothing in this plan implements it.

## Global Constraints

- `#![forbid(unsafe_code)]` stays in every crate. `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` are green after every task, and so is `cargo test -p vft-core --features ts --test ts_bindings`. `ConstructKind` has no ts-rs derive, so adding `ConstructKind::Gate` needs no re-bless.
- vft-core stays pure: no I/O, clock or locks in `vft-core` library code. Tests may read and write files.
- No new crate or package dependency, no decompressor, and no change to `Cargo.lock`. No package installs of any kind.
- No change to any `scoring.*` threshold or weight, and no change to the dev/held-out manifest (`$VFT_MANIFEST`).
- Everything is tuned on **dev** rows only (`--manifest "$VFT_MANIFEST" --side dev`). Held-out is scored **once**, in the results task, reported separately and never opened for tuning. Clusters are read on dev rows only.
- **One measured step per change, in the spec's §6.2 order:** shell rule (Task 2), then body classification, then corroboration. Each step is `bash eval/ab_dev.sh <step> "<flags A>" "<flags B>" [binA] [binB]`. Steps with a gate or parse id pass `--disable <id>` in flags A. A step with no id first saves the pre-change binary with `cp target/release/venusflytrap.exe "$VFT_RUNS/bin-before-<step>.exe"` and passes it as binA.
- **Stop rule for every measured task:** stop and report NEEDS_CONTEXT with the `$VFT_RUNS/<step>-ab.txt` file if dev ΔFP > 0, or if a malicious row falls that is not on the spec's expected-loss list (§4.3: a JS prototype-pollution payload, an OGNL payload, an MVEL payload, a base64-in-JSON form value). Do not tune ad hoc.
- **Serve regression (from Task 2 on):** `bash eval/decision_gate.sh diff "$VFT_BASELINE"` exits 0 (`bans_from_allowed` 0 and `invariant_violations` 0 in both runs), and every changed row it lists is attributable to a DQ2 id (spec §6.3). Task 1 changes no detection, so for Task 1 `bash eval/decision_gate.sh check "$VFT_BASELINE"` must print `decision gate: identical`.
- Existing eval report JSON fields and CSV columns keep their names and order. The one new CSV column is `top_field`, appended after `shadow`.
- `eval/compare_runs.py` keeps its CLI, output and exit codes: 0 identical decisions, 1 differences, 2 invalid input.
- Python always runs as `py -I -X utf8`. Python tests: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v`.
- Body parsers are total. They never panic, nesting is capped at 32, a parse failure falls back to the single `<body>` field, and field caps never drop text.
- Gate ids cannot be shadowed (the same config check that rejects shadowing a decoder). `ConstructKind::Gate` has no family. A gate only ever removes a `reach`, never adds one.
- Exit targets (spec §6.4; the results task checks them):
  - dev FP ≤ 99 rows with dev ΔTP ≥ 0 net of justification rows;
  - `bench_http` seeds and mutants retained ≥ 96 % and mutant recall ≥ 83.0 %, or a justification row per lost mutant family;
  - library p95 latency < 1 ms on the full corpus;
  - TCP replay `mismatch_block_vs_proxy_allow` 0, with `mismatch_upstream_5xx` and `mismatch_io` at 0.

  If the steps in this plan leave dev FP above 99, the results report the gap. Nothing is tuned to close it.
- Never associate the project with any outside project name, in code, comments, docs or commit messages. Never quote the synthetic `venusflytrap bench` output as a result.
- Commits: one per task, on branch `dq2-fp-budget` in the worktree `M:/Projects/venusflytrap-dq2`. Every commit message ends with the trailer line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No push and no change to `main`.

## Decisions

From the spec (§7) for the parts this plan covers. D1–D3 moved to DQ3 with §4.1. D4–D7, D9 (SQL gate) and D11 (P0) are outside this plan.

| # | Decision | Why |
|---|---|---|
| D8 | `cmd.chained-command` gets a shell command-position rule, not the SQL gate | All 37 dev FPs are `&id=`. A binary followed by `=` is an assignment or URL parameter, not a command |
| D10 | The corroboration key is `(origin field, family)`; derived engines never corroborate their own field | AI and API-safety items are functions of the graph result, not independent evidence |
| D12 | gzip and other compressed bodies get no text field, and there is no decompressor | None is in `Cargo.lock`, and 0 malicious dev bodies are compressed |
| D13 | Declared-binary bodies count as binary only when their bytes look binary | A Content-Type label alone must not hide a payload (parser-discrepancy evasion) |
| D14 | Changed constructs are measured by A/B through gate ids, not by shadow mode | Shadow mode is for new constructs; gates make A/B a config switch on one build |
| D15 | The per-header grammar matrix (§4.1) is deferred to DQ3 | It decides no dev FP (`cmd.shell-meta` d_fp = 0) and would lower the scores of malicious rows just below `monitor_at`. DQ3 needs it as a guard for header-borne constructs |

Taken by this plan:

| # | Decision | Why |
|---|---|---|
| P1 | `top_field` is the `FieldRef::label()` (`loc:name`) of the same contribution that `top` names: the one with the most points, the first on a tie (`top_contribution` in eval.rs). It is empty when nothing scored or that contribution has no field. `clusters.py` groups by `field` and falls back to `top_field` only when `field` is empty. It does not require the column, so DQ1-era CSVs still load. | NoEvidence rows have no `decided_by.field`, so DQ1's miss clusters showed `loc` `-` for every below-threshold miss. The fallback gives them a field without changing any group that already had one. |
| P2 | Row-level listings go in a new `eval/changes.py` with two subcommands, `gate` (serve diff) and `ab` (dev A/B). It loads compare_runs.py by path and reuses its `load`, `metrics`, `mcnemar_lines` and `ATTACK`. `compare_runs.py` does not change. | The diff and the A/B need per-row lists and JSON counters that compare_runs.py does not print. Keeping them in their own file leaves compare_runs.py's exit-code contract alone, and they get unit tests instead of untested inline Python in bash. |
| P3 | In `diff`, a changed decision is a change of `lib_verdict`, `serve_verdict` or `banned`. Rows whose score moved and no decision did are counted on the summary line, not listed. | Corroboration de-duplication moves many scores without moving a decision. Spec §6.3 lists decisions. |
| P4 | `ab` computes ΔTP, ΔFP and McNemar on the rows both runs share, and lists rows that only one run has. It prints the McNemar lines even when nothing moved (`b=0 c=0 p=1`). Recall and FP rate with Wilson intervals come from each run's JSON `library` block. | The host antivirus can delete corpus files between run A and run B (see Host facts). Fixed-shape output makes every `-ab.txt` copyable into the per-step table. |
| P5 | `diff` also compares the shared rows and lists rows that only one run has (`only in old:` / `only in new:`) instead of failing. | Same antivirus reason. An absent row is not a decision change. |
| P6 | Both DQ2 baselines are captured in Task 1, after its edits. They are the serve baseline (`decision_gate.sh capture`) and the dev baseline (`ab_dev.sh baseline "" ""`). Task 1 changes only the CSV output, which compare_runs.py ignores, so detection is still main `a990f26`'s. The serve counts must match DQ1's (TP 288, FP 278, FN 368) and the dev counts the facts (TP 149, FP 147, TN 16,463, FN 180). | Later tasks' `diff` must list `top_field`, so the baseline CSV needs the column too. Matching counts prove that the baseline is main. |
| P7 | `gate.cmd-position` keeps today's token rule (`binary_after_meta`) as the candidate test, and adds the text rule with AND: `cmd.chained-command` is reached only when `binary_after_meta(tokens) && (hits.off(&GATE_CMD_POSITION) \|\| command_in_position(text))`. A rejected candidate falls through to today's `cmd.shell-meta` latent. Sinks learn that a gate is disabled through the new `Hits::off(&self, c: &ConstructInfo) -> bool`. | AND makes "a gate only removes a reach" true by construction, so the step cannot add an FP. The latent keeps the separator visible as evidence. `Hits` already holds the `Disabled` set, so no sink signature changes. |
| P8 | The command-position rule runs on the field text, because the lexer drops whitespace. "Immediately followed" means the next character after the whole word (`[A-Za-z0-9_]+`, compared in lower case). Whitespace before `=`, `(`, `.` or `:` does not reject the word. | All 37 dev FPs have the `=` directly after the name (`&id=`). A shell command word followed by a space and then one of these characters is still in command position. |
| P9 | The spec's extension of the command word to empty quote pairs and backslashes (§4.3) is not in Task 2. It belongs with the SQL gate. | It exists to keep one dev TP that an SQL tautology hit catches today, and the SQL gate is outside this plan. The token candidate could not see such a word anyway, so Task 2 loses nothing by leaving it out. |

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `crates/vft-cli/src/eval.rs` | `top_contribution`; CSV column `top_field` | 1 |
| `eval/clusters.py`, `eval/test_clusters.py`, `eval/fixtures/clusters.csv`, `eval/fixtures/clusters_manifest.tsv` | `top_field` fallback when `field` is empty | 1 |
| `eval/changes.py` (new), `eval/test_changes.py` (new) | `gate` (changed serve decisions, bans and invariant counters) and `ab` (dev deltas, McNemar, Wilson CIs, fallen malicious rows) | 1 |
| `eval/ab_dev.sh` (new) | Dev-half A/B helper: two library runs, `<step>-ab.txt` | 1 (used by every measured task) |
| `eval/decision_gate.sh` | Adds the `diff` mode; header comment reworded; `capture` and `check` unchanged | 1 (used by every later task) |
| `crates/vft-core/src/graph/sinks/mod.rs` | `ConstructKind::Gate`, `Hits::off`, registry entry `gate.cmd-position`, test `only_decoders_lack_a_family` extended (Task 2). Registry entries `parse.body-binary` / `-json` / `-form` / `-multipart`, `limit.body-non-utf8` and `limit.body-unparsed` (body classification) | 2, body classification |
| `crates/vft-core/src/graph/sinks/shell.rs` | `GATE_CMD_POSITION`, `command_in_position`, unit tests | 2 |
| `crates/vft-core/src/config.rs`, `crates/vft-core/src/options.rs` | The shadow check (and its docs) rejects `Decoder \| Gate` ids | 2 |
| `crates/vft-core/src/body.rs` (new), `crates/vft-core/src/lib.rs` | `body_fields(content_type, body)`: binary / JSON / form / multipart / `<body>` classes, caps, body facts | body classification |
| `crates/vft-core/src/request.rs` | A `fields` variant that takes `&Disabled` and returns the body facts to shield.rs | body classification |
| `crates/vft-core/src/shield.rs` | Records `limit.body-non-utf8` / `limit.body-unparsed` from the body facts | body classification |
| `crates/vft-core/src/detect.rs` | `ApiSafetyDetector` matches the last name segment | body classification |
| `crates/vft-core/tests/fuzz_props.rs` | Body parsers are total | body classification |
| `crates/vft-core/src/score.rs` | `(origin, family)` de-duplication; derived items keyed by construct id | corroboration |
| `eval/RESULTS-DQ2.md` (new), `docs/BENCHMARK.md` (DQ2 status line after line 9) | Per-step table, justification table, ablation, held-out once, serve and TCP checks | results |

Task map: Task 1 is the measurement tooling and baselines, and Task 2 the shell command-position rule. The later tasks are body classification, corroboration de-duplication, and the final measurement and results; their parts number them.

### File Structure additions (Tasks 3–5)

| File | Responsibility | Tasks |
|---|---|---|
| `crates/vft-core/src/body.rs` (new) | Body classification: binary, JSON / ndjson leaves, form, multipart, `<body>` fallback, field cap, `BodyFacts` | 3 |
| `crates/vft-core/src/lib.rs` | `pub mod body;` | 3 |
| `crates/vft-core/src/request.rs` | `Request::header`, `Request::fields_with(&Disabled)`; `fields()` delegates | 3 |
| `crates/vft-core/src/graph/sinks/mod.rs` | Registry: `parse.body-binary`, `parse.body-json`, `parse.body-form`, `parse.body-multipart` (Decoder), `limit.body-non-utf8`, `limit.body-unparsed` (Limit) | 3 |
| `crates/vft-core/src/shield.rs` | Calls `fields_with(off)`, records the two body limits; body tests | 3 |
| `crates/vft-core/src/detect.rs` | `ApiSafetyDetector` last-segment rule for body fields | 3 |
| `crates/vft-core/tests/fuzz_props.rs` | `body_fields` never panics | 3 |
| `crates/vft-core/tests/fixtures/body_cases.txt` (new, generated) | One detection case extracted from the committed spec, `accept<TAB>text` | 3 |
| `crates/vft-core/src/score.rs` | `(origin field, family)` corroboration key, derived items, `origin()` | 4 |
| `crates/vft-core/src/judgment.rs` | `Family` derives `Hash` | 4 |
| `eval/RESULTS-DQ2.md` (new), `docs/BENCHMARK.md` | Measured results, one status line after line 9 | 5 |

Attack strings never appear in this plan or in test source. Tests that need a detection case read it from a fixture under `crates/vft-core/tests/fixtures/`, generated by a step that extracts the string from a committed document. If the host antivirus deletes a fixture file, re-run that step's extraction command; do not retype the string.

---

## Environment for every task

```bash
# Git Bash, from the worktree root M:/Projects/venusflytrap-dq2.
: "${VFT_CORPUS:?set VFT_CORPUS to the corpus testcases directory (ask the owner)}"
export VFT_BASELINE="$(git rev-parse --show-toplevel)/.superpowers/dq2/baseline"   # git-ignored
export VFT_RUNS="$(git rev-parse --show-toplevel)/.superpowers/dq2/runs"           # git-ignored
export VFT_MANIFEST="M:/Projects/venusflytrap-recall-runs/split/manifest.tsv"      # the existing dev / held-out split
B=./target/release/venusflytrap
mkdir -p "$VFT_BASELINE" "$VFT_RUNS"
```

The corpus path comes only from `VFT_CORPUS`, the same directory DQ1 used. If it is unset or the directory does not exist, stop and ask the owner; do not substitute another corpus. If `VFT_MANIFEST` does not exist, stop and ask the owner; do not create a new split (the manifest does not change). The `bench_http` seeds and mutants for the results task are in `M:/Projects/venusflytrap-recall-runs/m0/`.

Reference numbers at main `a990f26`: dev library, 16,939 samples, TP 149, FP 147, TN 16,463, FN 180 (FP rate 0.885 %); serve on the full corpus (distinct and pooled:100), TP 288, FP 278, FN 368. Scoring defaults are `weight_api` 0.6 and `monitor_at` 40. A Suspicious 0.6 limit adds about 20 points, a latent graph hit scores 27.5 and a reachable one 95.

### Host facts

- The host antivirus deletes some corpus `.black` files, at any time. A deleted file is not in the next run's CSV, so `check` can exit 2 with `compare_runs: row sets differ: N only in a, 0 only in b`. That is not a decision change when every row only in one run is a file that is now absent (or listed as `unreadable` in that run's JSON `failure_examples`). Check it, compare on the intersection, and report it:

```bash
for tag in distinct pooled100; do
  py -I -X utf8 eval/compare_runs.py --intersect "$VFT_BASELINE/serve-$tag.csv" "$VFT_BASELINE/now-serve-$tag.csv" > "$VFT_RUNS/intersect-$tag.txt"
  echo "$tag: compare exit $?"
  sed -n 's/^only in [ab]: //p' "$VFT_RUNS/intersect-$tag.txt" | while read -r rel; do
    if [ -e "$VFT_CORPUS/$rel" ] && ! grep -qF "$rel: unreadable" "$VFT_BASELINE/serve-$tag.json" "$VFT_BASELINE/now-serve-$tag.json"; then
      echo "PRESENT: $rel"
    fi
  done
done
```

  Accept `check` only when both compares exit 0 and no `PRESENT:` line is printed, and put the absent rel paths in the task report (the results task copies them into the results). Any `PRESENT:` line, or a compare exit 1, is a real difference: stop and report it. In Task 1's self-check, re-capture the baseline instead.
- `decision_gate.sh diff` and `ab_dev.sh` already compare on the intersection. They print `only in old:` / `only in new:` (diff) or `only in a:` / `only in b:` (ab) lines. Run the same `PRESENT:` check on those rel paths (`sed -n 's/^only in [a-z]*: //p'` on the saved output) and report the absent ones.

---

### Task 1: Measurement tooling and the DQ2 baselines

This task changes no detection. It adds the CSV column `top_field`, the dev A/B helper `eval/ab_dev.sh` and the serve mode `decision_gate.sh diff` (with its helper `eval/changes.py`). It then captures the two baselines that every later task compares against.

**Files:**
- Modify: `crates/vft-cli/src/eval.rs`: `top_construct` becomes `top_contribution` (around line 405); CSV header (around line 430); CSV row writer (around lines 524–544); tests `csv_names_the_deciding_field_and_top_construct` (around line 1150) and `promotion_counts_shadow_hits_by_class_and_the_csv_lists_them` (around line 1170); one new test
- Modify: `eval/clusters.py` (module docstring, `key`)
- Modify: `eval/fixtures/clusters.csv` (whole file below), `eval/fixtures/clusters_manifest.tsv` (one line appended)
- Test: `eval/test_clusters.py` (two tests edited, one added)
- Create: `eval/changes.py`, `eval/test_changes.py`
- Create: `eval/ab_dev.sh`
- Modify: `eval/decision_gate.sh` (whole file below)

**Interfaces:**
- Consumes: `eval/compare_runs.py` as it is: `load(path) -> (kind, {key: row})`, `metrics(kind, rows) -> dict` (`tp`, `fp`, `tn`, `fn`, `recall`, `fp_rate`), `mcnemar_lines(ra, rb) -> list[str]` (the two dicts must have the same keys), `ATTACK = ("Block", "Challenge")`. The eval JSON report fields `library.{tp,fp,tn,fn,recall,fp_rate,recall_ci95,fp_rate_ci95}`, `serve.bans_from_allowed` (`serve` is `null` in library mode) and `invariant_violations`. `venusflytrap eval --mode library|serve --manifest M --side dev --disable <id> --out <csv>`, which writes JSON to stdout. (`--mode` defaults to `serve`, so library runs must pass it.)
- Produces:
  - The eval CSV header `rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow,top_field`, 12 columns, with `top_field` at index 11. Its value is the `loc:name` of the contribution that `top` names, run through `csv_cell`, and empty when nothing scored or that contribution has no field.
  - `fn top_contribution(cs: &[vft_core::Contribution]) -> Option<&vft_core::Contribution>` (private to eval.rs).
  - `clusters.py`: `key(row)` uses `row["field"]`, or `row.get("top_field")` when `field` is empty. `top_field` is not a required column.
  - `eval/changes.py`: `load_rows(path) -> dict[str, dict]`, `load_report(path) -> dict`, `split(ra, rb) -> (shared, only_a, only_b)` (sorted rel lists), `changed(ra, rb) -> list[str]`, `score_only(ra, rb) -> int`, `fallen(ra, rb) -> list[str]`, `counters(report) -> (int, int)` (`bans_from_allowed`, `invariant_violations`), `gate_lines(tag, ra, rb, report) -> (list[str], bool)` and `ab_lines(ra, rb, rep_a, rep_b) -> list[str]`.
  - The `changes.py` CLI: `py -I -X utf8 eval/changes.py gate [--tag T] <old.csv> <new.csv> <new.json>` exits 0 when both counters are 0 and 1 otherwise. `py -I -X utf8 eval/changes.py ab <a.csv> <a.json> <b.csv> <b.json>` exits 0. Both exit 2 on invalid input.
  - `bash eval/ab_dev.sh <step> "<flags A>" "<flags B>" [binA] [binB]`. binA and binB default to `./target/release/venusflytrap`. It writes `$VFT_RUNS/<step>-a.csv`, `<step>-a.json`, `<step>-b.csv`, `<step>-b.json` and `<step>-ab.txt`, prints the `-ab.txt` and exits 0. It exits 2 on invalid input or a failed run. It does not build.
  - `-ab.txt` lines, in order:
    - `step:`, `a:` and `b:` (the binary and flags of each run);
    - `ab: <n> shared rows, <x> only in a, <y> only in b`;
    - `delta: tp=<+d> fp=<+d>`;
    - the McNemar legend and `mcnemar lib_verdict malicious|benign: b=<int> c=<int> p=<.4g>`;
    - `a: tp=… fp=… tn=… fn=… recall=<.2%> [<lo>, <hi>] fp_rate=<.3%> [<lo>, <hi>]`, and the same `b:` line;
    - `fallen: <k> malicious rows from Challenge/Block to Allow/Monitor`, then a header `rel	a	b	top_a	top_b	cause_b` and one tab-separated row per fallen rel;
    - `only in a: <rel>` and `only in b: <rel>`;
    - `== clusters a` and `== clusters b`, each followed by `clusters.py --top 15` output.
  - `bash eval/decision_gate.sh diff <dir>` re-runs serve (distinct and pooled:100) into `<dir>/now-serve-*` and prints, per run:
    - `diff <tag>: <n> shared rows, <k> changed decisions, <s> score-only changes, <x> only in old, <y> only in new`;
    - a header `rel	label	lib_verdict	serve_verdict	banned	cause	field	top	top_field`, then one tab-separated row per changed decision (`old->new` where a value moved; `cause`, `field`, `top` and `top_field` are the new run's);
    - `only in old: <rel>` and `only in new: <rel>`;
    - `bans_from_allowed=<n>` and `invariant_violations=<n>`.

    It ends with `decision gate diff: bans_from_allowed 0, invariant_violations 0` (exit 0) or `decision gate diff: FAIL (bans_from_allowed or invariant_violations is not 0)` (exit 1), and exits 2 on invalid input. `capture` and `check` behave exactly as before.
  - The baselines: `$VFT_BASELINE/serve-distinct.{csv,json}`, `$VFT_BASELINE/serve-pooled100.{csv,json}` and `$VFT_RUNS/baseline-{a,b}.{csv,json}` plus `$VFT_RUNS/baseline-ab.txt`.

- [ ] **Step 1: Confirm the tree is main's code**

Run: `git log --oneline a990f26..HEAD` → Expected: only docs commits on this branch, `docs: DQ2 false-positive-budget design` and the plan commit.
Run: `git diff --quiet a990f26 HEAD -- crates config eval ui Cargo.toml Cargo.lock; echo $?` → Expected: `0`. Anything else: stop and report, because the baselines would not be main.

- [ ] **Step 2: Write the failing Rust tests** (`crates/vft-cli/src/eval.rs`, `mod tests`)

In `csv_names_the_deciding_field_and_top_construct`, replace the line

```rust
        assert!(header.starts_with("rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top"), "{header}");
```

with

```rust
        assert_eq!(header, "rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow,top_field");
```

In the same test, directly after the line `assert!(!a[9].is_empty() && a[6].split('|').any(|c| c == a[9]), "top {} must be one of {}", a[9], a[6]);`, add

```rust
        assert_eq!((a.len(), a[11]), (12, "query:q"), "top_field names the top contribution's field: {a:?}");
```

and directly after the line `assert_eq!((b[0], b[2], b[8]), ("b.white", "Allow", ""), "{b:?}");`, add

```rust
        assert_eq!(b.len(), 12, "{b:?}");
        assert_eq!(b[9].is_empty(), b[11].is_empty(), "top_field is empty exactly when top is: {b:?}");
```

In `promotion_counts_shadow_hits_by_class_and_the_csv_lists_them`, replace

```rust
        assert_eq!(lines.next(), Some("rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow"));
```

with

```rust
        assert_eq!(lines.next(), Some("rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow,top_field"));
```

Add this test after `csv_cells_are_quoted_only_when_needed`:

```rust
    #[test]
    fn top_contribution_picks_the_most_points_and_the_first_on_a_tie() {
        let mk = |id: &str, name: &str, points: f32| vft_core::Contribution {
            engine: "test",
            field: Some(vft_core::FieldRef { loc: vft_core::Location::Query, name: name.into() }),
            construct: Some(id.into()),
            family: None,
            value: vft_core::FourValued::Suspicious,
            weight: 1.0,
            points,
            shadow: false,
        };
        assert!(top_contribution(&[]).is_none());
        assert!(top_contribution(&[mk("test.zero", "a", 0.0)]).is_none(), "a contribution with no points is never top");
        let cs = [mk("test.low", "a", 5.0), mk("test.high", "b", 20.0), mk("test.tie", "c", 20.0)];
        let top = top_contribution(&cs).unwrap();
        assert_eq!(top.construct.as_deref(), Some("test.high"));
        assert_eq!(top.field.as_ref().map(|f| f.label()).as_deref(), Some("query:b"));
    }
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p vft-cli top_contribution`
Expected: compile error `cannot find function `top_contribution` in this scope`.

- [ ] **Step 4: Implement `top_contribution` and the column**

Replace the whole `top_construct` function (doc comment included) with:

```rust
/// The contribution that added the most points (the first on a tie), as the
/// shield's `top_contribution` picks it; `None` when no contribution has
/// points. The CSV's `top` is its construct and `top_field` its field.
fn top_contribution(cs: &[vft_core::Contribution]) -> Option<&vft_core::Contribution> {
    let mut best: Option<&vft_core::Contribution> = None;
    for c in cs {
        if best.map_or(c.points > 0.0, |b| c.points > b.points) {
            best = Some(c);
        }
    }
    best
}
```

In `run`, change the header line to:

```rust
            writeln!(f, "rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow,top_field")?;
```

Replace the whole `if let Some(f) = csv_out.as_mut() { … }` block at the end of the per-sample loop with:

```rust
        if let Some(f) = csv_out.as_mut() {
            let constructs: Vec<&str> = lj.contributions.iter().filter(|c| !c.shadow).filter_map(|c| c.construct.as_deref()).collect();
            let field = lj.decided_by.field.as_ref().map(|r| r.label()).unwrap_or_default();
            let shadow: Vec<&str> = shadow_hits.iter().copied().collect();
            let top = top_contribution(&lj.contributions);
            let top_field = top.and_then(|c| c.field.as_ref()).map(|r| r.label()).unwrap_or_default();
            writeln!(
                f,
                "{},{},{:?},{},{},{},{},{:?}:{},{},{},{},{}",
                s.rel,
                s.label,
                lj.verdict,
                serve_verdict,
                lj.score,
                banned,
                constructs.join("|"),
                lj.decided_by.kind,
                lj.decided_by.option_key,
                csv_cell(&field),
                top.and_then(|c| c.construct.as_deref()).unwrap_or(""),
                shadow.join("|"),
                csv_cell(&top_field)
            )?;
        }
```

Run: `grep -n "top_construct" crates/vft-cli/src/eval.rs` → Expected: one line only, the test name `csv_names_the_deciding_field_and_top_construct`.

- [ ] **Step 5: Run the Rust tests to verify they pass**

Run: `cargo test -p vft-cli` → Expected: PASS, including `top_contribution_picks_the_most_points_and_the_first_on_a_tie`, `csv_names_the_deciding_field_and_top_construct` and `promotion_counts_shadow_hits_by_class_and_the_csv_lists_them`.

- [ ] **Step 6: Update the clusters fixture and write the failing Python tests**

Replace `eval/fixtures/clusters.csv` with the full file below. Every row gains the `shadow` and `top_field` columns. The new row `d/m4.black` is a below-threshold miss with no `field` but with a `top_field`. Its construct id `test.neutral` and header name `X-Sample` are neutral test values.

```csv
rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow,top_field
d/fp1.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:ID,sqli.union-select,,query:ID
d/fp2.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:id,sqli.union-select,,query:id
d/fp3.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:Id,sqli.union-select,,query:Id
d/fp4.white,0,Challenge,,75,false,cmd.shell-meta,Detection:scoring.challenge_at,"query:a,b",cmd.shell-meta,,"query:a,b"
d/tn1.white,0,Allow,,0,false,,NoEvidence:scoring.monitor_at,,,,
d/m1.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,,,
d/m2.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,,,
d/m3.black,1,Monitor,,45,false,xss.html-tag,Detection:scoring.monitor_at,cookie:session,xss.html-tag,,cookie:session
d/m4.black,1,Allow,,20,false,test.neutral,NoEvidence:scoring.monitor_at,,test.neutral,,header:X-Sample
d/tp1.black,1,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:id,sqli.union-select,,query:id
h/fp9.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:id,sqli.union-select,,query:id
h/m9.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,,,
```

Append the new row to the manifest:

Run: `printf 'd/m4.black\t1\t12\tdev\n' >> eval/fixtures/clusters_manifest.tsv`
Run: `tail -n 2 eval/fixtures/clusters_manifest.tsv | cat -A` → Expected: `h/m9.black^I1^I11^Iheldout^M$` (or the same without `^M`), then `d/m4.black^I1^I12^Idev$`.

In `eval/test_clusters.py`, replace the whole `test_misses_are_allow_or_monitor_on_malicious_rows` with:

```python
    def test_misses_are_allow_or_monitor_on_malicious_rows(self):
        total, n_groups, ranked = cl.clusters(dev_rows(), "1", cl.MISS, 20)
        self.assertEqual((total, n_groups), (4, 3))
        self.assertEqual(ranked[0], (("NoEvidence:scoring.monitor_at", "", "", ""), 2, ["d/m1.black", "d/m2.black"]))
        self.assertEqual(ranked[1][0], ("Detection:scoring.monitor_at", "xss.html-tag", "cookie", "session"))
        self.assertEqual(ranked[2], (("NoEvidence:scoring.monitor_at", "test.neutral", "header", "x-sample"), 1, ["d/m4.black"]))
```

In `test_cli_prints_both_tables`, replace the line

```python
        self.assertIn("misses (label 1, Allow/Monitor): 3 rows in 2 groups\n", out)
```

with

```python
        self.assertIn("misses (label 1, Allow/Monitor): 4 rows in 3 groups\n", out)
        self.assertIn("1\tNoEvidence:scoring.monitor_at\ttest.neutral\theader\tx-sample\td/m4.black\n", out)
```

Add this test after `test_top_limits_the_groups_shown_not_counted`:

```python
    def test_key_uses_top_field_only_when_field_is_empty(self):
        row = {"cause": "c", "top": "t", "field": "query:Name", "top_field": "header:Other"}
        self.assertEqual(cl.key(row), ("c", "t", "query", "name"))
        row["field"] = ""
        self.assertEqual(cl.key(row), ("c", "t", "header", "other"))
        del row["top_field"]
        self.assertEqual(cl.key(row), ("c", "t", "", ""), "a DQ1-era CSV has no top_field column")
```

Create `eval/test_changes.py`:

```python
"""Tests for eval/changes.py. Run: py -I -X utf8 -m unittest discover -s eval -p "test_*.py" """
import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("changes", HERE / "changes.py")
ch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ch)

FIELDS = ["rel", "label", "lib_verdict", "serve_verdict", "score", "banned", "constructs", "cause",
          "field", "top", "shadow", "top_field"]


def row(rel, label, lib, serve="", score="0", banned="false", top="",
        cause="NoEvidence:scoring.monitor_at", field="", top_field=""):
    return {"rel": rel, "label": label, "lib_verdict": lib, "serve_verdict": serve, "score": score,
            "banned": banned, "constructs": top, "cause": cause, "field": field, "top": top,
            "shadow": "", "top_field": top_field}


def table(*rows):
    return {r["rel"]: r for r in rows}


def report(bans=0, inv=0, serve=True):
    lib = {"tp": 1, "fp": 0, "tn": 1, "fn": 1, "recall": 0.5, "fp_rate": 0.0,
           "recall_ci95": [0.25, 0.75], "fp_rate_ci95": [0.0, 0.125]}
    return {"library": lib, "serve": {"metrics": lib, "bans_from_allowed": bans} if serve else None,
            "invariant_violations": inv}


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows.values())


def write_json(path, obj):
    Path(path).write_text(json.dumps(obj), encoding="utf-8")


def run_main(args):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            ch.main(args)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


OLD = table(
    row("a.white", "0", "Block", serve="Block", score="95", top="test.alpha",
        cause="Detection:scoring.block_at", field="query:q", top_field="query:q"),
    row("b.white", "0", "Allow", serve="Allow", score="10"),
    row("c.black", "1", "Block", serve="Block", score="95", top="test.alpha",
        cause="Detection:scoring.block_at", field="query:q", top_field="query:q"),
)
NEW = table(
    row("a.white", "0", "Allow", serve="Allow", score="20", top="test.alpha", top_field="query:q"),
    row("b.white", "0", "Allow", serve="Allow", score="12"),
    dict(OLD["c.black"]),
)


class GateTests(unittest.TestCase):
    def test_changed_lists_decision_moves_and_score_only_counts_the_rest(self):
        self.assertEqual(ch.changed(OLD, NEW), ["a.white"])
        self.assertEqual(ch.score_only(OLD, NEW), 1)

    def test_a_ban_change_is_a_decision_change(self):
        new = table(*[dict(r) for r in OLD.values()])
        new["c.black"]["banned"] = "true"
        self.assertEqual(ch.changed(OLD, new), ["c.black"])

    def test_gate_lines_print_the_new_cause_field_top_and_the_counters(self):
        lines, ok = ch.gate_lines("distinct", OLD, NEW, report())
        self.assertTrue(ok)
        self.assertEqual(lines[0], "diff distinct: 3 shared rows, 1 changed decisions, 1 score-only changes, "
                                   "0 only in old, 0 only in new")
        self.assertEqual(lines[1], "rel\tlabel\tlib_verdict\tserve_verdict\tbanned\tcause\tfield\ttop\ttop_field")
        self.assertEqual(lines[2], "a.white\t0\tBlock->Allow\tBlock->Allow\tfalse\t"
                                   "NoEvidence:scoring.monitor_at\t-\ttest.alpha\tquery:q")
        self.assertEqual(lines[-2:], ["bans_from_allowed=0", "invariant_violations=0"])

    def test_gate_fails_on_a_ban_from_allowed_or_an_invariant_violation(self):
        self.assertFalse(ch.gate_lines("d", OLD, OLD, report(bans=1))[1])
        self.assertFalse(ch.gate_lines("d", OLD, OLD, report(inv=1))[1])
        self.assertTrue(ch.gate_lines("d", OLD, OLD, report())[1])

    def test_rows_only_in_one_run_are_listed_not_compared(self):
        new = table(dict(OLD["a.white"]), dict(OLD["b.white"]), row("z.white", "0", "Allow"))
        lines, ok = ch.gate_lines("d", OLD, new, report())
        self.assertTrue(ok)
        self.assertTrue(lines[0].startswith("diff d: 2 shared rows, 0 changed decisions"), lines[0])
        self.assertIn("only in old: c.black", lines)
        self.assertIn("only in new: z.white", lines)

    def test_a_library_report_has_no_bans(self):
        self.assertEqual(ch.counters(report(serve=False, inv=2)), (0, 2))
        with self.assertRaises(ValueError):
            ch.counters({"library": {}})

    def test_cli_gate_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            old, new, rep = (str(Path(tmp, n)) for n in ("old.csv", "new.csv", "new.json"))
            write_csv(old, OLD)
            write_csv(new, NEW)
            write_json(rep, report())
            code, out, _ = run_main(["gate", "--tag", "distinct", old, new, rep])
            self.assertEqual(code, 0)
            self.assertIn("diff distinct: 3 shared rows, 1 changed decisions", out)
            write_json(rep, report(bans=1))
            self.assertEqual(run_main(["gate", old, new, rep])[0], 1)
            write_json(rep, {"library": {}})
            code, _, err = run_main(["gate", old, new, rep])
            self.assertEqual(code, 2)
            self.assertIn("invariant_violations", err)
            bench = str(Path(tmp, "bench.csv"))
            Path(bench).write_text("label,pred,score\n1,1,0.9\n", encoding="utf-8")
            self.assertEqual(run_main(["gate", bench, new, rep])[0], 2)


A = table(
    row("c.black", "1", "Block", score="95", top="test.alpha", cause="Detection:scoring.block_at"),
    row("d.black", "1", "Challenge", score="75", top="test.beta", cause="Detection:scoring.challenge_at"),
    row("e.black", "1", "Allow"),
    row("f.white", "0", "Block", score="95", top="test.alpha", cause="Detection:scoring.block_at"),
)
B = table(
    row("c.black", "1", "Monitor", score="45"),
    row("d.black", "1", "Block", score="95", top="test.beta", cause="Detection:scoring.block_at"),
    row("f.white", "0", "Allow"),
    row("g.black", "1", "Allow"),
)


class AbTests(unittest.TestCase):
    def test_fallen_is_malicious_rows_from_challenge_or_block_to_allow_or_monitor(self):
        self.assertEqual(ch.fallen(A, B), ["c.black"])

    def test_identical_runs_report_zero_deltas_and_no_fallen_rows(self):
        lines = ch.ab_lines(A, A, report(serve=False), report(serve=False))
        self.assertEqual(lines[0], "ab: 4 shared rows, 0 only in a, 0 only in b")
        self.assertIn("delta: tp=+0 fp=+0", lines)
        self.assertIn("mcnemar lib_verdict malicious: b=0 c=0 p=1", lines)
        self.assertIn("mcnemar lib_verdict benign: b=0 c=0 p=1", lines)
        self.assertIn("a: tp=1 fp=0 tn=1 fn=1 recall=50.00% [25.00%, 75.00%] "
                      "fp_rate=0.000% [0.000%, 12.500%]", lines)
        self.assertIn("fallen: 0 malicious rows from Challenge/Block to Allow/Monitor", lines)
        self.assertNotIn("rel\ta\tb\ttop_a\ttop_b\tcause_b", lines)

    def test_ab_lines_compare_shared_rows_and_list_the_fallen_ones(self):
        lines = ch.ab_lines(A, B, report(serve=False), report(serve=False))
        self.assertEqual(lines[0], "ab: 3 shared rows, 1 only in a, 1 only in b")
        self.assertIn("delta: tp=-1 fp=-1", lines)
        self.assertIn("mcnemar lib_verdict malicious: b=1 c=0 p=1", lines)
        self.assertIn("fallen: 1 malicious rows from Challenge/Block to Allow/Monitor", lines)
        self.assertIn("c.black\tBlock\tMonitor\ttest.alpha\t-\tNoEvidence:scoring.monitor_at", lines)
        self.assertEqual(lines[-2:], ["only in a: e.black", "only in b: g.black"])

    def test_cli_ab(self):
        with tempfile.TemporaryDirectory() as tmp:
            a_csv, a_json, b_csv, b_json = (str(Path(tmp, n)) for n in ("a.csv", "a.json", "b.csv", "b.json"))
            write_csv(a_csv, A)
            write_csv(b_csv, A)
            write_json(a_json, report(serve=False))
            write_json(b_json, report(serve=False))
            code, out, _ = run_main(["ab", a_csv, a_json, b_csv, b_json])
            self.assertEqual(code, 0)
            self.assertIn("delta: tp=+0 fp=+0\n", out)
            Path(b_json).write_text("not json", encoding="utf-8")
            self.assertEqual(run_main(["ab", a_csv, a_json, b_csv, b_json])[0], 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 7: Run the Python tests to verify they fail**

Run: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v`
Expected: FAIL. `test_misses_are_allow_or_monitor_on_malicious_rows`, `test_cli_prints_both_tables` and `test_key_uses_top_field_only_when_field_is_empty` fail, because `d/m4.black` keys to an empty `loc`. `test_changes` errors on import with `FileNotFoundError` for `changes.py`. The other existing tests pass.

- [ ] **Step 8: Implement the clusters fallback and `eval/changes.py`**

In `eval/clusters.py`, replace the first paragraph of the module docstring with:

```python
"""Rank false positives and misses in an eval CSV by shared cause.

Rows of `venusflytrap eval --out` are grouped by (cause, top construct, field
location, field name in lower case). The field is the deciding `field`, or the
top contribution's `top_field` when `field` is empty (a row below every
threshold has no deciding field); CSVs without `top_field` still load. False
positives are benign rows (label 0) whose library verdict is Challenge or
Block; misses are malicious rows (label 1) whose library verdict is Allow or
Monitor. Only the CSV (and the split manifest) is read, never a corpus file.
With --manifest and --side, rows of the other half are dropped before anything
is counted, so held-out rows stay unopened during development.
```

(The `Usage:` and `Exit status:` lines below it stay.) Replace `key` with:

```python
def key(row):
    field = row["field"] or row.get("top_field") or ""
    loc, _, name = field.partition(":")
    return (row["cause"], row["top"], loc, name.lower())
```

Create `eval/changes.py`:

```python
"""Row-level changes between two eval runs: DQ2's serve diff and dev A/B.

gate: every row whose lib_verdict, serve_verdict or banned changed between a
baseline serve run and a new one, with the new run's cause, field, top and
top_field; the number of rows whose score alone moved; then the new run's
bans_from_allowed and invariant_violations.

ab: on the rows both runs contain, delta TP / FP and the exact McNemar test per
class (eval/compare_runs.py); recall and FP rate with the Wilson 95 % intervals
of each run's JSON report; and every malicious row whose library verdict fell
from Challenge/Block to Allow/Monitor.

Only rel paths, verdicts, construct ids, causes and field names are printed,
never a request. Rows only in one run (a corpus file deleted between the runs)
are listed, never compared.

Usage: py -I -X utf8 eval/changes.py gate [--tag T] <old.csv> <new.csv> <new.json>
       py -I -X utf8 eval/changes.py ab <a.csv> <a.json> <b.csv> <b.json>
Exit status: gate 0 when bans_from_allowed and invariant_violations are 0, 1
otherwise; ab 0; both 2 on invalid input.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location("compare_runs", Path(__file__).with_name("compare_runs.py"))
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

DECISION = ("lib_verdict", "serve_verdict", "banned")
MISS = ("Allow", "Monitor")


def load_rows(path):
    """An eval CSV as {rel: row}. Raises ValueError for a bench CSV or bad header."""
    kind, rows = cr.load(path)
    if kind != "eval":
        raise ValueError(f"{path}: needs an eval CSV (keyed by rel)")
    return rows


def load_report(path):
    """The JSON report of `venusflytrap eval`. Raises ValueError when it is not JSON."""
    with open(path, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}: not a JSON report ({e})") from e


def split(ra, rb):
    """(rels in both runs, rels only in a, rels only in b), each sorted."""
    return sorted(ra.keys() & rb.keys()), sorted(ra.keys() - rb.keys()), sorted(rb.keys() - ra.keys())


def changed(ra, rb):
    """Shared rels whose lib_verdict, serve_verdict or banned differ, sorted."""
    return [k for k in split(ra, rb)[0] if any(ra[k][c] != rb[k][c] for c in DECISION)]


def score_only(ra, rb):
    """Shared rows whose score moved while every decision column stayed."""
    return sum(1 for k in split(ra, rb)[0]
               if ra[k]["score"] != rb[k]["score"] and all(ra[k][c] == rb[k][c] for c in DECISION))


def fallen(ra, rb):
    """Shared malicious rels whose lib_verdict went from Challenge/Block to Allow/Monitor."""
    return [k for k in split(ra, rb)[0]
            if ra[k]["label"] == "1" and ra[k]["lib_verdict"] in cr.ATTACK and rb[k]["lib_verdict"] in MISS]


def counters(report):
    """(bans_from_allowed, invariant_violations). A library report has no serve block: 0 bans."""
    if "invariant_violations" not in report:
        raise ValueError("JSON report has no invariant_violations")
    serve = report.get("serve") or {}
    return int(serve.get("bans_from_allowed", 0)), int(report["invariant_violations"])


def cell(s, limit=60):
    s = (s or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")
    s = s if len(s) <= limit else s[:limit] + "..."
    return s or "-"


def arrow(x, y):
    x, y = x or "-", y or "-"
    return x if x == y else f"{x}->{y}"


def gate_lines(tag, ra, rb, report):
    """(lines, ok): the changed decisions of run b against run a; ok when both counters are 0."""
    shared, only_a, only_b = split(ra, rb)
    rels = changed(ra, rb)
    out = [f"diff {tag}: {len(shared)} shared rows, {len(rels)} changed decisions, "
           f"{score_only(ra, rb)} score-only changes, {len(only_a)} only in old, {len(only_b)} only in new"]
    if rels:
        out.append("rel\tlabel\tlib_verdict\tserve_verdict\tbanned\tcause\tfield\ttop\ttop_field")
    for k in rels:
        x, y = ra[k], rb[k]
        out.append("\t".join([k, y["label"], arrow(x["lib_verdict"], y["lib_verdict"]),
                              arrow(x["serve_verdict"], y["serve_verdict"]), arrow(x["banned"], y["banned"]),
                              cell(y.get("cause")), cell(y.get("field")), cell(y.get("top")),
                              cell(y.get("top_field"))]))
    out += [f"only in old: {k}" for k in only_a] + [f"only in new: {k}" for k in only_b]
    bans, inv = counters(report)
    out += [f"bans_from_allowed={bans}", f"invariant_violations={inv}"]
    return out, bans == 0 and inv == 0


def rate_line(name, report):
    m = report["library"]
    (rlo, rhi), (flo, fhi) = m["recall_ci95"], m["fp_rate_ci95"]
    return (f"{name}: tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} "
            f"recall={m['recall']:.2%} [{rlo:.2%}, {rhi:.2%}] fp_rate={m['fp_rate']:.3%} [{flo:.3%}, {fhi:.3%}]")


def ab_lines(ra, rb, rep_a, rep_b):
    """The dev A/B report of run b against run a (see the module docstring)."""
    shared, only_a, only_b = split(ra, rb)
    if not shared:
        raise ValueError("the runs share no rows")
    a, b = {k: ra[k] for k in shared}, {k: rb[k] for k in shared}
    ma, mb = cr.metrics("eval", a), cr.metrics("eval", b)
    out = [f"ab: {len(shared)} shared rows, {len(only_a)} only in a, {len(only_b)} only in b",
           f"delta: tp={mb['tp'] - ma['tp']:+d} fp={mb['fp'] - ma['fp']:+d}"]
    out += cr.mcnemar_lines(a, b)
    out += [rate_line("a", rep_a), rate_line("b", rep_b)]
    rels = fallen(a, b)
    out.append(f"fallen: {len(rels)} malicious rows from Challenge/Block to Allow/Monitor")
    if rels:
        out.append("rel\ta\tb\ttop_a\ttop_b\tcause_b")
    for k in rels:
        out.append("\t".join([k, a[k]["lib_verdict"], b[k]["lib_verdict"], cell(a[k].get("top")),
                              cell(b[k].get("top")), cell(b[k].get("cause"))]))
    out += [f"only in a: {k}" for k in only_a] + [f"only in b: {k}" for k in only_b]
    return out


def main(argv):
    p = argparse.ArgumentParser(prog="changes.py", description="Row-level changes between two eval runs.")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate", help="changed serve decisions against a baseline")
    g.add_argument("--tag", default="serve")
    for name in ("old_csv", "new_csv", "new_json"):
        g.add_argument(name)
    ab = sub.add_parser("ab", help="dev A/B report")
    for name in ("a_csv", "a_json", "b_csv", "b_json"):
        ab.add_argument(name)
    a = p.parse_args(argv)
    try:
        if a.cmd == "gate":
            lines, ok = gate_lines(a.tag, load_rows(a.old_csv), load_rows(a.new_csv), load_report(a.new_json))
        else:
            lines, ok = ab_lines(load_rows(a.a_csv), load_rows(a.b_csv),
                                 load_report(a.a_json), load_report(a.b_json)), True
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"changes: {e}", file=sys.stderr)
        sys.exit(2)
    for line in lines:
        print(line)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 9: Run the Python tests to verify they pass**

Run: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v`
Expected: every test OK, including the new tests in `test_changes.py` and `test_clusters.py`, and every `test_compare_runs.py` test (compare_runs.py is unchanged).

- [ ] **Step 10: Write `eval/ab_dev.sh`**

```bash
#!/usr/bin/env bash
# Dev-half A/B for one DQ2 step: library mode on the dev rows of the split, run twice.
#   eval/ab_dev.sh <step> "<flags A>" "<flags B>" [binA] [binB]
# binA and binB default to ./target/release/venusflytrap; this script does not
# build. Each flags string is split into words and passed to `venusflytrap eval`
# (for example "--disable gate.cmd-position"); "" passes nothing.
# Writes $VFT_RUNS/<step>-a.{csv,json}, $VFT_RUNS/<step>-b.{csv,json} and
# $VFT_RUNS/<step>-ab.txt (eval/changes.py ab, then eval/clusters.py --top 15
# for each run), and prints the -ab.txt.
# Needs VFT_CORPUS, VFT_MANIFEST and VFT_RUNS. Exit status: 0 written, 2 invalid
# input or a failed run.
set -euo pipefail
: "${VFT_CORPUS:?set VFT_CORPUS to the corpus testcases directory}"
: "${VFT_MANIFEST:?set VFT_MANIFEST to the split manifest}"
: "${VFT_RUNS:?set VFT_RUNS to the runs directory}"
if [ $# -lt 3 ] || [ $# -gt 5 ]; then
  echo 'usage: eval/ab_dev.sh <step> "<flags A>" "<flags B>" [binA] [binB]' >&2
  exit 2
fi
step=$1
flags_a=$2
flags_b=$3
bin_a=${4:-./target/release/venusflytrap}
bin_b=${5:-./target/release/venusflytrap}
PY=${PY:-py -I -X utf8}
mkdir -p "$VFT_RUNS"
r="$VFT_RUNS/$step"

run_side() { # run_side <a|b> <binary> <flags>
  local side=$1 bin=$2 flags=$3
  # shellcheck disable=SC2086 # the flags string is split into words on purpose
  if ! "$bin" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side dev $flags \
    --out "$r-$side.csv" > "$r-$side.json"; then
    echo "ab_dev: run $side failed ($bin $flags)" >&2
    exit 2
  fi
}

run_side a "$bin_a" "$flags_a"
run_side b "$bin_b" "$flags_b"
{
  echo "step: $step"
  echo "a: $bin_a $flags_a"
  echo "b: $bin_b $flags_b"
  $PY eval/changes.py ab "$r-a.csv" "$r-a.json" "$r-b.csv" "$r-b.json"
  echo
  echo "== clusters a"
  $PY eval/clusters.py "$r-a.csv" --manifest "$VFT_MANIFEST" --side dev --top 15
  echo
  echo "== clusters b"
  $PY eval/clusters.py "$r-b.csv" --manifest "$VFT_MANIFEST" --side dev --top 15
} > "$r-ab.txt"
cat "$r-ab.txt"
```

Run: `bash -n eval/ab_dev.sh; echo $?` → Expected: `0`.
Run: `bash eval/ab_dev.sh only-one-arg; echo $?` → Expected: the usage line on stderr, then `2`.

- [ ] **Step 11: Rewrite `eval/decision_gate.sh` with the `diff` mode**

The old header comment and the `VFT_CORPUS` message named the corpus's upstream project. The new file calls it "the labelled corpus testcases directory". Apart from those comment lines, the mode list and the new `diff` block, the file is unchanged, and the `capture` and `check` paths run exactly the same commands. Replace the whole file with:

```bash
#!/usr/bin/env bash
# Serve-mode decision gate.
#   eval/decision_gate.sh capture <dir>  # write the baseline CSVs and JSON reports
#   eval/decision_gate.sh check <dir>    # re-run into <dir>/now-* and require identical decisions
#   eval/decision_gate.sh diff <dir>     # re-run into <dir>/now-* and list every changed decision
# Needs VFT_CORPUS (the labelled corpus testcases directory). check compares, per
# file: label, lib_verdict, serve_verdict, score, banned (eval/compare_runs.py).
# diff prints, for distinct and pooled:100, every row whose lib_verdict,
# serve_verdict or banned changed, with the new cause, field, top and top_field,
# then the new run's bans_from_allowed and invariant_violations
# (eval/changes.py gate). diff exits 0 when both counters are 0 in both runs,
# 1 otherwise, 2 on invalid input.
set -euo pipefail
: "${VFT_CORPUS:?set VFT_CORPUS to the labelled corpus testcases directory}"
mode=${1:?capture, check or diff}
dir=${2:?output directory}
case "$mode" in capture) prefix="" ;; check|diff) prefix="now-" ;; *) echo "mode must be capture, check or diff" >&2; exit 2 ;; esac
PY=${PY:-py -I -X utf8}
mkdir -p "$dir"
cargo build --release -p vft-cli
bin=target/release/venusflytrap
for sources in distinct pooled:100; do
  tag=${sources/:/}
  "$bin" eval --corpus "$VFT_CORPUS" --mode serve --sources "$sources" \
    --out "$dir/${prefix}serve-$tag.csv" > "$dir/${prefix}serve-$tag.json"
done
if [ "$mode" = check ]; then
  for tag in distinct pooled100; do
    $PY eval/compare_runs.py "$dir/serve-$tag.csv" "$dir/now-serve-$tag.csv"
  done
  echo "decision gate: identical"
fi
if [ "$mode" = diff ]; then
  status=0
  for tag in distinct pooled100; do
    rc=0
    $PY eval/changes.py gate --tag "$tag" "$dir/serve-$tag.csv" "$dir/now-serve-$tag.csv" "$dir/now-serve-$tag.json" || rc=$?
    if [ "$rc" -eq 2 ]; then exit 2; fi
    if [ "$rc" -ne 0 ]; then status=1; fi
  done
  if [ "$status" -eq 0 ]; then
    echo "decision gate diff: bans_from_allowed 0, invariant_violations 0"
  else
    echo "decision gate diff: FAIL (bans_from_allowed or invariant_violations is not 0)"
  fi
  exit "$status"
fi
```

Run: `bash -n eval/decision_gate.sh; echo $?` → Expected: `0`.
Run: `git grep -n "testcases directory" -- eval/decision_gate.sh` → Expected: exactly two lines (the header comment and the `VFT_CORPUS` message), both reading `labelled corpus testcases directory`.
Run: `git diff eval/decision_gate.sh` → Expected: the changed lines are the header comment, the `VFT_CORPUS` message, the `mode=` default text, the `case` line (`check|diff` and the error text), and the added `diff` block. The `cargo build`, serve-run loop and `check` block are unchanged.

- [ ] **Step 12: Line endings and workspace checks**

Run: `git add eval/ab_dev.sh eval/decision_gate.sh && git ls-files --eol eval/ab_dev.sh eval/decision_gate.sh`
Expected: both lines show `i/lf    w/lf    attr/text eol=lf`. If the working copy shows `w/crlf`, run `rm eval/ab_dev.sh eval/decision_gate.sh && git checkout -- eval/ab_dev.sh eval/decision_gate.sh`, then repeat the `git ls-files` check and `bash -n` on both.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.
Run: `cargo test -p vft-core --features ts --test ts_bindings` → Expected: PASS.

- [ ] **Step 13: Capture the DQ2 serve baseline**

Run: `bash eval/decision_gate.sh capture "$VFT_BASELINE"`
Expected: four files in `$VFT_BASELINE` (`serve-distinct.csv`, `serve-distinct.json`, `serve-pooled100.csv`, `serve-pooled100.json`).

Run:

```bash
for tag in distinct pooled100; do
  py -I -X utf8 -c "import json, sys; r = json.load(open(sys.argv[1], encoding='utf-8')); l, s = r['library'], r['serve']; print(sys.argv[2], 'samples', r['samples'], 'read_failures', r['read_failures'], 'library', [l[k] for k in ('tp', 'fp', 'fn')], 'serve', [s['metrics'][k] for k in ('tp', 'fp', 'fn')], 'invariant_violations', r['invariant_violations'], 'bans_from_allowed', s['bans_from_allowed'])" "$VFT_BASELINE/serve-$tag.json" "$tag"
done
head -n 1 "$VFT_BASELINE/serve-distinct.csv"
```

Expected: both runs show `library [288, 278, 368]`, `serve [288, 278, 368]`, `invariant_violations 0` and `bans_from_allowed 0`, which are DQ1's numbers, because detection is main's. The header line ends in `,top,shadow,top_field`. If a count differs, stop and report: either the tree is not main, or the corpus lost files, and the owner decides. Record `samples` and `read_failures` of both runs in the task report.

- [ ] **Step 14: Self-check `check` and `diff` against the new baseline**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE" | tee "$VFT_RUNS/gate-task1-check.txt"`
Expected: both `compare_runs.py` runs print `decision diffs: 0`, and the last line is `decision gate: identical`. If it exits 2 with `row sets differ`, follow the Host facts procedure; in this task, re-capture (Step 13) and repeat this step.

Run: `bash eval/decision_gate.sh diff "$VFT_BASELINE" > "$VFT_RUNS/gate-task1-diff.txt"; echo "exit $?"`
Expected: `exit 0`. The file holds `diff distinct: <n> shared rows, 0 changed decisions, 0 score-only changes, 0 only in old, 0 only in new` and the same line for `pooled100`, with `bans_from_allowed=0` and `invariant_violations=0` after each, and its last line is `decision gate diff: bans_from_allowed 0, invariant_violations 0`. Any changed decision or score-only change is a nondeterminism bug: stop and report it.

- [ ] **Step 15: Capture the dev baseline (A equals B)**

Run: `bash eval/ab_dev.sh baseline "" ""; echo "exit $?"`
Expected: `exit 0`, and `$VFT_RUNS/baseline-ab.txt` contains:
- `ab: 16939 shared rows, 0 only in a, 0 only in b`
- `delta: tp=+0 fp=+0`
- `mcnemar lib_verdict malicious: b=0 c=0 p=1` and `mcnemar lib_verdict benign: b=0 c=0 p=1`
- an `a:` and a `b:` line, both starting `tp=149 fp=147 tn=16463 fn=180 recall=45.29% [` and showing `fp_rate=0.885% [`
- `fallen: 0 malicious rows from Challenge/Block to Allow/Monitor`
- the two cluster sections.

ΔTP or ΔFP other than 0, a fallen row, or counts other than these: stop and report.

Run: `cmp "$VFT_RUNS/baseline-a.csv" "$VFT_RUNS/baseline-b.csv"; echo $?` → Expected: `0`, because library mode is deterministic and the two CSVs are byte-identical.

Run: `sed -n '/^misses/,/^$/p' "$VFT_RUNS/baseline-ab.txt" | head -n 7`
Expected: the miss table of run a. Its groups whose `top` is not `-` now show a `loc` and `name` (from `top_field`) instead of `-`. DQ1 found 148 dev misses scoring 28 to 39 with `cmd.shell-meta` on top, so a large `cmd.shell-meta` group with a header `loc` is likely. Copy the first five miss groups into the task report; the results task cites them. Note any group that has a `top` but `loc` `-` (its top contribution has no field).

- [ ] **Step 16: Commit**

```bash
git add crates/vft-cli/src/eval.rs eval/clusters.py eval/test_clusters.py eval/fixtures/clusters.csv eval/fixtures/clusters_manifest.tsv eval/changes.py eval/test_changes.py eval/ab_dev.sh eval/decision_gate.sh
git status --short   # Expected: only these nine files staged; .superpowers/ stays ignored
git commit -m "feat(eval): top_field column, dev A/B helper and serve decision diff" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

The task report records the following:
- `samples` and `read_failures` of both serve baselines;
- the paths `$VFT_RUNS/gate-task1-check.txt`, `$VFT_RUNS/gate-task1-diff.txt` and `$VFT_RUNS/baseline-ab.txt`;
- the first five dev miss groups;
- any absent corpus files (Host facts).

---

### Task 2: `gate.cmd-position`, the shell command-position rule *(measured: `cmdpos`)*

**What is wrong today.** `cmd.chained-command` (shell.rs `binary_after_meta`) works on tokens. It fires when the first identifier after `;`, `|`, `&`, `&&` or `||` is a name from `BINS`. The lexer drops whitespace and splits `=` off as its own token, so a URL query separator followed by a parameter assignment (`&name=value`) reads as a chained shell command whenever the parameter name is also a binary name. `id` is the common case. All 37 dev FP rows of this construct are exactly this, `&id=` (spec §3): 25 in a query value carrying JSON with an embedded URL, 7 in form bodies, 4 in Referer and 1 in protobuf.

**Change (spec §4.3, last two bullets; D8).** The construct keeps today's token test as the candidate. It is reached only if the field text also has a known binary in command position: a whole word after a separator and optional whitespace that is **not immediately followed by `=`, `(`, `.` or `:`**. A rejected candidate falls through to today's `cmd.shell-meta` latent (P7). The rule sits behind the new gate id `gate.cmd-position` (a new `ConstructKind::Gate`, with no family). `--disable gate.cmd-position` restores today's behaviour, so the A/B needs one build (D14). Gates cannot be shadowed.

**Files:**
- Modify: `crates/vft-core/src/graph/sinks/mod.rs`: `ConstructKind` (around line 20), the `ConstructInfo.family` and `pattern` doc comments (around lines 37 and 44), `REGISTRY` (end of the list, around line 123), `Hits` (around line 168), tests `only_decoders_lack_a_family` (around line 230) and one new test
- Modify: `crates/vft-core/src/graph/sinks/shell.rs`: `GATE_CMD_POSITION`, the chaining block of `detect` (lines 29–40), new `command_in_position`, new `mod tests`
- Modify: `crates/vft-core/src/config.rs`: the shadow check (around line 379), the `shadow` doc comment (around line 135), test `shadow_ids_must_be_registered_not_disabled_and_not_decoders` (around line 579)
- Modify: `crates/vft-core/src/options.rs:83` (the `shield.shadow` description)

**Interfaces:**
- Consumes: Task 1's `bash eval/ab_dev.sh <step> "<flags A>" "<flags B>"`, `bash eval/decision_gate.sh diff "$VFT_BASELINE"` and the baselines in `$VFT_BASELINE`. From the existing code: `Disabled::resolve(&[String]) -> Disabled`, `Disabled::is(&self, &ConstructInfo) -> bool`, `Hits::new(&Disabled)`, `Hits.reachable` / `Hits.latent: Vec<Pattern>` (`Pattern.name: String`), `SinkCtx { tokens: &[Token], text: &str }`, `crate::graph::tokenize::tokenize(&str) -> Vec<Token>`, and shell.rs's `BINS` and `binary_after_meta(tokens, bins)`.
- Produces:
  - `ConstructKind::Gate`, a variant with no family. Any later gate reuses it.
  - `pub static shell::GATE_CMD_POSITION: ConstructInfo` (`id: "gate.cmd-position"`, `family: None`, `kind: ConstructKind::Gate`), registered in `REGISTRY`. `venusflytrap ablate` therefore lists it automatically.
  - `Hits::off(&self, c: &ConstructInfo) -> bool`, which is true when `c` is in `shield.disabled`.
  - `fn command_in_position(text: &str, bins: &[&str]) -> bool` (private to shell.rs).
  - `Config::validate` reports `shield.shadow` with a message containing `is a gate` for a gate id. A gate id in `shield.disabled` is valid.

- [ ] **Step 1: Write the failing tests**

The existing positive cases stay as they are and must keep passing: `command_injection_detected`, `command_injection_still_caught_after_fp_fix`, `jquery_dollar_paren_is_not_cmdi` and `every_emitted_pattern_is_a_registered_id` in `crates/vft-core/src/graph/mod.rs`. shell.rs has no tests of its own today. Its new tests below build their command-position cases from `BINS` at run time, so no command string is written out.

Append to `crates/vft-core/src/graph/sinks/shell.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::sinks::Disabled;
    use crate::graph::tokenize::tokenize;

    /// (reachable names, latent names) of the shell sinks on `text`.
    fn shell_hits(text: &str, disabled: &Disabled) -> (Vec<String>, Vec<String>) {
        let tokens = tokenize(text);
        let mut hits = Hits::new(disabled);
        detect(&SinkCtx { tokens: &tokens, text }, &mut hits);
        (hits.reachable.into_iter().map(|p| p.name).collect(), hits.latent.into_iter().map(|p| p.name).collect())
    }

    const SEPARATORS: &[&str] = &[";", "|", "&", "&&", "||"];

    #[test]
    fn a_query_parameter_named_like_a_binary_is_not_a_chained_command() {
        let on = Disabled::default();
        for s in ["a=1&id=2", "format=json&id=v3", "page=2&id=7&sort=asc", "v=1&id.json", "q=1&id(3)", "q=1&id:2"] {
            let (reach, latent) = shell_hits(s, &on);
            assert!(!reach.iter().any(|n| n == "cmd.chained-command"), "{s:?}: {reach:?}");
            assert!(latent.iter().any(|n| n == "cmd.shell-meta"), "the separator stays visible as a latent on {s:?}: {latent:?}");
        }
    }

    #[test]
    fn disabling_the_gate_restores_the_token_rule() {
        let off = Disabled::resolve(&["gate.cmd-position".into()]);
        for s in ["a=1&id=2", "format=json&id=v3"] {
            let (reach, _) = shell_hits(s, &off);
            assert!(reach.iter().any(|n| n == "cmd.chained-command"), "today's behaviour on {s:?}: {reach:?}");
        }
    }

    #[test]
    fn command_position_needs_a_whole_word_not_followed_by_an_assignment_or_call() {
        let on = Disabled::default();
        for bin in BINS {
            for sep in SEPARATORS {
                for end in ["", " ", " x", ";", "|", "&", "<", ">", ")", "`", " =", " ("] {
                    for word in [bin.to_string(), bin.to_ascii_uppercase()] {
                        let s = format!("x{sep}{word}{end}");
                        assert!(command_in_position(&s, BINS), "{s:?}");
                        let s = format!("x{sep} {word}{end}");
                        assert!(command_in_position(&s, BINS), "{s:?}");
                    }
                }
                for bad in ["=", "(", ".", ":"] {
                    let s = format!("x{sep}{bin}{bad}");
                    assert!(!command_in_position(&s, BINS), "{s:?}");
                    let (reach, latent) = shell_hits(&s, &on);
                    assert!(!reach.iter().any(|n| n == "cmd.chained-command"), "{s:?}: {reach:?}");
                    assert!(latent.iter().any(|n| n == "cmd.shell-meta"), "{s:?}: {latent:?}");
                }
                let longer = format!("x{sep}{bin}x");
                assert!(!command_in_position(&longer, BINS), "not a whole word: {longer:?}");
                let longer = format!("x{sep}x{bin}");
                assert!(!command_in_position(&longer, BINS), "not a whole word: {longer:?}");
            }
        }
        assert!(!command_in_position("", BINS));
        assert!(!command_in_position("no separator here", BINS));
    }

    #[test]
    fn the_gate_only_removes_reaches() {
        let on = Disabled::default();
        let off = Disabled::resolve(&["gate.cmd-position".into()]);
        for bin in BINS {
            for sep in SEPARATORS {
                for end in ["", " x", "=1", "(", ".x", ":1", ";"] {
                    let s = format!("x{sep}{bin}{end}");
                    let (with_gate, _) = shell_hits(&s, &on);
                    let (without, _) = shell_hits(&s, &off);
                    for n in &with_gate {
                        assert!(without.contains(n), "the gate added {n} on {s:?}");
                    }
                }
            }
        }
    }
}
```

In `crates/vft-core/src/graph/sinks/mod.rs`, replace the body of `only_decoders_lack_a_family` (keep the name) so the whole test reads:

```rust
    #[test]
    fn only_decoders_lack_a_family() {
        for c in constructs() {
            assert_eq!(c.family.is_none(), matches!(c.kind, ConstructKind::Decoder | ConstructKind::Gate), "{}", c.id);
        }
        assert_eq!(lookup("gate.cmd-position").map(|c| c.kind), Some(ConstructKind::Gate));
    }
```

and add after `hits_drop_disabled_and_dedupe`:

```rust
    #[test]
    fn hits_report_whether_a_construct_is_off() {
        let d = Disabled::resolve(&["gate.cmd-position".into()]);
        let h = Hits::new(&d);
        assert!(h.off(&shell::GATE_CMD_POSITION));
        assert!(!h.off(&SIG_ONERROR));
        let none = Disabled::default();
        assert!(!Hits::new(&none).off(&shell::GATE_CMD_POSITION));
    }
```

In `crates/vft-core/src/config.rs`, inside `shadow_ids_must_be_registered_not_disabled_and_not_decoders`, add after its last assertion:

```rust
        assert!(issues("shield:\n  shadow: [gate.cmd-position]\n")
            .iter()
            .any(|i| i.key == "shield.shadow" && i.message.contains("is a gate")));
        assert!(issues("shield:\n  disabled: [gate.cmd-position]\n").is_empty(), "a gate can be disabled");
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vft-core --lib sinks`
Expected: compile errors. `GATE_CMD_POSITION` is not found in `shell`, there is no variant `Gate` on `ConstructKind`, there is no method `off` on `Hits`, and `command_in_position` is not found.

- [ ] **Step 3: Add `ConstructKind::Gate`, `Hits::off` and the registry entry** (`crates/vft-core/src/graph/sinks/mod.rs`)

Add the variant at the end of `ConstructKind`:

```rust
    /// A rule that narrows when an existing construct fires. It emits no
    /// evidence and has no family; putting its id in `shield.disabled`
    /// restores the construct's earlier behaviour, so an A/B needs one build.
    Gate,
```

Change the `family` doc comment in `ConstructInfo` to:

```rust
    /// `None` only for decoders and gates, which emit no evidence and belong
    /// to no attack family.
```

and the first doc line of `pattern` to:

```rust
    /// The pattern this construct emits. Decoders and gates never emit
    /// patterns; the registry test guarantees every other kind has a family.
```

Append to `REGISTRY`, after `&DECODE_B64_WHOLE,`:

```rust
    &shell::GATE_CMD_POSITION,
```

Add to `impl<'d> Hits<'d>`, after `latent`:

```rust
    /// Whether `c` is in `shield.disabled`. A sink asks this of a gate to
    /// decide whether to apply it.
    pub fn off(&self, c: &ConstructInfo) -> bool {
        self.disabled.is(c)
    }
```

- [ ] **Step 4: Implement the command-position rule** (`crates/vft-core/src/graph/sinks/shell.rs`)

After the `SHELL_META` static, add:

```rust
pub static GATE_CMD_POSITION: ConstructInfo = ConstructInfo { id: "gate.cmd-position", family: None, kind: ConstructKind::Gate, summary: "cmd.chained-command needs its binary as a whole word not directly followed by =, (, . or :; disabling it restores the token-only rule" };
```

Replace the chaining block of `detect` (the comment starting `// Chaining:` through the closing brace of the `if … else if has_meta` chain) with:

```rust
    // Chaining: a shell metacharacter followed (in command position) by a known
    // binary — `;`, `|`, `&`, `&&` or `||`, then the binary. Requiring the binary
    // to come *after* the separator avoids flagging benign values that merely
    // contain a short word and a separator elsewhere. The token test is the
    // candidate. `gate.cmd-position` also
    // requires the binary as a whole word on the text that is not directly
    // followed by `=`, `(`, `.` or `:`: `&id=2` is a URL parameter, not a command.
    // A rejected candidate stays visible as the `cmd.shell-meta` latent.
    let has_meta = tokens
        .iter()
        .any(|t| t.kind == TokenKind::ShellMeta && matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||"));
    if binary_after_meta(tokens, BINS) && (hits.off(&GATE_CMD_POSITION) || command_in_position(text, BINS)) {
        hits.reach(&CHAINED_COMMAND);
    } else if has_meta {
        hits.latent(&SHELL_META);
    }
```

Add after `binary_after_meta`:

```rust
/// The `gate.cmd-position` rule: some `;`, `|` or `&` is followed, after
/// optional whitespace, by a known binary as a whole word (`[A-Za-z0-9_]+`,
/// compared in lower case) whose next character is not `=`, `(`, `.` or `:`.
/// A binary name directly followed by one of those is an assignment, a URL
/// parameter, a call or a file name, not a command.
///
/// Works on the text because the lexer drops whitespace, so tokens cannot tell
/// `&id=2` from a separator, a binary and a later `=`.
fn command_in_position(text: &str, bins: &[&str]) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    for (i, &c) in chars.iter().enumerate() {
        if !matches!(c, ';' | '|' | '&') {
            continue;
        }
        let mut j = i + 1;
        while j < n && chars[j].is_whitespace() {
            j += 1;
        }
        let start = j;
        while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
            j += 1;
        }
        if start == j {
            continue;
        }
        let word = chars[start..j].iter().collect::<String>().to_ascii_lowercase();
        let assignment_like = j < n && matches!(chars[j], '=' | '(' | '.' | ':');
        if bins.contains(&word.as_str()) && !assignment_like {
            return true;
        }
    }
    false
}
```

- [ ] **Step 5: Reject shadowing a gate** (`crates/vft-core/src/config.rs`, `crates/vft-core/src/options.rs`)

In `validate`, replace the decoder check inside `for id in &sh.shadow` (the `if crate::graph::sinks::lookup(id).is_some_and(|c| c.kind == crate::graph::sinks::ConstructKind::Decoder) { … }` block) with:

```rust
            match crate::graph::sinks::lookup(id).map(|c| c.kind) {
                Some(crate::graph::sinks::ConstructKind::Decoder) => {
                    bad("shield.shadow", format!("{id:?} is a decoder; decoders emit no evidence and cannot be shadowed (use shield.disabled)"));
                }
                Some(crate::graph::sinks::ConstructKind::Gate) => {
                    bad("shield.shadow", format!("{id:?} is a gate; gates emit no evidence and cannot be shadowed (use shield.disabled)"));
                }
                _ => {}
            }
```

The decoder message is unchanged. In the `shadow` field's doc comment, change `decoders cannot be` / `shadowed.` to `decoders and gates cannot be` / `shadowed.`. In `crates/vft-core/src/options.rs:83`, change `decoders cannot be shadowed.` at the end of the `shield.shadow` description to `decoders and gates cannot be shadowed.`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p vft-core --lib sinks` → Expected: PASS, including `a_query_parameter_named_like_a_binary_is_not_a_chained_command`, `disabling_the_gate_restores_the_token_rule`, `command_position_needs_a_whole_word_not_followed_by_an_assignment_or_call`, `the_gate_only_removes_reaches`, `only_decoders_lack_a_family` and `hits_report_whether_a_construct_is_off`.
Run: `cargo test -p vft-core --lib graph::tests` → Expected: PASS (the existing positive cases, unchanged).
Run: `cargo test -p vft-core --lib config` → Expected: PASS, including `shadow_ids_must_be_registered_not_disabled_and_not_decoders`.

- [ ] **Step 7: Workspace checks**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green. A failing shield.rs or vft-proxy test means an existing probe relied on a binary name directly followed by `=`, `(`, `.` or `:`. Stop and report it with the test name; do not rewrite the probe.
Run: `cargo test -p vft-core --features ts --test ts_bindings` → Expected: PASS (`ConstructKind` is not on the wire).

- [ ] **Step 8: Dev A/B**

Run: `cargo build --release -p vft-cli`
Run: `bash eval/ab_dev.sh cmdpos "--disable gate.cmd-position" ""; echo "exit $?"`
Expected: `exit 0`. In `$VFT_RUNS/cmdpos-ab.txt`, side a (gate disabled) matches the dev baseline: `a: tp=149 fp=147 tn=16463 fn=180`. `delta:` shows `tp=+0` and an `fp` between `-37` and `+0`. `mcnemar lib_verdict benign` shows `c=0`, and `fallen:` shows 0 rows.

Apply the stop rule (Global Constraints). If dev ΔFP > 0, or any row is listed under `fallen:`, stop and report NEEDS_CONTEXT with `$VFT_RUNS/cmdpos-ab.txt`. The spec's expected losses all belong to the SQL gate, so for this step every fallen row is outside the list. Do not tune the rule.

Count the FP rows that carry the construct on each side:

```bash
py -I -X utf8 -c "import csv, sys
for path in sys.argv[1:]:
    rows = list(csv.DictReader(open(path, encoding='utf-8', newline='')))
    fp = [r for r in rows if r['label'] == '0' and r['lib_verdict'] in ('Block', 'Challenge')]
    hit = [r for r in fp if 'cmd.chained-command' in r['constructs'].split('|')]
    print(path.rsplit('/', 1)[-1], 'fp', len(fp), 'fp with cmd.chained-command', len(hit))
    for r in hit[:20]:
        print('  ', r['rel'], r['top'], r['field'] or r['top_field'])" "$VFT_RUNS/cmdpos-a.csv" "$VFT_RUNS/cmdpos-b.csv"
```

Expected: `cmdpos-a.csv … fp with cmd.chained-command 37`, which is the spec's count. A different side-a count is not a stop; report the number. On side b the count is 0, because each of those rows has the binary name directly before `=`. Any side-b row that still carries the construct is listed with its field; report those rows, but they do not stop the task. Rows that leave the count but stay FP are blocked by another construct. They explain why ΔFP can be smaller than 37, and they belong in the report by `top`.

- [ ] **Step 9: Serve regression**

Run: `bash eval/decision_gate.sh diff "$VFT_BASELINE" > "$VFT_RUNS/gate-task2-diff.txt"; echo "exit $?"`
Expected: `exit 0`, and the last line is `decision gate diff: bans_from_allowed 0, invariant_violations 0`. Exit 1: stop and report.

Check that every changed row is attributable to `gate.cmd-position` (spec §6.3). A row is attributable when its baseline row carried `cmd.chained-command`:

```bash
py -I -X utf8 -c "import csv, sys
rows = [l.split('\t') for l in open(sys.argv[1], encoding='utf-8').read().splitlines() if l.count('\t') == 8 and not l.startswith('rel\t')]
lib_moved, label = {}, {}
for f in rows:
    lib_moved[f[0]] = lib_moved.get(f[0], False) or '->' in f[2]
    label[f[0]] = f[1]
old = {r['rel']: r for r in csv.DictReader(open(sys.argv[2], encoding='utf-8', newline=''))}
print('changed rows', len(lib_moved), 'malicious', sum(v == '1' for v in label.values()))
for rel in sorted(lib_moved):
    if label[rel] == '1':
        print('MALICIOUS CHANGED:', rel)
    if 'cmd.chained-command' not in old[rel]['constructs'].split('|'):
        print('NOT ATTRIBUTABLE:' if lib_moved[rel] else 'KNOCK-ON (serve or banned only):', rel)" "$VFT_RUNS/gate-task2-diff.txt" "$VFT_BASELINE/serve-distinct.csv"
```

Expected: `malicious 0`, and no `MALICIOUS CHANGED:` or `NOT ATTRIBUTABLE:` line. A `KNOCK-ON` line can appear only for pooled:100: a row whose library verdict did not move, but whose serve verdict or ban changed because an earlier row of the same source changed. List those rows in the task report. Any `MALICIOUS CHANGED:` or `NOT ATTRIBUTABLE:` line: stop and report. Run the Host facts `PRESENT:` check on any `only in old:` / `only in new:` rel paths.

- [ ] **Step 10: Commit**

```bash
git add crates/vft-core/src/graph/sinks/mod.rs crates/vft-core/src/graph/sinks/shell.rs crates/vft-core/src/config.rs crates/vft-core/src/options.rs
git status --short   # Expected: only these four files staged
git commit -m "feat(core): gate.cmd-position: a chained command needs its binary in command position" -m "cmd.chained-command no longer fires on a query separator followed by a parameter assignment (&id=). New ConstructKind::Gate and Hits::off; gates cannot be shadowed." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

The task report records the following, for the results task's per-step table:
- from `$VFT_RUNS/cmdpos-ab.txt`, ΔTP, ΔFP, both McNemar lines and the `a:` / `b:` rate lines with their intervals;
- the side-a and side-b counts of FP rows with `cmd.chained-command`, and the `top` of each such row that stayed FP;
- the changed-row count from `$VFT_RUNS/gate-task2-diff.txt` and any `KNOCK-ON` rows;
- any absent corpus files.

---

---

### Task 3: Body classification (`body.rs`) *(measured: `body`, `body-<class>`, `body-nonutf8`)*

> **As shipped in DQ2a:** only the JSON split (`parse.body-json`) shipped. There is no binary class and no body hiding, form and multipart bodies stay one `<body>` field, and `limit.body-non-utf8` fires for declared text classes only. The steps below are the original plan. See the note at the top of spec §4.2, [`eval/RESULTS-DQ2.md`](../../../eval/RESULTS-DQ2.md) §3 and §13, and the Task 3 rulings in the DQ2 ledger.

**Files:**
- Create: `crates/vft-core/src/body.rs`
- Create (generated): `crates/vft-core/tests/fixtures/body_cases.txt`
- Modify: `crates/vft-core/src/lib.rs` (module list, line 20–32)
- Modify: `crates/vft-core/src/request.rs:69-134` (`fields`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (statics after line 72 and line 79; `REGISTRY` lines 81–124)
- Modify: `crates/vft-core/src/shield.rs:146` (fields loop) and `:171-183` (limits), tests module
- Modify: `crates/vft-core/src/detect.rs:93-96` (`ApiSafetyDetector`)
- Test: `crates/vft-core/src/body.rs` (unit tests), `crates/vft-core/src/shield.rs` (tests module), `crates/vft-core/tests/fuzz_props.rs`

**Interfaces:**
- Consumes: `graph::sinks::Disabled::is(&ConstructInfo)`; `ConstructKind::Decoder` / `ConstructKind::Limit` (and Task 2's `ConstructKind::Gate`, untouched here); `normalize::percent_decode_lossy(&str) -> String`; `serde_json` (already a vft-core dependency); `eval/ab_dev.sh` and `eval/decision_gate.sh diff` from Task 1.
- Produces:
  - `pub mod body` with `pub fn body_fields(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts)`, `pub struct BodyFacts { pub non_utf8: bool, pub unparsed: bool }`, `pub const MAX_BODY_FIELDS: usize = 256`, `pub const MAX_JSON_DEPTH: usize = 32`.
  - `Request::header(&self, name: &str) -> Option<&str>`; `Request::fields_with(&self, off: &Disabled) -> (Vec<Field>, BodyFacts)`; `Request::fields()` keeps its signature and equals `fields_with(&Disabled::default()).0`.
  - Body field names (`Field.name`, location `Body`; label `body:<name>`): `<body>` (fallback, as today), `json:<JSON-Pointer>`, `json-key:<pointer>`, `form:<name>`, `form-key:<name>`, `form-file:<part name>`, overflow `json:#rest` (JSON body) or `form:#rest` (form or multipart body). Names are clipped to 64 chars.
  - Registry statics `sinks::PARSE_BODY_BINARY`, `PARSE_BODY_JSON`, `PARSE_BODY_FORM`, `PARSE_BODY_MULTIPART` (kind `Decoder`, family `None`), `sinks::LIMIT_BODY_NON_UTF8` (`Limit`, Suspicious 0.6 at `weight_api`), `sinks::LIMIT_BODY_UNPARSED` (`Limit`, Suspicious at evidence weight 0 and engine weight 0, so 0 points).
  - `ApiSafetyDetector`: for `Location::Body` fields the `id` / `*_id` / `page` / `count` test applies to the last name segment (after the last `:` or `/`); other locations keep the whole-name test.
  - Test helper in the shield tests module: `fn fixture_lines(src: &'static str, kind: &str) -> Vec<&'static str>`.

Classification order inside `body_fields` (one call per body, and once per multipart part):

1. Empty body: no field.
2. Binary: gzip `1f 8b`, zip `PK 03 04`, PNG, JPEG `ff d8 ff` by magic, whatever the declared type. zlib (`78` + `01|5e|9c|da`), GIF and PDF magic is printable, so it also needs binary-looking bytes; so does a declared binary type (`protobuf`, `octet-stream`, `image/*`, `audio/*`, `video/*`). Binary-looking means a C0 control other than TAB/LF/CR, or invalid UTF-8 (D13). Requiring binary-looking bytes for printable magic is a deliberate tightening of the spec table: a printable magic prefix alone would otherwise hide a form body. Disabled `parse.body-binary`: the body becomes today's lossy `<body>`, without the non-UTF-8 fact.
3. `multipart/*` with a `boundary` (1–70 chars), top level only: each part is classified by its own Content-Type with this same order; `filename` is its own field. A body without a closing delimiter is unparsed and falls through.
4. `application/x-www-form-urlencoded`: split on raw `&`, then at the first `=`.
5. JSON, unless the type names `xml`: declared (type contains `json`; `ndjson` / `jsonl` line by line) or sniffed (first non-blank byte `{` or `[`). String leaves become fields; numbers, booleans and null do not. A key becomes a `json-key:` field only if it has a character outside letters, digits and `_ - . $ @`. A string leaf that is itself a JSON object or array is expanded once. Nesting deeper than 32, or a parse failure, falls through; for a declared type that sets `unparsed`.
6. Anything else: one field (`<body>` at top level, `form:<name>` for a part). Invalid UTF-8 here, or in a form body, sets `non_utf8`.

- [ ] **Step 1: Register the ids**

In `crates/vft-core/src/graph/sinks/mod.rs`, after `LIMIT_HEADER_NON_UTF8` (line 67) add:

```rust
pub static LIMIT_BODY_NON_UTF8: ConstructInfo = ConstructInfo { id: "limit.body-non-utf8", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "a text-class body carried bytes that are not valid UTF-8" };
pub static LIMIT_BODY_UNPARSED: ConstructInfo = ConstructInfo { id: "limit.body-unparsed", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "a body declared JSON, ndjson or multipart did not parse and was inspected whole (informational, 0 points)" };
```

After `DECODE_B64_WHOLE` (line 79) add:

```rust
pub static PARSE_BODY_BINARY: ConstructInfo = ConstructInfo { id: "parse.body-binary", family: None, kind: ConstructKind::Decoder, summary: "body classification: a body binary by magic bytes, or a declared binary type whose bytes look binary, gets no text field" };
pub static PARSE_BODY_JSON: ConstructInfo = ConstructInfo { id: "parse.body-json", family: None, kind: ConstructKind::Decoder, summary: "body classification: one json:<pointer> field per JSON string leaf; ndjson line by line" };
pub static PARSE_BODY_FORM: ConstructInfo = ConstructInfo { id: "parse.body-form", family: None, kind: ConstructKind::Decoder, summary: "body classification: a form body split on raw '&' into form:<name> and form-key:<name> fields" };
pub static PARSE_BODY_MULTIPART: ConstructInfo = ConstructInfo { id: "parse.body-multipart", family: None, kind: ConstructKind::Decoder, summary: "body classification: multipart parts, one level, each classified by its own Content-Type" };
```

In `REGISTRY`, after `&LIMIT_HEADER_NON_UTF8,` add `&LIMIT_BODY_NON_UTF8,` and `&LIMIT_BODY_UNPARSED,`; after `&DECODE_B64_WHOLE,` add `&PARSE_BODY_BINARY,`, `&PARSE_BODY_JSON,`, `&PARSE_BODY_FORM,`, `&PARSE_BODY_MULTIPART,`.

Run: `cargo test -p vft-core sinks::` → Expected: PASS (`ids_are_unique_and_dotted`, `only_decoders_lack_a_family` as extended by Task 2). The config check that rejects shadowing a decoder now also rejects `shield.shadow: [parse.body-json]`; no code change is needed for that.

- [ ] **Step 2: Generate the detection fixture**

The body tests need one SQL case that blocks on its own with today's SQL sinks. Take the first case of the committed spec's accepted list (section 6.4, "accepted:" line), so the string is never typed:

```bash
mkdir -p crates/vft-core/tests/fixtures
py -I -X utf8 - docs/superpowers/specs/2026-10-28-dq2-fp-budget-design.md crates/vft-core/tests/fixtures/body_cases.txt <<'EOF'
import re, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith("### 6.4 Exit"))
acc = next(l for l in lines[start:] if l.strip().startswith("- accepted:"))
first = re.findall(r"`([^`]+)`", acc)[0]
with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as f:
    f.write(f"accept\t{first}\n")
EOF
wc -l < crates/vft-core/tests/fixtures/body_cases.txt
```

Expected: `1`. Do not print the file in the task report.

- [ ] **Step 3: Write the failing unit tests**

Create `crates/vft-core/src/body.rs` with only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn names(ct: &str, body: &[u8]) -> Vec<String> {
        body_fields(Some(ct), body, &Disabled::default()).0.into_iter().map(|f| f.name).collect()
    }

    fn pairs(ct: &str, body: &[u8]) -> Vec<(String, String)> {
        body_fields(Some(ct), body, &Disabled::default()).0.into_iter().map(|f| (f.name, f.raw)).collect()
    }

    #[test]
    fn empty_body_has_no_field() {
        assert!(body_fields(None, b"", &Disabled::default()).0.is_empty());
    }

    #[test]
    fn protobuf_with_control_bytes_has_no_field() {
        let (f, facts) = body_fields(Some("application/x-protobuf"), &[0x0a, 0x03, b'a', b'b', b'c', 0x10, 0x01], &Disabled::default());
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(facts, BodyFacts::default());
    }

    #[test]
    fn printable_protobuf_is_inspected_as_text() {
        assert_eq!(pairs("application/x-protobuf", b"hello world"), vec![("<body>".to_string(), "hello world".to_string())]);
    }

    #[test]
    fn gzip_magic_is_binary_whatever_the_declared_type() {
        let (f, facts) = body_fields(Some("application/json"), &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0], &Disabled::default());
        assert!(f.is_empty());
        assert!(!facts.non_utf8 && !facts.unparsed);
    }

    #[test]
    fn printable_magic_alone_does_not_hide_a_form_body() {
        let n = names("application/x-www-form-urlencoded", b"%PDF-a=1&b=2");
        assert!(n.contains(&"form:b".to_string()), "{n:?}");
    }

    #[test]
    fn text_plain_json_is_split_into_string_leaves() {
        let mut n = names("text/plain", br#"{"user":{"id":"7","tags":["a","b"]},"n":5}"#);
        n.sort();
        assert_eq!(n, vec!["json:/user/id", "json:/user/tags/0", "json:/user/tags/1"]);
    }

    #[test]
    fn a_json_leaf_that_is_json_is_expanded_once() {
        let body = br#"{"payload":"{\"q\":\"x\",\"deep\":\"{\\\"z\\\":\\\"y\\\"}\"}"}"#;
        let p = pairs("application/json", body);
        assert!(p.contains(&("json:/payload/q".to_string(), "x".to_string())), "{p:?}");
        assert!(p.contains(&("json:/payload/deep".to_string(), r#"{"z":"y"}"#.to_string())), "{p:?}");
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn only_keys_with_non_identifier_characters_are_fields() {
        let n = names("application/json", br#"{"a b":"1","ok_key":"2"}"#);
        assert!(n.contains(&"json-key:/a b".to_string()), "{n:?}");
        assert!(!n.iter().any(|x| x == "json-key:/ok_key"));
    }

    #[test]
    fn json_pointer_tokens_are_escaped() {
        let n = names("application/json", br#"{"a/b":{"c~d":"1"}}"#);
        assert!(n.contains(&"json:/a~1b/c~0d".to_string()), "{n:?}");
    }

    #[test]
    fn ndjson_is_split_line_by_line() {
        let mut n = names("application/x-ndjson", b"{\"a\":\"1\"}\n\n{\"a\":\"2\"}\n");
        n.sort();
        assert_eq!(n, vec!["json:/0/a", "json:/1/a"]);
    }

    #[test]
    fn declared_json_that_does_not_parse_is_whole_and_unparsed() {
        let (f, facts) = body_fields(Some("application/json"), b"{\"a\":", &Disabled::default());
        assert_eq!(f.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["<body>"]);
        assert!(facts.unparsed);
    }

    #[test]
    fn json_nested_deeper_than_the_cap_is_whole() {
        let deep = format!("{}\"x\"{}", "[".repeat(MAX_JSON_DEPTH + 8), "]".repeat(MAX_JSON_DEPTH + 8));
        let (f, facts) = body_fields(Some("application/json"), deep.as_bytes(), &Disabled::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "<body>");
        assert!(facts.unparsed);
        // Sniffed (not declared) JSON falls back without the informational limit.
        let (f, facts) = body_fields(None, deep.as_bytes(), &Disabled::default());
        assert_eq!(f[0].name, "<body>");
        assert!(!facts.unparsed);
    }

    #[test]
    fn form_splits_on_raw_ampersand_before_decoding() {
        assert_eq!(
            pairs("application/x-www-form-urlencoded; charset=utf-8", b"a=1&b=x%26y&&c"),
            vec![
                ("form-key:a".to_string(), "a".to_string()),
                ("form:a".to_string(), "1".to_string()),
                ("form-key:b".to_string(), "b".to_string()),
                ("form:b".to_string(), "x%26y".to_string()),
                ("form-key:c".to_string(), "c".to_string()),
            ]
        );
    }

    #[test]
    fn form_names_are_percent_decoded() {
        assert!(names("application/x-www-form-urlencoded", b"i%64=5").contains(&"form:id".to_string()));
    }

    const MP: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"pic\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x01\r\n--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"id\":\"3\"}\r\n--XyZ--\r\n";

    #[test]
    fn multipart_parts_are_classified_by_their_own_type() {
        let (f, facts) = body_fields(Some("multipart/form-data; boundary=XyZ"), MP, &Disabled::default());
        let p: Vec<(String, String)> = f.into_iter().map(|f| (f.name, f.raw)).collect();
        assert_eq!(
            p,
            vec![
                ("form:note".to_string(), "hello".to_string()),
                ("form-file:pic".to_string(), "a.png".to_string()),
                ("json:/meta/id".to_string(), "3".to_string()),
            ]
        );
        assert_eq!(facts, BodyFacts::default());
    }

    #[test]
    fn multipart_without_a_closing_delimiter_is_whole() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello";
        let (f, facts) = body_fields(Some("multipart/form-data; boundary=XyZ"), body, &Disabled::default());
        assert_eq!(f.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["<body>"]);
        assert!(facts.unparsed);
    }

    #[test]
    fn a_disabled_class_falls_back_to_the_single_body_field() {
        let off = Disabled::resolve(&["parse.body-form".into()]);
        let (f, _) = body_fields(Some("application/x-www-form-urlencoded"), b"a=1&b=2", &off);
        assert_eq!(f.iter().map(|f| (f.name.as_str(), f.raw.as_str())).collect::<Vec<_>>(), vec![("<body>", "a=1&b=2")]);
        let off = Disabled::resolve(&["parse.body-binary".into()]);
        let (f, facts) = body_fields(Some("application/octet-stream"), &[0x00, 0xff, 0x01], &off);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "<body>");
        assert!(!facts.non_utf8, "a binary body is not a text-class body");
        let off = Disabled::resolve(&["parse.body-json".into()]);
        assert_eq!(names_with(&off, "application/json", br#"{"a":"1"}"#), vec!["<body>"]);
        let off = Disabled::resolve(&["parse.body-multipart".into()]);
        assert_eq!(names_with(&off, "multipart/form-data; boundary=XyZ", MP), vec!["<body>"]);
    }

    fn names_with(off: &Disabled, ct: &str, body: &[u8]) -> Vec<String> {
        body_fields(Some(ct), body, off).0.into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn invalid_utf8_in_a_text_body_is_a_fact() {
        let (f, facts) = body_fields(Some("text/plain"), b"caf\xe9 au lait", &Disabled::default());
        assert_eq!(f[0].name, "<body>");
        assert!(facts.non_utf8);
        let (_, facts) = body_fields(Some("application/x-www-form-urlencoded"), b"a=caf\xe9", &Disabled::default());
        assert!(facts.non_utf8);
    }

    #[test]
    fn the_field_cap_joins_the_rest_and_drops_nothing() {
        let members: Vec<String> = (0..300).map(|i| format!("\"k{i:03}\":\"v{i}\"")).collect();
        let body = format!("{{{}}}", members.join(","));
        let (f, _) = body_fields(Some("application/json"), body.as_bytes(), &Disabled::default());
        assert_eq!(f.len(), MAX_BODY_FIELDS);
        let rest = f.last().unwrap();
        assert_eq!(rest.name, "json:#rest");
        assert_eq!(rest.raw.lines().count(), 300 - (MAX_BODY_FIELDS - 1));
        let (f, _) = body_fields(Some("application/x-www-form-urlencoded"), "a=1&".repeat(300).as_bytes(), &Disabled::default());
        assert_eq!(f.last().unwrap().name, "form:#rest");
    }
}
```

Add `pub mod body;` to `crates/vft-core/src/lib.rs` (between `pub mod chain;` and `pub mod config;`).

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test -p vft-core body::` → Expected: compile errors `cannot find function body_fields`, `cannot find type BodyFacts`, `cannot find value MAX_JSON_DEPTH`.

- [ ] **Step 5: Write `body.rs`**

Put this above the test module:

```rust
//! Body classification (DQ2 spec section 4.2): split a request body into the
//! fields its consumer parses, so each JSON string leaf, form value or key and
//! multipart part is inspected under its own name. Binary bodies get no text
//! field. Anything else stays one `<body>` field, as before. Every class can be
//! switched off by its `parse.body-*` id, which restores `<body>` for it.

use crate::graph::sinks::{self, Disabled};
use crate::request::{Field, Location};

/// Fields one body may produce; past it the rest is joined into one `#rest` field.
pub const MAX_BODY_FIELDS: usize = 256;
/// JSON nesting deeper than this is not split (the body is inspected whole).
pub const MAX_JSON_DEPTH: usize = 32;
/// Field names are labels, not payload: clipped to this many chars.
const MAX_NAME_CHARS: usize = 64;

/// What classification found, for the limits the shield records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    /// A text-class body (or part) carried bytes that are not valid UTF-8.
    pub non_utf8: bool,
    /// A body declared JSON, ndjson or multipart did not parse, or nested
    /// deeper than [`MAX_JSON_DEPTH`], and was inspected whole.
    pub unparsed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Json,
    Form,
    Multipart,
    Other,
}

struct Out {
    fields: Vec<Field>,
    facts: BodyFacts,
}

impl Out {
    fn push(&mut self, name: String, raw: String) {
        self.fields.push(Field { loc: Location::Body, name, raw });
    }
}

/// Where a classified byte run sits: the whole body, or one multipart part.
struct Scope {
    /// Name of the single text field when the run is not split.
    text_name: String,
    /// JSON Pointer prefix of the run's leaves.
    pointer: String,
    /// Multipart is parsed one level deep only.
    multipart_ok: bool,
}

impl Scope {
    fn top() -> Self {
        Scope { text_name: "<body>".into(), pointer: String::new(), multipart_ok: true }
    }

    fn part(name: &str) -> Self {
        Scope { text_name: format!("form:{}", clip(name)), pointer: format!("/{}", escape(name)), multipart_ok: false }
    }
}

/// Split `body` into inspectable fields. `content_type` is the request's
/// Content-Type value. A class whose `parse.body-*` id is in `off` falls back
/// to the single `<body>` field.
pub fn body_fields(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts) {
    let mut out = Out { fields: Vec::new(), facts: BodyFacts::default() };
    if body.is_empty() {
        return (out.fields, out.facts);
    }
    let class = classify(content_type.unwrap_or(""), body, off, &Scope::top(), &mut out);
    let rest = if class == Class::Json { "json:#rest" } else { "form:#rest" };
    cap(&mut out.fields, rest);
    (out.fields, out.facts)
}

fn classify(ct: &str, bytes: &[u8], off: &Disabled, scope: &Scope, out: &mut Out) -> Class {
    let lc = ct.to_ascii_lowercase();
    if is_binary(&lc, bytes) {
        if off.is(&sinks::PARSE_BODY_BINARY) {
            // Today's single lossy field; the bytes are binary, so no non-UTF-8 fact.
            out.push(scope.text_name.clone(), String::from_utf8_lossy(bytes).into_owned());
        }
        return Class::Other;
    }
    if lc.starts_with("multipart/") && scope.multipart_ok && !off.is(&sinks::PARSE_BODY_MULTIPART) {
        match param(ct, "boundary").filter(|b| b.len() <= 70).and_then(|b| parts(bytes, &b)) {
            Some(ps) => {
                for (i, p) in ps.into_iter().enumerate() {
                    part(i, p, off, out);
                }
                return Class::Multipart;
            }
            None => out.facts.unparsed = true,
        }
    }
    if lc.contains("x-www-form-urlencoded") && !off.is(&sinks::PARSE_BODY_FORM) {
        let text = text_of(bytes, out);
        form(&text, out);
        return Class::Form;
    }
    if !lc.contains("xml") && !off.is(&sinks::PARSE_BODY_JSON) {
        let ndjson = lc.contains("ndjson") || lc.contains("jsonl");
        let declared = ndjson || lc.contains("json");
        let sniffed = matches!(bytes.iter().find(|b| !b.is_ascii_whitespace()), Some(b'{' | b'['));
        if declared || sniffed {
            let mut leaves = Vec::new();
            if json(bytes, ndjson, &scope.pointer, &mut leaves) {
                out.fields.extend(leaves);
                return Class::Json;
            }
            if declared {
                out.facts.unparsed = true;
            }
        }
    }
    let text = text_of(bytes, out);
    out.push(scope.text_name.clone(), text);
    Class::Other
}

/// Binary by magic bytes, or a declared binary type whose bytes look binary.
/// A label alone never hides text (D13); zlib, GIF and PDF magic is printable,
/// so it also needs binary-looking bytes.
fn is_binary(lc: &str, b: &[u8]) -> bool {
    let strong = b.starts_with(&[0x1f, 0x8b])
        || b.starts_with(b"PK\x03\x04")
        || b.starts_with(b"\x89PNG\r\n\x1a\n")
        || b.starts_with(&[0xff, 0xd8, 0xff]);
    let weak = (b.len() >= 2 && b[0] == 0x78 && matches!(b[1], 0x01 | 0x5e | 0x9c | 0xda))
        || b.starts_with(b"GIF87a")
        || b.starts_with(b"GIF89a")
        || b.starts_with(b"%PDF-");
    let declared = lc.contains("protobuf")
        || lc.contains("octet-stream")
        || lc.starts_with("image/")
        || lc.starts_with("audio/")
        || lc.starts_with("video/");
    strong || ((weak || declared) && looks_binary(b))
}

/// A C0 control other than TAB, LF and CR, or bytes that are not valid UTF-8.
fn looks_binary(b: &[u8]) -> bool {
    b.iter().any(|&c| c < 0x20 && !matches!(c, b'\t' | b'\n' | b'\r')) || std::str::from_utf8(b).is_err()
}

/// The text of a text-class run; invalid UTF-8 is decoded lossily and noted.
fn text_of(bytes: &[u8], out: &mut Out) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            out.facts.non_utf8 = true;
            String::from_utf8_lossy(bytes).into_owned()
        }
    }
}

/// Split on raw `&` (before any decoding; `normalize` decodes each value), then
/// at the first `=`. Names are percent-decoded for the label only.
fn form(text: &str, out: &mut Out) {
    for piece in text.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = piece.split_once('=').unwrap_or((piece, ""));
        let name = clip(&crate::normalize::percent_decode_lossy(&k.replace('+', " ")));
        if !k.is_empty() {
            out.push(format!("form-key:{name}"), k.to_string());
        }
        if !v.is_empty() {
            out.push(format!("form:{name}"), v.to_string());
        }
    }
}

/// Parse one JSON document (or ndjson lines, as `/<line>` members) and collect
/// its leaves under `prefix`. False when it does not parse or nests too deep.
fn json(bytes: &[u8], ndjson: bool, prefix: &str, leaves: &mut Vec<Field>) -> bool {
    use serde_json::Value;
    if ndjson {
        let Ok(text) = std::str::from_utf8(bytes) else { return false };
        for (i, line) in text.lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
            let Ok(v) = serde_json::from_str::<Value>(line) else { return false };
            if !walk(&v, &format!("{prefix}/{i}"), 0, true, leaves) {
                return false;
            }
        }
        return true;
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => walk(&v, prefix, 0, true, leaves),
        Err(_) => false,
    }
}

fn walk(v: &serde_json::Value, ptr: &str, depth: usize, expand: bool, leaves: &mut Vec<Field>) -> bool {
    use serde_json::Value;
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match v {
        Value::String(s) => {
            if expand {
                if let Some(inner) = nested(s) {
                    let mut sub = Vec::new();
                    if walk(&inner, ptr, depth + 1, false, &mut sub) {
                        leaves.extend(sub);
                        return true;
                    }
                }
            }
            leaves.push(leaf(format!("json:{}", clip(ptr)), s.clone()));
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                if !walk(x, &format!("{ptr}/{i}"), depth + 1, expand, leaves) {
                    return false;
                }
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                let p = format!("{ptr}/{}", escape(k));
                if !k.chars().all(is_ident) {
                    leaves.push(leaf(format!("json-key:{}", clip(&p)), k.clone()));
                }
                if !walk(x, &p, depth + 1, expand, leaves) {
                    return false;
                }
            }
        }
        _ => {}
    }
    true
}

/// A string leaf that is itself a JSON object or array (expanded once, depth <= 2).
fn nested(s: &str) -> Option<serde_json::Value> {
    let t = s.trim_start();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(s).ok().filter(|v| v.is_object() || v.is_array())
}

fn leaf(name: String, raw: String) -> Field {
    Field { loc: Location::Body, name, raw }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '$' | '@')
}

/// RFC 6901 reference token escaping.
fn escape(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_NAME_CHARS).collect()
}

/// A `key=value` parameter of a header value such as Content-Type or
/// Content-Disposition (the first `;` item is the type itself).
fn param(value: &str, key: &str) -> Option<String> {
    value
        .split(';')
        .skip(1)
        .find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim().eq_ignore_ascii_case(key).then(|| v.trim().trim_matches('"').to_string())
        })
        .filter(|v| !v.is_empty())
}

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if n.is_empty() || from > h.len() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w == n).map(|p| p + from)
}

/// The parts of a multipart body (content between delimiter lines), or None
/// when it is malformed: no delimiter, or no closing `--boundary--`.
fn parts<'a>(body: &'a [u8], boundary: &str) -> Option<Vec<&'a [u8]>> {
    let delim = format!("--{boundary}").into_bytes();
    let mut at = find(body, &delim, 0)? + delim.len();
    let mut out = Vec::new();
    loop {
        if body[at..].starts_with(b"--") {
            return Some(out);
        }
        let start = find(body, b"\n", at)? + 1;
        let mut next = start;
        let end = loop {
            let d = find(body, &delim, next)?;
            if d >= 1 && body[d - 1] == b'\n' {
                break d;
            }
            next = d + 1;
        };
        let mut content_end = end - 1;
        if content_end > start && body[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        out.push(&body[start..content_end.max(start)]);
        at = end + delim.len();
    }
}

/// One multipart part: its `filename` is a field of its own; its content is
/// classified by the part's Content-Type (one level: no nested multipart).
fn part(i: usize, p: &[u8], off: &Disabled, out: &mut Out) {
    let (head, content) = match find(p, b"\r\n\r\n", 0) {
        Some(h) => (&p[..h], &p[h + 4..]),
        None => match find(p, b"\n\n", 0) {
            Some(h) => (&p[..h], &p[h + 2..]),
            None => (p, &p[p.len()..]),
        },
    };
    let head = String::from_utf8_lossy(head);
    let (mut name, mut filename, mut ct) = (None, None, String::new());
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("content-disposition") {
            name = param(v, "name");
            filename = param(v, "filename");
        } else if k.trim().eq_ignore_ascii_case("content-type") {
            ct = v.trim().to_string();
        }
    }
    let name = name.unwrap_or_else(|| format!("part{i}"));
    if let Some(f) = filename {
        out.push(format!("form-file:{}", clip(&name)), f);
    }
    classify(&ct, content, off, &Scope::part(&name), out);
}

/// At most [`MAX_BODY_FIELDS`] fields: the overflow is joined (one per line)
/// into the last one and never dropped.
fn cap(fields: &mut Vec<Field>, rest_name: &str) {
    if fields.len() <= MAX_BODY_FIELDS {
        return;
    }
    let rest: Vec<String> = fields.drain(MAX_BODY_FIELDS - 1..).map(|f| f.raw).collect();
    fields.push(Field { loc: Location::Body, name: rest_name.into(), raw: rest.join("\n") });
}
```

- [ ] **Step 6: Run the unit tests**

Run: `cargo test -p vft-core body::` → Expected: PASS (19 tests).

- [ ] **Step 7: Write the failing request, shield and detector tests**

In `crates/vft-core/src/request.rs` tests, add:

```rust
    #[test]
    fn the_body_is_classified_by_its_content_type() {
        let mut req = Request::get("/x");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), "application/json".into()));
        req.body = br#"{"a":"1"}"#.to_vec();
        let names: Vec<String> = req.fields().into_iter().filter(|f| f.loc == Location::Body).map(|f| f.name).collect();
        assert_eq!(names, vec!["json:/a"]);
        let off = crate::graph::sinks::Disabled::resolve(&["parse.body-json".into()]);
        let (f, _) = req.fields_with(&off);
        assert!(f.iter().any(|f| f.loc == Location::Body && f.name == "<body>"));
        assert_eq!(req.header("content-type"), Some("application/json"));
    }
```

In the `crates/vft-core/src/shield.rs` tests module, add (if a helper named `fixture_lines` already exists there, reuse it and drop this copy):

```rust
    /// The `kind` cases (`accept` / `reject`) of a fixture file, one `kind<TAB>text` per line.
    fn fixture_lines(src: &'static str, kind: &str) -> Vec<&'static str> {
        src.lines().filter_map(|l| l.strip_prefix(kind)?.strip_prefix('\t')).collect()
    }

    fn body_case() -> &'static str {
        fixture_lines(include_str!("../tests/fixtures/body_cases.txt"), "accept")[0]
    }

    fn pct(s: &str) -> String {
        s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
    }

    fn body_req(ct: &str, body: Vec<u8>) -> Request {
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), ct.into()));
        req.body = body;
        req
    }

    fn fields_of(j: &Judgment, id: &str) -> Vec<String> {
        j.contributions.iter().filter(|c| c.construct.as_deref() == Some(id)).filter_map(|c| c.field.as_ref().map(|f| f.name.clone())).collect()
    }

    #[test]
    fn an_attack_in_a_json_leaf_is_found_under_the_leaf_name() {
        let body = serde_json::json!({"a": {"b": body_case()}}).to_string();
        let j = shield().inspect(&body_req("application/json", body.into_bytes()));
        assert_eq!(j.verdict, Verdict::Block, "{} {}", j.score, j.decided_by.msg);
        assert!(j.contributions.iter().any(|c| c.field.as_ref().is_some_and(|f| f.loc == Location::Body && f.name == "json:/a/b")), "{:?}", j.contributions);
    }

    #[test]
    fn a_form_id_value_gets_api_safety_on_its_last_name_segment() {
        let j = shield().inspect(&body_req("application/x-www-form-urlencoded", format!("id={}", pct(body_case())).into_bytes()));
        assert_eq!(fields_of(&j, "api.type-violation"), vec!["form:id".to_string()]);
        let j = shield().inspect(&body_req("application/json", serde_json::json!({"user": {"id": body_case()}}).to_string().into_bytes()));
        assert_eq!(fields_of(&j, "api.type-violation"), vec!["json:/user/id".to_string()]);
    }

    #[test]
    fn disabling_the_parse_ids_restores_the_single_body_field() {
        let mut cfg = Config::default();
        cfg.shield.disabled = ["parse.body-binary", "parse.body-json", "parse.body-form", "parse.body-multipart"].map(String::from).to_vec();
        let body = serde_json::json!({"a": {"b": body_case()}}).to_string();
        let j = Shield::new(cfg).inspect(&body_req("application/json", body.into_bytes()));
        assert_eq!(j.verdict, Verdict::Block);
        assert!(j.contributions.iter().filter_map(|c| c.field.as_ref()).filter(|f| f.loc == Location::Body).all(|f| f.name == "<body>"));
    }

    #[test]
    fn invalid_utf8_in_a_text_body_emits_the_limit_but_binary_does_not() {
        let j = shield().inspect(&body_req("text/plain", b"caf\xe9 au lait".to_vec()));
        assert_eq!(fields_of(&j, "limit.body-non-utf8"), vec!["<body>".to_string()]);
        let j = shield().inspect(&body_req("application/x-protobuf", vec![0x0a, 0x02, 0xff, 0xfe, 0x10, 0x01]));
        assert!(!has_construct(&j, "limit.body-non-utf8"));
        assert!(j.contributions.iter().all(|c| c.field.as_ref().is_none_or(|f| f.loc != Location::Body)), "a binary body has no text field");
        let mut cfg = Config::default();
        cfg.shield.disabled = vec!["limit.body-non-utf8".into()];
        assert!(!has_construct(&Shield::new(cfg).inspect(&body_req("text/plain", b"caf\xe9".to_vec())), "limit.body-non-utf8"));
    }

    #[test]
    fn an_unparsed_json_body_is_informational_only() {
        let j = shield().inspect(&body_req("application/json", b"{\"a\":".to_vec()));
        let c = j.contributions.iter().find(|c| c.construct.as_deref() == Some("limit.body-unparsed")).expect("limit.body-unparsed recorded");
        assert_eq!(c.points, 0.0);
        assert_eq!(j.verdict, Verdict::Allow);
        assert_eq!(j.score, 0);
    }
```

If `Option::is_none_or` is not available on the workspace toolchain, write `!c.field.as_ref().is_some_and(|f| f.loc == Location::Body)` instead.

In `crates/vft-core/src/detect.rs` tests, add:

```rust
    #[test]
    fn api_safety_uses_the_last_segment_of_a_body_field_name_only() {
        let a = graph::Analysis { reachable: vec![sinks::sql::UNION_SELECT.pattern()], latent: vec![], graph_truncated: false };
        let d = Disabled::default();
        let n = normalize("x", &Options::default());
        for (loc, name, hit) in [
            (Location::Body, "form:id", true),
            (Location::Body, "json:/user/id", true),
            (Location::Body, "json:/user_id", true),
            (Location::Body, "json:/identity", false),
            (Location::Query, "x:id", false),
            (Location::Query, "id", true),
        ] {
            let f = Field { loc, name: name.into(), raw: "x".into() };
            let e = ApiSafetyDetector.assess(&ctx_for(&f, &n, &a, &d));
            assert_eq!(e.value == FourValued::Dangerous, hit, "{loc:?} {name}");
        }
    }
```

In `crates/vft-core/tests/fuzz_props.rs`, inside `proptest! { … }`, add:

```rust
    #[test]
    fn body_classification_never_panics(
        ct in prop_oneof![
            Just("application/json"),
            Just("application/x-ndjson"),
            Just("application/x-www-form-urlencoded"),
            Just("multipart/form-data; boundary=b"),
            Just("application/x-protobuf"),
            Just(""),
        ],
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let (fields, _) = vft_core::body::body_fields(Some(ct), &bytes, &vft_core::graph::sinks::Disabled::default());
        prop_assert!(fields.len() <= vft_core::body::MAX_BODY_FIELDS);
    }
```

- [ ] **Step 8: Run them to verify they fail**

Run: `cargo test -p vft-core the_body_is_classified api_safety_uses_the_last_segment an_attack_in_a_json_leaf a_form_id_value disabling_the_parse_ids invalid_utf8_in_a_text_body an_unparsed_json_body`
Expected: compile errors for `fields_with` and `header`; after Step 9's request change only, the shield and detector tests fail on their assertions (no `json:/a/b` field, no `form:id` api hit, no body limits).

- [ ] **Step 9: Wire it in**

`crates/vft-core/src/request.rs`: add `use crate::body::BodyFacts;` and `use crate::graph::sinks::Disabled;` at the top. Replace the doc comment and body of `fields` (lines 69–133) with:

```rust
    /// The value of the first header named `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// All inspectable fields with every body class on (see [`Request::fields_with`]).
    pub fn fields(&self) -> Vec<Field> {
        self.fields_with(&Disabled::default()).0
    }

    /// All inspectable fields: query keys and values, headers, cookie names
    /// and values, and the body classified by [`crate::body::body_fields`]
    /// (JSON leaves, form values and keys, multipart parts, or one `<body>`
    /// field; none for a binary body). A `parse.body-*` id in `off` restores
    /// `<body>` for its class. The path is inspected separately (it has
    /// path-specific semantics such as traversal and recon). Also returns what
    /// body classification found, for the shield's body limits.
    ///
    /// Not inspected: the `Connection` header (hop-by-hop, stripped before
    /// forwarding) and `Content-Length` (validated by the HTTP front end), and
    /// a raw `Cookie` header whose every segment is a well-formed
    /// `token=value` pair (its names and values are inspected as cookie
    /// fields instead).
    pub fn fields_with(&self, off: &Disabled) -> (Vec<Field>, BodyFacts) {
        let mut out = Vec::new();
        // (the query, header and cookie loops of the old `fields`, unchanged)
        let (body, facts) = crate::body::body_fields(self.header("content-type"), &self.body, off);
        out.extend(body);
        (out, facts)
    }
```

Move the three existing loops (query, headers, cookies; old lines 80–124) verbatim to where the comment `(the query, header and cookie loops …)` stands, and delete that comment line. The old `if !self.body.is_empty() { … "<body>" … }` block is gone (`body_fields` returns no field for an empty body).

`crates/vft-core/src/shield.rs`, `inspect_view`: replace `'fields: for field in req.fields() {` with

```rust
        let (fields, body_facts) = req.fields_with(off);
        'fields: for field in fields {
```

and, right after the `limit.header-non-utf8` block (after line 183), add:

```rust
        let body_ref = || Some(FieldRef { loc: crate::request::Location::Body, name: "<body>".into() });
        if body_facts.non_utf8 && !off.is(&sinks::LIMIT_BODY_NON_UTF8) {
            rec.record(
                "adapter",
                self.cfg.scoring.weight_api,
                body_ref(),
                Evidence::new(FourValued::Suspicious, 0.6, vec![sinks::LIMIT_BODY_NON_UTF8.pattern()], "non-UTF-8 bytes in a text body"),
            );
        }
        if body_facts.unparsed && !off.is(&sinks::LIMIT_BODY_UNPARSED) {
            // Informational: engine weight 0, so 0 points; it says why the body stayed whole.
            rec.record(
                "adapter",
                0.0,
                body_ref(),
                Evidence::new(
                    FourValued::Suspicious,
                    0.0,
                    vec![sinks::LIMIT_BODY_UNPARSED.pattern()],
                    "body declared JSON, ndjson or multipart did not parse; inspected whole",
                ),
            );
        }
```

`crates/vft-core/src/detect.rs`, `ApiSafetyDetector::assess`: replace the first two statements (lines 94–96) with

```rust
        let lname = ctx.field.name.to_lowercase();
        // Body leaves carry their parameter in the last name segment
        // (`form:id`, `json:/user/id`); other locations use the whole name.
        let name = if ctx.field.loc == Location::Body {
            lname.rsplit([':', '/']).next().unwrap_or(&lname)
        } else {
            lname.as_str()
        };
        let looks_numeric_field = name == "id" || name.ends_with("_id") || name == "page" || name == "count";
```

- [ ] **Step 10: Run the tests**

Run: `cargo test -p vft-core` → Expected: PASS, including the new tests and every existing body test (an untyped body still becomes `<body>`).
Run: `cargo test -p vft-core --test fuzz_props body_classification_never_panics` → Expected: PASS.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green. `vft-proxy`'s `host_is_inspected_and_raw_cookie_not_double_counted` still calls `fields()` and passes unchanged.

- [ ] **Step 11: Measure (dev only)**

```bash
cargo build --release -p vft-cli
bash eval/ab_dev.sh body "--disable parse.body-binary --disable parse.body-json --disable parse.body-form --disable parse.body-multipart" ""
for c in binary json form multipart; do
  bash eval/ab_dev.sh "body-$c" "--disable parse.body-$c" ""
done
bash eval/ab_dev.sh body-nonutf8 "--disable limit.body-non-utf8" ""
bash eval/decision_gate.sh diff "$VFT_BASELINE" > "$VFT_RUNS/serve-diff-body.txt"; echo "diff exit $?"
tail -n 2 "$VFT_RUNS/serve-diff-body.txt"
```

Read only the summary lines of each `$VFT_RUNS/body*-ab.txt` (ΔTP, ΔFP, McNemar, CIs, the fallen-row list) and the last two lines of the serve diff; the changed serve rows are read once, in Task 5.

Expected: `body` ΔFP ≤ 0; `body-binary` ΔTP 0 (no malicious dev body is binary; spec section 4.2); `diff exit 0` with `bans_from_allowed 0` and `invariant_violations 0`. The `body` row includes the `ApiSafetyDetector` widening: with the four ids off every body is `<body>`, so the last-segment rule has nothing to act on in arm A.

Stop rule (every A/B above): if ΔFP > 0, or any malicious row falls (body classification has no expected losses), stop and report NEEDS_CONTEXT with the `-ab.txt` file. Do not tune. A `body-nonutf8` A/B with ΔFP > 0 falls under the same rule (the limit is new scoring).

Record in the task report: the ΔTP / ΔFP line of each of the six `-ab.txt` files, and the two serve-diff lines.

- [ ] **Step 12: Commit**

```bash
git add crates/vft-core/src/body.rs crates/vft-core/src/lib.rs crates/vft-core/src/request.rs crates/vft-core/src/graph/sinks/mod.rs crates/vft-core/src/shield.rs crates/vft-core/src/detect.rs crates/vft-core/tests/fuzz_props.rs crates/vft-core/tests/fixtures/body_cases.txt
git commit -m "feat(core): classify request bodies into JSON, form and multipart fields" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Corroboration de-duplication by `(origin field, family)` *(measured: `corroboration`, against a saved binary)*

**Files:**
- Modify: `crates/vft-core/src/score.rs:1-101` (`arbitrate`), tests module
- Modify: `crates/vft-core/src/judgment.rs:6` (`Family` derive)
- Test: `crates/vft-core/src/score.rs` (tests module)

**Interfaces:**
- Consumes: Task 3's body field names (each leaf is its own origin, D10); `sinks::AI_ANOMALY_SCORE`, `sinks::API_TYPE_VIOLATION`; `eval/ab_dev.sh` with binA.
- Produces: `pub fn origin(f: &FieldRef) -> FieldRef` in `score.rs` (the `FieldRef` without a derived `#…` suffix; a `#` directly after `:` is part of the name, so `json:#rest` stays whole); `Family` derives `Hash`. `arbitrate`'s signature and `Arbitration` are unchanged, and the points still sum to the unrounded score. No new option; `scoring.corroboration_cap` keeps its meaning.

Rules (spec section 4.4):
1. One counted item per `(origin field, key)`, keeping the strongest. The key is the first pattern's family; for `ai.anomaly-score` and `api.type-violation` (derived items) it is the construct id, because `api.type-violation` has family `Sqli`; for an item with no pattern it is the engine name. Chunks and split halves of one field share its origin, so they collapse.
2. The top item is the first maximal one, derived or not.
3. A derived item and any other item on the same origin never corroborate each other: when either one is the top, the other adds nothing. A derived item on another origin still corroborates.

- [ ] **Step 1: Save the pre-change binary**

Run (on the Task 3 commit, before editing anything):

```bash
cargo build --release -p vft-cli
cp target/release/venusflytrap.exe "$VFT_RUNS/bin-before-corroboration.exe"
git status --short crates
```

Expected: the copy exists; `git status` prints nothing under `crates`. If it prints anything, stop: the saved binary would not be the Task 3 commit.

- [ ] **Step 2: Write the failing tests**

Add to the `score.rs` tests module:

```rust
    use crate::judgment::{Family, Pattern};
    use crate::request::Location;

    fn on(field: &str, v: FourValued, w: f32, engine_weight: f32, family: Family, id: &str) -> Scored {
        Scored {
            engine: "t".into(),
            engine_weight,
            field: Some(FieldRef { loc: Location::Body, name: field.into() }),
            evidence: Evidence::new(v, w, vec![Pattern::new(family, id)], "x"),
        }
    }

    fn sums_to_score(a: &Arbitration) -> bool {
        (a.points.iter().sum::<f32>() - f32::from(a.score)).abs() <= 0.5
    }

    #[test]
    fn one_family_on_one_field_counts_once_at_its_strongest() {
        let cfg = ScoringConfig::default();
        // A latent graph item (27.5) recorded before a signature of the same family (72).
        let ev = vec![
            on("json:/q", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword"),
            on("json:/q", FourValued::Dangerous, 0.8, 0.9, Family::Sqli, "sig.union-all-select"),
        ];
        let a = arbitrate(&ev, &cfg, false);
        assert_eq!(a.score, 72);
        assert_eq!(a.points[0], 0.0);
        assert!(sums_to_score(&a));
    }

    #[test]
    fn different_families_on_one_field_still_corroborate() {
        let cfg = ScoringConfig::default();
        let ev = vec![
            on("json:/a", FourValued::Dangerous, 0.95, 1.0, Family::Sqli, "sqli.union-select"),
            on("json:/a", FourValued::Suspicious, 0.5, 1.0, Family::Xss, "xss.html-tag"),
        ];
        assert_eq!(arbitrate(&ev, &cfg, false).score, 98); // 95 + 2.75
    }

    #[test]
    fn body_leaves_are_separate_origins() {
        let cfg = ScoringConfig::default();
        let ev = vec![
            on("json:/a", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword"),
            on("json:/b", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword"),
        ];
        assert_eq!(arbitrate(&ev, &cfg, false).score, 30); // 27.5 + 2.75
    }

    #[test]
    fn a_derived_item_does_not_corroborate_its_own_field() {
        let cfg = ScoringConfig::default();
        let graph = on("form:q", FourValued::Dangerous, 0.95, 1.0, Family::Sqli, "sqli.union-select");
        let ai_same = on("form:q", FourValued::Dangerous, 0.6, 0.5, Family::Anomaly, "ai.anomaly-score");
        let a = arbitrate(&[graph.clone(), ai_same], &cfg, false);
        assert_eq!(a.score, 95);
        assert_eq!(a.points[1], 0.0);
        assert!(sums_to_score(&a));
        // On another field it still corroborates: 95 + 3.
        let ai_other = on("form:other", FourValued::Dangerous, 0.6, 0.5, Family::Anomaly, "ai.anomaly-score");
        assert_eq!(arbitrate(&[graph, ai_other], &cfg, false).score, 98);
    }

    #[test]
    fn a_derived_top_is_not_corroborated_by_its_own_field() {
        let cfg = ScoringConfig::default();
        // api.type-violation is Dangerous 0.7 at weight_api 0.6: 42 points. Its family is Sqli,
        // so it must not collapse into a Sqli graph item either: it is keyed by its id.
        let api = on("form:id", FourValued::Dangerous, 0.7, 0.6, Family::Sqli, "api.type-violation");
        let same = on("form:id", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword");
        let a = arbitrate(&[api.clone(), same], &cfg, false);
        assert_eq!(a.score, 42, "the derived item is the top and its own field adds nothing");
        assert!(sums_to_score(&a));
        let other = on("form:x", FourValued::Suspicious, 0.5, 1.0, Family::CommandInjection, "cmd.shell-meta");
        assert_eq!(arbitrate(&[api, other], &cfg, false).score, 45); // 42 + 2.75
    }

    #[test]
    fn origin_strips_only_a_derived_suffix() {
        let f = |n: &str| FieldRef { loc: Location::Query, name: n.into() };
        assert_eq!(origin(&f("id#2")).name, "id");
        assert_eq!(origin(&f("json:#rest")).name, "json:#rest");
        assert_eq!(origin(&f("<body>")).name, "<body>");
        assert_eq!(origin(&f("#x")).name, "#x");
        assert_eq!(origin(&f("id#2")).loc, Location::Query);
    }
```

If the module already imports any of these names, drop the duplicate `use`. The existing `duplicate_construct_on_same_field_counts_once`, `corroboration_is_capped` and `points_sum_to_the_unrounded_score` stay as they are and must still pass.

- [ ] **Step 3: Run them to verify they fail**

Run: `cargo test -p vft-core score::` → Expected: compile error `cannot find function origin`. With a stub `pub fn origin(f: &FieldRef) -> FieldRef { f.clone() }` in place, `one_family_on_one_field_counts_once_at_its_strongest` (75), `a_derived_item_does_not_corroborate_its_own_field` (98), `a_derived_top_is_not_corroborated_by_its_own_field` and `origin_strips_only_a_derived_suffix` fail.

- [ ] **Step 4: Implement**

`crates/vft-core/src/judgment.rs` line 6, on `Family`: `#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]`.

`crates/vft-core/src/score.rs`: replace the imports at the top with

```rust
use std::collections::hash_map::{Entry, HashMap};

use crate::config::ScoringConfig;
use crate::graph::sinks;
use crate::judgment::{Family, FieldRef, Verdict};
use crate::lattice::{Evidence, FourValued};
```

Add above `arbitrate`:

```rust
/// What a counted item is evidence of, within its origin field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Family(Family),
    /// A derived item, keyed by construct id (`api.type-violation` has family Sqli).
    Derived(String),
    /// An item with no pattern.
    Engine(String),
}

/// `ai.anomaly-score` and `api.type-violation` are computed from the graph
/// result on their own field: not independent evidence of it (D10).
fn is_derived(construct: &str) -> bool {
    construct == sinks::AI_ANOMALY_SCORE.id || construct == sinks::API_TYPE_VIOLATION.id
}

/// The field an item is about, without a derived `#…` suffix (`id#2` is `id`).
/// A `#` right after `:` (`json:#rest`) or at the start is part of the name.
pub fn origin(f: &FieldRef) -> FieldRef {
    let cut = f.name.char_indices().find(|&(i, c)| c == '#' && i > 0 && !f.name[..i].ends_with(':')).map(|(i, _)| i);
    FieldRef { loc: f.loc, name: cut.map_or_else(|| f.name.clone(), |i| f.name[..i].to_string()) }
}

struct Counted {
    item: usize,
    raw: f32,
    origin: Option<FieldRef>,
    derived: bool,
}
```

In `arbitrate`, replace everything from the comment `// One contribution per (field, construct)` (line 49) through the end of the `for (n, &(i, raw)) in counted.iter().enumerate() { … }` loop (line 90) with:

```rust
    // One item per (origin field, family), the strongest: chunks and split
    // halves of a field share its origin, and the graph and signature items of
    // one family on one field are one piece of evidence (D10).
    let mut slot: HashMap<(Option<FieldRef>, Key), usize> = HashMap::new();
    let mut counted: Vec<Counted> = Vec::new();
    for (i, s) in items.iter().enumerate().filter(|(_, s)| s.evidence.value.is_threat()) {
        let raw = value_points(s.evidence.value) * s.evidence.weight * s.engine_weight;
        let o = s.field.as_ref().map(origin);
        let (key, derived) = match s.evidence.patterns.first() {
            Some(p) if is_derived(&p.name) => (Key::Derived(p.name.clone()), true),
            Some(p) => (Key::Family(p.family), false),
            None => (Key::Engine(s.engine.clone()), false),
        };
        let c = Counted { item: i, raw, origin: o.clone(), derived };
        match slot.entry((o, key)) {
            Entry::Occupied(e) => {
                let n = *e.get();
                if raw > counted[n].raw {
                    counted[n] = c;
                }
            }
            Entry::Vacant(e) => {
                e.insert(counted.len());
                counted.push(c);
            }
        }
    }

    // The first maximal item is the top.
    let mut top_n: Option<usize> = None;
    let mut top = 0.0f32;
    for (n, c) in counted.iter().enumerate() {
        if c.raw > top {
            top = c.raw;
            top_n = Some(n);
        }
    }
    // A derived item and another item on the same origin never corroborate
    // each other, whichever of the two is the top (D10).
    let corroborates = |n: usize| -> bool {
        let Some(t) = top_n else { return false };
        n != t && !(counted[n].origin == counted[t].origin && (counted[n].derived || counted[t].derived))
    };
    let rest: f32 = (0..counted.len()).filter(|&n| corroborates(n)).map(|n| counted[n].raw).sum();
    let corroboration = (rest * 0.1).min(cfg.corroboration_cap);

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        // Damp, but never below the band the strongest danger reaches alone.
        score = (score * 0.9).max(band_floor(top, cfg));
    }

    // Points: the top keeps its raw points, the corroborating items share the
    // corroboration in proportion, everything else adds 0; clamping and damping
    // then scale every item alike, so the points sum to the unrounded score.
    let mut points = vec![0.0f32; items.len()];
    let share = if rest > 0.0 { corroboration / rest } else { 0.0 };
    for (n, c) in counted.iter().enumerate() {
        points[c.item] = if Some(n) == top_n {
            c.raw
        } else if corroborates(n) {
            c.raw * share
        } else {
            0.0
        };
    }
```

Leave the rest of `arbitrate` (from `let unscaled = top + corroboration;`) unchanged. The block above replaces the old `seen` set, `top`, `rest`, `corroboration`, the conflict damping and the `top_n` / `best` loop; none of them may remain.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p vft-core score::` → Expected: PASS (old and new).
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green; `crates/vft-core/tests/points.rs` passes unchanged. If a shield or proxy test that asserted a verdict now fails because its score relied on an AI or API item corroborating its own field, do not edit its expectation: report the test name and the old and new score (NEEDS_CONTEXT).

- [ ] **Step 6: Measure (dev only) against the saved binary**

```bash
cargo build --release -p vft-cli
bash eval/ab_dev.sh corroboration "" "" "$VFT_RUNS/bin-before-corroboration.exe"
py -I -X utf8 - "$VFT_RUNS" > "$VFT_RUNS/corroboration-hist.txt" <<'EOF'
import csv, sys
from collections import Counter
for tag in ("a", "b"):
    with open(f"{sys.argv[1]}/corroboration-{tag}.csv", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    for label in ("0", "1"):
        h = Counter(min(int(r["score"]) // 10, 9) for r in rows if r["label"] == label)
        cells = " ".join(f"{b * 10}-{b * 10 + 9 if b < 9 else 100}:{h[b]}" for b in range(10))
        print(f"{tag} label={label} {cells}")
    v = Counter(r["lib_verdict"] for r in rows)
    print(f"{tag} verdicts {dict(sorted(v.items()))} monitor={v['Monitor']}")
EOF
cat "$VFT_RUNS/corroboration-hist.txt"
bash eval/decision_gate.sh diff "$VFT_BASELINE" > "$VFT_RUNS/serve-diff-corroboration.txt"; echo "diff exit $?"
tail -n 2 "$VFT_RUNS/serve-diff-corroboration.txt"
```

Arm a is the Task 3 scorer, arm b this one. Expected: ΔFP ≤ 0 (spec section 4.4 expects about 0, because no single item scores between 55 and 70); the benign histogram does not move up; `diff exit 0`.

Stop rule: ΔFP > 0, or any malicious row in the fallen list of `corroboration-ab.txt`, stops the task: report NEEDS_CONTEXT with that file. A malicious row that falls here is a corroboration-dependent TP. It becomes a justification row (reason "its score depended on a derived item corroborating its own field", phase DQ3) only when the owner rules so. Do not tune.

Record in the task report: the ΔTP / ΔFP line, the McNemar lines, the histogram lines per arm and label, both Monitor counts, and the two serve-diff lines.

- [ ] **Step 7: Commit**

```bash
git add crates/vft-core/src/score.rs crates/vft-core/src/judgment.rs
git commit -m "feat(core): corroborate once per origin field and family; derived items never corroborate their own field" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Final acceptance, `eval/RESULTS-DQ2.md`, status line

**Files:**
- Create: `eval/RESULTS-DQ2.md`
- Modify: `docs/BENCHMARK.md` (one status line after line 9, the DQ1 line)

**Interfaces:**
- Consumes: every earlier task; the `-ab.txt` files of Task 2 (the `gate.cmd-position` step, under the step name Task 2 passed to `ab_dev.sh`), Task 3 (`body`, `body-binary`, `body-json`, `body-form`, `body-multipart`, `body-nonutf8`) and Task 4 (`corroboration`), plus `corroboration-hist.txt`; `eval/decision_gate.sh diff`; `venusflytrap ablate`; the `bench_http` example; `M:/Projects/venusflytrap-recall-runs/m0/` (`seeds.jsonl`, `mutants.jsonl`, `seeds.csv`, `mutants.csv`).
- Produces: documents only. No code changes in this task. From Step 6 on (held-out scored), no code changes at all: a failed check after that point is reported, not fixed.

Scope as measured: this DQ2 plan ships the shell command-position rule (Task 2), body classification (Task 3) and corroboration de-duplication (Task 4). The SQL grammar gate (spec section 4.3) and per-context canonicalisation (section 4.5) are deferred for the owner's decision. The spec's exit target (dev FP ≤ ~0.6%, at most 99 rows) is therefore not expected. The results report the reached dev FP and the deferred items as measured. **Merge rule:** every step has dev ΔFP ≤ 0, and no TP is lost outside the justification list.

The manifest's sides are `dev` (16,939 rows) and `heldout` (16,938 rows); `--side heldout` is the held-out run.

- [ ] **Step 1: Final checks on the finished tree**

```bash
cargo test --workspace && cargo clippy --all-targets -- -D warnings
cargo test -p vft-core --features ts --test ts_bindings
py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v
test -d ui/node_modules && (cd ui && npm run check && npm test) || echo "ui/node_modules absent: UI check not run"
git status --short
```

Expected: all green. `ts_bindings` passes with no regeneration (`ConstructKind` has no ts-rs derive, so nothing new reaches the wire). `git status` is clean apart from `.superpowers/`.

- [ ] **Step 2: Final dev run and clusters**

```bash
cargo build --release -p vft-cli && cargo build --release -p vft-cli --example bench_http
"$B" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side dev --out "$VFT_RUNS/final-dev.csv" > "$VFT_RUNS/final-dev.json"
py -I -X utf8 eval/clusters.py "$VFT_RUNS/final-dev.csv" --manifest "$VFT_MANIFEST" --side dev --top 15 > "$VFT_RUNS/clusters-final.txt"
```

Expected: exit 0. Do not open any corpus file that `clusters-final.txt` names; the results cite rel paths only.

- [ ] **Step 3: Dev baseline from main's code, and the paired comparison**

Build main's code (`a990f26`) in a temporary worktree, score dev with it, and remove the worktree:

```bash
BASE_WT="$(git rev-parse --show-toplevel)/.superpowers/dq2/base-a990f26"
git worktree add --detach "$BASE_WT" a990f26
cargo build --release -p vft-cli --manifest-path "$BASE_WT/Cargo.toml" --target-dir "$BASE_WT/target"
cp "$BASE_WT/target/release/venusflytrap.exe" "$VFT_RUNS/bin-a990f26.exe"
git worktree remove --force "$BASE_WT"
"$VFT_RUNS/bin-a990f26.exe" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side dev --out "$VFT_RUNS/base-dev.csv" > "$VFT_RUNS/base-dev.json"
py -I -X utf8 eval/compare_runs.py --intersect "$VFT_RUNS/base-dev.csv" "$VFT_RUNS/final-dev.csv" > "$VFT_RUNS/final-vs-base.txt"; echo "compare exit $?"
```

Expected: `base-dev.json` → `library` shows `tp` 149, `fp` 147, `tn` 16463, `fn` 180. If it differs, apply the Host facts procedure (a corpus file deleted since the baseline) and record the absent rel paths; any other difference is a stop (the baseline would not be main). `compare exit 1` is expected, because DQ2 changes decisions; `final-vs-base.txt` holds the McNemar b, c and p per class.

List every malicious dev row that fell (Challenge/Block to Allow/Monitor) between main and the final build:

```bash
py -I -X utf8 - "$VFT_RUNS/base-dev.csv" "$VFT_RUNS/final-dev.csv" > "$VFT_RUNS/final-fallen.txt" <<'EOF'
import csv, sys
def load(p):
    with open(p, encoding="utf-8", newline="") as f:
        return {r["rel"]: r for r in csv.DictReader(f)}
base, final = load(sys.argv[1]), load(sys.argv[2])
hit = {"Challenge", "Block"}
print("rel\tbase_verdict\tfinal_verdict\tbase_top\tfinal_top\tfinal_top_field")
for rel in sorted(set(base) & set(final)):
    b, f = base[rel], final[rel]
    if b["label"] == "1" and b["lib_verdict"] in hit and f["lib_verdict"] not in hit:
        print("\t".join([rel, b["lib_verdict"], f["lib_verdict"], b.get("top", ""), f.get("top", ""), f.get("top_field", "")]))
print(f"# only in base: {len(set(base) - set(final))}, only in final: {len(set(final) - set(base))}")
EOF
cat "$VFT_RUNS/final-fallen.txt"
for rel in $(tail -n +2 "$VFT_RUNS/final-fallen.txt" | grep -v '^#' | cut -f1); do
  echo "$rel: $(grep -lF "$rel" "$VFT_RUNS"/*-ab.txt | xargs -r -n1 basename | tr '\n' ' ')"
done > "$VFT_RUNS/final-fallen-steps.txt"
```

Every row of `final-fallen.txt` must appear in the fallen list of at least one step's `-ab.txt` (`final-fallen-steps.txt` names it). It must also be a row the owner accepted when that step stopped. A fallen row that no step listed, or that was never ruled on, breaks the merge rule: stop and report NEEDS_CONTEXT.

- [ ] **Step 4: Leave-one-out on dev**

```bash
"$B" ablate --corpus "$VFT_CORPUS" --manifest "$VFT_MANIFEST" --side dev --out "$VFT_RUNS/ablate-dev.tsv"
grep -E '^(gate\.cmd-position|parse\.body-|limit\.body-)' "$VFT_RUNS/ablate-dev.tsv"
```

This runs one dev pass per registered id and takes a while; start it with `run_in_background` and continue with Step 5. Expected: the TSV has a row for each of `gate.cmd-position`, `parse.body-binary`, `parse.body-json`, `parse.body-form`, `parse.body-multipart`, `limit.body-non-utf8`, `limit.body-unparsed`. Their `kind` column reads `Gate`, `Decoder` and `Limit`. `limit.body-unparsed` shows `d_tp` 0 and `d_fp` 0, because it is worth 0 points.

- [ ] **Step 5: bench_http robustness**

```bash
M0=M:/Projects/venusflytrap-recall-runs/m0
for set in seeds mutants; do
  ./target/release/examples/bench_http "$M0/$set.jsonl" "$VFT_RUNS/final-$set.csv" 2> "$VFT_RUNS/final-$set.txt"
done
cat "$VFT_RUNS/final-seeds.txt" "$VFT_RUNS/final-mutants.txt"
py -I -X utf8 - "$M0/mutants.csv" "$VFT_RUNS/final-mutants.csv" > "$VFT_RUNS/final-mutant-families.txt" <<'EOF'
import csv, sys
from collections import Counter
def preds(p):
    with open(p, encoding="utf-8", newline="") as f:
        return [r["pred"] for r in csv.DictReader(f)]
old, new = preds(sys.argv[1]), preds(sys.argv[2])
assert len(old) == len(new) == 660, (len(old), len(new))
# eval/mutate.py writes 30 mutants per seed, in seed order: 14 SQLi seeds, then 8 XSS seeds.
lost, gained = Counter(), Counter()
for i, (o, n) in enumerate(zip(old, new)):
    if o == "1" and n == "0":
        lost[i // 30] += 1
    if o == "0" and n == "1":
        gained[i // 30] += 1
for s in range(22):
    if lost[s] or gained[s]:
        print(f"seed {s} ({'sqli' if s < 14 else 'xss'}): lost {lost[s]}, gained {gained[s]}")
print(f"total lost {sum(lost.values())}, gained {sum(gained.values())}")
EOF
cat "$VFT_RUNS/final-mutant-families.txt"
```

Thresholds (spec section 6.2): mutants recall ≥ 0.830, and retained = mutants recall / seeds recall ≥ 0.96. Both come from the `recall=` fields of the two summary lines. A threshold that is missed needs a justification row per seed family with lost mutants (seed index and class from `final-mutant-families.txt`; the mutated strings are not copied into the results). The reference is M0 (`$M0/seeds.txt`, `$M0/mutants.txt`).

- [ ] **Step 6: Freeze; held-out once, then the full-corpus checks**

From here on, no code changes. Score held-out exactly once:

```bash
"$B" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side heldout --out "$VFT_RUNS/heldout.csv" > "$VFT_RUNS/heldout.json"
```

Do not run `clusters.py` or the fallen-row script on held-out, and do not open any held-out file. Report `heldout.json` → `library` as it is.

Full-corpus library run (latency) and the serve regression check:

```bash
"$B" eval --corpus "$VFT_CORPUS" --mode library --out "$VFT_RUNS/final-library.csv" > "$VFT_RUNS/final-library.json"
bash eval/decision_gate.sh diff "$VFT_BASELINE" > "$VFT_RUNS/serve-diff-final.txt"; echo "diff exit $?"
tail -n 2 "$VFT_RUNS/serve-diff-final.txt"
```

Expected: `final-library.json` → `latency_us_p50_p95_p99[1]` < 1000 (library p95 < 1 ms); `diff exit 0` (`bans_from_allowed 0`, `invariant_violations 0`).

Attribute every changed serve decision (spec section 6.3, item 1). The script reads the baseline CSVs and the `now-` CSVs that the diff run wrote:

```bash
py -I -X utf8 - "$VFT_BASELINE" "$VFT_MANIFEST" "$VFT_RUNS/final-fallen.txt" > "$VFT_RUNS/serve-attribution.txt" <<'EOF'
import csv, sys
from collections import Counter
base_dir, manifest, fallen_path = sys.argv[1:4]
SINKS = {"cmd.chained-command"}
side = {}
with open(manifest, encoding="utf-8") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t")
        if len(parts) >= 4:
            side[parts[0]] = parts[3]
justified = {l.split("\t")[0] for l in open(fallen_path, encoding="utf-8") if l.strip() and not l.startswith(("rel\t", "#"))}
def load(p):
    with open(p, encoding="utf-8", newline="") as f:
        return {r["rel"]: r for r in csv.DictReader(f)}
def category(o, n):
    if o.get("top") in SINKS or n.get("top") in SINKS:
        return "sink"
    names = [o.get("field", ""), o.get("top_field", ""), n.get("field", ""), n.get("top_field", "")]
    if any(x.startswith("body:") for x in names) or (n.get("top") or "").startswith("limit.body-"):
        return "body"
    if o["lib_verdict"] == n["lib_verdict"]:
        return "chain"
    if o.get("top") == n.get("top"):
        return "score-only"
    return "other"
hit = {"Challenge", "Block"}
for tag in ("distinct", "pooled100"):
    old, new = load(f"{base_dir}/serve-{tag}.csv"), load(f"{base_dir}/now-serve-{tag}.csv")
    counts = Counter()
    for rel in sorted(set(old) & set(new)):
        o, n = old[rel], new[rel]
        if (o["lib_verdict"], o["serve_verdict"]) == (n["lib_verdict"], n["serve_verdict"]):
            continue
        c = category(o, n)
        counts[c] += 1
        if c == "other":
            print(f"{tag}\tOTHER\t{rel}\t{o['label']}\t{o['lib_verdict']}->{n['lib_verdict']}\t{o.get('top', '')}->{n.get('top', '')}")
        if o["label"] == "1" and o["serve_verdict"] in hit and n["serve_verdict"] not in hit:
            s = side.get(rel, "?")
            if s == "dev" and rel not in justified:
                print(f"{tag}\tUNJUSTIFIED-DEV-LOSS\t{rel}")
            elif s != "dev":
                print(f"{tag}\tNON-DEV-LOSS\t{s}\t{rel}")
    print(f"{tag}\tcounts\t{dict(sorted(counts.items()))}")
EOF
cat "$VFT_RUNS/serve-attribution.txt"
```

Categories: `sink` (the old or new top is the changed sink), `body` (a body field is involved, or a body limit is the new top), `chain` (only the serve verdict moved: a ban or chain consequence), and `score-only` (same top, the score moved through corroboration). Expected: no `OTHER` line and no `UNJUSTIFIED-DEV-LOSS` line. If either appears, report NEEDS_CONTEXT with the file, and leave the code unchanged. `NON-DEV-LOSS` lines are held-out or unsplit rows: list their count and rel paths in the held-out section, as measured, without opening them. If the diff run exits 2 on row sets, apply the Host facts procedure.

TCP replay:

```bash
"$B" eval --corpus "$VFT_CORPUS" --mode tcp --limit 40000 > "$VFT_RUNS/tcp-full.json"; echo "tcp exit $?"
netstat -an | grep -c TIME_WAIT
```

Expected: `mismatch_block_vs_proxy_allow` 0, and `mismatch_upstream_5xx` and `mismatch_io` 0 (DQ1's level).

- [ ] **Step 7: Write `eval/RESULTS-DQ2.md`**

Copy every number from the saved files; estimate nothing. Each table or sentence with a number names its source file under `.superpowers/dq2/runs/` (or `baseline/`). No attack strings and no payload text: rows are cited by rel path, construct id and field name. Sections, in this order:

1. **Header.** One paragraph: DQ2 (this plan) ships the shell command-position rule (`gate.cmd-position`), body classification (`parse.body-*`, `limit.body-non-utf8`, `limit.body-unparsed`, the API-safety last-segment rule) and corroboration de-duplication. The SQL grammar gate (spec section 4.3) and per-context canonicalisation (section 4.5) are deferred for the owner's decision. Then bullets: baseline = code of main `a990f26` (`bin-a990f26.exe`, `base-dev.json`); measured tree = `git rev-parse --short HEAD`; machine = the Windows 11 host of `RESULTS-DQ1.md`; corpus = the one in `docs/BENCHMARK.md` section 1 (do not name it here); `samples` and `read_failures` of each run; absent-file rel paths from the Host facts procedure, if any.
2. **Dev result and exit.** Table `Run | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI]` with rows main (`base-dev.json`) and DQ2 final (`final-dev.json`), with percentages to two decimals. Below it, the McNemar lines from `final-vs-base.txt`. Then the exit lines, each stated as measured:
   - dev FP rows against the spec target of ≤ 99 (about 0.6%): "reached N (x.xx%)", and "target met" or "target not met";
   - dev ΔTP = final TP − base TP, and the same net of the justification rows (ΔTP + rows in section 4);
   - merge rule: for each step in section 3, ΔFP ≤ 0 (yes/no), and whether every fallen malicious row is in section 4 (from Step 3).
3. **Per-step table (dev).** `Step | Task | ΔTP | ΔFP | McNemar malicious b/c/p | McNemar benign b/c/p | Recall [CI] after | FP rate [CI] after | Source`, one row each for Task 2's step, `body` (Task 3), and `corroboration` (Task 4), then the Task 3 sub-rows `body-binary`, `body-json`, `body-form`, `body-multipart`, `body-nonutf8`, marked as per-id A/Bs, not additive. Each row's source is its `<step>-ab.txt`.
4. **Justification table.** `rel | construct (main's top) | step it fell in | reason | recovered in`, one row per line of `final-fallen.txt` and per mutant seed family that missed a threshold in Step 5. Take the step from `final-fallen-steps.txt` and the reason from the owner's ruling at that step's stop. "None" if the file has no rows.
5. **Corroboration.** The score histogram per label and the Monitor counts, before and after, from `corroboration-hist.txt`, plus one sentence on where the benign mass moved, as measured.
6. **Leave-one-out (dev).** The `ablate-dev.tsv` rows for the seven DQ2 ids, then the ten rows with the largest `net`, each with `id | kind | d_tp | d_fp | net`.
7. **Robustness.** `bench_http` seeds and mutants: TP / FN, recall, retained (mutants recall / seeds recall), p50/p95/p99, from `final-seeds.txt` and `final-mutants.txt`, beside M0's (`m0/seeds.txt`, `m0/mutants.txt`). State the thresholds (retained ≥ 96%, mutant recall ≥ 83.0%) and whether each is met, plus `final-mutant-families.txt` by seed index and class.
8. **Latency.** Library p50/p95/p99 on the full corpus (`final-library.json` → `latency_us_p50_p95_p99`) against the p95 < 1 ms budget.
9. **Held-out, scored once.** Table `TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI]` from `heldout.json`. Say it was scored once, after the last step, from the frozen tree, and never used for tuning. Add the earlier held-out measurement from `eval/RESULTS-RECALL.md` (M2a: recall 0.4251, FP rate 0.0078), labelled as earlier code and not a paired comparison. Add the count and rel paths of `NON-DEV-LOSS` lines from `serve-attribution.txt`.
10. **Serve regression check.** `serve-diff-final.txt` exit, `bans_from_allowed`, `invariant_violations`; the category counts per source mode from `serve-attribution.txt`; "no unattributed change" or the stop that happened.
11. **TCP replay.** The table of `RESULTS-DQ1.md` section 5 (`replayed | matched_block | matched_allow | proxy_rejected | not_replayable | block_vs_proxy_allow | allow_vs_proxy_403 | upstream_5xx | io | other | mismatched`) from `tcp-full.json`, plus the TIME_WAIT count and the exit status, compared with DQ1's run.
12. **Remaining dev FP clusters.** The FP table of `clusters-final.txt` (top 15) with its totals line; dev rows only, held-out not read.
13. **Deferred, and what remains.** State that dev FP reached N rows, against the ≤ 99 target. Then list the deferred items with their spec sections:
    - the SQL grammar gate for `sqli.union-select`, `sqli.boolean-tautology` and `sqli.stacked-query` (section 4.3; D4–D7, D9), which the spec's D4 sizes at the prose, search and telemetry classes behind 77 dev FPs;
    - per-context canonicalisation (section 4.5, D11);
    - the per-header grammar matrix (section 4.1, D15);
    - the clusters of section 12 that fall outside DQ2's sinks (spec section 8).

    Recorded for DQ3: binary classification by strong magic (gzip, zip, PNG, JPEG) applies whatever the declared type (spec section 4.2), so a form or JSON body whose first bytes are such a magic gets no text field, while a backend that ignores the magic would still parse it. Body classification requires binary-looking bytes only for printable magic (zlib, GIF, PDF), a tightening of the spec table.

- [ ] **Step 8: Status line in `docs/BENCHMARK.md`**

After line 9 (the line starting `Status: DQ1 (measurement foundation)`), add one line, worded from the measured results. Each number in angle brackets is replaced by its measured value from the named file before committing:

```markdown
Status: DQ2 (false-positive budget, first part) changes detection, so the full-corpus numbers below predate it. On dev rows, false positives went from <base-dev.json fp> to <final-dev.json fp> and true positives from <base-dev.json tp> to <final-dev.json tp>; held-out, scored once, has recall <heldout.json recall> and FP rate <heldout.json fp_rate>. The SQL grammar gate and per-context canonicalisation are deferred; the per-step table, the justification table and the serve and TCP checks are in [`eval/RESULTS-DQ2.md`](../eval/RESULTS-DQ2.md).
```

If the serve or TCP check did not pass, or a robustness threshold was missed, say so in that line instead of implying a clean result.

Run: `sed -n 8,11p docs/BENCHMARK.md` → Expected: the SP2 line, the DQ1 line, the new DQ2 line, then the blank line.

- [ ] **Step 9: Commit**

```bash
git add eval/RESULTS-DQ2.md docs/BENCHMARK.md
git commit -m "docs: DQ2 measured results" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

