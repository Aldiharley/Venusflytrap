# DQ1 — Measurement Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every eval number carries a Wilson 95 % interval, two runs can be compared pairwise (McNemar), false positives and misses can be ranked by shared cause, new constructs can run in shadow without touching any decision, the TCP replay runs clean on the full corpus, and the libinjection / regex baselines read exactly the requests the engine reads — with every corpus decision identical to main.

**Architecture:** Statistics and reporting live in `vft-cli` (`eval.rs`) and the Python tools under `eval/`. The one engine change, shadow constructs, is pure and lives in `vft-core`: a shadowed id is switched off for judging (exactly as `shield.disabled` would), and a second inspection pass with only `shield.disabled` off records the shadow ids that fired as zero-point `shadow` contributions. With `shield.shadow` empty the second pass never runs, so the decision gate (`eval/decision_gate.sh`) re-runs the corpus after every task marked *Gate* and must report identical decisions.

**Tech Stack:** Rust 2021 workspace (vft-core, vft-proxy, vft-cli), tokio 1.54.1, serde / serde_json, ts-rs 12.0.1 (optional `ts` feature), Python 3.13 standard library (`csv`, `math`, `argparse`, `unittest`), Git Bash for the gate script.

**Spec:** `docs/superpowers/specs/2026-10-28-dq1-measurement-foundation-design.md` (sections 3.1–3.7, 5, 6).

## Global Constraints

- `#![forbid(unsafe_code)]` stays in every crate; `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` are green after every task. `cargo test -p vft-core --features ts --test ts_bindings` stays green too (it compares the committed bindings byte for byte).
- vft-core stays pure: no I/O, clock or locks in `vft-core` library code. Tests may read and write files.
- **No detection change.** With `shield.shadow` empty, after every task marked *Gate*, `bash eval/decision_gate.sh check "$VFT_BASELINE"` must print `decision gate: identical`. The baseline is captured in Task 1 (the first task that needs it) from code identical to main `69d0e32`.
- Existing eval report JSON fields and CSV columns keep their names and order. New JSON fields go at the end of their struct; new CSV columns are appended after `cause`, in the order `field`, `top`, `shadow`.
- `eval/compare_runs.py` exit codes are unchanged: 0 identical decisions, 1 differences, 2 invalid input. The McNemar test only prints.
- Python is always run as `py -I -X utf8`. Python tests: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v`.
- No new crate or package dependency. The only manifest change: vft-cli's tokio requirement floor goes from `1.41.0` to `1.54.1` (the version already in `Cargo.lock`; `TcpStream::set_zero_linger` needs >= 1.50). `Cargo.lock` does not change.
- No package installs of any kind (npm installs are run by the owner). `ui/src/lib/api/types.ts` is edited as plain text. `npm run check` and `npm test` run only if `ui/node_modules` exists in this worktree; otherwise the results file records them as not run.
- Never associate the project with any outside project name, in code, docs or commit messages. Never quote the synthetic `venusflytrap bench` result as a result.
- Clusters are read on **dev** rows only (`--manifest "$VFT_MANIFEST" --side dev`). Held-out rows are never opened. The gate and the full-corpus runs compare identity and totals, not individual held-out payloads.
- Commits: one per task, on branch `dq1-measurement` in the worktree `M:/Projects/venusflytrap-dq1`. Every commit message ends with the trailer line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. No push and no change to `main`.

## Decisions this plan takes

| # | Decision | Why |
|---|---|---|
| D1 | A shadowed construct is judged **exactly as if it were in `shield.disabled`**: the shield's judging set is `disabled ∪ shadow`; when `shield.shadow` is non-empty a second inspection with only `disabled` off finds the shadow ids that fired, and those contributions are appended with `shadow: true`, `points: 0`. | Removing patterns from evidence after the fact (spec 3.4, first bullet) would still let a shadow hit raise the score through detectors that read the token graph (the anomaly oracle adds 0.5 for any reachable sink; `api.type-violation` fires on any reachable sink). Judging as if disabled makes "never influences score, verdict, `decided_by`, `event_for` or bans" true by construction and testable: the unit test compares a shadow run with a disabled run. |
| D2 | Hard-pin constructs (`honeypot.decoy-hit`, `intel.deny-listed`, `limit.payload-truncated`) may be shadowed (D1 handles them like disabled). Decoder ids may not: a cross-field issue on `shield.shadow`, next to the required "also in `shield.disabled`" issue. | Decoders emit no evidence, so shadowing one would silently do nothing. |
| D3 | The CSV gains a `top` column (the construct of the contribution with the most points, the first on a tie, empty when nothing scored) between `field` and `shadow`. | `clusters.py` groups by "top construct" (spec 3.3), which is not otherwise in the CSV: `cause` carries only kind and option key, and `constructs` is in recording order, not by points. |
| D4 | `compare_runs.py --intersect` (opt-in, eval CSVs only) compares the rows both runs contain and prints every row only in one run. Without the flag nothing changes. | The host antivirus deletes corpus files between runs, which makes the gate exit 2 with "row sets differ" although no decision moved (see Host facts). |
| D5 | Replay clients call `TcpStream::set_zero_linger()` instead of `set_linger(Some(Duration::ZERO))`. | Same `SO_LINGER = 0`; `set_linger` is deprecated in tokio 1.54.1 and would fail `clippy -D warnings`. |
| D6 | `--dump-requests` writes every string (path, query, headers, cookies, body) as the Latin-1 view of its UTF-8 bytes; the path is in the URI form the engine receives (`adapt::from_parts`), and the raw `Cookie` header goes only into `cookies`, as `parse_corpus.py` does. | `baselines.py` encodes every field with `latin-1`, so it hands libinjection exactly the bytes the engine inspects. |
| D7 | `--promotion` adds `promotion` (one row per `shield.shadow` id, zero rows included) as the last field of the JSON report and prints the same table to stderr; it counts against the **library** verdict. Without `--promotion` the field is omitted. | Keeps stdout a single JSON document and the existing report shape unchanged. |
| D8 | McNemar: b = blocked (Block/Challenge) in run a only, c = blocked in run b only, per class; `serve_verdict` is tested only when every row of both runs has one (library-mode CSVs leave it empty). | Spec 3.2 names b, c without defining their direction. |
| D9 | `eval::run` takes an `Outputs` struct (CSV path, promotion flag, dump path) instead of more positional parameters. | A seventh and eighth parameter would trip `clippy::too_many_arguments`. |

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `.gitattributes` (new) | LF for `*.sh` and `ui/src/gen/**` | 1 |
| `eval/compare_runs.py`, `eval/test_compare_runs.py` | McNemar, `--intersect` | 2 |
| `crates/vft-cli/src/eval.rs` | `wilson`, CIs in `Metrics`, `Outputs`, CSV `field`/`top`/`shadow`, promotion counts, keep-alive replay upstream, zero-linger client, request dump | 3, 4, 6, 7, 8 |
| `crates/vft-cli/src/main.rs` | `--shadow`, `--promotion`, `--dump-requests` | 4, 6, 8 |
| `crates/vft-cli/Cargo.toml` | tokio floor 1.54.1 | 7 |
| `eval/clusters.py`, `eval/test_clusters.py`, `eval/fixtures/clusters.csv`, `eval/fixtures/clusters_manifest.tsv` (new) | Ranked FP / miss groups from a CSV | 4 |
| `crates/vft-core/src/config.rs`, `crates/vft-core/src/options.rs` | `shield.shadow` leaf, descriptor, cross-field checks | 5 |
| `crates/vft-core/src/judgment.rs` | `Contribution.shadow` | 5 |
| `crates/vft-core/src/graph/sinks/mod.rs` | `Disabled::has` | 5 |
| `crates/vft-core/src/shield.rs` | Judging set, second pass, `inspect_view` | 5 |
| `crates/vft-core/src/chain.rs` | `event_for` ignores shadow contributions | 5 |
| `crates/vft-proxy/src/audit.rs` | Audit line carries `shadow` | 5 |
| `ui/src/gen/Contribution.ts` (regenerated), `ui/src/lib/api/types.ts` | Wire type mirror | 5 |
| `eval/RESULTS-DQ1.md` (new), `docs/BENCHMARK.md` | Measured results, one status line | 9 |

## Environment for every task

```bash
# Git Bash, from the worktree root M:/Projects/venusflytrap-dq1.
: "${VFT_CORPUS:?set VFT_CORPUS to the corpus testcases directory (ask the owner)}"
export VFT_BASELINE="$(git rev-parse --show-toplevel)/.superpowers/dq1/baseline"   # git-ignored
export VFT_RUNS="$(git rev-parse --show-toplevel)/.superpowers/dq1/runs"           # git-ignored
export VFT_MANIFEST="M:/Projects/venusflytrap-recall-runs/split/manifest.tsv"      # the existing dev / held-out split
export VFT_LIBINJ="C:/Users/DENNIS~1/AppData/Local/Temp/claude/C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu/da1b01dd-cef6-4b76-bba8-0e55e99fd9e4/scratchpad/ext/libinjection.dll"
B=./target/release/venusflytrap
mkdir -p "$VFT_BASELINE" "$VFT_RUNS"
```

The corpus path comes only from `VFT_CORPUS`. If it is unset or the directory does not exist, stop and ask the owner; do not substitute another corpus. If `VFT_MANIFEST` does not exist, stop and ask the owner; do not create a new split (spec section 2: the manifest does not change).

### Host facts

- The host antivirus deletes some corpus `.black` files, at any time. A deleted file is not in the next run's CSV, so the gate can exit 2 with `compare_runs: row sets differ: N only in a, 0 only in b`. That is not a decision change when every row only in one run is a file that is now absent (or listed as `unreadable` in that run's JSON `failure_examples`). Check it, compare on the intersection, and report it:

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

  Accept the gate only when both compares exit 0 and no `PRESENT:` line is printed; put the absent rel paths in the task report (Task 9 copies them into the results). Any `PRESENT:` line, or a compare exit 1, is a real difference: stop and report it. `--intersect` exists from Task 2 on; if this happens in Task 1, re-capture the baseline instead.

---

### Task 1: Line endings, baseline capture

**Files:**
- Create: `.gitattributes`
- Renormalise: `eval/decision_gate.sh`, `ui/src/gen/*.ts`

**Interfaces:**
- Produces: `.gitattributes` with `*.sh text eol=lf` and `ui/src/gen/** text eol=lf`; the baseline `$VFT_BASELINE/serve-distinct.{csv,json}` and `$VFT_BASELINE/serve-pooled100.{csv,json}`, captured from code identical to main `69d0e32`. Every later gate step reads them.

- [ ] **Step 1: Confirm the tree is main's code**

Run: `git log --oneline 69d0e32..HEAD` → Expected: only the two docs commits on this branch, `docs: DQ1 measurement-foundation design` and `docs: DQ1 measurement-foundation plan`.
Run: `git diff --quiet 69d0e32 HEAD -- crates config eval ui Cargo.toml Cargo.lock; echo $?` → Expected: `0`. Anything else: stop and report; the baseline would not be main.

- [ ] **Step 2: Write `.gitattributes`**

```gitattributes
# Shell scripts run under bash on Windows, WSL and CI; generated console types
# are compared byte for byte by crates/vft-core/tests/ts_bindings.rs.
*.sh text eol=lf
ui/src/gen/** text eol=lf
```

- [ ] **Step 3: Renormalise and refresh the working copies**

Run: `git add .gitattributes && git add --renormalize .`
Run: `git status --short` → Expected: `A  .gitattributes` (the index already holds LF for these files, so nothing else is staged; if other files appear, they are the renormalisation and belong in this commit).
Run: `rm eval/decision_gate.sh ui/src/gen/*.ts && git checkout -- eval/decision_gate.sh ui/src/gen`
Run: `git ls-files --eol eval/decision_gate.sh ui/src/gen/Judgment.ts` → Expected: both lines show `i/lf    w/lf    attr/text eol=lf`.
Run: `bash -n eval/decision_gate.sh; echo $?` → Expected: `0`.
Run: `cargo test -p vft-core --features ts --test ts_bindings` → Expected: PASS.

- [ ] **Step 4: Capture the baseline**

Run: `bash eval/decision_gate.sh capture "$VFT_BASELINE"`
Expected: four files in `$VFT_BASELINE`. In `serve-distinct.json`, `library` and `serve.metrics` both show `"tp": 288`, `"fp": 278`, `"fn": 368`, and `invariant_violations` is `0`. If TP, FP or FN differ, stop and report: the tree is not main.
Record `samples` and `read_failures` from both JSON files in the task report.

- [ ] **Step 5: Self-check the gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: last line `decision gate: identical`. If it exits 2 with `row sets differ` (a corpus file vanished between the two runs), run Step 4 again, then this step.

- [ ] **Step 6: Workspace checks**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 7: Commit**

```bash
git add .gitattributes
git commit -m "build: LF line endings for shell scripts and generated types" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: McNemar test and `--intersect` in `compare_runs.py` *(Gate)*

**Files:**
- Modify: `eval/compare_runs.py` (whole file below)
- Test: `eval/test_compare_runs.py` (append)

**Interfaces:**
- Consumes: eval CSVs with at least `rel,label,lib_verdict,serve_verdict,score,banned`.
- Produces: `py -I -X utf8 eval/compare_runs.py [--intersect] <a.csv> <b.csv>`; functions `mcnemar_p(b: int, c: int) -> float`, `discordant(ra: dict, rb: dict, col: str, label: str) -> tuple[int, int]`, `mcnemar_lines(ra: dict, rb: dict) -> list[str]`, `intersect(a, b) -> (a, b, only_a: list[str], only_b: list[str])` where `a`, `b` are `load()` results. Output lines: `mcnemar <lib_verdict|serve_verdict> <malicious|benign>: b=<int> c=<int> p=<float, :.4g>`, `intersect: <n> rows only in a, <m> only in b (not compared)`, `only in a: <rel>`, `only in b: <rel>`.

- [ ] **Step 1: Write the failing tests** (append to `eval/test_compare_runs.py`, above `if __name__ == "__main__":`)

```python
def run_main(args):
    """Run compare_runs.main; returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cr.main(args)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class McNemarTests(unittest.TestCase):
    def test_no_discordant_pairs_is_p_1(self):
        self.assertEqual(cr.mcnemar_p(0, 0), 1.0)

    def test_one_sided_split(self):
        # n = 5, all on one side: 2 * C(5,0) / 2^5
        self.assertAlmostEqual(cr.mcnemar_p(0, 5), 0.0625)
        self.assertAlmostEqual(cr.mcnemar_p(5, 0), 0.0625)

    def test_exact_small_case(self):
        # n = 7, k = 1: 2 * (C(7,0) + C(7,1)) / 2^7 = 2 * 8 / 128
        self.assertAlmostEqual(cr.mcnemar_p(1, 6), 0.125)

    def test_balanced_split_caps_at_1(self):
        self.assertEqual(cr.mcnemar_p(3, 3), 1.0)

    def test_discordant_pairs_are_counted_per_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "m1.black,1,Block,,95,false,\nm2.black,1,Allow,,0,false,\n"
                      "m3.black,1,Block,,95,false,\nb1.white,0,Allow,,0,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "m1.black,1,Allow,,0,false,\nm2.black,1,Challenge,,75,false,\n"
                      "m3.black,1,Block,,95,false,\nb1.white,0,Block,,95,false,\n")
            (_, ra), (_, rb) = cr.load(a), cr.load(b)
            self.assertEqual(cr.discordant(ra, rb, "lib_verdict", "1"), (1, 1))
            self.assertEqual(cr.discordant(ra, rb, "lib_verdict", "0"), (0, 1))

    def test_cli_prints_mcnemar_only_when_decisions_differ(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "m.black,1,Allow,,0,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "m.black,1,Block,,95,false,\n")
            code, out, _ = run_main([a, a])
            self.assertEqual(code, 0)
            self.assertNotIn("mcnemar", out)
            code, out, _ = run_main([a, b])
            self.assertEqual(code, 1)
            self.assertIn("mcnemar lib_verdict malicious: b=0 c=1 p=1\n", out)
            self.assertIn("mcnemar lib_verdict benign: b=0 c=0 p=1\n", out)
            self.assertNotIn("mcnemar serve_verdict", out, "library CSVs have no serve verdicts")

    def test_cli_adds_serve_verdict_when_both_runs_have_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "m.black,1,Allow,Allow,0,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "m.black,1,Allow,Block,95,false,\n")
            code, out, _ = run_main([a, b])
            self.assertEqual(code, 1)
            self.assertIn("mcnemar lib_verdict malicious: b=0 c=0 p=1\n", out)
            self.assertIn("mcnemar serve_verdict malicious: b=0 c=1 p=1\n", out)


class IntersectTests(unittest.TestCase):
    def test_row_set_mismatch_without_intersect_is_still_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "x.white,0,Allow,,0,false,\ny.black,1,Block,,95,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "x.white,0,Allow,,0,false,\n")
            code, _, err = run_main([a, b])
            self.assertEqual(code, 2)
            self.assertIn("row sets differ", err)

    def test_intersect_compares_shared_rows_and_lists_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "x.white,0,Allow,,0,false,\ny.black,1,Block,,95,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "x.white,0,Allow,,0,false,\n")
            code, out, _ = run_main(["--intersect", a, b])
            self.assertEqual(code, 0)
            self.assertIn("intersect: 1 rows only in a, 0 only in b (not compared)\n", out)
            self.assertIn("only in a: y.black\n", out)

    def test_intersect_still_reports_decision_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "x.black,1,Allow,,0,false,\ny.black,1,Block,,95,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "x.black,1,Block,,95,false,\n")
            code, out, _ = run_main(["--intersect", a, b])
            self.assertEqual(code, 1)
            self.assertIn("decision diffs: 1", out)

    def test_intersect_rejects_bench_csvs(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", "label,pred,score\n1,1,95\n")
            code, _, err = run_main(["--intersect", a, a])
            self.assertEqual(code, 2)
            self.assertIn("--intersect needs two eval CSVs", err)
```

- [ ] **Step 2: Run them to see them fail**

Run: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v`
Expected: the new tests ERROR with `AttributeError: module 'compare_runs' has no attribute 'mcnemar_p'` (and `discordant`), and the `--intersect` CLI tests fail (exit 2, `--intersect` read as a path). The existing tests pass.

- [ ] **Step 3: Implement** (replace `eval/compare_runs.py` with)

```python
"""Compare two evaluation runs: decision equivalence and metric deltas.

Accepts CSVs from `venusflytrap eval --out` (keyed by rel) or from the
bench_http example (keyed by row). Latency and construct names are ignored;
everything that decides the outcome is compared. When decisions differ, an
exact McNemar test on the discordant pairs is printed per class (malicious
rows: detection; benign rows: false positives) for lib_verdict and, when every
row of both runs has one, serve_verdict.

--intersect (eval CSVs only) compares the rows both runs contain and lists every
other row, for a corpus that lost files between the runs.

Usage: py -I -X utf8 eval/compare_runs.py [--intersect] <a.csv> <b.csv>
Exit status: 0 identical decisions, 1 differences, 2 invalid input.
"""
import csv
import math
import sys

EVAL_COLS = ("label", "lib_verdict", "serve_verdict", "score", "banned")
BENCH_COLS = ("label", "pred", "score")
ATTACK = ("Block", "Challenge")


def load(path):
    """Returns (kind, {key: row_dict}) with kind 'eval' or 'bench'.

    The format is taken from the header. Raises ValueError for an unrecognized
    or incomplete header, or a file with no data rows.
    """
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        if "rel" in fields:
            kind, required = "eval", ("rel",) + EVAL_COLS
        elif all(c in fields for c in BENCH_COLS):
            kind, required = "bench", BENCH_COLS
        else:
            raise ValueError(f"{path}: unrecognized header {fields!r} "
                             f"(expected eval 'rel,...' or bench 'label,pred,score,...')")
        missing = [c for c in required if c not in fields]
        if missing:
            raise ValueError(f"{path}: {kind} header is missing columns {missing}")
        rows = list(reader)
    if not rows:
        raise ValueError(f"{path}: no data rows")
    if kind == "eval":
        return kind, {r["rel"]: r for r in rows}
    return kind, {str(i): r for i, r in enumerate(rows)}


def is_attack(kind, row):
    if kind == "eval":
        return row["lib_verdict"] in ATTACK
    return row["pred"] == "1"


def metrics(kind, rows):
    m = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for r in rows.values():
        pred, label = is_attack(kind, r), r["label"] == "1"
        m[{(True, True): "tp", (True, False): "fp", (False, False): "tn", (False, True): "fn"}[(pred, label)]] += 1
    m["recall"] = m["tp"] / max(m["tp"] + m["fn"], 1)
    m["fp_rate"] = m["fp"] / max(m["fp"] + m["tn"], 1)
    return m


def compare(a, b):
    """Raises ValueError on a format mismatch or differing row sets."""
    (ka, ra), (kb, rb) = a, b
    if ka != kb:
        raise ValueError(f"cannot compare a {ka} CSV with a {kb} CSV")
    cols = EVAL_COLS if ka == "eval" else BENCH_COLS
    if ra.keys() != rb.keys():
        raise ValueError(f"row sets differ: {len(ra.keys() - rb.keys())} only in a, {len(rb.keys() - ra.keys())} only in b")
    diffs = []
    for key in sorted(ra):
        x, y = ra[key], rb[key]
        changed = [c for c in cols if x[c] != y[c]]
        if changed:
            diffs.append((key, {c: (x[c], y[c]) for c in changed}))
    return diffs, metrics(ka, ra), metrics(kb, rb)


def intersect(a, b):
    """Keep only the rows both eval runs contain.

    Returns (a, b, only_a, only_b) with the dropped keys sorted. Raises
    ValueError for bench CSVs (keyed by row number) or when no row is shared.
    """
    (ka, ra), (kb, rb) = a, b
    if ka != "eval" or kb != "eval":
        raise ValueError("--intersect needs two eval CSVs")
    common = ra.keys() & rb.keys()
    if not common:
        raise ValueError("--intersect: the runs share no rows")
    only_a = sorted(ra.keys() - common)
    only_b = sorted(rb.keys() - common)
    return (ka, {k: ra[k] for k in common}), (kb, {k: rb[k] for k in common}), only_a, only_b


def mcnemar_p(b, c):
    """Two-sided exact McNemar p-value: binomial(b + c, 1/2) on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def discordant(ra, rb, col, label):
    """(b, c) over the rows with `label`: b = blocked in a only, c = blocked in b only.

    Blocked means Block or Challenge in `col`. Both runs must hold the same keys.
    """
    b = c = 0
    for key, x in ra.items():
        if x["label"] != label:
            continue
        in_a, in_b = x[col] in ATTACK, rb[key][col] in ATTACK
        if in_a and not in_b:
            b += 1
        elif in_b and not in_a:
            c += 1
    return b, c


def mcnemar_lines(ra, rb):
    """A legend, then one line per verdict column and class."""
    cols = ["lib_verdict"]
    if all(r["serve_verdict"] for r in ra.values()) and all(r["serve_verdict"] for r in rb.values()):
        cols.append("serve_verdict")
    out = ["mcnemar (exact, two-sided): b = blocked in a only, c = blocked in b only"]
    for col in cols:
        for label, name in (("1", "malicious"), ("0", "benign")):
            b, c = discordant(ra, rb, col, label)
            out.append(f"mcnemar {col} {name}: b={b} c={c} p={mcnemar_p(b, c):.4g}")
    return out


def main(argv):
    use_intersect = "--intersect" in argv
    paths = [x for x in argv if x != "--intersect"]
    if len(paths) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    only_a, only_b = [], []
    try:
        a, b = load(paths[0]), load(paths[1])
        if use_intersect:
            a, b, only_a, only_b = intersect(a, b)
        diffs, ma, mb = compare(a, b)
    except (OSError, ValueError) as e:
        print(f"compare_runs: {e}", file=sys.stderr)
        sys.exit(2)
    if use_intersect:
        print(f"intersect: {len(only_a)} rows only in a, {len(only_b)} only in b (not compared)")
        for key in only_a:
            print(f"only in a: {key}")
        for key in only_b:
            print(f"only in b: {key}")
    for name, m in (("a", ma), ("b", mb)):
        print(f"{name}: tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} "
              f"recall={m['recall']:.4f} fp_rate={m['fp_rate']:.4f}")
    print(f"delta: tp={mb['tp'] - ma['tp']:+d} fp={mb['fp'] - ma['fp']:+d}")
    print(f"decision diffs: {len(diffs)}")
    for key, d in diffs[:20]:
        print(f"  {key}: {d}")
    if diffs and a[0] == "eval":
        for line in mcnemar_lines(a[1], b[1]):
            print(line)
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 4: Run the tests**

Run: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v` → Expected: all pass (the existing compare and split tests included).

- [ ] **Step 5: Gate** (exercises the new script on real CSVs)

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical`. On exit 2 with `row sets differ`, follow Host facts.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 6: Commit**

```bash
git add eval/compare_runs.py eval/test_compare_runs.py
git commit -m "feat(eval): McNemar test and --intersect in compare_runs" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Wilson 95 % intervals in eval metrics *(Gate)*

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`Metrics`, `Metrics::finish`, new `wilson`, tests)

**Interfaces:**
- Produces: `fn wilson(k: u64, n: u64) -> (f64, f64)` (private to `eval.rs`; `(0.0, 0.0)` for `n == 0`); `Metrics.recall_ci95: [f64; 2]` and `Metrics.fp_rate_ci95: [f64; 2]`, serialized after `fp_rate` (JSON arrays `[lo, hi]`). Every `library` and `serve.metrics` object in the report carries them.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `eval.rs`)

```rust
    #[test]
    fn wilson_matches_known_intervals() {
        let close = |(lo, hi): (f64, f64), (a, b): (f64, f64)| (lo - a).abs() < 1e-4 && (hi - b).abs() < 1e-4;
        assert_eq!(wilson(0, 0), (0.0, 0.0));
        assert!(close(wilson(0, 10), (0.0, 0.2775)), "{:?}", wilson(0, 10));
        assert!(close(wilson(5, 10), (0.2366, 0.7634)), "{:?}", wilson(5, 10));
        assert!(close(wilson(10, 10), (0.7225, 1.0)), "{:?}", wilson(10, 10));
    }

    #[test]
    fn metrics_carry_wilson_intervals_after_the_existing_fields() {
        let mut m = Metrics::default();
        for i in 0..10 {
            m.add(i < 5, 1); // 5 TP, 5 FN
        }
        for _ in 0..10 {
            m.add(false, 0); // 10 TN
        }
        let m = m.finish();
        assert!((m.recall_ci95[0] - 0.2366).abs() < 1e-4 && (m.recall_ci95[1] - 0.7634).abs() < 1e-4, "{:?}", m.recall_ci95);
        assert!(m.fp_rate_ci95[0].abs() < 1e-12 && (m.fp_rate_ci95[1] - 0.2775).abs() < 1e-4, "{:?}", m.fp_rate_ci95);
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.starts_with("{\"tp\":5,\"fp\":0,\"tn\":10,\"fn\":5,\"recall\":0.5,"), "{s}");
        let at = |k: &str| s.find(k).unwrap_or_else(|| panic!("{k} missing in {s}"));
        assert!(at("\"fp_rate\":") < at("\"recall_ci95\":") && at("\"recall_ci95\":") < at("\"fp_rate_ci95\":"), "{s}");
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-cli wilson` → Expected: compile error, `cannot find function 'wilson'` and `no field 'recall_ci95' on type 'Metrics'`.

- [ ] **Step 3: Implement**

Replace the `Metrics` struct and its `impl` with:

```rust
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Metrics {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
    pub recall: f64,
    pub precision: f64,
    pub f1: f64,
    pub fp_rate: f64,
    /// Wilson 95 % interval of `recall` (TP out of TP + FN).
    pub recall_ci95: [f64; 2],
    /// Wilson 95 % interval of `fp_rate` (FP out of FP + TN).
    pub fp_rate_ci95: [f64; 2],
}

impl Metrics {
    fn add(&mut self, predicted_attack: bool, label: u8) {
        match (predicted_attack, label) {
            (true, 1) => self.tp += 1,
            (true, _) => self.fp += 1,
            (false, 0) => self.tn += 1,
            (false, _) => self.fn_ += 1,
        }
    }
    fn finish(mut self) -> Self {
        let r = self.tp as f64 / (self.tp + self.fn_).max(1) as f64;
        let p = self.tp as f64 / (self.tp + self.fp).max(1) as f64;
        self.recall = r;
        self.precision = p;
        self.f1 = if r + p > 0.0 { 2.0 * r * p / (r + p) } else { 0.0 };
        self.fp_rate = self.fp as f64 / (self.fp + self.tn).max(1) as f64;
        let (lo, hi) = wilson(self.tp, self.tp + self.fn_);
        self.recall_ci95 = [lo, hi];
        let (lo, hi) = wilson(self.fp, self.fp + self.tn);
        self.fp_rate_ci95 = [lo, hi];
        self
    }
}

/// Wilson score interval for `k` successes in `n` trials at z = 1.96 (95 %),
/// clamped to [0, 1]. `(0, 0)` when `n` is 0.
fn wilson(k: u64, n: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 0.0);
    }
    const Z: f64 = 1.96;
    let n = n as f64;
    let p = k as f64 / n;
    let z2 = Z * Z;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let half = Z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt() / denom;
    ((center - half).max(0.0), (center + half).min(1.0))
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p vft-cli` → Expected: PASS.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 5: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (Host facts on exit 2).
Run: `grep -A2 '"recall_ci95"' "$VFT_BASELINE/now-serve-distinct.json" | head -4` → Expected: a two-number array whose bounds contain `recall`.

- [ ] **Step 6: Commit**

```bash
git add crates/vft-cli/src/eval.rs
git commit -m "feat(eval): Wilson 95% intervals for recall and FP rate" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `field` and `top` CSV columns, FP and miss clusters *(Gate)*

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`Outputs`, `run` signature and CSV writer, `csv_cell`, `top_construct`, `ablate`, tests)
- Modify: `crates/vft-cli/src/main.rs` (the `eval::run` call)
- Create: `eval/clusters.py`, `eval/test_clusters.py`, `eval/fixtures/clusters.csv`, `eval/fixtures/clusters_manifest.tsv`

**Interfaces:**
- Consumes: `Judgment.decided_by.field: Option<FieldRef>`, `FieldRef::label() -> String` (`query:id`), `Contribution.points`.
- Produces: `#[derive(Debug, Default, Clone, Copy)] pub struct Outputs<'a> { pub csv: Option<&'a Path> }`; `pub fn run(cfg: Config, samples: &[Sample], serve: bool, sources: Sources, step_ms: u64, out: Outputs<'_>) -> anyhow::Result<Report>`; `fn csv_cell(s: &str) -> std::borrow::Cow<'_, str>` (RFC 4180 quoting); `fn top_construct(cs: &[vft_core::Contribution]) -> Option<&str>`. CSV header `rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top`; `field` is `decided_by.field` as `loc:name` (empty when none), `top` the construct of the contribution with the most points (first on a tie; empty when no contribution has points). `eval/clusters.py <csv> [--manifest M --side dev|heldout] [--top N]` with `REQUIRED`, `ATTACK = ("Block", "Challenge")`, `MISS = ("Allow", "Monitor")`, `load(path) -> list[dict]`, `load_manifest(path) -> dict[str, str]` (rel → side), `select(rows, sides, side) -> list[dict]`, `key(row) -> (cause, top, loc, name_lower)`, `clusters(rows, label: str, verdicts, top: int) -> (total: int, n_groups: int, ranked: list[(key, count, examples[:3])])`.

- [ ] **Step 1: Write the failing Rust tests** (append to `mod tests` in `eval.rs`)

```rust
    #[test]
    fn csv_cells_are_quoted_only_when_needed() {
        assert_eq!(csv_cell("query:id"), "query:id");
        assert_eq!(csv_cell("query:a,b"), "\"query:a,b\"");
        assert_eq!(csv_cell("x\"y"), "\"x\"\"y\"");
        assert_eq!(csv_cell("a\nb"), "\"a\nb\"");
    }

    #[test]
    fn csv_names_the_deciding_field_and_top_construct() {
        let attack = Sample { rel: "a.black".into(), label: 1, raw: b"GET /?q=1%20union%20select%20a,b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let benign = Sample { rel: "b.white".into(), label: 0, raw: b"GET /?q=hello HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let p = std::env::temp_dir().join(format!("vft-eval-csv-{}.csv", std::process::id()));
        run(Config::default(), &[attack, benign], false, Sources::Distinct, 100, Outputs { csv: Some(&p) }).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        let mut lines = text.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top"), "{header}");
        let a: Vec<&str> = lines.next().unwrap().split(',').collect();
        assert_eq!(a[0], "a.black");
        assert!(matches!(a[2], "Block" | "Challenge"), "{a:?}");
        assert_eq!(a[8], "query:q", "{a:?}");
        assert!(!a[9].is_empty() && a[6].split('|').any(|c| c == a[9]), "top {} must be one of {}", a[9], a[6]);
        let b: Vec<&str> = lines.next().unwrap().split(',').collect();
        assert_eq!((b[0], b[2], b[8]), ("b.white", "Allow", ""), "{b:?}");
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-cli csv_` → Expected: compile errors, `cannot find function 'csv_cell'` and `cannot find struct ... 'Outputs'`.

- [ ] **Step 3: Implement the Rust side**

In `eval.rs`, add above `pub fn run`:

```rust
/// Optional outputs of [`run`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Outputs<'a> {
    /// Per-sample CSV.
    pub csv: Option<&'a Path>,
}

/// One CSV cell (RFC 4180): quoted when it holds a comma, a quote or a line break.
fn csv_cell(s: &str) -> std::borrow::Cow<'_, str> {
    if s.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\"")).into()
    } else {
        s.into()
    }
}

/// The construct of the contribution that added the most points (the first on
/// a tie), as the shield's `top_contribution` picks it; `None` when no
/// contribution has points.
fn top_construct(cs: &[vft_core::Contribution]) -> Option<&str> {
    let mut best: Option<&vft_core::Contribution> = None;
    for c in cs {
        if best.map_or(c.points > 0.0, |b| c.points > b.points) {
            best = Some(c);
        }
    }
    best.and_then(|c| c.construct.as_deref())
}
```

Change the signature of `run` from `..., step_ms: u64, csv: Option<&Path>) -> anyhow::Result<Report> {` to:

```rust
pub fn run(cfg: Config, samples: &[Sample], serve: bool, sources: Sources, step_ms: u64, out: Outputs<'_>) -> anyhow::Result<Report> {
```

In `run`, replace `let mut csv_out = match csv {` with `let mut csv_out = match out.csv {`, and replace the header line with:

```rust
            writeln!(f, "rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top")?;
```

Replace the row block (`if let Some(f) = csv_out.as_mut() { ... }`) with:

```rust
        if let Some(f) = csv_out.as_mut() {
            let constructs: Vec<&str> = lj.contributions.iter().filter_map(|c| c.construct.as_deref()).collect();
            let field = lj.decided_by.field.as_ref().map(|r| r.label()).unwrap_or_default();
            writeln!(
                f,
                "{},{},{:?},{},{},{},{},{:?}:{},{},{}",
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
                top_construct(&lj.contributions).unwrap_or("")
            )?;
        }
```

In `ablate`, replace `Ok(run(c, samples, false, sources, 100, None)?.library)` with `Ok(run(c, samples, false, sources, 100, Outputs::default())?.library)`.

In `main.rs`, replace `let report = eval::run(cfg, &samples, mode == EvalMode::Serve, sources, step_ms, out.as_deref())?;` with:

```rust
            let report = eval::run(cfg, &samples, mode == EvalMode::Serve, sources, step_ms, eval::Outputs { csv: out.as_deref() })?;
```

Run: `cargo test -p vft-cli` → Expected: PASS.

- [ ] **Step 4: Write the cluster fixture**

`eval/fixtures/clusters.csv` (two dev false-positive groups that differ only in field-name case merge; one benign Allow and one malicious Block that are neither; two dev miss groups; one held-out FP and one held-out miss):

```csv
rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top
d/fp1.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:ID,sqli.union-select
d/fp2.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:id,sqli.union-select
d/fp3.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:Id,sqli.union-select
d/fp4.white,0,Challenge,,75,false,cmd.shell-meta,Detection:scoring.challenge_at,"query:a,b",cmd.shell-meta
d/tn1.white,0,Allow,,0,false,,NoEvidence:scoring.monitor_at,,
d/m1.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,
d/m2.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,
d/m3.black,1,Monitor,,45,false,xss.html-tag,Detection:scoring.monitor_at,cookie:session,xss.html-tag
d/tp1.black,1,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:id,sqli.union-select
h/fp9.white,0,Block,,95,false,sqli.union-select,Detection:scoring.block_at,query:id,sqli.union-select
h/m9.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,
```

`eval/fixtures/clusters_manifest.tsv` (tab-separated: rel, label, sha256, side):

```
d/fp1.white	0	01	dev
d/fp2.white	0	02	dev
d/fp3.white	0	03	dev
d/fp4.white	0	04	dev
d/tn1.white	0	05	dev
d/m1.black	1	06	dev
d/m2.black	1	07	dev
d/m3.black	1	08	dev
d/tp1.black	1	09	dev
h/fp9.white	0	10	heldout
h/m9.black	1	11	heldout
```

- [ ] **Step 5: Write the failing Python tests** (`eval/test_clusters.py`)

```python
"""Tests for eval/clusters.py. Run: py -I -X utf8 -m unittest discover -s eval -p "test_*.py" """
import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("clusters", HERE / "clusters.py")
cl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cl)

CSV = str(HERE / "fixtures" / "clusters.csv")
MANIFEST = str(HERE / "fixtures" / "clusters_manifest.tsv")


def dev_rows():
    return cl.select(cl.load(CSV), cl.load_manifest(MANIFEST), "dev")


def run_main(args):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cl.main(args)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class ClusterTests(unittest.TestCase):
    def test_false_positives_group_by_cause_top_and_lowercased_field(self):
        total, n_groups, ranked = cl.clusters(dev_rows(), "0", cl.ATTACK, 20)
        self.assertEqual((total, n_groups), (4, 2))
        self.assertEqual(ranked[0], (("Detection:scoring.block_at", "sqli.union-select", "query", "id"), 3,
                                     ["d/fp1.white", "d/fp2.white", "d/fp3.white"]))
        self.assertEqual(ranked[1][0], ("Detection:scoring.challenge_at", "cmd.shell-meta", "query", "a,b"))

    def test_misses_are_allow_or_monitor_on_malicious_rows(self):
        total, n_groups, ranked = cl.clusters(dev_rows(), "1", cl.MISS, 20)
        self.assertEqual((total, n_groups), (3, 2))
        self.assertEqual(ranked[0], (("NoEvidence:scoring.monitor_at", "", "", ""), 2, ["d/m1.black", "d/m2.black"]))
        self.assertEqual(ranked[1][0], ("Detection:scoring.monitor_at", "xss.html-tag", "cookie", "session"))

    def test_side_drops_held_out_rows_before_counting(self):
        total, _, ranked = cl.clusters(cl.load(CSV), "0", cl.ATTACK, 20)
        self.assertEqual((total, ranked[0][1]), (5, 4), "without --side the held-out FP is counted")
        self.assertFalse(any(r["rel"].startswith("h/") for r in dev_rows()))

    def test_top_limits_the_groups_shown_not_counted(self):
        total, n_groups, ranked = cl.clusters(dev_rows(), "0", cl.ATTACK, 1)
        self.assertEqual((total, n_groups, len(ranked)), (4, 2, 1))

    def test_cli_prints_both_tables(self):
        code, out, _ = run_main([CSV, "--manifest", MANIFEST, "--side", "dev", "--top", "5"])
        self.assertEqual(code, 0)
        self.assertIn("false positives (label 0, Challenge/Block): 4 rows in 2 groups\n", out)
        self.assertIn("misses (label 1, Allow/Monitor): 3 rows in 2 groups\n", out)
        self.assertIn("3\tDetection:scoring.block_at\tsqli.union-select\tquery\tid\td/fp1.white d/fp2.white d/fp3.white\n", out)
        self.assertNotIn("h/", out)

    def test_missing_column_exits_2_and_names_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp, "old.csv")
            p.write_text("rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause\n"
                         "x.white,0,Block,,95,false,,Detection:scoring.block_at\n", encoding="utf-8")
            code, _, err = run_main([str(p)])
            self.assertEqual(code, 2)
            self.assertIn("missing column 'field'", err)

    def test_row_missing_from_the_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = Path(tmp, "m.tsv")
            m.write_text("d/fp1.white\t0\t01\tdev\n", encoding="utf-8")
            code, _, err = run_main([CSV, "--manifest", str(m), "--side", "dev"])
            self.assertEqual(code, 2)
            self.assertIn("is not in the manifest", err)

    def test_manifest_and_side_go_together(self):
        code, _, err = run_main([CSV, "--side", "dev"])
        self.assertEqual(code, 2)
        self.assertIn("--manifest and --side go together", err)


if __name__ == "__main__":
    unittest.main()
```

Run: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v` → Expected: `test_clusters` errors with `FileNotFoundError` for `clusters.py`; the other suites pass.

- [ ] **Step 6: Implement `eval/clusters.py`**

```python
"""Rank false positives and misses in an eval CSV by shared cause.

Rows of `venusflytrap eval --out` are grouped by (cause, top construct, field
location, field name in lower case). False positives are benign rows (label 0)
whose library verdict is Challenge or Block; misses are malicious rows (label
1) whose library verdict is Allow or Monitor. Only the CSV (and the split
manifest) is read, never a corpus file. With --manifest and --side, rows of the
other half are dropped before anything is counted, so held-out rows stay
unopened during development.

Usage: py -I -X utf8 eval/clusters.py <csv> [--manifest M --side dev|heldout] [--top N]
Exit status: 0 printed, 2 invalid input.
"""
import argparse
import csv
import sys
from collections import defaultdict

REQUIRED = ("rel", "label", "lib_verdict", "cause", "field", "top")
ATTACK = ("Block", "Challenge")
MISS = ("Allow", "Monitor")


def load(path):
    """The CSV rows as dicts. Raises ValueError naming the first missing column."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        missing = [c for c in REQUIRED if c not in fields]
        if missing:
            raise ValueError(f"{path}: missing column {missing[0]!r} (needs {', '.join(REQUIRED)})")
        return list(reader)


def load_manifest(path):
    """rel -> side from eval/split.py's manifest.tsv (rel, label, sha256, side)."""
    sides = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            cols = line.split("\t")
            if len(cols) != 4:
                raise ValueError(f"{path}:{n}: expected 4 tab-separated columns")
            sides[cols[0]] = cols[3]
    return sides


def select(rows, sides, side):
    """The rows on `side`. Every row must be in the manifest."""
    out = []
    for r in rows:
        s = sides.get(r["rel"])
        if s is None:
            raise ValueError(f"{r['rel']} is not in the manifest")
        if s == side:
            out.append(r)
    return out


def key(row):
    loc, _, name = row["field"].partition(":")
    return (row["cause"], row["top"], loc, name.lower())


def clusters(rows, label, verdicts, top):
    """(rows matched, groups, the `top` largest groups as (key, count, first 3 rels))."""
    groups = defaultdict(list)
    for r in rows:
        if r["label"] == label and r["lib_verdict"] in verdicts:
            groups[key(r)].append(r["rel"])
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    total = sum(len(v) for v in groups.values())
    return total, len(groups), [(k, len(v), sorted(v)[:3]) for k, v in ranked[:top]]


def printable(s, limit=60):
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else s[:limit] + "..."


def show(title, result):
    total, n_groups, ranked = result
    print(f"{title}: {total} rows in {n_groups} groups")
    print("count\tcause\ttop\tloc\tname\texamples")
    for (cause, top, loc, name), n, examples in ranked:
        print(f"{n}\t{cause}\t{top or '-'}\t{loc or '-'}\t{printable(name) or '-'}\t{' '.join(examples)}")


def main(argv):
    p = argparse.ArgumentParser(prog="clusters.py", description="Rank false positives and misses by shared cause.")
    p.add_argument("csv")
    p.add_argument("--manifest")
    p.add_argument("--side", choices=("dev", "heldout"))
    p.add_argument("--top", type=int, default=20)
    a = p.parse_args(argv)
    if (a.manifest is None) != (a.side is None):
        print("clusters: --manifest and --side go together", file=sys.stderr)
        sys.exit(2)
    try:
        rows = load(a.csv)
        if a.manifest:
            rows = select(rows, load_manifest(a.manifest), a.side)
    except (OSError, ValueError) as e:
        print(f"clusters: {e}", file=sys.stderr)
        sys.exit(2)
    show("false positives (label 0, Challenge/Block)", clusters(rows, "0", ATTACK, a.top))
    print()
    show("misses (label 1, Allow/Monitor)", clusters(rows, "1", MISS, a.top))


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 7: Run all tests**

Run: `py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v` → Expected: all pass.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 8: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (compare_runs ignores the new columns; Host facts on exit 2).
Run: `head -1 "$VFT_BASELINE/now-serve-distinct.csv"` → Expected: `rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top`.
Run: `py -I -X utf8 eval/clusters.py "$VFT_BASELINE/now-serve-distinct.csv" --manifest "$VFT_MANIFEST" --side dev --top 3` → Expected: exit 0 and both tables (this reads only the CSV and the manifest; do not open any listed file).

- [ ] **Step 9: Commit**

```bash
git add crates/vft-cli/src/eval.rs crates/vft-cli/src/main.rs eval/clusters.py eval/test_clusters.py eval/fixtures/clusters.csv eval/fixtures/clusters_manifest.tsv
git commit -m "feat(eval): field and top CSV columns, FP and miss clusters" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Shadow constructs in vft-core *(Gate)*

**Files:**
- Modify: `crates/vft-core/src/config.rs` (`ShieldConfig`, its `Default`, `cross_field_issues`, tests)
- Modify: `crates/vft-core/src/options.rs` (`REGISTRY`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (`Disabled::has`)
- Modify: `crates/vft-core/src/judgment.rs` (`Contribution`)
- Modify: `crates/vft-core/src/shield.rs` (`Shield`, `with_oracle`, `inspect_counting`, new `inspect_view`, `inspect_text`, `record_graph_truncated`, `top_contribution`, three `Contribution` literals, tests)
- Modify: `crates/vft-core/src/chain.rs` (`event_for`, test literals, test)
- Modify: `crates/vft-proxy/src/audit.rs` (`ContribLine`, test)
- Regenerate: `ui/src/gen/Contribution.ts`; Modify: `ui/src/lib/api/types.ts`

**Interfaces:**
- Produces: `ShieldConfig.shadow: Vec<String>` (default empty; YAML `shield: { shadow: [...] }`); registry key `shield.shadow` (`ConstructIds`, section `shield`, `Advanced`, `Live`); cross-field issues on `shield.shadow` for an id also in `shield.disabled` and for a decoder id; `pub shadow: bool` on `vft_core::Contribution` (serialized, last field, `false` everywhere except shadow hits); `Disabled::has(&self, id: &str) -> bool`; private `Shield::inspect_view(&self, req: &Request, off: &Disabled) -> (Judgment, usize)`. A shadow hit is a contribution with `shadow == true`, `points == 0.0` and its construct id; the score, verdict, `decided_by`, `event_for` and bans are exactly those of a run with the same ids in `shield.disabled`. TypeScript: `Contribution.shadow: boolean`. Audit lines: `contributions[].shadow`.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `config.rs`:

```rust
    #[test]
    fn shadow_ids_must_be_registered_not_disabled_and_not_decoders() {
        assert!(issues("shield:\n  shadow: [sqli.union-select]\n").is_empty());
        assert!(issues("shield:\n  shadow: [nope.nope]\n").iter().any(|i| i.key == "shield.shadow"));
        assert!(issues("shield:\n  disabled: [sqli.union-select]\n  shadow: [sqli.union-select]\n")
            .iter()
            .any(|i| i.key == "shield.shadow" && i.message.contains("shield.disabled")));
        assert!(issues("shield:\n  shadow: [decode.entity]\n")
            .iter()
            .any(|i| i.key == "shield.shadow" && i.message.contains("decoder")));
    }
```

Append to `mod tests` in `shield.rs`:

```rust
    #[test]
    fn a_shadowed_construct_is_recorded_but_decides_nothing() {
        let mut sqli = Request::get("/items");
        sqli.query.push(("id".into(), "1 union select password from users".into()));
        let mut scanner = browser("/index.html", "10.0.0.30".parse().unwrap());
        scanner.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("user-agent"));
        scanner.headers.push(("User-Agent".into(), "sqlmap/1.7".into()));
        let mut denied = Request::get("/index.html");
        denied.src_ip = Some("192.0.2.9".parse().unwrap());
        let cases = vec![
            ("sqli.union-select", sqli),
            ("honeypot.decoy-hit", Request::get("/.git/config")),
            ("intel.scanner-ua", scanner),
            ("intel.deny-listed", denied),
        ];
        let scored = |j: &Judgment| -> Vec<(Option<String>, u32)> {
            j.contributions.iter().filter(|c| !c.shadow).map(|c| (c.construct.clone(), c.points.to_bits())).collect()
        };
        for (id, req) in cases {
            let mut live = Config::default();
            live.intel.deny_ips = vec!["192.0.2.9".into()];
            let mut shadow = live.clone();
            shadow.shield.shadow = vec![id.into()];
            let mut off = live.clone();
            off.shield.disabled = vec![id.into()];
            assert!(has_construct(&Shield::new(live).inspect(&req), id), "{id} must fire on its request");
            let s = Shield::new(shadow).inspect(&req);
            let d = Shield::new(off).inspect(&req);
            assert_eq!((s.score, s.verdict), (d.score, d.verdict), "{id}");
            assert_eq!(
                (s.decided_by.kind, s.decided_by.option_key, &s.decided_by.construct, &s.decided_by.field, &s.decided_by.msg),
                (d.decided_by.kind, d.decided_by.option_key, &d.decided_by.construct, &d.decided_by.field, &d.decided_by.msg),
                "{id}"
            );
            assert_eq!(crate::chain::event_for(&s), crate::chain::event_for(&d), "{id}");
            assert_eq!(scored(&s), scored(&d), "{id}: the scored contributions are the disabled run's");
            let hits: Vec<&Contribution> = s.contributions.iter().filter(|c| c.shadow).collect();
            assert!(!hits.is_empty(), "{id} is kept as a shadow contribution");
            assert!(hits.iter().all(|c| c.construct.as_deref() == Some(id) && c.points == 0.0), "{id}: {hits:?}");
            assert!(d.contributions.iter().all(|c| !c.shadow), "{id}");
        }
    }

    #[test]
    fn a_shadowed_honeypot_hit_never_bans() {
        let mut cfg = Config::default();
        cfg.shield.shadow = vec!["honeypot.decoy-hit".into()];
        let s = Shield::new(cfg);
        let mut chain = ChainTracker::new(&s.config().chain);
        let mut hp = Request::get("/.git/config");
        hp.src_ip = Some("10.0.0.40".parse().unwrap());
        let j = s.inspect_stateful(&hp, &mut chain, 0);
        assert!(!j.banned(), "{}", j.decided_by.msg);
        assert_ne!(j.decided_by.kind, CauseKind::Honeypot);
        assert!(j.contributions.iter().any(|c| c.shadow && c.construct.as_deref() == Some("honeypot.decoy-hit")));
        assert_eq!(chain.ban_count(), 0);
    }
```

Append to `mod tests` in `chain.rs`:

```rust
    #[test]
    fn shadow_contributions_never_stage_a_source() {
        let sqli = Contribution {
            engine: "graph-taint",
            field: None,
            construct: Some("sqli.union-select".into()),
            family: Some(Family::Sqli),
            value: FourValued::Dangerous,
            weight: 0.95,
            points: 0.0,
            shadow: true,
        };
        assert_eq!(event_for(&judgment(Verdict::Block, vec![sqli.clone()])), Event::Benign);
        let mut ua = scanner_ua();
        ua.shadow = true;
        assert_eq!(event_for(&judgment(Verdict::Challenge, vec![ua])), Event::Benign);
        let live = Contribution { shadow: false, ..sqli };
        assert_eq!(event_for(&judgment(Verdict::Block, vec![live])), Event::Exfiltration);
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-core shadow` → Expected: compile errors, `no field 'shadow' on type 'ShieldConfig'` and `struct 'Contribution' has no field named 'shadow'`.

- [ ] **Step 3: Config, registry, `Disabled::has`**

In `config.rs`, in `ShieldConfig` after `pub disabled: Vec<String>,`:

```rust
    /// Construct ids that are detected and recorded but never score: the request
    /// is judged as if they were in `disabled`, and each hit is kept as a
    /// `shadow` contribution with 0 points. While non-empty, every request is
    /// inspected twice. An id may not also be in `disabled`; decoders cannot be
    /// shadowed.
    pub shadow: Vec<String>,
```

In `impl Default for ShieldConfig`, after `disabled: Vec::new(),` add `shadow: Vec::new(),`.

In `cross_field_issues`, after the `max_normalize_work` check (before `let s = &self.scoring;`):

```rust
        for id in &sh.shadow {
            if sh.disabled.iter().any(|d| d == id) {
                bad("shield.shadow", format!("{id:?} is also in shield.disabled; an id is either disabled or shadowed"));
            }
            if crate::graph::sinks::lookup(id).is_some_and(|c| c.kind == crate::graph::sinks::ConstructKind::Decoder) {
                bad("shield.shadow", format!("{id:?} is a decoder; decoders emit no evidence and cannot be shadowed (use shield.disabled)"));
            }
        }
```

In `options.rs` `REGISTRY`, directly after the `shield.disabled` entry:

```rust
    opt("shield.shadow", ConstructIds, "shield", "Construct ids detected and recorded but never scored: requests are judged as if they were in `shield.disabled`, and each hit is kept as a shadow contribution. Every request is inspected twice while the list is non-empty. An id may not also be in `shield.disabled`; decoders cannot be shadowed.", Advanced, Live),
```

In `graph/sinks/mod.rs`, inside `impl Disabled` after `pub fn is`:

```rust
    /// Whether `id` is in the set (for ids carried as strings, such as a
    /// contribution's construct).
    pub fn has(&self, id: &str) -> bool {
        self.0.contains(id)
    }
```

- [ ] **Step 4: `Contribution.shadow`**

In `judgment.rs`, in `Contribution` after `pub points: f32,`:

```rust
    /// A `shield.shadow` construct: it fired, but the request was judged as if
    /// it were disabled. Always 0 points; ignored by the score, the verdict,
    /// `decided_by` and the kill chain.
    pub shadow: bool,
```

Add `shadow: false,` after `points: ...,` in every existing `Contribution { ... }` literal: `shield.rs` (`banned_judgment`, `chain_contribution`, and both literals in `Recorder::record`) and `chain.rs` tests (the literal in `scanner_ua()` and the `recon` literal in `recon_stages_only_when_the_request_is_not_allowed`). Any literal missed here fails to compile with `missing field 'shadow' in initializer of 'Contribution'`; fix each the same way.

- [ ] **Step 5: Shield — judging set and second pass**

Replace the `Shield` struct with:

```rust
pub struct Shield {
    cfg: Config,
    norm_opts: Options,
    honeypot: Honeypot,
    intel: Intel,
    oracle: Box<dyn AiOracle>,
    /// Constructs off when judging: `shield.disabled` plus `shield.shadow`.
    disabled: Disabled,
    /// `shield.disabled` alone, set only when `shield.shadow` is non-empty: the
    /// second pass that finds which shadow constructs fired.
    observe: Option<Disabled>,
    /// `shield.shadow`.
    shadow: Disabled,
}
```

In `with_oracle`, replace `let disabled = Disabled::resolve(&cfg.shield.disabled);` with:

```rust
        let off: Vec<String> = cfg.shield.disabled.iter().chain(&cfg.shield.shadow).cloned().collect();
        let disabled = Disabled::resolve(&off);
        let shadow = Disabled::resolve(&cfg.shield.shadow);
        let observe = (!cfg.shield.shadow.is_empty()).then(|| Disabled::resolve(&cfg.shield.disabled));
```

and replace its closing `Shield { ... }` literal with:

```rust
        Shield {
            cfg,
            norm_opts,
            honeypot,
            intel,
            oracle,
            disabled,
            observe,
            shadow,
        }
```

Replace the head of `inspect_counting` (its doc comment and the line `fn inspect_counting(&self, req: &Request) -> (Judgment, usize) {`) with the new `inspect_counting` plus the head of `inspect_view`; the old body stays as the body of `inspect_view`:

```rust
    /// [`Shield::inspect`], plus the normalization work it spent (folded chars).
    ///
    /// With `shield.shadow` set, the request is judged with the shadow ids off
    /// (exactly as if they were in `shield.disabled`), then inspected again with
    /// only `shield.disabled` off; the shadow ids that fired in that pass are
    /// appended as `shadow` contributions with 0 points. They never reach the
    /// score, the verdict, `decided_by` or the chain.
    fn inspect_counting(&self, req: &Request) -> (Judgment, usize) {
        let (mut j, work) = self.inspect_view(req, &self.disabled);
        if let Some(full) = &self.observe {
            let (seen, _) = self.inspect_view(req, full);
            j.contributions.extend(
                seen.contributions
                    .into_iter()
                    .filter(|c| c.construct.as_deref().is_some_and(|id| self.shadow.has(id)))
                    .map(|c| Contribution { points: 0.0, shadow: true, ..c }),
            );
        }
        (j, work)
    }

    /// One inspection with the constructs in `off` switched off.
    fn inspect_view(&self, req: &Request, off: &Disabled) -> (Judgment, usize) {
```

In the body of `inspect_view`, replace every `self.disabled` with `off`, and pass `off` on:
- `graph::GraphOpts { disabled: &self.disabled, ...}` → `graph::GraphOpts { disabled: off, ... }`
- `.filter(|_| !self.disabled.is(&sinks::LIMIT_HEADER_NON_UTF8))` → `.filter(|_| !off.is(&sinks::LIMIT_HEADER_NON_UTF8))`
- `self.record_graph_truncated(&mut rec, FieldRef::path());` → `self.record_graph_truncated(&mut rec, FieldRef::path(), off);`
- `!self.disabled.is(&sinks::LIMIT_PAYLOAD_TRUNCATED)` → `!off.is(&sinks::LIMIT_PAYLOAD_TRUNCATED)`
- `intent_evidence(req, &self.cfg, &self.disabled)` → `intent_evidence(req, &self.cfg, off)`
- `if !self.disabled.is(&sinks::INTEL_SCANNER_UA)` → `if !off.is(&sinks::INTEL_SCANNER_UA)`
- `!self.disabled.is(&sinks::INTEL_DENY_LISTED)` → `!off.is(&sinks::INTEL_DENY_LISTED)`
- `if self.disabled.is(&sinks::HONEYPOT_DECOY_HIT)` → `if off.is(&sinks::HONEYPOT_DECOY_HIT)`

In `inspect_text` (it already receives `gopts`, whose `disabled` is `off`; adding a parameter would trip `clippy::too_many_arguments`):
- `self.record_graph_truncated(rec, fref.clone());` → `self.record_graph_truncated(rec, fref.clone(), gopts.disabled);`
- `disabled: &self.disabled,` → `disabled: gopts.disabled,`

Replace `record_graph_truncated`'s signature and first line with:

```rust
    fn record_graph_truncated(&self, rec: &mut Recorder, field: FieldRef, off: &Disabled) {
        if off.is(&sinks::LIMIT_GRAPH_TRUNCATED) {
```

In `top_contribution`, replace `for c in cs {` with `for c in cs.iter().filter(|c| !c.shadow) {`.

Run: `grep -n "self.disabled" crates/vft-core/src/shield.rs` → Expected: exactly one hit, `let (mut j, work) = self.inspect_view(req, &self.disabled);`.

- [ ] **Step 6: `event_for` ignores shadow contributions**

In `chain.rs`, replace the body of `event_for` up to the `Event::Benign` return with:

```rust
pub fn event_for(j: &Judgment) -> Event {
    let dangerous = |f: Family| {
        j.contributions
            .iter()
            .any(|c| !c.shadow && c.value == FourValued::Dangerous && c.family == Some(f))
    };
    if j.decided_by.kind == CauseKind::Honeypot {
        return Event::Honeypot;
    }
    if j.verdict.rank() >= Verdict::Challenge.rank() {
        let exfil = j.contributions.iter().any(|c| {
            !c.shadow
                && c.value == FourValued::Dangerous
                && c.construct.as_deref().is_some_and(|n| EXFIL_CONSTRUCTS.iter().any(|c| c.id == n))
        });
        if exfil {
            return Event::Exfiltration;
        }
        if ATTACK_FAMILIES.iter().any(|f| dangerous(*f)) {
            return Event::Exploitation;
        }
    }
    // An allowed request never stages a source, whatever the config (principle 2).
    if dangerous(Family::Recon) && j.verdict.rank() >= Verdict::Monitor.rank() {
        return Event::Recon;
    }
    let scanner = j
        .contributions
        .iter()
        .any(|c| !c.shadow && c.construct.as_deref() == Some(sinks::INTEL_SCANNER_UA.id) && c.value.is_threat());
    if scanner && j.verdict.rank() >= Verdict::Challenge.rank() {
        return Event::Enumeration;
    }
    Event::Benign
}
```

- [ ] **Step 7: Audit line**

In `crates/vft-proxy/src/audit.rs`, add `shadow: bool,` after `points: f32,` in `struct ContribLine`, and `shadow: c.shadow,` after `points: c.points,` in `record`. In the test `lines_carry_timestamp_and_request_id`, after the `points` assertion add:

```rust
        assert_eq!(v["contributions"][0]["shadow"], false, "{v}");
```

- [ ] **Step 8: Run the Rust tests**

Run: `cargo test -p vft-core shadow` → Expected: PASS (4 tests).
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green (`every_config_leaf_has_exactly_one_descriptor` and `sections_and_help_are_filled_in` cover the new leaf).

- [ ] **Step 9: Regenerate the TypeScript bindings and mirror the field**

Run: `cargo test -p vft-core --features ts --test ts_bindings` → Expected: FAIL, `stale bindings ... ["Contribution.ts"]`.
Run: `VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings && cargo test -p vft-core --features ts --test ts_bindings` → Expected: PASS twice.
Run: `git status --short ui/src/gen` → Expected: only ` M ui/src/gen/Contribution.ts`, now ending in `shadow: boolean, };` with the doc comment above it.
Run: `cargo clippy -p vft-core --all-targets --features ts -- -D warnings` → Expected: green.

In `ui/src/lib/api/types.ts`, replace the `Contribution` interface with:

```ts
export interface Contribution {
  engine: string; field: FieldRef | null; construct: string | null; family: Family | null;
  value: FourValued; weight: number; points: number; shadow: boolean;
}
```

Run: `test -d ui/node_modules && (cd ui && npm run check && npm test) || echo "ui/node_modules absent: UI check not run"` → Expected: either both UI commands pass, or the "not run" line (record which in the task report; Task 9 copies it into the results).

- [ ] **Step 10: Gate** (shadow list empty)

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (Host facts on exit 2).

- [ ] **Step 11: Commit**

```bash
git add crates/vft-core crates/vft-proxy/src/audit.rs ui/src/gen/Contribution.ts ui/src/lib/api/types.ts
git commit -m "feat(core): shadow constructs, recorded but never scored" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: `shadow` CSV column, `--shadow` and `--promotion` *(Gate)*

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`Outputs`, `PromotionRow`, `Report`, `run`, tests)
- Modify: `crates/vft-cli/src/main.rs` (`Eval` arguments and handler)

**Interfaces:**
- Consumes: `Contribution.shadow`, `ShieldConfig.shadow` (Task 5); `Outputs`, `top_construct`, `csv_cell` (Task 4).
- Produces: `Outputs { csv: Option<&'a Path>, promotion: bool }`; `#[derive(Debug, Default, Clone, PartialEq, Serialize)] pub struct PromotionRow { pub construct: String, pub would_tp: u64, pub would_fp: u64, pub already: u64, pub promote: bool }`; `Report.promotion: Option<Vec<PromotionRow>>` as the last report field, omitted from JSON when `None`; CSV header `rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow` (`constructs` now lists non-shadow contributions only; `shadow` is the `|`-joined sorted set of shadow ids that fired); CLI `venusflytrap eval --shadow <id>` (repeatable) and `--promotion` (needs a non-empty `shield.shadow`; library or serve mode).

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `eval.rs`)

```rust
    #[test]
    fn promotion_counts_shadow_hits_by_class_and_the_csv_lists_them() {
        let mk = |rel: &str, label, raw: &str| Sample { rel: rel.into(), label, raw: raw.as_bytes().to_vec(), unreadable: None };
        let samples = vec![
            mk("a.black", 1, "GET /?q=hello HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n"),
            mk("b.white", 0, "GET /index.html HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n"),
            mk("c.black", 1, "GET /?id=1%20union%20select%20password%20from%20users HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n"),
            mk("d.white", 0, "GET /?q=hello HTTP/1.1\r\nHost: x\r\n\r\n"),
        ];
        let mut cfg = Config::default();
        cfg.shield.shadow = vec!["intel.scanner-ua".into()];
        let p = std::env::temp_dir().join(format!("vft-eval-promo-{}.csv", std::process::id()));
        let r = run(cfg, &samples, false, Sources::Distinct, 100, Outputs { csv: Some(&p), promotion: true }).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!(
            r.promotion,
            Some(vec![PromotionRow { construct: "intel.scanner-ua".into(), would_tp: 1, would_fp: 1, already: 1, promote: false }])
        );
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow"));
        for line in lines {
            let cols: Vec<&str> = line.split(',').collect();
            let want = if cols[0] == "d.white" { "" } else { "intel.scanner-ua" };
            assert_eq!(cols[10], want, "{line}");
            assert!(!cols[6].split('|').any(|c| c == "intel.scanner-ua"), "{line}");
        }
    }

    #[test]
    fn reports_without_promotion_omit_the_field() {
        let s = Sample { rel: "a.white".into(), label: 0, raw: b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let r = run(Config::default(), &[s], false, Sources::Distinct, 100, Outputs::default()).unwrap();
        assert!(r.promotion.is_none());
        assert!(!serde_json::to_string(&r).unwrap().contains("\"promotion\""));
    }
```

In `csv_names_the_deciding_field_and_top_construct` (Task 4), replace `Outputs { csv: Some(&p) }` with `Outputs { csv: Some(&p), ..Default::default() }`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-cli promotion` → Expected: compile errors, `struct 'Outputs' has no field named 'promotion'` and `cannot find struct ... 'PromotionRow'`.

- [ ] **Step 3: Implement in `eval.rs`**

Change the collections import to `use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};`.

Replace `Outputs` with:

```rust
/// Optional outputs of [`run`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Outputs<'a> {
    /// Per-sample CSV.
    pub csv: Option<&'a Path>,
    /// Count shadow-construct hits per class into `Report.promotion` (`--promotion`).
    pub promotion: bool,
}
```

Add after `ExplainCounts`'s `impl`:

```rust
/// What promoting one shadow construct would change on the scored samples,
/// measured against the library verdict with the construct still in shadow.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct PromotionRow {
    pub construct: String,
    /// Fires on a malicious row the live verdict misses (Allow/Monitor).
    pub would_tp: u64,
    /// Fires on a benign row the live verdict allows (Allow/Monitor).
    pub would_fp: u64,
    /// Fires on a row the live verdict already blocks (Block/Challenge).
    pub already: u64,
    /// The promotion rule: `would_tp > would_fp`.
    pub promote: bool,
}
```

In `Report`, after `pub latency_us_p50_p95_p99: [u64; 3],`:

```rust
    /// Per `shield.shadow` id, with `--promotion` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promotion: Option<Vec<PromotionRow>>,
```

In `run`, before `let shield = Arc::new(Shield::new(cfg));`:

```rust
    let mut promo: BTreeMap<String, PromotionRow> = cfg
        .shield
        .shadow
        .iter()
        .map(|id| (id.clone(), PromotionRow { construct: id.clone(), ..Default::default() }))
        .collect();
```

Replace the CSV header line with:

```rust
            writeln!(f, "rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow")?;
```

Directly after `lib.add(attack(lj.verdict), s.label);`:

```rust
        let shadow_hits: BTreeSet<&str> = lj.contributions.iter().filter(|c| c.shadow).filter_map(|c| c.construct.as_deref()).collect();
        if out.promotion {
            for id in &shadow_hits {
                let row = promo
                    .entry(id.to_string())
                    .or_insert_with(|| PromotionRow { construct: id.to_string(), ..Default::default() });
                if attack(lj.verdict) {
                    row.already += 1;
                } else if s.label == 1 {
                    row.would_tp += 1;
                } else {
                    row.would_fp += 1;
                }
            }
        }
```

Replace the CSV row block with:

```rust
        if let Some(f) = csv_out.as_mut() {
            let constructs: Vec<&str> = lj.contributions.iter().filter(|c| !c.shadow).filter_map(|c| c.construct.as_deref()).collect();
            let field = lj.decided_by.field.as_ref().map(|r| r.label()).unwrap_or_default();
            let shadow: Vec<&str> = shadow_hits.iter().copied().collect();
            writeln!(
                f,
                "{},{},{:?},{},{},{},{},{:?}:{},{},{},{}",
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
                top_construct(&lj.contributions).unwrap_or(""),
                shadow.join("|")
            )?;
        }
```

(`top_construct` never picks a shadow contribution: they have 0 points and it needs points > 0.)

In the returned `Report`, after `latency_us_p50_p95_p99: [pct(0.5), pct(0.95), pct(0.99)],`:

```rust
        promotion: out.promotion.then(|| {
            promo
                .into_values()
                .map(|mut r| {
                    r.promote = r.would_tp > r.would_fp;
                    r
                })
                .collect()
        }),
```

- [ ] **Step 4: CLI** (`main.rs`)

In `Command::Eval`, after the `disable` field:

```rust
        /// Run a construct in shadow (repeatable): detected and recorded as a
        /// shadow contribution, never scored.
        #[arg(long)]
        shadow: Vec<String>,
        /// Report, per shadow construct, the rows it would gain (would_tp),
        /// cost (would_fp) or not change (already) if promoted.
        #[arg(long)]
        promotion: bool,
```

Replace the head of the `Command::Eval` arm up to and including the `cfg.validate()` line with:

```rust
        Command::Eval { corpus, mode, sources, step_ms, out, limit, manifest, side, disable, shadow, promotion } => {
            let mut cfg = load_config(cli.config.as_ref())?;
            cfg.shield.disabled.extend(disable);
            cfg.shield.shadow.extend(shadow);
            cfg.validate().map_err(|e| anyhow::anyhow!(e.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("; ")))?;
            if promotion && cfg.shield.shadow.is_empty() {
                anyhow::bail!("--promotion needs construct ids in shield.shadow (config file or --shadow)");
            }
```

Inside `if mode == EvalMode::Tcp {`, as its first statement:

```rust
                if promotion {
                    anyhow::bail!("--promotion needs --mode library or serve");
                }
```

Replace the `eval::run` call and the `println!` after it with:

```rust
            let report = eval::run(cfg, &samples, mode == EvalMode::Serve, sources, step_ms, eval::Outputs { csv: out.as_deref(), promotion })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if let Some(rows) = &report.promotion {
                eprintln!("construct\twould_tp\twould_fp\talready\tpromote");
                for r in rows {
                    eprintln!("{}\t{}\t{}\t{}\t{}", r.construct, r.would_tp, r.would_fp, r.already, r.promote);
                }
            }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p vft-cli` → Expected: PASS.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.
Run: `cargo run --release -p vft-cli -- eval --corpus "$VFT_CORPUS" --mode library --promotion; echo "exit $?"` → Expected: the error `--promotion needs construct ids in shield.shadow (config file or --shadow)` and a non-zero exit.

- [ ] **Step 6: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (Host facts on exit 2).
Run: `grep -c '"promotion"' "$VFT_BASELINE/now-serve-distinct.json"` → Expected: `0`.

- [ ] **Step 7: Commit**

```bash
git add crates/vft-cli/src/eval.rs crates/vft-cli/src/main.rs
git commit -m "feat(eval): shadow CSV column, --shadow and --promotion" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Keep-alive replay upstream and zero-linger clients *(Gate)*

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`send_and_read`, `run_tcp`, new `connect`, `serve_keepalive`, `content_length`, tests)
- Modify: `crates/vft-cli/Cargo.toml` (tokio floor)

**Interfaces:**
- Produces: `async fn connect(addr: std::net::SocketAddr, limit: std::time::Duration) -> Result<tokio::net::TcpStream, String>` (connect, then `set_zero_linger`; errors `connect: ...`, `connect timeout`, `set_zero_linger: ...`); `async fn serve_keepalive(s: tokio::net::TcpStream)` (answers every request on a connection with `HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n`, reading each head and its `Content-Length` body; returns on EOF, error, or a head it cannot frame); `fn content_length(head: &[u8]) -> Option<usize>` (0 when absent, `None` for `Transfer-Encoding` or a bad length). `TcpReport` is unchanged.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `eval.rs`)

```rust
    #[test]
    fn content_length_frames_a_request_head() {
        assert_eq!(content_length(b"POST / HTTP/1.1\r\ncontent-length: 12\r\n\r\n"), Some(12));
        assert_eq!(content_length(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Some(0));
        assert_eq!(content_length(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), None);
        assert_eq!(content_length(b"POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n"), None);
    }

    #[test]
    fn replay_upstream_keeps_connections_alive() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                let (s, _) = l.accept().await.unwrap();
                serve_keepalive(s).await;
            });
            let want: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            // A body split across writes, then a second request on the same connection.
            c.write_all(b"POST /a HTTP/1.1\r\nhost: x\r\ncontent-length: 5\r\n\r\nab").await.unwrap();
            c.write_all(b"cde").await.unwrap();
            c.write_all(b"GET /b HTTP/1.1\r\nhost: x\r\n\r\n").await.unwrap();
            let mut got = vec![0u8; 2 * want.len()];
            tokio::time::timeout(std::time::Duration::from_secs(5), c.read_exact(&mut got)).await.unwrap().unwrap();
            assert_eq!(&got[..want.len()], want);
            assert_eq!(&got[want.len()..], want);
            // Still open: a third request is answered too.
            c.write_all(b"GET /c HTTP/1.1\r\n\r\n").await.unwrap();
            let mut third = vec![0u8; want.len()];
            tokio::time::timeout(std::time::Duration::from_secs(5), c.read_exact(&mut third)).await.unwrap().unwrap();
            assert_eq!(&third[..], want);
        });
    }

    #[test]
    fn replay_client_sockets_close_without_time_wait() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let s = connect(l.local_addr().unwrap(), std::time::Duration::from_secs(5)).await.unwrap();
            assert_eq!(s.linger().unwrap(), Some(std::time::Duration::ZERO));
        });
    }

    #[test]
    fn tcp_replay_of_many_bodies_has_no_upstream_or_io_mismatch() {
        let samples: Vec<Sample> = (0..60)
            .map(|i| Sample {
                rel: format!("{i:02}.white"),
                label: 0,
                raw: format!(
                    "POST /form HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=item{i}&note={}",
                    "a".repeat(i * 1000)
                )
                .into_bytes(),
                unreadable: None,
            })
            .collect();
        let r = run_tcp(Config::default(), &samples, 100).unwrap();
        assert_eq!((r.mismatch_upstream_5xx, r.mismatch_io, r.mismatched), (0, 0, 0), "{r:?}");
        assert_eq!(r.matched_allow, 60, "{r:?}");
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-cli replay` → Expected: compile errors, `cannot find function 'serve_keepalive'`, `'connect'`, `'content_length'`.

- [ ] **Step 3: Implement**

In `crates/vft-cli/Cargo.toml`, change the tokio line to:

```toml
tokio = { version = "1.54.1", features = ["rt-multi-thread", "net", "io-util", "time", "macros"] }
```

In `eval.rs`, add above `send_and_read`:

```rust
/// Connect with zero linger: closing sends RST, so neither end of a replayed
/// connection enters TIME_WAIT and a full-corpus replay does not exhaust
/// loopback ports.
async fn connect(addr: std::net::SocketAddr, limit: std::time::Duration) -> Result<tokio::net::TcpStream, String> {
    let sock = match tokio::time::timeout(limit, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connect: {e}")),
        Err(_) => return Err("connect timeout".into()),
    };
    sock.set_zero_linger().map_err(|e| format!("set_zero_linger: {e}"))?;
    Ok(sock)
}

/// The Content-Length of a request head (0 when absent); `None` for
/// `Transfer-Encoding` or a length that does not parse.
fn content_length(head: &[u8]) -> Option<usize> {
    let mut len = 0usize;
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = line[..colon].trim_ascii();
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return None;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            len = std::str::from_utf8(line[colon + 1..].trim_ascii()).ok()?.parse().ok()?;
        }
    }
    Some(len)
}

/// The replay's stand-in upstream: answers every request on a connection with
/// an empty 200 and keeps the connection open, so the proxy's pooled client
/// reuses it. Reads each request head and its Content-Length body; returns when
/// the peer closes, on an error, or on a head it cannot frame.
async fn serve_keepalive(mut s: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let head_end = loop {
            if let Some(i) = find(&buf, b"\r\n\r\n") {
                break i + 4;
            }
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let Some(body_len) = content_length(&buf[..head_end]) else {
            return;
        };
        while buf.len() < head_end + body_len {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf.drain(..head_end + body_len);
        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.is_err() {
            return;
        }
    }
}
```

In `send_and_read`, replace the `let mut sock = match ... { ... };` block (the connect with its three arms) with:

```rust
    let mut sock = connect(addr, limit).await?;
```

In `run_tcp`, delete the line `use tokio::io::{AsyncReadExt, AsyncWriteExt};` and replace the upstream task with:

```rust
        tokio::spawn(async move {
            while let Ok((s, _)) = up.accept().await {
                tokio::spawn(serve_keepalive(s));
            }
        });
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p vft-cli` → Expected: PASS (the existing `replay_io_failures_are_errors_and_early_replies_are_read` and `tcp_report_separates_block_and_allow_matches` included).
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green, no deprecation warning.
Run: `git diff --stat Cargo.lock` → Expected: no change.

- [ ] **Step 5: Full-corpus TCP replay**

Run: `cargo build --release -p vft-cli && "$B" eval --corpus "$VFT_CORPUS" --mode tcp --limit 40000 > "$VFT_RUNS/tcp-full-task7.json"; echo "exit $?"`
Run right after it: `netstat -an | grep -c TIME_WAIT`
Expected: exit 0; in the JSON `mismatch_upstream_5xx` 0, `mismatch_io` 0, `mismatch_block_vs_proxy_allow` 0, `mismatch_allow_vs_proxy_403` 0. Record every counter, the TIME_WAIT count and the run time in the task report.
If `mismatch_upstream_5xx` or `mismatch_io` is not 0, stop and use the systematic-debugging skill on the replay harness (the listed examples name the files; look only at their sizes with `wc -c`, never open payloads, since the full corpus includes held-out rows, and never fix by changing engine or proxy code). Any other non-zero mismatch bucket is reported with its examples; it is explained in Task 9, not hidden.

- [ ] **Step 6: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (Host facts on exit 2).

- [ ] **Step 7: Commit**

```bash
git add crates/vft-cli/src/eval.rs crates/vft-cli/Cargo.toml
git commit -m "fix(eval): keep-alive replay upstream and zero-linger clients" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: `eval --dump-requests` for the baselines *(Gate)*

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`Outputs`, `latin1`, `DumpRow`, `dump_line`, `run`, tests)
- Modify: `crates/vft-cli/src/main.rs` (`--dump-requests`)

**Interfaces:**
- Consumes: `Outputs`, `run` (Tasks 4, 6); `vft_core::Request` as built by `adapt::from_parts`.
- Produces: `Outputs { csv: Option<&'a Path>, promotion: bool, dump: Option<&'a Path> }`; `fn latin1(b: &[u8]) -> String`; `fn dump_line(rel: &str, label: u8, req: &vft_core::Request) -> serde_json::Result<String>`; CLI `venusflytrap eval --dump-requests <jsonl>` (library or serve mode). One JSON object per scored sample, keys in this order: `label` (0/1), `method`, `path`, `query` (`[[k, v], ...]`), `headers` (`[[name, value], ...]`, no `cookie`), `cookies` (`[[k, v], ...]`), `body`, `rel`. Every string is the Latin-1 view of its UTF-8 bytes (D6). Unreadable and unparseable samples write nothing.

- [ ] **Step 1: Write the failing tests** (append to `mod tests` in `eval.rs`)

```rust
    #[test]
    fn latin1_maps_each_byte_to_one_char() {
        assert_eq!(latin1(b"a=1"), "a=1");
        assert_eq!(latin1("\u{e9}".as_bytes()), "\u{c3}\u{a9}");
        assert_eq!(latin1(&[0xe9]), "\u{e9}");
    }

    #[test]
    fn dump_requests_writes_parse_corpus_rows_for_scored_samples_only() {
        let mut raw = b"POST /f?a=1 HTTP/1.1\r\nHost: x\r\nCookie: s=1; t=2\r\n\r\nname=".to_vec();
        raw.push(0xe9);
        let samples = vec![
            Sample { rel: "d/a.white".into(), label: 0, raw, unreadable: None },
            Sample { rel: "d/b.black".into(), label: 1, raw: b"\r\n\r\n".to_vec(), unreadable: None },
            Sample { rel: "d/c.black".into(), label: 1, raw: Vec::new(), unreadable: Some("denied".into()) },
        ];
        let p = std::env::temp_dir().join(format!("vft-eval-dump-{}.jsonl", std::process::id()));
        let r = run(Config::default(), &samples, false, Sources::Distinct, 100, Outputs { dump: Some(&p), ..Default::default() }).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        assert_eq!((r.parse_failures, r.read_failures), (1, 1));
        assert_eq!(
            text.lines().collect::<Vec<_>>(),
            vec!["{\"label\":0,\"method\":\"POST\",\"path\":\"/f\",\"query\":[[\"a\",\"1\"]],\"headers\":[[\"host\",\"x\"]],\"cookies\":[[\"s\",\"1\"],[\"t\",\"2\"]],\"body\":\"name=\u{e9}\",\"rel\":\"d/a.white\"}"]
        );
    }
```

In `promotion_counts_shadow_hits_by_class_and_the_csv_lists_them` (Task 6), replace `Outputs { csv: Some(&p), promotion: true }` with `Outputs { csv: Some(&p), promotion: true, dump: None }`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-cli dump` → Expected: compile errors, `cannot find function 'latin1'` and `struct 'Outputs' has no field named 'dump'`.

- [ ] **Step 3: Implement in `eval.rs`**

In `Outputs`, after `pub promotion: bool,`:

```rust
    /// JSONL of every scored request as the engine receives it (`--dump-requests`).
    pub dump: Option<&'a Path>,
```

Add after `Outputs`:

```rust
/// Latin-1 view of bytes: each byte becomes the char with that code point, so
/// Python's `s.encode("latin-1")` returns exactly these bytes.
fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| char::from(c)).collect()
}

/// One `--dump-requests` line, in `eval/parse_corpus.py`'s schema plus `rel`.
#[derive(Serialize)]
struct DumpRow<'a> {
    label: u8,
    method: &'a str,
    path: String,
    query: Vec<[String; 2]>,
    headers: Vec<[String; 2]>,
    cookies: Vec<[String; 2]>,
    body: String,
    rel: &'a str,
}

/// The request exactly as `adapt::from_parts` built it. Every string is the
/// Latin-1 view of its UTF-8 bytes; the raw `Cookie` header goes only into
/// `cookies`, as in parse_corpus.py.
fn dump_line(rel: &str, label: u8, req: &vft_core::Request) -> serde_json::Result<String> {
    let pair = |(k, v): &(String, String)| [latin1(k.as_bytes()), latin1(v.as_bytes())];
    serde_json::to_string(&DumpRow {
        label,
        method: &req.method,
        path: latin1(req.path.as_bytes()),
        query: req.query.iter().map(pair).collect(),
        headers: req.headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("cookie")).map(pair).collect(),
        cookies: req.cookies.iter().map(pair).collect(),
        body: latin1(&req.body),
        rel,
    })
}
```

In `run`, after the `csv_out` block:

```rust
    let mut dump_out = match out.dump {
        Some(p) => Some(std::io::BufWriter::new(std::fs::File::create(p)?)),
        None => None,
    };
```

Directly after `let req = adapt::from_parts(&p.parts, &p.body, Some(ip));`:

```rust
        if let Some(w) = dump_out.as_mut() {
            writeln!(w, "{}", dump_line(&s.rel, s.label, &req)?)?;
        }
```

After the sample loop (before `lat.sort_unstable();`):

```rust
    if let Some(mut w) = dump_out {
        w.flush()?;
    }
```

- [ ] **Step 4: CLI** (`main.rs`)

In `Command::Eval`, after the `promotion` field:

```rust
        /// Write every scored request, as the engine receives it, to this JSONL
        /// file in eval/parse_corpus.py's schema (plus `rel`), for eval/baselines.py.
        #[arg(long)]
        dump_requests: Option<PathBuf>,
```

Add `dump_requests` to the destructuring: `Command::Eval { corpus, mode, sources, step_ms, out, limit, manifest, side, disable, shadow, promotion, dump_requests } => {`.

Replace the tcp-mode guard `if promotion { anyhow::bail!("--promotion needs --mode library or serve"); }` with:

```rust
                if promotion || dump_requests.is_some() {
                    anyhow::bail!("--promotion and --dump-requests need --mode library or serve");
                }
```

Replace `eval::Outputs { csv: out.as_deref(), promotion }` with `eval::Outputs { csv: out.as_deref(), promotion, dump: dump_requests.as_deref() }`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p vft-cli` → Expected: PASS.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 6: Real-corpus count check**

```bash
cargo build --release -p vft-cli
"$B" eval --corpus "$VFT_CORPUS" --mode library --dump-requests "$VFT_RUNS/requests-task8.jsonl" > "$VFT_RUNS/dump-check.json"
wc -l < "$VFT_RUNS/requests-task8.jsonl"
py -I -X utf8 -c "import json,sys; r=json.load(open(sys.argv[1],encoding='utf-8')); print(r['samples']-r['read_failures']-r['parse_failures'])" "$VFT_RUNS/dump-check.json"
py -I -X utf8 -c "import json,sys; r=json.loads(open(sys.argv[1],encoding='utf-8').readline()); print(list(r))" "$VFT_RUNS/requests-task8.jsonl"
```

Expected: the two counts are equal; the key list is `['label', 'method', 'path', 'query', 'headers', 'cookies', 'body', 'rel']`.

- [ ] **Step 7: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (Host facts on exit 2).

- [ ] **Step 8: Commit**

```bash
git add crates/vft-cli/src/eval.rs crates/vft-cli/src/main.rs
git commit -m "feat(eval): --dump-requests for the baselines" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Acceptance runs, `eval/RESULTS-DQ1.md`, status line *(Gate)*

**Files:**
- Create: `eval/RESULTS-DQ1.md`
- Modify: `docs/BENCHMARK.md` (one status line, after the SP2 status line)

**Interfaces:**
- Consumes: everything above. Produces only documents.

- [ ] **Step 1: Final checks on the finished tree**

```bash
cargo test --workspace && cargo clippy --all-targets -- -D warnings
cargo test -p vft-core --features ts --test ts_bindings
py -I -X utf8 -m unittest discover -s eval -p "test_*.py" -v
test -d ui/node_modules && (cd ui && npm run check && npm test) || echo "ui/node_modules absent: UI check not run"
bash eval/decision_gate.sh check "$VFT_BASELINE"
```

Expected: all green; last gate line `decision gate: identical` (Host facts on exit 2; keep the list of absent files).

- [ ] **Step 2: Measured runs** (full corpus)

```bash
cargo build --release -p vft-cli
"$B" eval --corpus "$VFT_CORPUS" --mode library --out "$VFT_RUNS/library.csv" --dump-requests "$VFT_RUNS/requests.jsonl" > "$VFT_RUNS/library.json"
"$B" eval --corpus "$VFT_CORPUS" --mode serve --sources distinct --out "$VFT_RUNS/serve-distinct.csv" > "$VFT_RUNS/serve-distinct.json"
"$B" eval --corpus "$VFT_CORPUS" --mode serve --sources pooled:100 --out "$VFT_RUNS/serve-pooled100.csv" > "$VFT_RUNS/serve-pooled100.json"
"$B" eval --corpus "$VFT_CORPUS" --mode tcp --limit 40000 > "$VFT_RUNS/tcp-full.json"; echo "tcp exit $?"; netstat -an | grep -c TIME_WAIT
```

Expected: library and serve runs exit 0; tcp exit 0 with `mismatch_upstream_5xx` 0 and `mismatch_io` 0.

- [ ] **Step 3: Baselines on identical inputs**

```bash
py -I -X utf8 -c "import ctypes, sys; ctypes.CDLL(sys.argv[1]); print('libinjection loads')" "$VFT_LIBINJ"
py -I -X utf8 eval/baselines.py "$VFT_RUNS/requests.jsonl" "$VFT_RUNS/baselines.json" "$VFT_LIBINJ"
py -I -X utf8 - "$VFT_RUNS/baselines.json" <<'EOF'
import json, math, sys
def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))
for r in json.load(open(sys.argv[1], encoding="utf-8")):
    print(r["engine"], "recall_ci95", wilson(r["tp"], r["tp"] + r["fn"]), "fp_rate_ci95", wilson(r["fp"], r["fp"] + r["tn"]))
EOF
```

`baselines.py` needs only the Python standard library and the libinjection shared library at `$VFT_LIBINJ`. If the first command fails (missing file or load error), do not build or download anything: record in the results that the baselines were not re-measured, quote the error line, and give the exact command above for the owner to run. Otherwise expect `tp + fn` plus `fp + tn` to equal the JSONL line count (`wc -l < "$VFT_RUNS/requests.jsonl"`).

- [ ] **Step 4: Dev-only clusters and a promotion mechanics check**

```bash
"$B" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side dev --out "$VFT_RUNS/library-dev.csv" > "$VFT_RUNS/library-dev.json"
py -I -X utf8 eval/clusters.py "$VFT_RUNS/library-dev.csv" --manifest "$VFT_MANIFEST" --side dev --top 10 > "$VFT_RUNS/clusters-dev.txt"
"$B" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side dev --shadow intel.scanner-ua --promotion > "$VFT_RUNS/promotion-dev.json"
```

Do not open any corpus file listed in `clusters-dev.txt`; the results cite rel paths only.

- [ ] **Step 5: Write `eval/RESULTS-DQ1.md`**

Copy every number from the run outputs; estimate nothing. Sections, in this order:

1. **Header.** One paragraph: DQ1 changes no detection; it adds intervals, paired comparison, clustering, shadow constructs, a clean TCP replay and identical baseline inputs. Then bullets: baseline = code of main `69d0e32` (captured in Task 1); measured tree = `git rev-parse --short HEAD`; machine = the Windows 11 host of `RESULTS-SP2.md`; corpus = the `VFT_CORPUS` directory used for SP2 (refer to `docs/BENCHMARK.md` section 1, do not name it here); `samples` and `read_failures` of each run.
2. **Decision gate.** `decision gate: identical` for `distinct` and `pooled:100`, plus any absent-file rows from the Host facts procedure (rel paths, with "absent from the corpus directory, deleted by the host antivirus"), or "row sets matched".
3. **Recall and FP rate with Wilson 95 % intervals.** Table `Run | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI]` with rows `library` (`library.json` → `library`), `serve, distinct` (`serve-distinct.json` → `serve.metrics`), `serve, pooled:100` (`serve-pooled100.json` → `serve.metrics`). Recall and FP rate as percentages with two decimals; intervals from `recall_ci95` and `fp_rate_ci95`. One sentence on what the interval width means for the 658-attack class (the recall interval is wide because the malicious class is small).
4. **Baselines on identical inputs.** Table `Engine | TP | FP | TN | FN | Recall [95 % CI] | FP rate [95 % CI]` for libinjection and the regex baseline from `baselines.json` and Step 3's intervals, plus the Venusflytrap library row from section 3 for reference. State: input = `requests.jsonl` from `--dump-requests` (line count), the same requests the engine scored; the path is in the URI form the engine receives (raw `<`, `>`, spaces percent-encoded); the earlier Python-parsed baseline numbers in `docs/BENCHMARK.md` stay in the history as such. If not measured: the error line and the command.
5. **TCP replay.** Table with the columns of `RESULTS-SP1.md` section "TCP replay, bucketed (I6)": `replayed | matched_block | matched_allow | proxy_rejected | not_replayable | block_vs_proxy_allow | allow_vs_proxy_403 | upstream_5xx | io | other | mismatched`, from `tcp-full.json`, plus the TIME_WAIT count, the exit status and the run time. One sentence comparing with SP1's full run (upstream_5xx 767, io 9). List and explain every non-zero mismatch bucket from `mismatch_examples`; list `proxy_rejected_examples` as before.
6. **Top false-positive and miss clusters (dev only).** The two tables from `clusters-dev.txt` (top 10 each), with the totals line of each. Say they are dev rows only (`--side dev`), held-out rows were not read, and examples are rel paths whose payloads were not opened for this file.
7. **Promotion mechanics check.** The `promotion` row from `promotion-dev.json` for `intel.scanner-ua`, labelled as a check that the counters work on real data, not a promotion decision (no new construct exists in DQ1).
8. **UI check.** Whether `npm run check` / `npm test` ran (Task 5 Step 9 and Step 1 here) or were not run because `ui/node_modules` is absent in the worktree; in that case the owner runs `npm ci` then both commands.

- [ ] **Step 6: Status line in `docs/BENCHMARK.md`**

After the line starting `Status: SP2 (explainable judgments)`, add one line, worded from the measured results, of this form:

```markdown
Status: DQ1 (measurement foundation) changes no detection; the numbers below stand. Wilson 95 % intervals, the libinjection and regex baselines re-measured on the engine's own parsed requests, and the full-corpus TCP replay are in [`eval/RESULTS-DQ1.md`](../eval/RESULTS-DQ1.md).
```

If the baselines were not re-measured, or the TCP replay still shows upstream_5xx or io mismatches, say so in that line instead of claiming them.

- [ ] **Step 7: Commit**

```bash
git add eval/RESULTS-DQ1.md docs/BENCHMARK.md
git commit -m "docs: DQ1 measured results" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Acceptance map (spec section 6)

| Acceptance item | Where it is proven |
|---|---|
| `cargo test --workspace`, `cargo clippy --all-targets -- -D warnings` | Every task; Task 9 Step 1 |
| `py -I -X utf8 -m unittest` for `eval/*.py` | Tasks 2, 4; Task 9 Step 1 |
| UI `npm test` / `npm run check` after the binding regeneration | Task 5 Step 9 and Task 9 Step 1 when `ui/node_modules` exists; otherwise recorded as not run (Task 9 section 8) |
| Decision gate identical with `shield.shadow` empty | Tasks 2–9 (*Gate*), baseline from Task 1 |
| Wilson intervals; `wilson(k, 0) = (0, 0)` | Task 3 tests; Task 9 section 3 |
| McNemar b, c, p per class; p = 1 for b + c = 0; exit codes unchanged | Task 2 tests |
| `field` column; `clusters.py` groups, `--side`, exit 2 naming a missing column | Task 4 tests and fixture; Task 9 section 6 |
| A shadowed construct changes no score / verdict / `decided_by` and appears as a shadow contribution | Task 5 `a_shadowed_construct_is_recorded_but_decides_nothing`, `a_shadowed_honeypot_hit_never_bans`, `shadow_contributions_never_stage_a_source` |
| `shield.shadow` vs `shield.disabled` cross-field issue | Task 5 `shadow_ids_must_be_registered_not_disabled_and_not_decoders` |
| `Contribution.shadow` in the generated TS and `types.ts` | Task 5 Step 9 |
| `shadow` CSV column and `--promotion` counts | Task 6 tests; Task 9 section 7 |
| Full-corpus TCP replay with upstream_5xx = 0 and io = 0 | Task 7 Step 5; Task 9 section 5 |
| `--dump-requests` in parse_corpus.py's schema; baselines re-measured on it | Task 8 tests and Step 6; Task 9 section 4 |
| `.gitattributes` LF for `*.sh` and `ui/src/gen/**` | Task 1 |
