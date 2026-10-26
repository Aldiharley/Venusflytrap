# Recall Lift, Plan A (M0–M2a: baseline, registry, fail-closed fixes) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay the measured foundation for recall lift: a fixed dev/held-out split, an M0 baseline, a construct registry with per-construct disable switches and ablation, and the decoder and truncation fixes (H1, L5, C2, C3), all without tuning on held-out data.

**Architecture:** Recall-lift builds on SP1's branch (`sp1-serve-hardening`) after SP1's Task 12 is committed. The token-graph sinks move from `graph/mod.rs` into `graph/sinks/{sql,xss,shell,path}.rs` and emit through a `Hits` collector that takes `&'static ConstructInfo` registry entries, so every pattern name is a registered dotted id and disabled constructs are dropped at the source. Evaluation reuses SP1's raw-file `venusflytrap eval` (library mode) with a split manifest, a `--disable` flag and a new `ablate` command; robustness keeps using `bench_http` on `mutate.py` output.

**Tech Stack:** Rust 2021 workspace (`vft-core`, `vft-proxy`, `vft-cli`), clap, serde/serde_yaml/serde_json, proptest; Python 3.13 for `eval/` scripts (run with `py -I -X utf8`); Git Bash on Windows.

**Spec:** `docs/superpowers/specs/2026-10-25-recall-lift-design.md` (commit `e30e54f` on local `main`). Plan B (M2b–M5: body structuring with `limit.body-unparsed` and `shield.body_parse`, the new decoders, the new constructs, the 256-field-cap regression test) is written after this plan lands, against the code as it is then.

**Deviation from the spec (§7.2):** `constructs()` returns `&'static [&'static ConstructInfo]`, not `&'static [ConstructInfo]`. Each construct is its own `static` that `Hits` takes by reference, and a static slice cannot hold copies of them. Recorded in the shared session note for SP1.

## Global Constraints

- `#![forbid(unsafe_code)]` in every crate.
- `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` green at the end of every task.
- `vft-core` stays I/O-free and deterministic: no clock, no file or network access in the detection path.
- No `unwrap()`/`expect()` on attacker-reachable paths in non-test code.
- Never quote the synthetic-corpus result (96.1% recall / 0 FP) as a result.
- Do not associate Venusflytrap with outside project names in code, docs or commit messages.
- Rules, decoders and tests are written from **dev** misses only. Held-out misses are never opened. Held-out is scored once per milestone, at its end (Task 4 for M0, Task 12 for M2a).
- Equivalence diffs (Tasks 6, 7) may cover the full corpus because they compare identity, not quality. If a diff is non-empty, fix it from code reasoning and dev rows only; do not open held-out payloads.
- Every measured number goes into `eval/RESULTS-RECALL.md`. Report regressions plainly.
- Commits go on branch `recall-lift` in worktree `M:/Projects/venusflytrap-recall`. The owner approves committing per task before execution starts (Task 0). Never push; never touch `main` without explicit approval.
- Do not modify `eval/parse_corpus.py`, `eval/baselines.py`, `eval/mutate.py` or `crates/vft-cli/examples/bench_http.rs`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Eval data locations (this machine)

```bash
EVAL=C:/Users/DENNIS~1/AppData/Local/Temp/claude/C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu/da1b01dd-cef6-4b76-bba8-0e55e99fd9e4/scratchpad
CORPUS=$EVAL/ext/blazehttp/testcases     # 33,219 .white + 658 .black
JSONL=$EVAL/run0/corpus.jsonl            # from eval/parse_corpus.py
LIBINJ=$EVAL/ext/libinjection.dll
OUT=M:/Projects/venusflytrap-recall-runs # run outputs (outside the repo); create it in Task 0
B=./target/release/venusflytrap          # run from M:/Projects/venusflytrap-recall
BH=./target/release/examples/bench_http
```

Every task's shell steps assume these variables are set and the current directory is `M:/Projects/venusflytrap-recall`.

If `$EVAL` no longer exists (it is under the OS temp folder), recreate it:

```bash
mkdir -p "$EVAL/ext" "$EVAL/run0" && cd "$EVAL/ext"
git clone -q --depth 1 https://github.com/chaitin/blazehttp
git clone -q --depth 1 https://github.com/libinjection/libinjection
gcc -shared -O2 -o libinjection.dll libinjection/src/libinjection_sqli.c libinjection/src/libinjection_xss.c libinjection/src/libinjection_html5.c
cd M:/Projects/venusflytrap-recall && py -I -X utf8 eval/parse_corpus.py "$CORPUS" "$JSONL"   # parsed=33877 skipped=0
```

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `eval/split.py` (new) | fixed label-stratified 50/50 split, manifest + per-half JSONL | 1 |
| `eval/test_split.py` (new) | unit tests for `split.py` | 1 |
| `eval/compare_runs.py` (new) | equivalence diff and metric deltas between two run CSVs | 2 |
| `eval/test_compare_runs.py` (new) | unit tests for `compare_runs.py` | 2 |
| `crates/vft-cli/src/eval.rs` | manifest filter, `ablate` | 3, 7 |
| `crates/vft-cli/src/main.rs` | `--manifest/--side/--disable` flags, `ablate` subcommand | 3, 7 |
| `eval/RESULTS-RECALL.md` (new) | every measured number | 4, 6–12 |
| `crates/vft-core/src/graph/sinks/mod.rs` (new) | registry, `Hits`, `Disabled`, `SinkCtx`, non-graph and decoder/limit statics | 5–11 |
| `crates/vft-core/src/graph/sinks/{sql,xss,shell,path}.rs` (new) | sink detectors moved from `graph/mod.rs` | 6 |
| `crates/vft-core/src/graph/mod.rs` | `analyze`, `analyze_with`, `GraphOpts`, windowing | 6, 7, 10 |
| `crates/vft-core/src/detect.rs`, `honeypot.rs`, `intel.rs`, `chain.rs`, `shield.rs` | use registry ids; respect `Disabled`; limits; chunking | 6, 7, 10, 11 |
| `crates/vft-core/src/config.rs` | `shield.disabled`, `shield.max_graph_windows`, `shield.max_inspect_bytes` + validation | 7, 10, 11 |
| `crates/vft-core/src/normalize/mod.rs` | `percent_decode_lossy`, decoder gating, L5, `chunks`, `truncated` | 8, 9, 11 |
| `crates/vft-core/src/request.rs` | use `normalize::percent_decode_lossy` | 8 |

---

### Task 0: Worktree, approval, baseline build

**Files:** none changed.

- [ ] **Step 1: Confirm SP1 has landed its last task**

Run: `cd M:/Projects/venusflytrap-sp1 && git log --oneline -3 && git status --short`
Expected: the newest commit is SP1's Task 12 ("Honest docs, final measurement, Claude Doc update") and the tree is clean. If not, stop and tell the controller: Plan A starts from SP1's final tip.

- [ ] **Step 2: Create the worktree and branch**

```bash
cd M:/Projects/venusflytrap
git worktree add -b recall-lift ../venusflytrap-recall sp1-serve-hardening
cd ../venusflytrap-recall && git log --oneline -1
mkdir -p M:/Projects/venusflytrap-recall-runs
```

Expected: `venusflytrap-recall` exists on branch `recall-lift` at SP1's tip.

- [ ] **Step 3: Bring the spec onto the branch**

```bash
cd M:/Projects/venusflytrap-recall
git show main:docs/superpowers/specs/2026-10-25-recall-lift-design.md > docs/superpowers/specs/2026-10-25-recall-lift-design.md
cp ../venusflytrap/docs/superpowers/plans/2026-10-25-recall-lift-plan-a-foundation.md docs/superpowers/plans/   # the plan is not committed on main
```

- [ ] **Step 4: Verify the base is green**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"` and `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2`
Expected: every `test result: ok`, clippy finishes with no warnings.

- [ ] **Step 5: Get commit approval**

Ask the owner: "Plan A will commit once per task on branch `recall-lift` in `M:/Projects/venusflytrap-recall` (never pushed, never on `main`). OK to commit per task without asking each time?" Record the answer. If the answer is no, ask before every commit step below.

- [ ] **Step 6: Commit the spec and plan on the branch**

```bash
git add docs/superpowers/specs/2026-10-25-recall-lift-design.md docs/superpowers/plans/2026-10-25-recall-lift-plan-a-foundation.md
git commit -m "docs: recall-lift spec and plan A

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1: Fixed dev/held-out split (`eval/split.py`)

**Files:**
- Create: `eval/split.py`
- Test: `eval/test_split.py`

**Interfaces:**
- Produces: `eval/split.py <testcases_dir> <out_dir> [<corpus.jsonl>]` writing `<out_dir>/manifest.tsv` (tab-separated `relpath`, `label`, `sha256`, `side`; relpath uses `/`), and, with a JSONL argument, `<out_dir>/dev.jsonl` and `<out_dir>/heldout.jsonl`. Functions `walk(root)`, `assign(items)`.

- [ ] **Step 1: Write the failing test**

`eval/test_split.py`:

```python
"""Tests for eval/split.py. Run: py -I -X utf8 eval/test_split.py"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("split", Path(__file__).with_name("split.py"))
split = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(split)


def make_corpus(root, files):
    """files: list of (relpath, bytes)."""
    for rel, data in files:
        p = Path(root, rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


class SplitTests(unittest.TestCase):
    def test_label_stratified_halves(self):
        items = [(f"a/{i}.white", 0, f"{i:064x}") for i in range(11)]
        items += [(f"b/{i}.black", 1, f"{i + 100:064x}") for i in range(5)]
        side = split.assign(items)
        dev_benign = sum(1 for r, l, _ in items if l == 0 and side[r] == "dev")
        dev_mal = sum(1 for r, l, _ in items if l == 1 and side[r] == "dev")
        self.assertEqual(dev_benign, 6)  # ceil(11/2)
        self.assertEqual(dev_mal, 3)  # ceil(5/2)

    def test_deterministic(self):
        items = [(f"x/{i}.white", 0, f"{(i * 7919) % 97:064x}") for i in range(40)]
        self.assertEqual(split.assign(items), split.assign(list(reversed(items))))

    def test_identical_files_stay_on_one_side(self):
        # four distinct hashes, the 2nd and 3rd smallest are the same file content
        items = [("p.white", 0, "1" * 64), ("q.white", 0, "2" * 64),
                 ("r.white", 0, "2" * 64), ("s.white", 0, "3" * 64)]
        side = split.assign(items)
        self.assertEqual(side["q.white"], side["r.white"])

    def test_main_writes_manifest_and_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "testcases")
            files = [("00/a.white", b"GET /a HTTP/1.1\r\n\r\n"),
                     ("00/b.white", b"GET /b HTTP/1.1\r\n\r\n"),
                     ("01/c.black", b"GET /?q=1 union select 2 HTTP/1.1\r\n\r\n"),
                     ("01/d.black", b"GET /?q=<script> HTTP/1.1\r\n\r\n")]
            make_corpus(root, files)
            walked = split.walk(str(root))
            jsonl = Path(tmp, "corpus.jsonl")
            with open(jsonl, "w", encoding="utf-8") as w:
                for rel, label, _ in walked:
                    w.write(json.dumps({"label": label, "path": "/" + rel}) + "\n")
            out = Path(tmp, "out")
            split.main([str(root), str(out), str(jsonl)])
            rows = [l.split("\t") for l in Path(out, "manifest.tsv").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 4)
            self.assertEqual({r[0] for r in rows}, {"00/a.white", "00/b.white", "01/c.black", "01/d.black"})
            dev = Path(out, "dev.jsonl").read_text(encoding="utf-8").splitlines()
            held = Path(out, "heldout.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual((len(dev), len(held)), (2, 2))
            self.assertEqual(sorted(json.loads(l)["label"] for l in dev), [0, 1])

    def test_unreadable_file_is_keyed_on_its_path(self):
        key = split.sha256_of("no/such/file.black", "no/such/file.black")
        self.assertTrue(key.startswith("unreadable:"))
        self.assertEqual(key, split.sha256_of("no/such/file.black", "no/such/file.black"))

    def test_label_mismatch_with_jsonl_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "testcases")
            make_corpus(root, [("a.white", b"x"), ("b.black", b"y")])
            jsonl = Path(tmp, "corpus.jsonl")
            jsonl.write_text('{"label": 1}\n{"label": 0}\n', encoding="utf-8")
            with self.assertRaises(SystemExit):
                split.main([str(root), str(Path(tmp, "out")), str(jsonl)])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `py -I -X utf8 eval/test_split.py`
Expected: FAIL with `FileNotFoundError` (no `split.py`).

- [ ] **Step 3: Implement `eval/split.py`**

```python
"""Fixed, label-stratified 50/50 dev / held-out split of a blazehttp-style corpus.

Key: SHA-256 of each raw .white/.black file. Within each label, files are sorted
by (key, relative path) and the first half (rounded up) is dev; a run of
byte-identical files is never split across the cut. No randomness.

Writes <out>/manifest.tsv (relpath, label, sha256, side). Given the JSONL that
eval/parse_corpus.py produced from the same directory, also writes
<out>/dev.jsonl and <out>/heldout.jsonl; lines are paired with files by
repeating parse_corpus.py's os.walk order, and every label is checked.

Usage: py -I -X utf8 eval/split.py <testcases_dir> <out_dir> [<corpus.jsonl>]
"""
import hashlib
import json
import os
import sys


def walk(root):
    """(relpath, label, abspath) for every .white/.black file, in parse_corpus.py's order."""
    out = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if fn.endswith(".white"):
                label = 0
            elif fn.endswith(".black"):
                label = 1
            else:
                continue
            p = os.path.join(dirpath, fn)
            out.append((os.path.relpath(p, root).replace("\\", "/"), label, p))
    return out


def sha256_of(path, rel):
    """SHA-256 of the file. A file the host will not let us read (on this machine
    two .black files are blocked, likely by antivirus) is keyed on its relative
    path instead, so it still gets a fixed side; the manifest marks it."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError as e:
        print(f"warning: unreadable, keyed on path: {rel} ({e})", file=sys.stderr)
        return "unreadable:" + hashlib.sha256(rel.encode("utf-8")).hexdigest()


def assign(items):
    """items: iterable of (relpath, label, sha256). Returns {relpath: 'dev' | 'heldout'}."""
    items = list(items)
    side = {}
    for label in (0, 1):
        group = sorted((it for it in items if it[1] == label), key=lambda it: (it[2], it[0]))
        cut = (len(group) + 1) // 2
        # Keep byte-identical files together: extend dev over a run that straddles the cut.
        while 0 < cut < len(group) and group[cut][2] == group[cut - 1][2]:
            cut += 1
        for i, it in enumerate(group):
            side[it[0]] = "dev" if i < cut else "heldout"
    return side


def main(argv):
    if len(argv) not in (2, 3):
        sys.exit(__doc__)
    root, out_dir = argv[0], argv[1]
    files = walk(root)
    items = [(rel, label, sha256_of(p, rel)) for rel, label, p in files]
    side = assign(items)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "manifest.tsv"), "w", encoding="utf-8", newline="\n") as m:
        for rel, label, sha in items:
            m.write(f"{rel}\t{label}\t{sha}\t{side[rel]}\n")
    if len(argv) == 3:
        with open(argv[2], encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        if len(lines) != len(files):
            sys.exit(f"corpus.jsonl has {len(lines)} records but {root} has {len(files)} files")
        with open(os.path.join(out_dir, "dev.jsonl"), "w", encoding="utf-8", newline="\n") as d, \
             open(os.path.join(out_dir, "heldout.jsonl"), "w", encoding="utf-8", newline="\n") as h:
            for (rel, label, _), line in zip(files, lines):
                if json.loads(line)["label"] != label:
                    sys.exit(f"label mismatch pairing {rel} with its JSONL line")
                (d if side[rel] == "dev" else h).write(line if line.endswith("\n") else line + "\n")
    for s in ("dev", "heldout"):
        counts = {lab: sum(1 for rel, l, _ in items if l == lab and side[rel] == s) for lab in (0, 1)}
        print(f"{s}: benign={counts[0]} malicious={counts[1]}")


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `py -I -X utf8 eval/test_split.py`
Expected: `OK` (6 tests).

- [ ] **Step 5: Produce the real split**

```bash
py -I -X utf8 eval/split.py "$CORPUS" "$OUT/split" "$JSONL"
```

Expected output (matches the spec's §4.1 prototype):

```
dev: benign=16610 malicious=329
heldout: benign=16609 malicious=329
```

Expected on stderr: two `warning: unreadable, keyed on path` lines (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`; this host denies reading them). Their JSONL lines exist because `parse_corpus.py` read them before the block, so the per-half JSONL files stay complete. If the counts differ, stop and report them; do not adjust the algorithm to hit the numbers.

- [ ] **Step 6: Commit**

```bash
git add eval/split.py eval/test_split.py
git commit -m "feat(eval): fixed label-stratified dev/held-out split keyed on raw-file SHA-256

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Run comparison (`eval/compare_runs.py`)

**Files:**
- Create: `eval/compare_runs.py`
- Test: `eval/test_compare_runs.py`

**Interfaces:**
- Consumes: CSVs from `venusflytrap eval --out` (header `rel,label,lib_verdict,serve_verdict,score,banned,constructs`) or from `bench_http` (header `label,pred,score,latency_us`).
- Produces: `py -I -X utf8 eval/compare_runs.py <a.csv> <b.csv>`. It prints the TP/FP/TN/FN of each file and the delta, then the rows whose decision columns differ (first 20). Exit 0 if identical, 1 if any decision column differs. Decision columns: eval format `label, lib_verdict, serve_verdict, score, banned` keyed by `rel`; bench format `label, pred, score` keyed by row index. Function `compare(a_rows, b_rows) -> (diffs, metrics_a, metrics_b)`.

- [ ] **Step 1: Write the failing test**

`eval/test_compare_runs.py`:

```python
"""Tests for eval/compare_runs.py. Run: py -I -X utf8 eval/test_compare_runs.py"""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("compare_runs", Path(__file__).with_name("compare_runs.py"))
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

EVAL_HDR = "rel,label,lib_verdict,serve_verdict,score,banned,constructs\n"


def write(tmp, name, text):
    p = Path(tmp, name)
    p.write_text(text, encoding="utf-8")
    return str(p)


class CompareTests(unittest.TestCase):
    def test_identical_eval_runs_differ_only_in_constructs(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "x.black,1,Block,Block,95,false,union-select\n")
            b = write(tmp, "b.csv", EVAL_HDR + "x.black,1,Block,Block,95,false,sqli.union-select\n")
            diffs, ma, mb = cr.compare(cr.load(a), cr.load(b))
            self.assertEqual(diffs, [])
            self.assertEqual(ma, mb)

    def test_verdict_change_is_a_diff_and_metrics_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "x.black,1,Allow,Allow,0,false,\ny.white,0,Allow,Allow,0,false,\n")
            b = write(tmp, "b.csv", EVAL_HDR + "x.black,1,Block,Block,95,false,\ny.white,0,Allow,Allow,0,false,\n")
            diffs, ma, mb = cr.compare(cr.load(a), cr.load(b))
            self.assertEqual(len(diffs), 1)
            self.assertEqual((ma["tp"], mb["tp"]), (0, 1))

    def test_bench_format_by_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", "label,pred,score,latency_us\n1,1,95,10\n1,0,20,9\n")
            b = write(tmp, "b.csv", "label,pred,score,latency_us\n1,1,95,99\n1,0,20,1\n")
            diffs, ma, mb = cr.compare(cr.load(a), cr.load(b))
            self.assertEqual(diffs, [])
            self.assertEqual(ma["tp"], 1)

    def test_challenge_counts_as_attack(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR + "x.black,1,Challenge,Challenge,75,false,\n")
            _, ma, _ = cr.compare(cr.load(a), cr.load(a))
            self.assertEqual(ma["tp"], 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `py -I -X utf8 eval/test_compare_runs.py`
Expected: FAIL with `FileNotFoundError` (no `compare_runs.py`).

- [ ] **Step 3: Implement `eval/compare_runs.py`**

```python
"""Compare two evaluation runs: decision equivalence and metric deltas.

Accepts CSVs from `venusflytrap eval --out` (keyed by rel) or from the
bench_http example (keyed by row). Latency and construct names are ignored;
everything that decides the outcome is compared.

Usage: py -I -X utf8 eval/compare_runs.py <a.csv> <b.csv>
Exit status: 0 identical decisions, 1 differences.
"""
import csv
import sys

EVAL_COLS = ("label", "lib_verdict", "serve_verdict", "score", "banned")
BENCH_COLS = ("label", "pred", "score")


def load(path):
    """Returns (kind, {key: row_dict}) with kind 'eval' or 'bench'."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if rows and "rel" in rows[0]:
        return "eval", {r["rel"]: r for r in rows}
    return "bench", {str(i): r for i, r in enumerate(rows)}


def is_attack(kind, row):
    if kind == "eval":
        return row["lib_verdict"] in ("Block", "Challenge")
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
    (ka, ra), (kb, rb) = a, b
    if ka != kb:
        sys.exit(f"cannot compare a {ka} CSV with a {kb} CSV")
    cols = EVAL_COLS if ka == "eval" else BENCH_COLS
    if ra.keys() != rb.keys():
        sys.exit(f"row sets differ: {len(ra.keys() - rb.keys())} only in a, {len(rb.keys() - ra.keys())} only in b")
    diffs = []
    for key in sorted(ra):
        x, y = ra[key], rb[key]
        changed = [c for c in cols if x[c] != y[c]]
        if changed:
            diffs.append((key, {c: (x[c], y[c]) for c in changed}))
    return diffs, metrics(ka, ra), metrics(kb, rb)


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    diffs, ma, mb = compare(load(argv[0]), load(argv[1]))
    for name, m in (("a", ma), ("b", mb)):
        print(f"{name}: tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} "
              f"recall={m['recall']:.4f} fp_rate={m['fp_rate']:.4f}")
    print(f"delta: tp={mb['tp'] - ma['tp']:+d} fp={mb['fp'] - ma['fp']:+d}")
    print(f"decision diffs: {len(diffs)}")
    for key, d in diffs[:20]:
        print(f"  {key}: {d}")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `py -I -X utf8 eval/test_compare_runs.py`
Expected: `OK` (4 tests).

- [ ] **Step 5: Commit**

```bash
git add eval/compare_runs.py eval/test_compare_runs.py
git commit -m "feat(eval): compare two runs for decision equivalence and metric deltas

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Split manifest in `venusflytrap eval`

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (add `load_manifest`, `select_side` and their tests)
- Modify: `crates/vft-cli/src/main.rs` (`Eval` gains `--manifest` and `--side`)

**Interfaces:**
- Consumes: `eval::Sample { rel, label, raw, unreadable }`, `eval::load_corpus`, `manifest.tsv` from Task 1.
- Produces: `pub fn load_manifest(path: &Path) -> anyhow::Result<HashMap<String, (u8, String)>>`; `pub fn select_side(samples: Vec<Sample>, manifest: &HashMap<String, (u8, String)>, side: &str) -> anyhow::Result<Vec<Sample>>`. CLI: `venusflytrap eval --corpus DIR --mode library --manifest M --side dev|heldout`.

- [ ] **Step 1: Write the failing tests** (append inside the existing `#[cfg(test)] mod tests` in `crates/vft-cli/src/eval.rs`)

```rust
    fn sample(rel: &str, label: u8) -> Sample {
        Sample { rel: rel.into(), label, raw: b"GET / HTTP/1.1\r\n\r\n".to_vec(), unreadable: None }
    }

    fn manifest_file(text: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vft-manifest-{}-{}.tsv", std::process::id(), text.len()));
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn select_side_keeps_only_that_side() {
        let p = manifest_file("a.white\t0\tff\tdev\nb.black\t1\tee\theldout\n");
        let m = load_manifest(&p).unwrap();
        let picked = select_side(vec![sample("a.white", 0), sample("b.black", 1)], &m, "dev").unwrap();
        assert_eq!(picked.iter().map(|s| s.rel.as_str()).collect::<Vec<_>>(), vec!["a.white"]);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn select_side_rejects_unknown_files_and_label_mismatch() {
        let p = manifest_file("a.white\t0\tff\tdev\n");
        let m = load_manifest(&p).unwrap();
        assert!(select_side(vec![sample("zzz.white", 0)], &m, "dev").is_err());
        assert!(select_side(vec![sample("a.white", 1)], &m, "dev").is_err());
        assert!(select_side(vec![sample("a.white", 0)], &m, "test").is_err());
        let _ = std::fs::remove_file(p);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vft-cli select_side`
Expected: FAIL to compile with "cannot find function `load_manifest`".

- [ ] **Step 3: Implement** (add to `crates/vft-cli/src/eval.rs` after `load_corpus`; add `use std::collections::HashMap;` to the imports)

```rust
/// Read `manifest.tsv` from `eval/split.py`: relpath, label, sha256, side.
pub fn load_manifest(path: &Path) -> anyhow::Result<HashMap<String, (u8, String)>> {
    let text = std::fs::read_to_string(path)?;
    let mut m = HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() != 4 {
            anyhow::bail!("{}:{}: expected 4 tab-separated columns", path.display(), n + 1);
        }
        let label: u8 = cols[1].parse()?;
        m.insert(cols[0].to_string(), (label, cols[3].to_string()));
    }
    Ok(m)
}

/// Keep the samples on `side` ("dev" or "heldout"). Every sample must be in the
/// manifest with the same label, so a stale manifest fails loudly.
pub fn select_side(samples: Vec<Sample>, manifest: &HashMap<String, (u8, String)>, side: &str) -> anyhow::Result<Vec<Sample>> {
    if side != "dev" && side != "heldout" {
        anyhow::bail!("--side must be dev or heldout, got {side:?}");
    }
    let mut out = Vec::new();
    for s in samples {
        let Some((label, sd)) = manifest.get(&s.rel) else {
            anyhow::bail!("{} is not in the manifest", s.rel);
        };
        if *label != s.label {
            anyhow::bail!("{}: manifest label {} != corpus label {}", s.rel, label, s.label);
        }
        if sd == side {
            out.push(s);
        }
    }
    Ok(out)
}
```

In `crates/vft-cli/src/main.rs`, add to the `Eval` variant:

```rust
        /// Split manifest from eval/split.py (use with --side).
        #[arg(long, requires = "side")]
        manifest: Option<PathBuf>,
        /// Which half of the split to score: dev or heldout.
        #[arg(long, requires = "manifest")]
        side: Option<String>,
```

and change the `Command::Eval` arm to:

```rust
        Command::Eval { corpus, mode, sources, step_ms, out, manifest, side } => {
            let cfg = load_config(cli.config.as_ref())?;
            let sources: eval::Sources = sources.parse().map_err(anyhow::Error::msg)?;
            let mut samples = eval::load_corpus(&corpus)?;
            if let (Some(m), Some(s)) = (manifest.as_ref(), side.as_deref()) {
                samples = eval::select_side(samples, &eval::load_manifest(m)?, s)?;
            }
            let report = eval::run(cfg, &samples, mode == EvalMode::Serve, sources, step_ms, out.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.invariant_violations > 0 || report.serve.as_ref().is_some_and(|s| s.bans_from_allowed > 0) {
                std::process::exit(3);
            }
        }
```

- [ ] **Step 4: Run the tests and the real split**

Run: `cargo test -p vft-cli select_side` → Expected: 2 passed.
Then:

```bash
cargo build --release -p vft-cli
./target/release/venusflytrap eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev | grep -E '"samples"|"tp"|"fp"'
```

Expected: `"samples": 16939` and library tp/fp values (record them in Task 4).

- [ ] **Step 5: Clippy, then commit**

Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

```bash
git add crates/vft-cli/src/eval.rs crates/vft-cli/src/main.rs
git commit -m "feat(cli): eval --manifest/--side scores one half of the fixed split

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: M0 baseline measurement

**Files:**
- Create: `eval/RESULTS-RECALL.md`
- Modify: `README.md`, `docs/BENCHMARK.md` only if they still contain the synthetic table (Step 5)

**Interfaces:**
- Consumes: Tasks 1–3; SP1's `eval/RESULTS-SP1.md` for comparison.
- Produces: M0 reference runs in `$OUT/m0/` used by every later task: `lib_full.csv`, `serve_full.csv`, `lib_dev.csv`, `lib_heldout.csv`, `seeds.csv`, `mutants.csv`.

- [ ] **Step 1: Run every M0 measurement**

```bash
B=./target/release/venusflytrap; BH=./target/release/examples/bench_http; M="$OUT/split/manifest.tsv"; R="$OUT/m0"; mkdir -p "$R"
cargo build --release -p vft-cli --bins --examples
$B eval --corpus "$CORPUS" --mode library --out "$R/lib_full.csv" > "$R/lib_full.json"
$B eval --corpus "$CORPUS" --mode serve   --out "$R/serve_full.csv" > "$R/serve_full.json"
$B eval --corpus "$CORPUS" --mode library --manifest "$M" --side dev     --out "$R/lib_dev.csv" > "$R/lib_dev.json"
$B eval --corpus "$CORPUS" --mode library --manifest "$M" --side heldout --out "$R/lib_heldout.csv" > "$R/lib_heldout.json"
py -I -X utf8 eval/mutate.py "$R/seeds.jsonl" "$R/mutants.jsonl"
$BH "$R/seeds.jsonl" "$R/seeds.csv" 2> "$R/seeds.txt"
$BH "$R/mutants.jsonl" "$R/mutants.csv" 2> "$R/mutants.txt"
py -I -X utf8 eval/baselines.py "$OUT/split/dev.jsonl"     "$R/baselines_dev.json"     "$LIBINJ"
py -I -X utf8 eval/baselines.py "$OUT/split/heldout.jsonl" "$R/baselines_heldout.json" "$LIBINJ"
```

Expected: every command exits 0. `seeds.txt` and `mutants.txt` each hold one `engine=venusflytrap tp=… recall=…` line.

- [ ] **Step 2: Check the robustness reference**

Retained = mutants recall ÷ seeds recall. Expected near the spec's 0.8303 / 0.8636 = 96%. SP1's scoring changes may move it; record whatever is measured, and from here on it is the floor for the gate (§4.4: retained ≥ 96% and mutant recall ≥ 83.0%; if M0 itself is below either, record that and use M0's own values as the floor).

- [ ] **Step 3: Write `eval/RESULTS-RECALL.md`**

Create the file with this structure and fill every cell from the JSON/TXT outputs of Step 1 (no estimates; copy the numbers):

```markdown
# Recall-lift results

All numbers measured on this machine, release build. Library mode = `Shield::inspect`
(stateless); serve mode = `Pipeline::decide` (stateful, raw Cookie). Split: `eval/split.py`
(SHA-256 of raw files, label-stratified 50/50). Held-out is scored once per milestone.

## M0 — baseline on SP1's tip (commit <short sha>)

| Run | Samples | TP | FP | TN | FN | Recall | Precision | F1 | FP rate | p50/p95/p99 µs |
|---|---|---|---|---|---|---|---|---|---|---|
| library, full | | | | | | | | | | |
| serve, full | | | | | | | | | | |
| library, dev | | | | | | | | | | |
| library, held-out | | | | | | | | | | |

| Baseline (per half) | TP | FP | FN | Recall | Precision | FP rate |
|---|---|---|---|---|---|---|
| libinjection, dev | | | | | | |
| libinjection, held-out | | | | | | |
| regex, dev | | | | | | |
| regex, held-out | | | | | | |

Robustness (bench_http, mutate.py seed 1337): seeds recall ___, mutants recall ___, retained ___%.

Contamination log: before the split existed (2026-10-25), about 30 example payloads from the
full corpus were read while sizing the misses; some are in the held-out half.

Input notes: `venusflytrap eval` cannot read 2 malicious files on this host (access denied), so its
recall is over the malicious files it scores (656 on the full corpus; per-half counts from the JSON
`read_failures`). The libinjection and regex baselines read the Python-parsed JSONL, which still holds
those 2 requests (an input-fairness gap SP1 also records).
```

- [ ] **Step 4: Update the Claude Doc (controller step)**

The controller (not a subagent) updates doc `c555ba6b-ff38-4ea4-875c-3b4f08f0c8fe` (body node `4fa1b04f-a2b2`): Methodology gets the split and contamination log; Results gets an M0 row set (dev / held-out / full). Use the docs tools; read with `sinceRev` first.

- [ ] **Step 5: Remove synthetic headline numbers if SP1 left any**

Run: `grep -n "96.1\|0.000%\|100.0%" README.md docs/BENCHMARK.md`
SP1's Task 12 (`3ae8a6a`) already published real-corpus numbers in both files. `96.1%` lines that describe **mutation retention** (83.03 / 86.36) are real results, not the synthetic headline: leave them. If `README.md` still has the synthetic "Measured results" table, replace that section with the M0 library-full row, the libinjection and regex full-corpus rows from SP1's `eval/RESULTS-SP1.md`, and the robustness line, and say the corpus is blazehttp (33,877 real requests). If `docs/BENCHMARK.md` is still the synthetic report, add this first line under its title: `> Synthetic corpus only. These numbers are not results; see eval/RESULTS-RECALL.md for real-corpus measurements.` If grep finds nothing, change neither file.

- [ ] **Step 6: Commit**

```bash
git add eval/RESULTS-RECALL.md README.md docs/BENCHMARK.md
git commit -m "docs(eval): M0 baseline on the fixed split; no synthetic headline numbers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Construct registry

**Files:**
- Create: `crates/vft-core/src/graph/sinks/mod.rs` (registry only in this task; sink files arrive in Task 6)
- Modify: `crates/vft-core/src/graph/mod.rs` (add `pub mod sinks;`)

**Interfaces:**
- Produces (all in `vft_core::graph::sinks`):
  - `pub enum ConstructKind { Sink, Latent, Signature, Decoder, Limit }` (Signature = rule-based detections outside the token graph: signatures, API safety, recon, honeypot, intel)
  - `pub struct ConstructInfo { pub id: &'static str, pub family: Option<Family>, pub kind: ConstructKind, pub summary: &'static str }` with `pub fn pattern(&self) -> Pattern`
  - `pub fn constructs() -> &'static [&'static ConstructInfo]`, `pub fn lookup(id: &str) -> Option<&'static ConstructInfo>`, `pub fn unknown_ids(ids: &[String]) -> Vec<String>`
  - `pub struct Disabled` with `pub fn resolve(ids: &[String]) -> Disabled`, `pub fn is(&self, c: &ConstructInfo) -> bool`, `Default`, `Clone`, `Debug`
  - `pub struct Hits<'d> { pub reachable: Vec<Pattern>, pub latent: Vec<Pattern>, .. }` with `new(&'d Disabled)`, `reach(&mut self, &'static ConstructInfo)`, `latent(&mut self, &'static ConstructInfo)`, `reached(&self, Family) -> bool`
  - `pub struct SinkCtx<'a> { pub tokens: &'a [Token], pub text: &'a str }`
  - statics for non-graph constructs: `SIG_UNION_ALL_SELECT`, `SIG_CLASSIC_OR`, `SIG_SCHEMA_ENUM`, `SIG_ALERT_SCRIPT`, `SIG_ONERROR`, `SIG_ETC_PASSWD`, `SIG_CAT_SUBST`, `API_TYPE_VIOLATION`, `RECON_SENSITIVE_PATH`, `HONEYPOT_DECOY_HIT`, `INTEL_SCANNER_UA`, `LIMIT_HEADER_NON_UTF8`

- [ ] **Step 1: Write the failing tests** (bottom of the new `graph/sinks/mod.rs`; create the file with only this test module first, plus `pub mod sinks;` in `graph/mod.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_dotted() {
        let mut seen = std::collections::HashSet::new();
        for c in constructs() {
            assert!(seen.insert(c.id), "duplicate id {}", c.id);
            assert!(c.id.contains('.') && !c.id.starts_with('.') && !c.id.ends_with('.'), "not dotted: {}", c.id);
            assert!(
                c.id.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-'),
                "bad characters in {}",
                c.id
            );
            assert!(!c.summary.is_empty(), "{} has no summary", c.id);
        }
    }

    #[test]
    fn only_decoders_lack_a_family() {
        for c in constructs() {
            assert_eq!(c.family.is_none(), c.kind == ConstructKind::Decoder, "{}", c.id);
        }
    }

    #[test]
    fn lookup_and_unknown_ids() {
        assert_eq!(lookup("honeypot.decoy-hit").map(|c| c.id), Some("honeypot.decoy-hit"));
        assert!(lookup("nope.nope").is_none());
        assert_eq!(unknown_ids(&["honeypot.decoy-hit".into(), "nope.nope".into()]), vec!["nope.nope".to_string()]);
    }

    #[test]
    fn hits_drop_disabled_and_dedupe() {
        let d = Disabled::resolve(&["sig.onerror".into()]);
        let mut h = Hits::new(&d);
        h.reach(&SIG_ONERROR);
        h.reach(&SIG_CLASSIC_OR);
        h.reach(&SIG_CLASSIC_OR);
        h.latent(&SIG_ETC_PASSWD);
        assert_eq!(h.reachable.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["sig.classic-or"]);
        assert_eq!(h.latent.len(), 1);
        assert!(h.reached(Family::Sqli));
        assert!(!h.reached(Family::Xss));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p vft-core --lib graph::sinks`
Expected: FAIL to compile with "cannot find function `constructs`".

- [ ] **Step 3: Implement the registry** (top of `graph/sinks/mod.rs`, above the tests)

```rust
//! Construct registry and sink collection.
//!
//! Every pattern the engine can emit, every decoder and every inspection limit
//! has one stable dotted id here (`sqli.union-select`). Sinks emit through
//! [`Hits`], which takes the registry entry itself, so an unregistered id cannot
//! be emitted and a disabled construct is dropped at the source. Ids are never
//! reused; a rename keeps the old id as an alias entry.

use std::collections::HashSet;

use super::tokenize::{Token, TokenKind};
use crate::judgment::{Family, Pattern};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstructKind {
    /// A formed construct in the token graph (blocks on its own).
    Sink,
    /// A lone dangerous token with no construct (weak signal).
    Latent,
    /// A rule-based detection outside the token graph: signatures, API safety,
    /// recon, honeypot, intel.
    Signature,
    /// A normalizer decoding stage.
    Decoder,
    /// An inspection limit that fails closed.
    Limit,
}

#[derive(Debug)]
pub struct ConstructInfo {
    pub id: &'static str,
    /// `None` only for decoders, which belong to no attack family.
    pub family: Option<Family>,
    pub kind: ConstructKind,
    pub summary: &'static str,
}

impl ConstructInfo {
    /// The pattern this construct emits. Decoders never emit patterns; the
    /// registry test guarantees every other kind has a family.
    pub fn pattern(&self) -> Pattern {
        Pattern::new(self.family.unwrap_or(Family::Limit), self.id)
    }
}

// --- Constructs emitted outside the token graph -------------------------------

pub static SIG_UNION_ALL_SELECT: ConstructInfo = ConstructInfo { id: "sig.union-all-select", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "literal `union all select`" };
pub static SIG_CLASSIC_OR: ConstructInfo = ConstructInfo { id: "sig.classic-or", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "literal `' or '1'='1`" };
pub static SIG_SCHEMA_ENUM: ConstructInfo = ConstructInfo { id: "sig.schema-enum", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "literal `information_schema`" };
pub static SIG_ALERT_SCRIPT: ConstructInfo = ConstructInfo { id: "sig.alert-script", family: Some(Family::Xss), kind: ConstructKind::Signature, summary: "literal `<script>alert`" };
pub static SIG_ONERROR: ConstructInfo = ConstructInfo { id: "sig.onerror", family: Some(Family::Xss), kind: ConstructKind::Signature, summary: "literal `onerror=`" };
pub static SIG_ETC_PASSWD: ConstructInfo = ConstructInfo { id: "sig.etc-passwd", family: Some(Family::PathTraversal), kind: ConstructKind::Signature, summary: "literal `/etc/passwd`" };
pub static SIG_CAT_SUBST: ConstructInfo = ConstructInfo { id: "sig.cat-subst", family: Some(Family::CommandInjection), kind: ConstructKind::Signature, summary: "literal `$(cat `" };
pub static API_TYPE_VIOLATION: ConstructInfo = ConstructInfo { id: "api.type-violation", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "numeric-looking field (id, *_id, page, count) carries a formed construct" };
pub static RECON_SENSITIVE_PATH: ConstructInfo = ConstructInfo { id: "recon.sensitive-path-probe", family: Some(Family::Recon), kind: ConstructKind::Signature, summary: "canonical path starts with a configured sensitive path" };
pub static HONEYPOT_DECOY_HIT: ConstructInfo = ConstructInfo { id: "honeypot.decoy-hit", family: Some(Family::Honeypot), kind: ConstructKind::Signature, summary: "canonical path hits a configured decoy" };
pub static INTEL_SCANNER_UA: ConstructInfo = ConstructInfo { id: "intel.scanner-ua", family: Some(Family::Intel), kind: ConstructKind::Signature, summary: "User-Agent matches a scanner fingerprint" };
pub static LIMIT_HEADER_NON_UTF8: ConstructInfo = ConstructInfo { id: "limit.header-non-utf8", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "a header carried bytes that are not UTF-8" };

static REGISTRY: &[&ConstructInfo] = &[
    &SIG_UNION_ALL_SELECT,
    &SIG_CLASSIC_OR,
    &SIG_SCHEMA_ENUM,
    &SIG_ALERT_SCRIPT,
    &SIG_ONERROR,
    &SIG_ETC_PASSWD,
    &SIG_CAT_SUBST,
    &API_TYPE_VIOLATION,
    &RECON_SENSITIVE_PATH,
    &HONEYPOT_DECOY_HIT,
    &INTEL_SCANNER_UA,
    &LIMIT_HEADER_NON_UTF8,
];

/// Every registered construct, decoder and limit.
pub fn constructs() -> &'static [&'static ConstructInfo] {
    REGISTRY
}

pub fn lookup(id: &str) -> Option<&'static ConstructInfo> {
    REGISTRY.iter().copied().find(|c| c.id == id)
}

/// The ids in `ids` that name no registered construct (for config validation).
pub fn unknown_ids(ids: &[String]) -> Vec<String> {
    ids.iter().filter(|i| lookup(i).is_none()).cloned().collect()
}

/// The constructs switched off by `shield.disabled`.
#[derive(Debug, Clone, Default)]
pub struct Disabled(HashSet<&'static str>);

impl Disabled {
    /// Resolve configured ids. Unknown ids are skipped here; `Config::validate`
    /// reports them, so a validated config never reaches this with one.
    pub fn resolve(ids: &[String]) -> Disabled {
        Disabled(ids.iter().filter_map(|i| lookup(i)).map(|c| c.id).collect())
    }

    pub fn is(&self, c: &ConstructInfo) -> bool {
        self.0.contains(c.id)
    }
}

/// Sink output for one field: reachable and latent patterns, de-duplicated,
/// with disabled constructs dropped.
pub struct Hits<'d> {
    disabled: &'d Disabled,
    pub reachable: Vec<Pattern>,
    pub latent: Vec<Pattern>,
}

impl<'d> Hits<'d> {
    pub fn new(disabled: &'d Disabled) -> Self {
        Hits { disabled, reachable: Vec::new(), latent: Vec::new() }
    }

    pub fn reach(&mut self, c: &'static ConstructInfo) {
        push_unique(&mut self.reachable, c, self.disabled);
    }

    pub fn latent(&mut self, c: &'static ConstructInfo) {
        push_unique(&mut self.latent, c, self.disabled);
    }

    /// True if a reachable pattern of `family` has been recorded.
    pub fn reached(&self, family: Family) -> bool {
        self.reachable.iter().any(|p| p.family == family)
    }
}

fn push_unique(v: &mut Vec<Pattern>, c: &'static ConstructInfo, disabled: &Disabled) {
    if disabled.is(c) || v.iter().any(|p| p.name == c.id) {
        return;
    }
    v.push(c.pattern());
}

/// What a sink sees: one window of tokens and the whole normalized field text.
pub struct SinkCtx<'a> {
    pub tokens: &'a [Token],
    pub text: &'a str,
}

pub(crate) fn has_kw(tokens: &[Token], kw: &str) -> bool {
    tokens.iter().any(|t| t.kind == TokenKind::SqlKeyword && t.text == kw)
}

pub(crate) fn has_quote(tokens: &[Token]) -> bool {
    tokens.iter().any(|t| t.kind == TokenKind::Quote)
}
```

In `crates/vft-core/src/graph/mod.rs`, below `mod tokenize;` add `pub mod sinks;`. `has_kw`/`has_quote` are unused until Task 6: add `#[allow(dead_code)]` to both in this task and remove it in Task 6.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p vft-core --lib graph::sinks` → Expected: 4 passed.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/vft-core/src/graph/sinks/mod.rs crates/vft-core/src/graph/mod.rs
git commit -m "feat(core): construct registry with dotted ids, Disabled and Hits

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Move sinks into the registry (M1, behavior-identical)

**Files:**
- Create: `crates/vft-core/src/graph/sinks/sql.rs`, `xss.rs`, `shell.rs`, `path.rs`
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (declare the files, extend `REGISTRY`, drop the `dead_code` allows)
- Modify: `crates/vft-core/src/graph/mod.rs` (detectors removed; `analyze` delegates; test names updated)
- Modify: `crates/vft-core/src/detect.rs`, `honeypot.rs`, `intel.rs`, `chain.rs`, `shield.rs` (registry ids)
- Modify: `crates/vft-proxy/src/audit.rs` (test expects the new id)

**Interfaces:**
- Consumes: Task 5's registry types.
- Produces: `graph::analyze(text) -> Analysis` (unchanged signature) and `graph::analyze_with(text: &str, disabled: &Disabled) -> Analysis`; sink statics `sql::{UNION_SELECT, BOOLEAN_TAUTOLOGY, QUOTE_BREAKOUT, STACKED_QUERY, SQL_KEYWORD, FN_SLEEP, FN_BENCHMARK, FN_UPDATEXML, FN_EXTRACTVALUE, FN_LOAD_FILE, FN_PG_SLEEP}`, `xss::{SCRIPT_TAG, EVENT_HANDLER, DANGEROUS_PROTO, TAG_WITH_HANDLER, HTML_TAG}`, `shell::{CMD_SUBSTITUTION, CHAINED_COMMAND, SHELL_META}`, `path::{DIRECTORY_TRAVERSAL, DOTDOT_SEGMENT}`. Each file has `pub fn detect(cx: &SinkCtx, hits: &mut Hits)`.

Id map (old name → id): `union-select`→`sqli.union-select`, `boolean-tautology`→`sqli.boolean-tautology`, `quote-breakout`→`sqli.quote-breakout`, `stacked-query`→`sqli.stacked-query`, `sql-keyword`→`sqli.sql-keyword`, `sleep`/`benchmark`/`updatexml`/`extractvalue`/`load_file`/`pg_sleep`→`sqli.fn-sleep`/`sqli.fn-benchmark`/`sqli.fn-updatexml`/`sqli.fn-extractvalue`/`sqli.fn-load-file`/`sqli.fn-pg-sleep`, `script-tag`→`xss.script-tag`, `event-handler`→`xss.event-handler`, `dangerous-proto`→`xss.dangerous-proto`, `tag-with-handler`→`xss.tag-with-handler`, `html-tag`→`xss.html-tag`, `cmd-substitution`→`cmd.cmd-substitution`, `chained-command`→`cmd.chained-command`, `shell-meta`→`cmd.shell-meta`, `directory-traversal`→`path.directory-traversal`, `dotdot-segment`→`path.dotdot-segment`, signatures→`sig.*` (Task 5), `type-violation`→`api.type-violation`, `sensitive-path-probe`→`recon.sensitive-path-probe`, `decoy-hit`→`honeypot.decoy-hit`, `scanner-ua`→`intel.scanner-ua`.

- [ ] **Step 1: Save the pre-refactor reference runs**

```bash
R="$OUT/pre-m1"; mkdir -p "$R"; B=./target/release/venusflytrap; BH=./target/release/examples/bench_http
cargo build --release -p vft-cli --bins --examples
$B eval --corpus "$CORPUS" --mode library --out "$R/lib_full.csv" > /dev/null
$B eval --corpus "$CORPUS" --mode serve   --out "$R/serve_full.csv" > /dev/null
$BH "$OUT/m0/seeds.jsonl" "$R/seeds.csv" 2>/dev/null; $BH "$OUT/m0/mutants.jsonl" "$R/mutants.csv" 2>/dev/null
```

- [ ] **Step 2: Write the failing test** (in `graph/mod.rs` tests)

```rust
    #[test]
    fn every_emitted_pattern_is_a_registered_id() {
        for s in [
            "-1 union select username,password from users",
            "admin' or 1=1 -- ",
            "1; drop table users",
            "select sleep(5) pg_sleep benchmark updatexml extractvalue load_file",
            "<script>alert(1)</script>",
            "<svg onload=alert(1)> javascript:x",
            "<b>x</b>",
            "127.0.0.1; cat /etc/passwd",
            "$(cat /etc/passwd)",
            "a;b",
            "../../../../etc/passwd",
            "../x",
        ] {
            let a = analyze(s);
            for p in a.reachable.iter().chain(a.latent.iter()) {
                assert!(sinks::lookup(&p.name).is_some(), "unregistered pattern {:?} from {s:?}", p.name);
            }
        }
    }
```

Run: `cargo test -p vft-core --lib every_emitted_pattern` → Expected: FAIL (`"union-select"` is not registered).

- [ ] **Step 3: Create the sink files**

`crates/vft-core/src/graph/sinks/sql.rs`:

```rust
//! SQL injection sinks.

use super::{has_kw, has_quote, ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::{Token, TokenKind};
use crate::judgment::Family;

pub static UNION_SELECT: ConstructInfo = ConstructInfo { id: "sqli.union-select", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "UNION followed by SELECT" };
pub static BOOLEAN_TAUTOLOGY: ConstructInfo = ConstructInfo { id: "sqli.boolean-tautology", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "equal operands compared after OR/AND or with a quote breakout (1=1, 'a'='a')" };
pub static QUOTE_BREAKOUT: ConstructInfo = ConstructInfo { id: "sqli.quote-breakout", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "a quote immediately followed by OR, AND or UNION" };
pub static STACKED_QUERY: ConstructInfo = ConstructInfo { id: "sqli.stacked-query", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "';' followed by a DML or DDL keyword" };
pub static SQL_KEYWORD: ConstructInfo = ConstructInfo { id: "sqli.sql-keyword", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "SELECT or UNION with no SQL construct formed" };
pub static FN_SLEEP: ConstructInfo = ConstructInfo { id: "sqli.fn-sleep", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `sleep`" };
pub static FN_BENCHMARK: ConstructInfo = ConstructInfo { id: "sqli.fn-benchmark", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `benchmark`" };
pub static FN_UPDATEXML: ConstructInfo = ConstructInfo { id: "sqli.fn-updatexml", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `updatexml`" };
pub static FN_EXTRACTVALUE: ConstructInfo = ConstructInfo { id: "sqli.fn-extractvalue", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `extractvalue`" };
pub static FN_LOAD_FILE: ConstructInfo = ConstructInfo { id: "sqli.fn-load-file", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `load_file`" };
pub static FN_PG_SLEEP: ConstructInfo = ConstructInfo { id: "sqli.fn-pg-sleep", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `pg_sleep`" };

static LATENT_FNS: &[(&str, &ConstructInfo)] = &[
    ("sleep", &FN_SLEEP),
    ("benchmark", &FN_BENCHMARK),
    ("updatexml", &FN_UPDATEXML),
    ("extractvalue", &FN_EXTRACTVALUE),
    ("load_file", &FN_LOAD_FILE),
    ("pg_sleep", &FN_PG_SLEEP),
];

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let tokens = cx.tokens;
    // UNION ... SELECT (order-respecting, comments already stripped).
    let mut seen_union = false;
    for t in tokens {
        if t.kind == TokenKind::SqlKeyword && t.text == "union" {
            seen_union = true;
        }
        if seen_union && t.kind == TokenKind::SqlKeyword && t.text == "select" {
            hits.reach(&UNION_SELECT);
            break;
        }
    }

    // Tautology / boolean-based: OR/AND <x> <cmp> <x>  e.g. or 1=1, or 'a'='a'.
    if detect_tautology(tokens) {
        hits.reach(&BOOLEAN_TAUTOLOGY);
    }

    // Quote breakout: a string quote immediately followed by a boolean/union SQL
    // keyword (`' OR`, `' AND`, `' UNION`). Requiring adjacency avoids flagging a
    // stray apostrophe from a contraction ("it's") that happens to co-occur with
    // the word "or" elsewhere in the value.
    if quote_then_bool(tokens) {
        hits.reach(&QUOTE_BREAKOUT);
    }

    // Stacked queries: ';' followed by a DML/DDL keyword.
    let mut semi = false;
    for t in tokens {
        if t.kind == TokenKind::Punct && t.text == ";" {
            semi = true;
        } else if semi
            && t.kind == TokenKind::SqlKeyword
            && matches!(
                t.text.as_str(),
                "select" | "insert" | "update" | "delete" | "drop" | "exec" | "create"
            )
        {
            hits.reach(&STACKED_QUERY);
            break;
        }
    }

    // Classic error/based functions as latent signal.
    for &(needle, c) in LATENT_FNS {
        if cx.text.contains(needle) {
            hits.latent(c);
        }
    }

    // Lone SELECT/UNION without structure is latent only.
    if !hits.reached(Family::Sqli) && (has_kw(tokens, "select") || seen_union) {
        hits.latent(&SQL_KEYWORD);
    }
}

fn detect_tautology(tokens: &[Token]) -> bool {
    // A tautology (`1=1`, `'a'='a'`) is only an *attack* when it sits in a query
    // context: led by a boolean operator (OR/AND), or appearing where a quote has
    // broken out of a string literal. Bare `1 = 1` in prose is NOT flagged —
    // that is the false-positive the semantic approach exists to avoid.
    let quote_present = has_quote(tokens);
    let t = tokens;
    for i in 0..t.len() {
        if t[i].kind == TokenKind::Comparator && (t[i].text == "=" || t[i].text == "like") {
            if i == 0 || i + 1 >= t.len() {
                continue;
            }
            let l = &t[i - 1];
            let r = &t[i + 1];
            let operandish = |k: TokenKind| {
                matches!(k, TokenKind::Number | TokenKind::Ident | TokenKind::String)
            };
            if operandish(l.kind) && operandish(r.kind) {
                // A tautology requires the two operands to actually be equal
                // (`1=1`, `5=5`, `x=x`). That alone is not an attack ("whether
                // 1 = 1" in prose), so also require injection context: led by a
                // boolean operator, or a quote breakout present. This rejects
                // benign "salt and pepper = tasty" (operands differ).
                let equal = l.text == r.text;
                let preceded_by_bool = i >= 2
                    && t[i - 2].kind == TokenKind::SqlKeyword
                    && (t[i - 2].text == "or" || t[i - 2].text == "and");
                if equal && (preceded_by_bool || quote_present) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if a Quote token is immediately followed by a boolean/union SQL keyword.
fn quote_then_bool(tokens: &[Token]) -> bool {
    tokens.windows(2).any(|w| {
        w[0].kind == TokenKind::Quote
            && w[1].kind == TokenKind::SqlKeyword
            && matches!(w[1].text.as_str(), "or" | "and" | "union")
    })
}
```

`crates/vft-core/src/graph/sinks/xss.rs`:

```rust
//! Cross-site scripting sinks.

use super::{has_quote, ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::TokenKind;
use crate::judgment::Family;

pub static SCRIPT_TAG: ConstructInfo = ConstructInfo { id: "xss.script-tag", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "`<script` tag" };
pub static EVENT_HANDLER: ConstructInfo = ConstructInfo { id: "xss.event-handler", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "on*= handler in a new tag or after an attribute breakout" };
pub static DANGEROUS_PROTO: ConstructInfo = ConstructInfo { id: "xss.dangerous-proto", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "`javascript:` or `data:text/html`" };
pub static TAG_WITH_HANDLER: ConstructInfo = ConstructInfo { id: "xss.tag-with-handler", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "svg/img/iframe/body/video tag with an event handler" };
pub static HTML_TAG: ConstructInfo = ConstructInfo { id: "xss.html-tag", family: Some(Family::Xss), kind: ConstructKind::Latent, summary: "an HTML tag with no XSS construct formed" };

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let (tokens, text) = (cx.tokens, cx.text);
    let has_tag_open = tokens.iter().any(|t| t.kind == TokenKind::TagOpen);
    let has_handler = tokens.iter().any(|t| t.kind == TokenKind::EventHandler);
    // <script>
    if text.contains("<script") {
        hits.reach(&SCRIPT_TAG);
    }
    // Event-handler attribute, either inside a new tag (`<svg onload=`) or an
    // attribute-breakout into an existing tag (`x" onmouseover=alert(1)`), which
    // has a quote but no new tag (M3).
    if has_handler && (has_tag_open || has_quote(tokens)) {
        hits.reach(&EVENT_HANDLER);
    }
    // javascript:/data: protocol
    if text.contains("javascript:") || text.contains("data:text/html") {
        hits.reach(&DANGEROUS_PROTO);
    }
    // svg/img/iframe with handler
    for tag in ["<svg", "<img", "<iframe", "<body", "<video"] {
        if text.contains(tag) && tokens.iter().any(|t| t.kind == TokenKind::EventHandler) {
            hits.reach(&TAG_WITH_HANDLER);
            break;
        }
    }
    if !hits.reached(Family::Xss) && has_tag_open {
        hits.latent(&HTML_TAG);
    }
}
```

`crates/vft-core/src/graph/sinks/shell.rs`:

```rust
//! Command injection sinks.

use super::{ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::{Token, TokenKind};
use crate::judgment::Family;

pub static CMD_SUBSTITUTION: ConstructInfo = ConstructInfo { id: "cmd.cmd-substitution", family: Some(Family::CommandInjection), kind: ConstructKind::Sink, summary: "`$(` or backtick; reachable with a known binary in command position, latent otherwise" };
pub static CHAINED_COMMAND: ConstructInfo = ConstructInfo { id: "cmd.chained-command", family: Some(Family::CommandInjection), kind: ConstructKind::Sink, summary: "shell separator followed by a known binary in command position" };
pub static SHELL_META: ConstructInfo = ConstructInfo { id: "cmd.shell-meta", family: Some(Family::CommandInjection), kind: ConstructKind::Latent, summary: "shell separator with no binary after it" };

const BINS: &[&str] = &[
    "cat", "ls", "id", "whoami", "wget", "curl", "nc", "bash", "sh", "ping", "nslookup",
    "uname", "pwd", "chmod", "rm", "python", "perl",
];

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let (tokens, text) = (cx.tokens, cx.text);
    // Command substitution $( ) or backticks. A bare `$(` is usually jQuery
    // (`$(document)`, `$('#id')`) and a lone backtick is often just a 0x60 byte
    // in a binary body, so substitution only forms a construct when a known
    // binary sits in command position right after the opener; otherwise latent.
    if text.contains("$(") || text.contains('`') {
        if substitution_runs_binary(text, BINS) {
            hits.reach(&CMD_SUBSTITUTION);
        } else {
            hits.latent(&CMD_SUBSTITUTION);
        }
    }
    // Chaining: a shell metacharacter followed (in command position) by a known
    // binary — `; cat`, `| whoami`, `&& wget`. Requiring the binary to come
    // *after* the separator avoids flagging benign values that merely contain a
    // short word and a separator elsewhere ("cat;dog" is not command injection).
    let has_meta = tokens
        .iter()
        .any(|t| t.kind == TokenKind::ShellMeta && matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||"));
    if binary_after_meta(tokens, BINS) {
        hits.reach(&CHAINED_COMMAND);
    } else if has_meta {
        hits.latent(&SHELL_META);
    }
}

/// True if a `$(` or backtick opener is followed, in command position, by a
/// known binary — optionally behind a path (`$(/bin/cat`, `` `/usr/bin/id ``).
///
/// Works on the text rather than tokens because command position depends on
/// whitespace, which the lexer drops (`$(cat /etc/passwd)` would otherwise read
/// as the path `cat/etc/passwd`).
fn substitution_runs_binary(text: &str, bins: &[&str]) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    for i in 0..n {
        let mut j = if chars[i] == '`' {
            i + 1
        } else if chars[i] == '$' && i + 1 < n && chars[i + 1] == '(' {
            i + 2
        } else {
            continue;
        };
        while j < n && chars[j].is_whitespace() {
            j += 1;
        }
        let start = j;
        while j < n && (chars[j].is_ascii_alphanumeric() || matches!(chars[j], '_' | '/' | '.' | '-')) {
            j += 1;
        }
        let word: String = chars[start..j].iter().collect();
        let cmd = word.rsplit('/').next().unwrap_or("");
        if bins.contains(&cmd) {
            return true;
        }
    }
    false
}

/// True if the first identifier following a shell metacharacter is a known
/// binary (command position).
fn binary_after_meta(tokens: &[Token], bins: &[&str]) -> bool {
    let mut armed = false;
    for t in tokens {
        match t.kind {
            TokenKind::ShellMeta if matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||") => {
                armed = true;
            }
            TokenKind::Punct if t.text == ";" => {
                armed = true;
            }
            TokenKind::Ident if armed => {
                return bins.contains(&t.text.as_str());
            }
            // any other token in command position resets (e.g. `=`, number)
            _ if armed => {
                armed = false;
            }
            _ => {}
        }
    }
    false
}
```

`crates/vft-core/src/graph/sinks/path.rs`:

```rust
//! Path traversal sinks.

use super::{ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::judgment::Family;

pub static DIRECTORY_TRAVERSAL: ConstructInfo = ConstructInfo { id: "path.directory-traversal", family: Some(Family::PathTraversal), kind: ConstructKind::Sink, summary: "two or more ../ segments, or one with a sensitive target" };
pub static DOTDOT_SEGMENT: ConstructInfo = ConstructInfo { id: "path.dotdot-segment", family: Some(Family::PathTraversal), kind: ConstructKind::Latent, summary: "a single ../ with no sensitive target" };

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let text = cx.text;
    let dots = text.matches("../").count() + text.matches("..\\").count();
    if dots >= 1 {
        // sensitive target raises to reachable
        let sensitive = ["etc/passwd", "etc/shadow", "win.ini", "boot.ini", "/proc/"]
            .iter()
            .any(|s| text.contains(s));
        if dots >= 2 || sensitive {
            hits.reach(&DIRECTORY_TRAVERSAL);
        } else {
            hits.latent(&DOTDOT_SEGMENT);
        }
    }
}
```

In `graph/sinks/mod.rs`: add `pub mod path; pub mod shell; pub mod sql; pub mod xss;` at the top, remove the two `#[allow(dead_code)]`, and extend `REGISTRY` (keep it in this order: graph sinks first, then the Task 5 entries):

```rust
static REGISTRY: &[&ConstructInfo] = &[
    &sql::UNION_SELECT,
    &sql::BOOLEAN_TAUTOLOGY,
    &sql::QUOTE_BREAKOUT,
    &sql::STACKED_QUERY,
    &sql::SQL_KEYWORD,
    &sql::FN_SLEEP,
    &sql::FN_BENCHMARK,
    &sql::FN_UPDATEXML,
    &sql::FN_EXTRACTVALUE,
    &sql::FN_LOAD_FILE,
    &sql::FN_PG_SLEEP,
    &xss::SCRIPT_TAG,
    &xss::EVENT_HANDLER,
    &xss::DANGEROUS_PROTO,
    &xss::TAG_WITH_HANDLER,
    &xss::HTML_TAG,
    &shell::CMD_SUBSTITUTION,
    &shell::CHAINED_COMMAND,
    &shell::SHELL_META,
    &path::DIRECTORY_TRAVERSAL,
    &path::DOTDOT_SEGMENT,
    &SIG_UNION_ALL_SELECT,
    &SIG_CLASSIC_OR,
    &SIG_SCHEMA_ENUM,
    &SIG_ALERT_SCRIPT,
    &SIG_ONERROR,
    &SIG_ETC_PASSWD,
    &SIG_CAT_SUBST,
    &API_TYPE_VIOLATION,
    &RECON_SENSITIVE_PATH,
    &HONEYPOT_DECOY_HIT,
    &INTEL_SCANNER_UA,
    &LIMIT_HEADER_NON_UTF8,
];
```

- [ ] **Step 4: Replace the detectors in `graph/mod.rs`**

Delete `has_kw`, `detect_sql`, `detect_tautology`, `has_quote`, `quote_then_bool`, `detect_xss`, `detect_shell`, `substitution_runs_binary`, `binary_after_meta`, `detect_path` and the `use crate::judgment::{Family, Pattern};` line. Replace `analyze` with:

```rust
use crate::judgment::Pattern;
use sinks::{Disabled, Hits, SinkCtx};

/// Analyze one normalized field value with every construct enabled.
pub fn analyze(text: &str) -> Analysis {
    analyze_with(text, &Disabled::default())
}

/// Analyze one normalized field value, skipping disabled constructs.
pub fn analyze_with(text: &str, disabled: &Disabled) -> Analysis {
    let mut tokens = tokenize(text);
    let graph_truncated = tokens.len() > MAX_NODES;
    if graph_truncated {
        tokens.truncate(MAX_NODES);
    }

    // At the WAF boundary the entire field is attacker-controlled, so any
    // structural sink we find *is* reachable from the tainted source. We still
    // distinguish "formed a dangerous construct" (reachable) from "contains a
    // lone dangerous token" (latent) to keep false positives down.
    let mut hits = Hits::new(disabled);
    let cx = SinkCtx { tokens: &tokens, text };
    sinks::sql::detect(&cx, &mut hits);
    sinks::xss::detect(&cx, &mut hits);
    sinks::shell::detect(&cx, &mut hits);
    sinks::path::detect(&cx, &mut hits);

    Analysis {
        reachable: hits.reachable,
        latent: hits.latent,
        graph_truncated,
    }
}
```

In the `graph/mod.rs` tests, change `p.name == "cmd-substitution"` to `p.name == "cmd.cmd-substitution"`, and add `use crate::judgment::Family;` to the test module if the compiler asks for it.

- [ ] **Step 5: Point every other emitter and name match at the registry**

`crates/vft-core/src/detect.rs`: replace the `SIGNATURES` table and its loop:

```rust
static SIGNATURES: &[(&str, &ConstructInfo)] = &[
    ("union all select", &sinks::SIG_UNION_ALL_SELECT),
    ("' or '1'='1", &sinks::SIG_CLASSIC_OR),
    ("information_schema", &sinks::SIG_SCHEMA_ENUM),
    ("<script>alert", &sinks::SIG_ALERT_SCRIPT),
    ("onerror=", &sinks::SIG_ONERROR),
    ("/etc/passwd", &sinks::SIG_ETC_PASSWD),
    ("$(cat ", &sinks::SIG_CAT_SUBST),
];
```

with the loop body `for &(needle, c) in SIGNATURES { if t.contains(needle) { hits.push(c.pattern()); } }`; replace `Pattern::new(Family::Sqli, "type-violation")` with `sinks::API_TYPE_VIOLATION.pattern()` and `Pattern::new(Family::Recon, "sensitive-path-probe")` with `sinks::RECON_SENSITIVE_PATH.pattern()`. Imports: `use crate::graph::sinks::{self, ConstructInfo};`; drop `Family`/`Pattern` from the `judgment` import if they become unused.

`crates/vft-core/src/honeypot.rs`: `vec![crate::graph::sinks::HONEYPOT_DECOY_HIT.pattern()]`.
`crates/vft-core/src/intel.rs`: `vec![crate::graph::sinks::INTEL_SCANNER_UA.pattern()]`.
`crates/vft-core/src/shield.rs`: `vec![crate::graph::sinks::LIMIT_HEADER_NON_UTF8.pattern()]`; in its tests change `Some("union-select")` to `Some("sqli.union-select")`.
`crates/vft-core/src/chain.rs`: replace `EXFIL_CONSTRUCTS` and its use:

```rust
use crate::graph::sinks::{self, ConstructInfo};

// `sqli.fn-load-file` is only ever latent, so it can never satisfy the
// Dangerous check below; kept as found (renaming must not change behavior).
static EXFIL_CONSTRUCTS: &[&ConstructInfo] = &[
    &sinks::sql::UNION_SELECT,
    &sinks::SIG_UNION_ALL_SELECT,
    &sinks::SIG_SCHEMA_ENUM,
    &sinks::sql::FN_LOAD_FILE,
];
```

and in `event_for`: `.is_some_and(|n| EXFIL_CONSTRUCTS.iter().any(|c| c.id == n))`. In its tests change `"scanner-ua"` to `"intel.scanner-ua"`.
`crates/vft-proxy/src/audit.rs` test: `c["construct"] == "sqli.union-select"`.

Then confirm no old names remain:

```bash
grep -rn '"union-select"\|"boolean-tautology"\|"quote-breakout"\|"stacked-query"\|"sql-keyword"\|"script-tag"\|"event-handler"\|"dangerous-proto"\|"tag-with-handler"\|"html-tag"\|"cmd-substitution"\|"chained-command"\|"shell-meta"\|"directory-traversal"\|"dotdot-segment"\|"decoy-hit"\|"scanner-ua"\|"type-violation"\|"sensitive-path-probe"\|"union-all-select"\|"schema-enum"' crates ui
```

Expected: no output.

- [ ] **Step 6: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED|panicked"` → every `test result: ok`.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

- [ ] **Step 7: Prove behavior is identical**

```bash
R="$OUT/m1"; mkdir -p "$R"
cargo build --release -p vft-cli --bins --examples
$B eval --corpus "$CORPUS" --mode library --out "$R/lib_full.csv" > /dev/null
$B eval --corpus "$CORPUS" --mode serve   --out "$R/serve_full.csv" > /dev/null
$BH "$OUT/m0/seeds.jsonl" "$R/seeds.csv" 2>/dev/null; $BH "$OUT/m0/mutants.jsonl" "$R/mutants.csv" 2>/dev/null
for f in lib_full serve_full seeds mutants; do py -I -X utf8 eval/compare_runs.py "$OUT/pre-m1/$f.csv" "$R/$f.csv" | tail -1; done
```

Expected: `decision diffs: 0` four times. Any diff is a bug in this task: fix it before committing (Global Constraints: no held-out payload inspection).

- [ ] **Step 8: Record and commit**

Add to `eval/RESULTS-RECALL.md` under `## M1 — registry refactor`: "Decision diffs vs M0 build: library 0, serve 0, seeds 0, mutants 0 (33,877 + 33,877 + 22 + 660 requests)."

```bash
git add crates eval/RESULTS-RECALL.md
git commit -m "refactor(core): sinks move to graph/sinks with registered dotted ids (M1, decisions unchanged)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: `shield.disabled`, `--disable` and `ablate`

**Files:**
- Modify: `crates/vft-core/src/config.rs` (`ShieldConfig.disabled`, validation, tests)
- Modify: `crates/vft-core/src/graph/mod.rs` (`GraphOpts`)
- Modify: `crates/vft-core/src/detect.rs` (`FieldCtx.disabled`; signature/API/intent respect it)
- Modify: `crates/vft-core/src/shield.rs` (build `Disabled`; pass it everywhere; honeypot/intel/limit gating)
- Modify: `crates/vft-cli/src/eval.rs`, `crates/vft-cli/src/main.rs` (`--disable`, `ablate`)

**Interfaces:**
- Consumes: Task 5 `Disabled`, `unknown_ids`, `constructs()`; Task 6 `analyze_with`.
- Produces:
  - `ShieldConfig { pub disabled: Vec<String>, .. }` (YAML `shield.disabled: [ids]`, default empty), validated with key `shield.disabled`.
  - `pub struct GraphOpts<'a> { pub disabled: &'a Disabled, pub max_windows: usize }` and `analyze_with(text: &str, opts: &GraphOpts) -> Analysis` (replaces Task 6's two-argument form; `max_windows` is 1 in this task, so behavior matches today's single truncated window).
  - `FieldCtx { field, norm, analysis, disabled: &'a Disabled }`.
  - `pub fn intent_evidence(req: &Request, cfg: &Config, disabled: &Disabled) -> Evidence`.
  - `eval::ablate(cfg: &Config, samples: &[Sample], ids: &[&'static str]) -> anyhow::Result<Vec<AblationRow>>`, `pub struct AblationRow { pub id: &'static str, pub kind: String, pub tp: u64, pub fp: u64, pub d_tp: i64, pub d_fp: i64 }` where `d_tp = base.tp - tp` (true positives that construct contributes) and `d_fp = base.fp - fp`.
  - CLI: `venusflytrap eval … --disable <id>` (repeatable); `venusflytrap ablate --corpus DIR [--manifest M --side S] [--id ID]… --out ablation.tsv`.

- [ ] **Step 1: Write the failing tests**

`crates/vft-core/src/config.rs` tests:

```rust
    #[test]
    fn disabled_ids_must_be_registered() {
        assert!(issues("shield:\n  disabled: [nope.nope]\n").iter().any(|i| i.key == "shield.disabled"));
        assert!(issues("shield:\n  disabled: [sqli.union-select]\n").is_empty());
    }
```

`crates/vft-core/src/shield.rs` tests:

```rust
    #[test]
    fn disabling_a_construct_removes_it_from_judgments() {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), "1 union select password from users".into()));
        let on = Shield::new(Config::default()).inspect(&req);
        assert!(on.contributions.iter().any(|c| c.construct.as_deref() == Some("sqli.union-select")));
        let mut cfg = Config::default();
        cfg.shield.disabled = vec!["sqli.union-select".into()];
        let off = Shield::new(cfg).inspect(&req);
        assert!(!off.contributions.iter().any(|c| c.construct.as_deref() == Some("sqli.union-select")));
    }

    #[test]
    fn disabling_the_honeypot_skips_it() {
        let cfg = Config::default();
        let decoy = cfg.honeypot.decoy_paths.first().cloned().expect("default config has a decoy path");
        let req = Request::get(decoy);
        let mut off_cfg = Config::default();
        off_cfg.shield.disabled = vec!["honeypot.decoy-hit".into()];
        let j = Shield::new(off_cfg).inspect(&req);
        assert!(!j.contributions.iter().any(|c| c.construct.as_deref() == Some("honeypot.decoy-hit")));
    }
```

`crates/vft-cli/src/eval.rs` tests:

```rust
    #[test]
    fn ablate_reports_what_a_construct_contributes() {
        let attack = Sample { rel: "a.black".into(), label: 1, raw: b"GET /?q=1%20union%20select%20a,b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let benign = Sample { rel: "b.white".into(), label: 0, raw: b"GET /?q=hello HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let rows = ablate(&Config::default(), &[attack, benign], &["sqli.union-select"]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "sqli.union-select");
        assert_eq!((rows[0].d_tp, rows[0].d_fp), (1, 0));
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --workspace disabl 2>&1 | grep -E "error|FAILED" | head` and `cargo test -p vft-cli ablate`
Expected: compile errors (no field `disabled`, no function `ablate`).

- [ ] **Step 3: Implement config**

In `ShieldConfig` add, with a doc comment, `pub disabled: Vec<String>,` and `disabled: Vec::new(),` in `Default`. In `Config::validate`, after the `deep_threshold` check:

```rust
        for id in crate::graph::sinks::unknown_ids(&sh.disabled) {
            bad("shield.disabled", format!("unknown construct id {id:?}"));
        }
```

- [ ] **Step 4: Implement `GraphOpts`** (`graph/mod.rs`; replace Task 6's `analyze_with`)

```rust
/// How to run the token graph over one field.
pub struct GraphOpts<'a> {
    pub disabled: &'a Disabled,
    /// Token windows of `MAX_NODES` to analyze before giving up (fail-closed
    /// handling arrives with windowing; 1 = today's single truncated window).
    pub max_windows: usize,
}

/// Analyze one normalized field value with every construct enabled.
pub fn analyze(text: &str) -> Analysis {
    analyze_with(text, &GraphOpts { disabled: &Disabled::default(), max_windows: 1 })
}

/// Analyze one normalized field value, skipping disabled constructs.
pub fn analyze_with(text: &str, opts: &GraphOpts) -> Analysis {
    let mut tokens = tokenize(text);
    let graph_truncated = tokens.len() > MAX_NODES;
    if graph_truncated {
        tokens.truncate(MAX_NODES);
    }
    let mut hits = Hits::new(opts.disabled);
    let cx = SinkCtx { tokens: &tokens, text };
    sinks::sql::detect(&cx, &mut hits);
    sinks::xss::detect(&cx, &mut hits);
    sinks::shell::detect(&cx, &mut hits);
    sinks::path::detect(&cx, &mut hits);
    Analysis { reachable: hits.reachable, latent: hits.latent, graph_truncated }
}
```

- [ ] **Step 5: Thread `Disabled` through detectors and the shield**

`detect.rs`: add `pub disabled: &'a Disabled,` to `FieldCtx` (import `crate::graph::sinks::Disabled`). In `SignatureDetector::assess` skip disabled signatures: `if t.contains(needle) && !ctx.disabled.is(c)`. In `ApiSafetyDetector::assess` guard the type-violation branch with `&& !ctx.disabled.is(&sinks::API_TYPE_VIOLATION)`. Change `intent_evidence` to take `disabled: &Disabled` and return `Evidence::none("recon disabled")` first thing when `disabled.is(&sinks::RECON_SENSITIVE_PATH)`. Update the test helper `ctx_for` to set `disabled: &Disabled::default()` (bind a `let d = Disabled::default();` in each test and pass `&d`), and the `intent_flags_env_probe` test to pass `&Disabled::default()`.

`shield.rs`: add a field `disabled: Disabled` to `Shield`, built in `with_oracle` with `Disabled::resolve(&cfg.shield.disabled)` (before `cfg` moves into the struct). In `inspect`:

```rust
        let gopts = graph::GraphOpts { disabled: &self.disabled, max_windows: 1 };
```

use `graph::analyze_with(&n.text, &gopts)` for fields and for the path; add `disabled: &self.disabled` to `FieldCtx`; call `intent_evidence(req, &self.cfg, &self.disabled)`; wrap the UA intel call in `if !self.disabled.is(&sinks::INTEL_SCANNER_UA) { … }`; replace `let honeypot_hit = self.honeypot.check(req);` with `let honeypot_hit = if self.disabled.is(&sinks::HONEYPOT_DECOY_HIT) { None } else { self.honeypot.check(req) };`; and guard the non-UTF-8 header record with `&& !self.disabled.is(&sinks::LIMIT_HEADER_NON_UTF8)`. Import `crate::graph::sinks::{self, Disabled}`.

- [ ] **Step 6: Implement `--disable` and `ablate`** (`vft-cli`)

`eval.rs`:

```rust
#[derive(Debug, Serialize)]
pub struct AblationRow {
    pub id: &'static str,
    pub kind: String,
    pub tp: u64,
    pub fp: u64,
    /// True positives this construct contributes: baseline TP minus TP with it disabled.
    pub d_tp: i64,
    /// False positives this construct contributes.
    pub d_fp: i64,
}

/// Leave-one-out over `ids` in library mode: one baseline run, then one run per
/// id with only that id added to `shield.disabled`.
pub fn ablate(cfg: &Config, samples: &[Sample], ids: &[&'static str]) -> anyhow::Result<Vec<AblationRow>> {
    let lib = |c: Config| -> anyhow::Result<Metrics> {
        let sources: Sources = "distinct".parse().map_err(anyhow::Error::msg)?;
        Ok(run(c, samples, false, sources, 100, None)?.library)
    };
    let base = lib(cfg.clone())?;
    let mut rows = Vec::new();
    for &id in ids {
        let info = vft_core::graph::sinks::lookup(id).ok_or_else(|| anyhow::anyhow!("unknown construct id {id:?}"))?;
        let mut c = cfg.clone();
        if !c.shield.disabled.iter().any(|d| d == id) {
            c.shield.disabled.push(id.to_string());
        }
        let m = lib(c)?;
        rows.push(AblationRow {
            id: info.id,
            kind: format!("{:?}", info.kind),
            tp: m.tp,
            fp: m.fp,
            d_tp: base.tp as i64 - m.tp as i64,
            d_fp: base.fp as i64 - m.fp as i64,
        });
    }
    Ok(rows)
}
```

`main.rs`: add to `Eval`:

```rust
        /// Disable a construct or decoder by id (repeatable).
        #[arg(long)]
        disable: Vec<String>,
```

and in the arm, after loading `cfg` (make it `let mut cfg`): `cfg.shield.disabled.extend(disable); cfg.validate().map_err(|e| anyhow::anyhow!(e.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("; ")))?;`. Add a subcommand:

```rust
    /// Leave-one-out ablation in library mode; writes a TSV.
    Ablate {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long, requires = "side")]
        manifest: Option<PathBuf>,
        #[arg(long, requires = "manifest")]
        side: Option<String>,
        /// Construct ids to ablate (repeatable); default: every registered construct.
        #[arg(long = "id")]
        ids: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
```

with the arm:

```rust
        Command::Ablate { corpus, manifest, side, ids, out } => {
            let cfg = load_config(cli.config.as_ref())?;
            let mut samples = eval::load_corpus(&corpus)?;
            if let (Some(m), Some(s)) = (manifest.as_ref(), side.as_deref()) {
                samples = eval::select_side(samples, &eval::load_manifest(m)?, s)?;
            }
            let all: Vec<&'static str> = vft_core::graph::sinks::constructs().iter().map(|c| c.id).collect();
            let chosen: Vec<&'static str> = if ids.is_empty() {
                all
            } else {
                let mut v = Vec::new();
                for id in &ids {
                    let c = vft_core::graph::sinks::lookup(id).ok_or_else(|| anyhow::anyhow!("unknown construct id {id:?}"))?;
                    v.push(c.id);
                }
                v
            };
            let rows = eval::ablate(&cfg, &samples, &chosen)?;
            let mut f = std::io::BufWriter::new(std::fs::File::create(&out)?);
            writeln!(f, "id\tkind\ttp\tfp\td_tp\td_fp\tnet")?;
            for r in &rows {
                writeln!(f, "{}\t{}\t{}\t{}\t{}\t{}\t{}", r.id, r.kind, r.tp, r.fp, r.d_tp, r.d_fp, r.d_tp - r.d_fp)?;
            }
        }
```

(`use std::io::Write;` in `main.rs` if not already imported.)

- [ ] **Step 7: Run tests, clippy, and the equivalence check**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED|panicked"` → all ok.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.
Then repeat Task 6 Step 7 into `$OUT/m1b` and compare against `$OUT/pre-m1`. Expected: `decision diffs: 0` four times.

- [ ] **Step 8: First ablation on dev (existing constructs, report only)**

```bash
$B ablate --corpus "$CORPUS" --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/m1b/ablation_dev.tsv"
```

Copy the TSV into `eval/RESULTS-RECALL.md` under `## M1 — existing constructs, leave-one-out on dev` as a table. These predate recall-lift: report only, nothing is dropped (spec §4.3).

- [ ] **Step 9: Commit**

```bash
git add crates eval/RESULTS-RECALL.md
git commit -m "feat: shield.disabled switches constructs off; eval --disable and ablate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Lossy percent decoding (H1)

**Files:**
- Modify: `crates/vft-core/src/normalize/mod.rs` (`percent_decode_lossy`, `Options.disabled`, gated URL step)
- Modify: `crates/vft-core/src/request.rs` (delete the private stand-in; call `normalize::percent_decode_lossy`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (`DECODE_PERCENT_LOSSY`)
- Modify: `crates/vft-core/src/shield.rs` (`norm_opts.disabled`)
- Test: `crates/vft-core/src/normalize/mod.rs`, `crates/vft-core/src/shield.rs`

**Interfaces:**
- Consumes: `Disabled`, registry.
- Produces: `pub fn percent_decode_lossy(s: &str) -> String` in `vft_core::normalize`; `Options { max_payload, decode_cap, deep_threshold, pub disabled: Disabled }` (`Options::default()` has nothing disabled); `pub fn decode_fixpoint_with(input: &str, cap: u8, disabled: &Disabled) -> (String, u8)` (`decode_fixpoint(input, cap)` keeps its signature and delegates); static `sinks::DECODE_PERCENT_LOSSY` (id `decode.percent-lossy`, kind Decoder, family None).

- [ ] **Step 1: Save the pre-change dev run**

```bash
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/pre-h1_dev.csv" > /dev/null
```

- [ ] **Step 2: Write the failing tests**

`normalize/mod.rs` tests:

```rust
    #[test]
    fn one_bad_byte_does_not_disable_url_decoding() {
        let n = norm("admin%27%20or%201%3D1--%20&x=%ff");
        assert!(n.text.contains("admin' or 1=1"), "got: {}", n.text);
    }

    #[test]
    fn percent_decode_lossy_cases() {
        assert_eq!(percent_decode_lossy("a%41%2"), "aA%2");
        assert_eq!(percent_decode_lossy("%ff"), "\u{fffd}");
        assert_eq!(percent_decode_lossy("%zz"), "%zz");
    }
```

`shield.rs` tests:

```rust
    #[test]
    fn sqli_survives_an_invalid_utf8_escape_in_the_same_field() {
        let mut req = Request::get("/login");
        req.method = "POST".into();
        req.body = b"user=admin%27%20or%201%3D1--%20&x=%ff".to_vec();
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }
```

Run: `cargo test -p vft-core --lib one_bad_byte sqli_survives` → Expected: FAIL (the first two assertions fail; `percent_decode_lossy` is not found in `normalize`).

- [ ] **Step 3: Implement**

`graph/sinks/mod.rs`: add, and append `&DECODE_PERCENT_LOSSY` to `REGISTRY`:

```rust
// --- Decoders -------------------------------------------------------------------

pub static DECODE_PERCENT_LOSSY: ConstructInfo = ConstructInfo { id: "decode.percent-lossy", family: None, kind: ConstructKind::Decoder, summary: "URL decoding: '+' to space, %XX byte by byte, lossy UTF-8" };
```

`normalize/mod.rs`: add `use crate::graph::sinks::{self, Disabled};`; add `pub disabled: Disabled,` to `Options` and `disabled: Disabled::default(),` to its `Default`; move the function from `request.rs` here as public:

```rust
/// Percent-decode to bytes, then UTF-8 lossily. One invalid byte (`%ff`) yields
/// U+FFFD instead of disabling URL decoding for the whole field (H1).
pub fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
```

Thread `disabled`: `normalize` calls `decode_fixpoint_with(&bounded, opts.decode_cap, &opts.disabled)`; add

```rust
/// Apply decoders repeatedly until a pass makes no change or the cap is hit.
pub fn decode_fixpoint(input: &str, cap: u8) -> (String, u8) {
    decode_fixpoint_with(input, cap, &Disabled::default())
}

/// [`decode_fixpoint`] with some decoders switched off.
pub fn decode_fixpoint_with(input: &str, cap: u8, disabled: &Disabled) -> (String, u8) {
    let mut cur = input.to_string();
    let mut layers = 0u8;
    for _ in 0..cap {
        let next = decode_once(&cur, disabled);
        if next == cur {
            break;
        }
        cur = next;
        layers += 1;
    }
    (cur, layers)
}
```

and change `decode_once(s: &str)` to `decode_once(s: &str, disabled: &Disabled)` with the URL step:

```rust
    // URL / percent decoding.
    if (out.contains('%') || out.contains('+')) && !disabled.is(&sinks::DECODE_PERCENT_LOSSY) {
        let d = percent_decode_lossy(&out.replace('+', " "));
        if d != out {
            out = d;
        }
    }
```

`request.rs`: delete the private `percent_decode_lossy` and its doc comment; in `canonical_path` call `crate::normalize::percent_decode_lossy(&s)`.

`shield.rs` `with_oracle`: build `let disabled = Disabled::resolve(&cfg.shield.disabled);` first, set `disabled: disabled.clone()` in `Options { … }`, and store `disabled` in the struct.

- [ ] **Step 4: Run tests and clippy**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED|panicked"` → all ok.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

- [ ] **Step 5: A/B on dev (fixed decoder: strict rule)**

```bash
cargo build --release -p vft-cli --bins
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/h1_dev.csv" > /dev/null
py -I -X utf8 eval/compare_runs.py "$OUT/pre-h1_dev.csv" "$OUT/h1_dev.csv"
```

Gate (spec §4.4, widened or fixed decoder): delta TP must be greater than delta FP. If it is not, report the numbers to the controller and stop; do not tune. Record the two metric lines and the delta in `eval/RESULTS-RECALL.md` under `## M2a`.

- [ ] **Step 6: Commit**

```bash
git add crates eval/RESULTS-RECALL.md
git commit -m "fix(core): lossy percent decoding never skips the URL layer (H1); shared with canonical_path

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Decoder ids and base64 before '+' (L5)

**Files:**
- Modify: `crates/vft-core/src/normalize/mod.rs`
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (`DECODE_ENTITY`, `DECODE_ESC_HEX`, `DECODE_B64_WHOLE`)
- Test: `crates/vft-core/src/normalize/mod.rs`, `crates/vft-core/src/shield.rs`

**Interfaces:**
- Consumes: Task 8's `decode_once(s, disabled)`.
- Produces: statics `sinks::DECODE_ENTITY` (`decode.entity`), `sinks::DECODE_ESC_HEX` (`decode.esc-hex`), `sinks::DECODE_B64_WHOLE` (`decode.b64-whole`), all kind Decoder, family None, registered.

- [ ] **Step 1: Save the pre-change dev run**

```bash
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/pre-l5_dev.csv" > /dev/null
```

- [ ] **Step 2: Write the failing tests**

`normalize/mod.rs` tests:

```rust
    #[test]
    fn base64_with_plus_decodes() {
        // base64 of `<svg onload=alert(1)>>` contains '+'
        let n = norm("PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+Pg==");
        assert!(n.text.contains("<svg onload=alert(1)>"), "got: {}", n.text);
    }

    #[test]
    fn decoders_can_be_disabled() {
        let opts = Options { disabled: Disabled::resolve(&["decode.entity".into()]), ..Options::default() };
        assert!(normalize("&lt;script&gt;", &opts).text.contains("&lt;script&gt;"));
        let opts = Options { disabled: Disabled::resolve(&["decode.esc-hex".into()]), ..Options::default() };
        assert!(normalize("\\x3cscript", &opts).text.contains("\\x3cscript"));
    }
```

`shield.rs` tests:

```rust
    #[test]
    fn base64_xss_with_plus_in_a_header_blocks() {
        let mut req = Request::get("/");
        req.headers.push(("x-data".into(), "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+Pg==".into()));
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }
```

Run: `cargo test -p vft-core --lib base64_with_plus decoders_can_be_disabled base64_xss_with_plus` → Expected: FAIL.

- [ ] **Step 3: Implement**

`graph/sinks/mod.rs` (append each to `REGISTRY`):

```rust
pub static DECODE_ENTITY: ConstructInfo = ConstructInfo { id: "decode.entity", family: None, kind: ConstructKind::Decoder, summary: "HTML entities: numeric, plus a fixed set of named ones" };
pub static DECODE_ESC_HEX: ConstructInfo = ConstructInfo { id: "decode.esc-hex", family: None, kind: ConstructKind::Decoder, summary: "\\xNN and \\uNNNN escapes" };
pub static DECODE_B64_WHOLE: ConstructInfo = ConstructInfo { id: "decode.b64-whole", family: None, kind: ConstructKind::Decoder, summary: "a field that is base64 as a whole; also tried before '+' becomes a space" };
```

`normalize/mod.rs` `decode_once`: at the very top, before the URL step (L5: `+` must not become a space before base64 is tried):

```rust
    // Whole-field base64 first: '+' is a base64 character, and the URL step
    // below turns it into a space (L5).
    if !disabled.is(&sinks::DECODE_B64_WHOLE) {
        if let Some(d) = try_whole_base64(s) {
            return d;
        }
    }
```

Gate the remaining stages: `if out.contains('&') && !disabled.is(&sinks::DECODE_ENTITY)`, `if (out.contains("\\x") || out.contains("\\u")) && !disabled.is(&sinks::DECODE_ESC_HEX)`, and the trailing base64 stage with `if !disabled.is(&sinks::DECODE_B64_WHOLE)`.

- [ ] **Step 4: Run tests and clippy**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED|panicked"` → all ok.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

- [ ] **Step 5: A/B on dev (fixed decoder: strict rule)**

```bash
cargo build --release -p vft-cli --bins
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/l5_dev.csv" > /dev/null
py -I -X utf8 eval/compare_runs.py "$OUT/pre-l5_dev.csv" "$OUT/l5_dev.csv"
```

Gate: delta TP greater than delta FP, else report and stop. Note in the results that `parse_corpus.py`/`parse_qsl` and many adapters already turn `+` into a space in query values, so L5 can only act on bodies, headers and cookies: a small or zero delta is expected and is reported as measured. Record under `## M2a`.

- [ ] **Step 6: Commit**

```bash
git add crates eval/RESULTS-RECALL.md
git commit -m "fix(core): try whole-field base64 before '+' becomes a space (L5); decoders get ids

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Token windowing and `limit.graph-truncated` (C2)

**Files:**
- Modify: `crates/vft-core/src/graph/mod.rs` (windowed `analyze_with`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (`LIMIT_GRAPH_TRUNCATED`)
- Modify: `crates/vft-core/src/config.rs` (`shield.max_graph_windows`, default 32, validated 1..=1024)
- Modify: `crates/vft-core/src/shield.rs` (use config; emit the limit)
- Test: `crates/vft-core/src/graph/mod.rs`, `crates/vft-core/src/shield.rs`, `crates/vft-core/src/config.rs`

**Interfaces:**
- Consumes: `GraphOpts`, `Hits`, `Recorder`.
- Produces: `pub const WINDOW_OVERLAP: usize = 64;` in `graph`; `ShieldConfig.max_graph_windows: usize`; static `sinks::LIMIT_GRAPH_TRUNCATED` (id `limit.graph-truncated`, family `Limit`, kind Limit). `Analysis.graph_truncated` now means "windows ran out", and the shield turns it into Suspicious evidence (weight 0.6, engine `limit`, engine weight `scoring.weight_api`).

- [ ] **Step 1: Save the pre-change dev run**

```bash
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/pre-c2_dev.csv" > /dev/null
```

- [ ] **Step 2: Write the failing tests**

`graph/mod.rs` tests:

```rust
    #[test]
    fn attack_after_padding_is_found_in_a_later_window() {
        let text = format!("{} 1 union select a,b from users", ",".repeat(4100));
        let opts = GraphOpts { disabled: &sinks::Disabled::default(), max_windows: 32 };
        let a = analyze_with(&text, &opts);
        assert!(a.reachable.iter().any(|p| p.name == "sqli.union-select"), "{a:?}");
        assert!(!a.graph_truncated);
    }

    #[test]
    fn running_out_of_windows_is_reported() {
        let text = ",".repeat(10_000);
        let opts = GraphOpts { disabled: &sinks::Disabled::default(), max_windows: 2 };
        assert!(analyze_with(&text, &opts).graph_truncated);
    }
```

`shield.rs` tests:

```rust
    #[test]
    fn comma_padding_does_not_hide_sqli() {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), format!("{} 1 union select a,b from users", ",".repeat(4100))));
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }

    #[test]
    fn exhausted_windows_emit_a_limit() {
        let mut cfg = Config::default();
        cfg.shield.max_graph_windows = 1;
        let mut req = Request::get("/items");
        req.query.push(("q".into(), ",".repeat(5000)));
        let j = Shield::new(cfg).inspect(&req);
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.graph-truncated")));
    }
```

`config.rs` tests:

```rust
    #[test]
    fn graph_windows_bounds() {
        assert!(issues("shield:\n  max_graph_windows: 0\n").iter().any(|i| i.key == "shield.max_graph_windows"));
        assert!(issues("shield:\n  max_graph_windows: 32\n").is_empty());
    }
```

Run: `cargo test --workspace windows comma_padding graph_windows 2>&1 | grep -E "error|FAILED" | head` → Expected: failures (no field `max_graph_windows`; padding test sees Allow).

- [ ] **Step 3: Implement**

`graph/sinks/mod.rs` (append to `REGISTRY`):

```rust
// --- Limits ---------------------------------------------------------------------

pub static LIMIT_GRAPH_TRUNCATED: ConstructInfo = ConstructInfo { id: "limit.graph-truncated", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "a field needed more token windows than shield.max_graph_windows" };
```

`graph/mod.rs`: add `pub const WINDOW_OVERLAP: usize = 64;` next to `MAX_NODES`, update the `GraphOpts::max_windows` doc ("4096-token windows overlapping by 64; when they run out, `graph_truncated` is set and the shield emits `limit.graph-truncated`"), and replace `analyze_with`'s body:

```rust
pub fn analyze_with(text: &str, opts: &GraphOpts) -> Analysis {
    let tokens = tokenize(text);
    let mut hits = Hits::new(opts.disabled);
    // Overlapping windows so a construct cannot hide on a window seam. Text-level
    // checks inside the sinks see the whole field in every window; `Hits`
    // de-duplicates what they report.
    let mut start = 0;
    let mut windows = 0;
    let mut graph_truncated = false;
    loop {
        let end = (start + MAX_NODES).min(tokens.len());
        let cx = SinkCtx { tokens: &tokens[start..end], text };
        sinks::sql::detect(&cx, &mut hits);
        sinks::xss::detect(&cx, &mut hits);
        sinks::shell::detect(&cx, &mut hits);
        sinks::path::detect(&cx, &mut hits);
        windows += 1;
        if end == tokens.len() {
            break;
        }
        if windows >= opts.max_windows {
            graph_truncated = true;
            break;
        }
        start = end - WINDOW_OVERLAP;
    }
    Analysis { reachable: hits.reachable, latent: hits.latent, graph_truncated }
}
```

and change `analyze` to `max_windows: 32`.

`config.rs`: `ShieldConfig` gains a documented `pub max_graph_windows: usize,` (default `32`); `validate` adds:

```rust
        if !(1..=1024).contains(&sh.max_graph_windows) {
            bad("shield.max_graph_windows", format!("must be in 1..=1024, got {}", sh.max_graph_windows));
        }
```

`shield.rs`: `GraphOpts { disabled: &self.disabled, max_windows: self.cfg.shield.max_graph_windows }`. After each field's (and the path's) analysis:

```rust
            if analysis.graph_truncated && !self.disabled.is(&sinks::LIMIT_GRAPH_TRUNCATED) {
                rec.record(
                    "limit",
                    self.cfg.scoring.weight_api,
                    Some(fref.clone()),
                    Evidence::new(
                        FourValued::Suspicious,
                        0.6,
                        vec![sinks::LIMIT_GRAPH_TRUNCATED.pattern()],
                        "field exceeded shield.max_graph_windows; not fully inspected",
                    ),
                );
            }
```

(for the path use `Some(FieldRef::path())`; `fref` must be cloned before it moves into the AI detector's record).

- [ ] **Step 4: Run tests and clippy**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED|panicked"` → all ok.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

- [ ] **Step 5: Gate on dev (limit / fail-closed fix: 0 added FPs)**

```bash
cargo build --release -p vft-cli --bins
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/c2_dev.csv" > /dev/null
py -I -X utf8 eval/compare_runs.py "$OUT/pre-c2_dev.csv" "$OUT/c2_dev.csv"
```

Gate (spec §4.4, limits and fail-closed fixes): delta FP must be 0 and the two regression tests above must pass. If delta FP > 0, report and stop. Record under `## M2a`.

- [ ] **Step 6: Commit**

```bash
git add crates eval/RESULTS-RECALL.md
git commit -m "fix(core): analyze long fields in overlapping token windows; limit.graph-truncated fails closed (C2)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Field chunking and `limit.payload-truncated` (C3)

**Files:**
- Modify: `crates/vft-core/src/normalize/mod.rs` (`chunks`, `CHUNK_OVERLAP`, `Normalized.truncated`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (`LIMIT_PAYLOAD_TRUNCATED`)
- Modify: `crates/vft-core/src/config.rs` (`shield.max_inspect_bytes`, default 1 MiB, validated `>= max_payload`)
- Modify: `crates/vft-core/src/shield.rs` (per-chunk inspection under a request budget)
- Test: `crates/vft-core/src/normalize/mod.rs`, `crates/vft-core/src/shield.rs`, `crates/vft-core/src/config.rs`, `crates/vft-core/tests/fuzz_props.rs`

**Interfaces:**
- Consumes: Task 10's limit recording pattern.
- Produces: `pub const CHUNK_OVERLAP: usize = 256;` and `pub fn chunks(s: &str, max: usize) -> Vec<&str>` in `vft_core::normalize`; `Normalized.truncated: bool` (true when normalization had to cut text); `ShieldConfig.max_inspect_bytes: usize`; static `sinks::LIMIT_PAYLOAD_TRUNCATED` (id `limit.payload-truncated`, family `Limit`, kind Limit), emitted once per request as Suspicious (weight 0.6, engine `limit`).

- [ ] **Step 1: Save the pre-change dev run**

```bash
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/pre-c3_dev.csv" > /dev/null
```

- [ ] **Step 2: Write the failing tests**

`normalize/mod.rs` tests:

```rust
    #[test]
    fn chunks_cover_everything_with_overlap() {
        let s: String = "ab€".repeat(1000); // 3,000 chars, multi-byte included
        let cs = chunks(&s, 1024);
        assert!(cs.iter().all(|c| c.chars().count() <= 1024));
        assert!(s.starts_with(cs[0]) && s.ends_with(cs[cs.len() - 1]));
        for w in cs.windows(2) {
            let tail: String = w[0].chars().rev().take(CHUNK_OVERLAP).collect::<Vec<_>>().into_iter().rev().collect();
            assert!(w[1].starts_with(&tail), "chunks must overlap by CHUNK_OVERLAP chars");
        }
        assert_eq!(chunks("short", 1024), vec!["short"]);
    }
```

`shield.rs` tests:

```rust
    #[test]
    fn attack_past_max_payload_blocks() {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), format!("{} 1 union select a,b from users", "a".repeat(70_000))));
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }

    #[test]
    fn exceeding_the_inspection_budget_emits_a_limit() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let mut req = Request::get("/items");
        req.query.push(("q".into(), "a".repeat(200_000)));
        let j = Shield::new(cfg).inspect(&req);
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.payload-truncated")));
    }
```

`config.rs` tests:

```rust
    #[test]
    fn inspect_budget_at_least_one_field() {
        assert!(issues("shield:\n  max_inspect_bytes: 1000\n").iter().any(|i| i.key == "shield.max_inspect_bytes"));
        assert!(issues("shield:\n  max_inspect_bytes: 1048576\n").is_empty());
    }
```

Run: `cargo test --workspace chunks_cover attack_past exceeding_the inspect_budget 2>&1 | grep -E "error|FAILED" | head` → Expected: failures.

- [ ] **Step 3: Implement**

`graph/sinks/mod.rs` (append to `REGISTRY`):

```rust
pub static LIMIT_PAYLOAD_TRUNCATED: ConstructInfo = ConstructInfo { id: "limit.payload-truncated", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "the request exceeded shield.max_inspect_bytes, or normalization had to cut a field" };
```

`normalize/mod.rs`: add `pub truncated: bool,` to `Normalized` (doc: "normalization cut text: the input exceeded `max_payload`, or NFKC expansion did"); in `normalize`, set `let mut truncated = input.chars().count() > opts.max_payload;` before bounding, set `truncated = true;` inside the existing post-fold cap branch, and return it. Add:

```rust
/// Characters shared by neighbouring chunks, so a payload cannot hide on a seam.
pub const CHUNK_OVERLAP: usize = 256;

/// Split `s` into chunks of at most `max` chars that overlap by
/// [`CHUNK_OVERLAP`] chars. A string of at most `max` chars is one chunk.
pub fn chunks(s: &str, max: usize) -> Vec<&str> {
    let idx: Vec<usize> = s.char_indices().map(|(i, _)| i).collect();
    let n = idx.len();
    if n <= max {
        return vec![s];
    }
    let step = max.saturating_sub(CHUNK_OVERLAP).max(1);
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let end = (start + max).min(n);
        let lo = idx[start];
        let hi = if end == n { s.len() } else { idx[end] };
        out.push(&s[lo..hi]);
        if end == n {
            break;
        }
        start += step;
    }
    out
}
```

`config.rs`: `ShieldConfig` gains a documented `pub max_inspect_bytes: usize,` (default `1024 * 1024`); `validate` adds:

```rust
        if sh.max_inspect_bytes < sh.max_payload {
            bad("shield.max_inspect_bytes", format!("must be >= shield.max_payload ({}), got {}", sh.max_payload, sh.max_inspect_bytes));
        }
```

`shield.rs` `inspect`: wrap the per-field work in a chunk loop under a byte budget (the path keeps its single `normalize` call and only adds `payload_truncated |= n.truncated;`):

```rust
        let mut budget = self.cfg.shield.max_inspect_bytes;
        let mut payload_truncated = false;
        'fields: for field in req.fields() {
            let fref = FieldRef::of(&field);
            for chunk in crate::normalize::chunks(&field.raw, self.cfg.shield.max_payload) {
                if chunk.len() > budget {
                    payload_truncated = true;
                    break 'fields;
                }
                budget -= chunk.len();
                let n = normalize(chunk, &self.norm_opts);
                payload_truncated |= n.truncated;
                max_layers = max_layers.max(n.layers);
                let analysis = graph::analyze_with(&n.text, &gopts);
                if analysis.graph_truncated && !self.disabled.is(&sinks::LIMIT_GRAPH_TRUNCATED) {
                    rec.record(
                        "limit",
                        self.cfg.scoring.weight_api,
                        Some(fref.clone()),
                        Evidence::new(
                            FourValued::Suspicious,
                            0.6,
                            vec![sinks::LIMIT_GRAPH_TRUNCATED.pattern()],
                            "field exceeded shield.max_graph_windows; not fully inspected",
                        ),
                    );
                }
                let ctx = FieldCtx {
                    field: &field,
                    norm: &n,
                    analysis: &analysis,
                    disabled: &self.disabled,
                };
                for (det, w) in &field_detectors {
                    let e = det.assess(&ctx);
                    rec.record(det.name(), *w, Some(fref.clone()), e);
                }
                let e = ai.assess(&ctx);
                rec.record(ai.name(), self.cfg.scoring.weight_ai, Some(fref.clone()), e);
            }
        }
        if payload_truncated && !self.disabled.is(&sinks::LIMIT_PAYLOAD_TRUNCATED) {
            rec.record(
                "limit",
                self.cfg.scoring.weight_api,
                None,
                Evidence::new(
                    FourValued::Suspicious,
                    0.6,
                    vec![sinks::LIMIT_PAYLOAD_TRUNCATED.pattern()],
                    "request exceeded shield.max_inspect_bytes or a field was cut; not fully inspected",
                ),
            );
        }
```

This replaces the whole existing `for field in req.fields() { … }` loop; its body is the Task 10 version moved inside the chunk loop, with `fref.clone()` everywhere.

`tests/fuzz_props.rs`: add

```rust
proptest! {
    #[test]
    fn chunks_never_panic_and_cover(s in ".{0,3000}", max in 300usize..2000) {
        let cs = vft_core::normalize::chunks(&s, max);
        prop_assert!(!cs.is_empty());
        prop_assert!(cs.iter().all(|c| c.chars().count() <= max));
    }
}
```

- [ ] **Step 4: Run tests and clippy**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED|panicked"` → all ok.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -2` → no warnings.

- [ ] **Step 5: Gate on dev (limit / fail-closed fix: 0 added FPs)**

```bash
cargo build --release -p vft-cli --bins
$B eval --corpus "$CORPUS" --mode library --manifest "$OUT/split/manifest.tsv" --side dev --out "$OUT/c3_dev.csv" > /dev/null
py -I -X utf8 eval/compare_runs.py "$OUT/pre-c3_dev.csv" "$OUT/c3_dev.csv"
```

Gate: delta FP must be 0 and the regression tests must pass. Chunking now inspects text past 64 KiB that was never inspected before, so an FP increase here is a real finding: report it and stop, do not tune. Record under `## M2a`.

- [ ] **Step 6: Commit**

```bash
git add crates eval/RESULTS-RECALL.md
git commit -m "fix(core): inspect long fields in overlapping chunks under a request budget; limit.payload-truncated (C3)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: M2a measurement, gates and reporting

**Files:**
- Modify: `eval/RESULTS-RECALL.md`
- Modify: shared note `C:\Users\Dennis Liu\AppData\Roaming\Claude\side-session-notes\local_dbc8a8c9-3962-4004-86bc-3d21d8e61098\recall-lift-interface-decisions.md` (controller step)

**Interfaces:**
- Consumes: everything above. This is the only place held-out is scored after M0.

- [ ] **Step 1: Full measurement**

```bash
R="$OUT/m2a"; mkdir -p "$R"; M="$OUT/split/manifest.tsv"
cargo build --release -p vft-cli --bins --examples
$B eval --corpus "$CORPUS" --mode library --out "$R/lib_full.csv" > "$R/lib_full.json"
$B eval --corpus "$CORPUS" --mode serve   --out "$R/serve_full.csv" > "$R/serve_full.json"
$B eval --corpus "$CORPUS" --mode library --manifest "$M" --side dev     --out "$R/lib_dev.csv" > "$R/lib_dev.json"
$B eval --corpus "$CORPUS" --mode library --manifest "$M" --side heldout --out "$R/lib_heldout.csv" > "$R/lib_heldout.json"
$BH "$OUT/m0/seeds.jsonl" "$R/seeds.csv" 2> "$R/seeds.txt"; $BH "$OUT/m0/mutants.jsonl" "$R/mutants.csv" 2> "$R/mutants.txt"
$B ablate --corpus "$CORPUS" --manifest "$M" --side dev --out "$R/ablation_dev.tsv"
```

- [ ] **Step 2: Check every gate (spec §4.4) and write them down**

| Gate | Source | Pass when |
|---|---|---|
| tests + clippy | Task 11 Step 4 | green |
| dev FP rate | `lib_dev.json` | ≤ 1.0% |
| H1, L5 (fixed decoders) | Tasks 8–9 A/B | ΔTP > ΔFP |
| C2, C3 (limits) | Tasks 10–11 | ΔFP = 0, regression tests pass |
| robustness | `seeds.txt`, `mutants.txt` | retained ≥ 96% and mutant recall ≥ 83.0% (or ≥ M0's own values if M0 was lower) |
| latency | `lib_full.json` | p95 < 1,000 µs |

Write the M2a section of `eval/RESULTS-RECALL.md` with the same tables as M0 (library full, serve full, dev, held-out; robustness line), a "change vs M0" column for dev and held-out, the gate table with pass/fail per row, and the ablation TSV as a table. A failed gate is written as failed, with the numbers.

- [ ] **Step 3: Commit**

```bash
git add eval/RESULTS-RECALL.md
git commit -m "docs(eval): M2a results, gates and dev ablation

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Controller: Claude Doc and notes**

Update doc `c555ba6b-ff38-4ea4-875c-3b4f08f0c8fe` (read with `sinceRev` first): Results gets the M2a rows next to M0, and a new "Ablations" tab holds the dev ablation table. In the shared note, record the final option keys and defaults (`shield.disabled`, `shield.max_graph_windows` = 32, `shield.max_inspect_bytes` = 1048576) and the registered construct list (`venusflytrap ablate` order = `constructs()` order).

- [ ] **Step 5: Report to the owner**

Summarize: M0 vs M2a for dev, held-out and full; each gate's result; anything that failed or regressed, plainly. Ask whether to proceed to Plan B (body structuring, the new decoders, the new constructs).
