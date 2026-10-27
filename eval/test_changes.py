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
