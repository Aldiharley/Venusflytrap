"""Tests for eval/compare_runs.py. Run: py -I -X utf8 eval/test_compare_runs.py"""
import contextlib
import importlib.util
import io
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

    def test_header_only_runs_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR)
            b = write(tmp, "b.csv", EVAL_HDR)
            with self.assertRaises(ValueError):
                cr.compare(cr.load(a), cr.load(b))

    def test_zero_byte_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", "")
            with self.assertRaises(ValueError):
                cr.load(a)

    def test_unknown_header_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", "foo,bar\n1,2\n")
            with self.assertRaises(ValueError):
                cr.load(a)

    def test_cli_rejects_header_only_runs_with_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write(tmp, "a.csv", EVAL_HDR)
            b = write(tmp, "b.csv", EVAL_HDR)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit) as cm:
                    cr.main([a, b])
            self.assertEqual(cm.exception.code, 2)
            self.assertIn("no data rows", err.getvalue())


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


if __name__ == "__main__":
    unittest.main()
