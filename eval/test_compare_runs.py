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
