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
        self.assertEqual((total, n_groups), (4, 3))
        self.assertEqual(ranked[0], (("NoEvidence:scoring.monitor_at", "", "", ""), 2, ["d/m1.black", "d/m2.black"]))
        self.assertEqual(ranked[1][0], ("Detection:scoring.monitor_at", "xss.html-tag", "cookie", "session"))
        self.assertEqual(ranked[2], (("NoEvidence:scoring.monitor_at", "test.neutral", "header", "x-sample"), 1, ["d/m4.black"]))

    def test_side_drops_held_out_rows_before_counting(self):
        total, _, ranked = cl.clusters(cl.load(CSV), "0", cl.ATTACK, 20)
        self.assertEqual((total, ranked[0][1]), (5, 4), "without --side the held-out FP is counted")
        self.assertFalse(any(r["rel"].startswith("h/") for r in dev_rows()))

    def test_top_limits_the_groups_shown_not_counted(self):
        total, n_groups, ranked = cl.clusters(dev_rows(), "0", cl.ATTACK, 1)
        self.assertEqual((total, n_groups, len(ranked)), (4, 2, 1))

    def test_key_uses_top_field_only_when_field_is_empty(self):
        row = {"cause": "c", "top": "t", "field": "query:Name", "top_field": "header:Other"}
        self.assertEqual(cl.key(row), ("c", "t", "query", "name"))
        row["field"] = ""
        self.assertEqual(cl.key(row), ("c", "t", "header", "other"))
        del row["top_field"]
        self.assertEqual(cl.key(row), ("c", "t", "", ""), "a DQ1-era CSV has no top_field column")

    def test_cli_prints_both_tables(self):
        code, out, _ = run_main([CSV, "--manifest", MANIFEST, "--side", "dev", "--top", "5"])
        self.assertEqual(code, 0)
        self.assertIn("false positives (label 0, Challenge/Block): 4 rows in 2 groups\n", out)
        self.assertIn("misses (label 1, Allow/Monitor): 4 rows in 3 groups\n", out)
        self.assertIn("1\tNoEvidence:scoring.monitor_at\ttest.neutral\theader\tx-sample\td/m4.black\n", out)
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
