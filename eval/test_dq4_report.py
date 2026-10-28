"""Tests for eval/dq4_report.py. Run: py -I -X utf8 eval/test_dq4_report.py"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("dq4_report", Path(__file__).with_name("dq4_report.py"))
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)

LIB_HDR = "rel,label,lib_verdict,serve_verdict,score,banned,constructs\n"


def write(d, name, text):
    Path(d, name).write_text(text, encoding="utf-8")


class FamilyTests(unittest.TestCase):
    def test_bookkeeping_rules_are_not_families(self):
        self.assertEqual(dr.families(["920350", "949110", "980170", "942100", "942101"]), ["920", "942"])

    def test_fp_families_count_rows_not_rules(self):
        run = {"a": (0, True, "blocked", "403"), "b": (0, True, "blocked", "403"), "c": (0, True, "blocked", "403"),
               "d": (0, False, "passed", "200"), "e": (1, True, "blocked", "403")}
        rules = {"a": ["920350", "949110"], "b": ["920350", "942100", "942200"], "e": ["942100"]}
        f = dr.fp_families(run, rules, sorted(run))
        self.assertEqual(f["fp_rows"], 3)
        self.assertEqual(f["fp_rows_without_joined_rules"], 1)
        self.assertEqual(f["rows_where_family_fired"], {"920": 2, "942": 1})
        self.assertEqual(f["rows_where_family_is_the_only_one"], {"920": 1})
        self.assertEqual((f["fp_rows_with_920"], f["fp_rows_920_only"], f["fp_rows_without_920"]), (2, 1, 0))
        self.assertEqual(f["top_rules"], {"920350": 2, "942100": 1, "942200": 1})

    def test_nearest_prefers_the_closest_fp_rate_then_recall(self):
        s = [("x", {"fp_rate": 0.02, "recall": 0.5}), ("y", {"fp_rate": 0.008, "recall": 0.4}),
             ("z", {"fp_rate": 0.004, "recall": 0.6})]
        self.assertEqual(dr.nearest(s, 0.006)[0], "z")
        self.assertEqual(dr.nearest(s, 0.0081)[0], "y")


class BuildTests(unittest.TestCase):
    def test_build_scores_shared_rows_and_never_counts_failed_as_blocked(self):
        d = tempfile.mkdtemp()
        write(d, "lib.csv", LIB_HDR + "a.black,1,Block,,9,false,\nb.black,1,Allow,,0,false,\n"
                                     "c.white,0,Allow,,0,false,\nd.white,0,Challenge,,5,false,\ne.white,0,Allow,,0,false,\n")
        hdr = "rel,label,verdict,status\n"
        write(d, "modsecurity-pl1-t5.csv", hdr + "a.black,1,failed,400\nb.black,1,blocked,403\n"
                                                 "c.white,0,blocked,403\nd.white,0,passed,200\n")
        write(d, "vft-serve.csv", hdr + "a.black,1,blocked,403\nb.black,1,passed,200\n"
                                        "c.white,0,passed,200\nd.white,0,blocked,403\n")
        write(d, "rules-modsecurity-pl1-t5.json", json.dumps({"c.white": ["920350", "949110"]}))
        write(d, "expected.txt", "a.black\nb.black\nc.white\nd.white\ne.white\nf.black\n")
        r = dr.build(d, Path(d, "lib.csv"), Path(d, "expected.txt"))
        self.assertEqual(r["rows_shared"], 4)
        self.assertEqual(r["rows_only_in_library"], 1)
        self.assertEqual(r["corpus_missing"], ["f.black"])
        m = r["engines"]["modsecurity-pl1-t5"]
        self.assertEqual((m["tp"], m["fp"], m["tn"], m["fn"]), (1, 1, 1, 1))
        self.assertEqual(m["failed"], {"malicious:400": 1})
        self.assertEqual(m["mcnemar_vs_vft_library"]["malicious"], {"b": 1, "c": 1, "p": 1.0})
        self.assertEqual(m["fp_by_family"]["rows_where_family_fired"], {"920": 1})
        self.assertEqual(r["engines"]["vft-serve"]["disagree_with_library"],
                         {"blocked_serve_only": 0, "blocked_library_only": 0, "blocked_library_only_failed_in_serve": 0})
        self.assertEqual(r["vft_library_full_corpus"]["fp"], 1)
        self.assertEqual(r["matched_fpr"]["nearest"]["modsecurity"]["setting"], "modsecurity-pl1-t5")


if __name__ == "__main__":
    unittest.main()
