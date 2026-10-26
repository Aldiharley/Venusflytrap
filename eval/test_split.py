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
