import os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import confidence as c

HERE = os.path.dirname(__file__)

class T(unittest.TestCase):
    def test_wilson_lower_bound(self):
        self.assertEqual(c.wilson_lower(0, 0), 0.0)
        self.assertAlmostEqual(c.wilson_lower(4, 5), 0.3755, places=3)
        self.assertAlmostEqual(c.wilson_lower(100, 100), 0.963, places=3)

    def test_counts_only_challenge_and_block_rows(self):
        rows = c.read_rows(os.path.join(HERE, 'fixtures', 'confidence_sample.csv'))
        counts = c.count(rows)
        self.assertEqual(counts, {'sqli.union-select': (4, 1), 'xss.script-tag': (1, 0)})

    def test_table_drops_constructs_below_five_rows(self):
        table = c.table({'sqli.union-select': (4, 1), 'xss.script-tag': (1, 0)}, min_rows=5)
        self.assertEqual(table, [('sqli.union-select', 37)])

    def test_rust_and_ts_outputs(self):
        rs = c.render_rust([('a.b', 9), ('c.d', 80)], 'src.csv', 'abc123', '2026-10-29')
        self.assertIn('("a.b", 9),', rs)
        self.assertIn('pub static TABLE', rs)
        ts = c.render_ts([('a.b', 9)], 'src.csv', 'abc123', '2026-10-29')
        self.assertIn("'a.b': 9,", ts)

if __name__ == '__main__':
    unittest.main()
