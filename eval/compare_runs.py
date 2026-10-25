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
