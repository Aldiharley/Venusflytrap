"""Compare two evaluation runs: decision equivalence and metric deltas.

Accepts CSVs from `venusflytrap eval --out` (keyed by rel) or from the
bench_http example (keyed by row). Latency and construct names are ignored;
everything that decides the outcome is compared.

Usage: py -I -X utf8 eval/compare_runs.py <a.csv> <b.csv>
Exit status: 0 identical decisions, 1 differences, 2 invalid input.
"""
import csv
import sys

EVAL_COLS = ("label", "lib_verdict", "serve_verdict", "score", "banned")
BENCH_COLS = ("label", "pred", "score")


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


def main(argv):
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    try:
        diffs, ma, mb = compare(load(argv[0]), load(argv[1]))
    except (OSError, ValueError) as e:
        print(f"compare_runs: {e}", file=sys.stderr)
        sys.exit(2)
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
