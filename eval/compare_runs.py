"""Compare two evaluation runs: decision equivalence and metric deltas.

Accepts CSVs from `venusflytrap eval --out` (keyed by rel) or from the
bench_http example (keyed by row). Latency and construct names are ignored;
everything that decides the outcome is compared. When decisions differ, an
exact McNemar test on the discordant pairs is printed per class (malicious
rows: detection; benign rows: false positives) for lib_verdict and, when every
row of both runs has one, serve_verdict.

--intersect (eval CSVs only) compares the rows both runs contain and lists every
other row, for a corpus that lost files between the runs.

Usage: py -I -X utf8 eval/compare_runs.py [--intersect] <a.csv> <b.csv>
Exit status: 0 identical decisions, 1 differences, 2 invalid input.
"""
import csv
import math
import sys

EVAL_COLS = ("label", "lib_verdict", "serve_verdict", "score", "banned")
BENCH_COLS = ("label", "pred", "score")
ATTACK = ("Block", "Challenge")


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
        return row["lib_verdict"] in ATTACK
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


def intersect(a, b):
    """Keep only the rows both eval runs contain.

    Returns (a, b, only_a, only_b) with the dropped keys sorted. Raises
    ValueError for bench CSVs (keyed by row number) or when no row is shared.
    """
    (ka, ra), (kb, rb) = a, b
    if ka != "eval" or kb != "eval":
        raise ValueError("--intersect needs two eval CSVs")
    common = ra.keys() & rb.keys()
    if not common:
        raise ValueError("--intersect: the runs share no rows")
    only_a = sorted(ra.keys() - common)
    only_b = sorted(rb.keys() - common)
    return (ka, {k: ra[k] for k in common}), (kb, {k: rb[k] for k in common}), only_a, only_b


def mcnemar_p(b, c):
    """Two-sided exact McNemar p-value: binomial(b + c, 1/2) on the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def discordant(ra, rb, col, label):
    """(b, c) over the rows with `label`: b = blocked in a only, c = blocked in b only.

    Blocked means Block or Challenge in `col`. Both runs must hold the same keys.
    """
    b = c = 0
    for key, x in ra.items():
        if x["label"] != label:
            continue
        in_a, in_b = x[col] in ATTACK, rb[key][col] in ATTACK
        if in_a and not in_b:
            b += 1
        elif in_b and not in_a:
            c += 1
    return b, c


def mcnemar_lines(ra, rb):
    """A legend, then one line per verdict column and class."""
    cols = ["lib_verdict"]
    if all(r["serve_verdict"] for r in ra.values()) and all(r["serve_verdict"] for r in rb.values()):
        cols.append("serve_verdict")
    out = ["mcnemar (exact, two-sided): b = blocked in a only, c = blocked in b only"]
    for col in cols:
        for label, name in (("1", "malicious"), ("0", "benign")):
            b, c = discordant(ra, rb, col, label)
            out.append(f"mcnemar {col} {name}: b={b} c={c} p={mcnemar_p(b, c):.4g}")
    return out


def main(argv):
    use_intersect = "--intersect" in argv
    paths = [x for x in argv if x != "--intersect"]
    if len(paths) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    only_a, only_b = [], []
    try:
        a, b = load(paths[0]), load(paths[1])
        if use_intersect:
            a, b, only_a, only_b = intersect(a, b)
        diffs, ma, mb = compare(a, b)
    except (OSError, ValueError) as e:
        print(f"compare_runs: {e}", file=sys.stderr)
        sys.exit(2)
    if use_intersect:
        print(f"intersect: {len(only_a)} rows only in a, {len(only_b)} only in b (not compared)")
        for key in only_a:
            print(f"only in a: {key}")
        for key in only_b:
            print(f"only in b: {key}")
    for name, m in (("a", ma), ("b", mb)):
        print(f"{name}: tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} "
              f"recall={m['recall']:.4f} fp_rate={m['fp_rate']:.4f}")
    print(f"delta: tp={mb['tp'] - ma['tp']:+d} fp={mb['fp'] - ma['fp']:+d}")
    print(f"decision diffs: {len(diffs)}")
    for key, d in diffs[:20]:
        print(f"  {key}: {d}")
    if diffs and a[0] == "eval":
        for line in mcnemar_lines(a[1], b[1]):
            print(line)
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
