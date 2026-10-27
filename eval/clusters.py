"""Rank false positives and misses in an eval CSV by shared cause.

Rows of `venusflytrap eval --out` are grouped by (cause, top construct, field
location, field name in lower case). The field is the deciding `field`, or the
top contribution's `top_field` when `field` is empty (a row below every
threshold has no deciding field); CSVs without `top_field` still load. False
positives are benign rows (label 0) whose library verdict is Challenge or
Block; misses are malicious rows (label 1) whose library verdict is Allow or
Monitor. Only the CSV (and the split manifest) is read, never a corpus file.
With --manifest and --side, rows of the other half are dropped before anything
is counted, so held-out rows stay unopened during development.

Usage: py -I -X utf8 eval/clusters.py <csv> [--manifest M --side dev|heldout] [--top N]
Exit status: 0 printed, 2 invalid input.
"""
import argparse
import csv
import sys
from collections import defaultdict

REQUIRED = ("rel", "label", "lib_verdict", "cause", "field", "top")
ATTACK = ("Block", "Challenge")
MISS = ("Allow", "Monitor")


def load(path):
    """The CSV rows as dicts. Raises ValueError naming the first missing column."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        missing = [c for c in REQUIRED if c not in fields]
        if missing:
            raise ValueError(f"{path}: missing column {missing[0]!r} (needs {', '.join(REQUIRED)})")
        return list(reader)


def load_manifest(path):
    """rel -> side from eval/split.py's manifest.tsv (rel, label, sha256, side)."""
    sides = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            cols = line.split("\t")
            if len(cols) != 4:
                raise ValueError(f"{path}:{n}: expected 4 tab-separated columns")
            sides[cols[0]] = cols[3]
    return sides


def select(rows, sides, side):
    """The rows on `side`. Every row must be in the manifest."""
    out = []
    for r in rows:
        s = sides.get(r["rel"])
        if s is None:
            raise ValueError(f"{r['rel']} is not in the manifest")
        if s == side:
            out.append(r)
    return out


def key(row):
    field = row["field"] or row.get("top_field") or ""
    loc, _, name = field.partition(":")
    return (row["cause"], row["top"], loc, name.lower())


def clusters(rows, label, verdicts, top):
    """(rows matched, groups, the `top` largest groups as (key, count, first 3 rels))."""
    groups = defaultdict(list)
    for r in rows:
        if r["label"] == label and r["lib_verdict"] in verdicts:
            groups[key(r)].append(r["rel"])
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    total = sum(len(v) for v in groups.values())
    return total, len(groups), [(k, len(v), sorted(v)[:3]) for k, v in ranked[:top]]


def printable(s, limit=60):
    s = s.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else s[:limit] + "..."


def show(title, result):
    total, n_groups, ranked = result
    print(f"{title}: {total} rows in {n_groups} groups")
    print("count\tcause\ttop\tloc\tname\texamples")
    for (cause, top, loc, name), n, examples in ranked:
        print(f"{n}\t{cause}\t{top or '-'}\t{loc or '-'}\t{printable(name) or '-'}\t{' '.join(examples)}")


def main(argv):
    p = argparse.ArgumentParser(prog="clusters.py", description="Rank false positives and misses by shared cause.")
    p.add_argument("csv")
    p.add_argument("--manifest")
    p.add_argument("--side", choices=("dev", "heldout"))
    p.add_argument("--top", type=int, default=20)
    a = p.parse_args(argv)
    if (a.manifest is None) != (a.side is None):
        print("clusters: --manifest and --side go together", file=sys.stderr)
        sys.exit(2)
    try:
        rows = load(a.csv)
        if a.manifest:
            rows = select(rows, load_manifest(a.manifest), a.side)
    except (OSError, ValueError) as e:
        print(f"clusters: {e}", file=sys.stderr)
        sys.exit(2)
    show("false positives (label 0, Challenge/Block)", clusters(rows, "0", ATTACK, a.top))
    print()
    show("misses (label 1, Allow/Monitor)", clusters(rows, "1", MISS, a.top))


if __name__ == "__main__":
    main(sys.argv[1:])
