"""Fixed, label-stratified 50/50 dev / held-out split of a blazehttp-style corpus.

Key: SHA-256 of each raw .white/.black file. Within each label, files are sorted
by (key, relative path) and the first half (rounded up) is dev; a run of
byte-identical files is never split across the cut. No randomness.

Writes <out>/manifest.tsv (relpath, label, sha256, side). Given the JSONL that
eval/parse_corpus.py produced from the same directory, also writes
<out>/dev.jsonl and <out>/heldout.jsonl; lines are paired with files by
repeating parse_corpus.py's os.walk order, and every label is checked.

Usage: py -I -X utf8 eval/split.py <testcases_dir> <out_dir> [<corpus.jsonl>]
"""
import hashlib
import json
import os
import sys


def walk(root):
    """(relpath, label, abspath) for every .white/.black file, in parse_corpus.py's order."""
    out = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if fn.endswith(".white"):
                label = 0
            elif fn.endswith(".black"):
                label = 1
            else:
                continue
            p = os.path.join(dirpath, fn)
            out.append((os.path.relpath(p, root).replace("\\", "/"), label, p))
    return out


def sha256_of(path, rel):
    """SHA-256 of the file. A file the host will not let us read (on this machine
    two .black files are blocked, likely by antivirus) is keyed on its relative
    path instead, so it still gets a fixed side; the manifest marks it."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError as e:
        print(f"warning: unreadable, keyed on path: {rel} ({e})", file=sys.stderr)
        return "unreadable:" + hashlib.sha256(rel.encode("utf-8")).hexdigest()


def assign(items):
    """items: iterable of (relpath, label, sha256). Returns {relpath: 'dev' | 'heldout'}."""
    items = list(items)
    side = {}
    for label in (0, 1):
        group = sorted((it for it in items if it[1] == label), key=lambda it: (it[2], it[0]))
        cut = (len(group) + 1) // 2
        # Keep byte-identical files together: extend dev over a run that straddles the cut.
        while 0 < cut < len(group) and group[cut][2] == group[cut - 1][2]:
            cut += 1
        for i, it in enumerate(group):
            side[it[0]] = "dev" if i < cut else "heldout"
    return side


def main(argv):
    if len(argv) not in (2, 3):
        sys.exit(__doc__)
    root, out_dir = argv[0], argv[1]
    files = walk(root)
    items = [(rel, label, sha256_of(p, rel)) for rel, label, p in files]
    side = assign(items)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "manifest.tsv"), "w", encoding="utf-8", newline="\n") as m:
        for rel, label, sha in items:
            m.write(f"{rel}\t{label}\t{sha}\t{side[rel]}\n")
    if len(argv) == 3:
        with open(argv[2], encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        if len(lines) != len(files):
            sys.exit(f"corpus.jsonl has {len(lines)} records but {root} has {len(files)} files")
        with open(os.path.join(out_dir, "dev.jsonl"), "w", encoding="utf-8", newline="\n") as d, \
             open(os.path.join(out_dir, "heldout.jsonl"), "w", encoding="utf-8", newline="\n") as h:
            for (rel, label, _), line in zip(files, lines):
                if json.loads(line)["label"] != label:
                    sys.exit(f"label mismatch pairing {rel} with its JSONL line")
                (d if side[rel] == "dev" else h).write(line if line.endswith("\n") else line + "\n")
    for s in ("dev", "heldout"):
        counts = {lab: sum(1 for rel, l, _ in items if l == lab and side[rel] == s) for lab in (0, 1)}
        print(f"{s}: benign={counts[0]} malicious={counts[1]}")


if __name__ == "__main__":
    main(sys.argv[1:])
