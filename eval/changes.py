"""Row-level changes between two eval runs: DQ2's serve diff and dev A/B.

gate: every row whose lib_verdict, serve_verdict or banned changed between a
baseline serve run and a new one, with the new run's cause, field, top and
top_field; the number of rows whose score alone moved; then the new run's
bans_from_allowed and invariant_violations.

ab: on the rows both runs contain, delta TP / FP and the exact McNemar test per
class (eval/compare_runs.py); recall and FP rate with the Wilson 95 % intervals
of each run's JSON report; and every malicious row whose library verdict fell
from Challenge/Block to Allow/Monitor.

Only rel paths, verdicts, construct ids, causes and field names are printed,
never a request. Rows only in one run (a corpus file deleted between the runs)
are listed, never compared.

Usage: py -I -X utf8 eval/changes.py gate [--tag T] <old.csv> <new.csv> <new.json>
       py -I -X utf8 eval/changes.py ab <a.csv> <a.json> <b.csv> <b.json>
Exit status: gate 0 when bans_from_allowed and invariant_violations are 0, 1
otherwise; ab 0; both 2 on invalid input.
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location("compare_runs", Path(__file__).with_name("compare_runs.py"))
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)

DECISION = ("lib_verdict", "serve_verdict", "banned")
MISS = ("Allow", "Monitor")


def load_rows(path):
    """An eval CSV as {rel: row}. Raises ValueError for a bench CSV or bad header."""
    kind, rows = cr.load(path)
    if kind != "eval":
        raise ValueError(f"{path}: needs an eval CSV (keyed by rel)")
    return rows


def load_report(path):
    """The JSON report of `venusflytrap eval`. Raises ValueError when it is not JSON."""
    with open(path, encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}: not a JSON report ({e})") from e


def split(ra, rb):
    """(rels in both runs, rels only in a, rels only in b), each sorted."""
    return sorted(ra.keys() & rb.keys()), sorted(ra.keys() - rb.keys()), sorted(rb.keys() - ra.keys())


def changed(ra, rb):
    """Shared rels whose lib_verdict, serve_verdict or banned differ, sorted."""
    return [k for k in split(ra, rb)[0] if any(ra[k][c] != rb[k][c] for c in DECISION)]


def score_only(ra, rb):
    """Shared rows whose score moved while every decision column stayed."""
    return sum(1 for k in split(ra, rb)[0]
               if ra[k]["score"] != rb[k]["score"] and all(ra[k][c] == rb[k][c] for c in DECISION))


def fallen(ra, rb):
    """Shared malicious rels whose lib_verdict went from Challenge/Block to Allow/Monitor."""
    return [k for k in split(ra, rb)[0]
            if ra[k]["label"] == "1" and ra[k]["lib_verdict"] in cr.ATTACK and rb[k]["lib_verdict"] in MISS]


def counters(report):
    """(bans_from_allowed, invariant_violations). A library report has no serve block: 0 bans."""
    if "invariant_violations" not in report:
        raise ValueError("JSON report has no invariant_violations")
    serve = report.get("serve") or {}
    return int(serve.get("bans_from_allowed", 0)), int(report["invariant_violations"])


def cell(s, limit=60):
    s = (s or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")
    s = s if len(s) <= limit else s[:limit] + "..."
    return s or "-"


def arrow(x, y):
    x, y = x or "-", y or "-"
    return x if x == y else f"{x}->{y}"


def gate_lines(tag, ra, rb, report):
    """(lines, ok): the changed decisions of run b against run a; ok when both counters are 0."""
    shared, only_a, only_b = split(ra, rb)
    rels = changed(ra, rb)
    out = [f"diff {tag}: {len(shared)} shared rows, {len(rels)} changed decisions, "
           f"{score_only(ra, rb)} score-only changes, {len(only_a)} only in old, {len(only_b)} only in new"]
    if rels:
        out.append("rel\tlabel\tlib_verdict\tserve_verdict\tbanned\tcause\tfield\ttop\ttop_field")
    for k in rels:
        x, y = ra[k], rb[k]
        out.append("\t".join([k, y["label"], arrow(x["lib_verdict"], y["lib_verdict"]),
                              arrow(x["serve_verdict"], y["serve_verdict"]), arrow(x["banned"], y["banned"]),
                              cell(y.get("cause")), cell(y.get("field")), cell(y.get("top")),
                              cell(y.get("top_field"))]))
    out += [f"only in old: {k}" for k in only_a] + [f"only in new: {k}" for k in only_b]
    bans, inv = counters(report)
    out += [f"bans_from_allowed={bans}", f"invariant_violations={inv}"]
    return out, bans == 0 and inv == 0


def rate_line(name, report):
    m = report["library"]
    (rlo, rhi), (flo, fhi) = m["recall_ci95"], m["fp_rate_ci95"]
    return (f"{name}: tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']} "
            f"recall={m['recall']:.2%} [{rlo:.2%}, {rhi:.2%}] fp_rate={m['fp_rate']:.3%} [{flo:.3%}, {fhi:.3%}]")


def ab_lines(ra, rb, rep_a, rep_b):
    """The dev A/B report of run b against run a (see the module docstring)."""
    shared, only_a, only_b = split(ra, rb)
    if not shared:
        raise ValueError("the runs share no rows")
    a, b = {k: ra[k] for k in shared}, {k: rb[k] for k in shared}
    ma, mb = cr.metrics("eval", a), cr.metrics("eval", b)
    out = [f"ab: {len(shared)} shared rows, {len(only_a)} only in a, {len(only_b)} only in b",
           f"delta: tp={mb['tp'] - ma['tp']:+d} fp={mb['fp'] - ma['fp']:+d}"]
    out += cr.mcnemar_lines(a, b)
    out += [rate_line("a", rep_a), rate_line("b", rep_b)]
    rels = fallen(a, b)
    out.append(f"fallen: {len(rels)} malicious rows from Challenge/Block to Allow/Monitor")
    if rels:
        out.append("rel\ta\tb\ttop_a\ttop_b\tcause_b")
    for k in rels:
        out.append("\t".join([k, a[k]["lib_verdict"], b[k]["lib_verdict"], cell(a[k].get("top")),
                              cell(b[k].get("top")), cell(b[k].get("cause"))]))
    out += [f"only in a: {k}" for k in only_a] + [f"only in b: {k}" for k in only_b]
    return out


def main(argv):
    p = argparse.ArgumentParser(prog="changes.py", description="Row-level changes between two eval runs.")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate", help="changed serve decisions against a baseline")
    g.add_argument("--tag", default="serve")
    for name in ("old_csv", "new_csv", "new_json"):
        g.add_argument(name)
    ab = sub.add_parser("ab", help="dev A/B report")
    for name in ("a_csv", "a_json", "b_csv", "b_json"):
        ab.add_argument(name)
    a = p.parse_args(argv)
    try:
        if a.cmd == "gate":
            lines, ok = gate_lines(a.tag, load_rows(a.old_csv), load_rows(a.new_csv), load_report(a.new_json))
        else:
            lines, ok = ab_lines(load_rows(a.a_csv), load_rows(a.b_csv),
                                 load_report(a.a_json), load_report(a.b_json)), True
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"changes: {e}", file=sys.stderr)
        sys.exit(2)
    for line in lines:
        print(line)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv[1:])
