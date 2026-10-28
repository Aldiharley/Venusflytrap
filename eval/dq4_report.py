"""DQ4 report: external CRS baselines against Venusflytrap on the same replayed rows.

Reads the per-row CSVs written by eval/replay_external.py (via eval/baselines/run_settings.py)
and Venusflytrap's library CSV (`venusflytrap eval --mode library --out`), and prints a JSON
report with, per engine and setting, TP/FP/TN/FN, recall and FP rate with Wilson 95 %
intervals, the failed rows by status, exact McNemar against Venusflytrap per class, the CRS
setting nearest Venusflytrap's FP rate per engine, and CRS false positives by rule family.
Only counts, rel paths and rule ids are printed.

Usage: py -I -X utf8 eval/dq4_report.py --runs DIR --vft-library CSV [--expected FILE] > report.json
"""
import argparse
import csv
import importlib.util
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rx = _load("replay_external")
cr = _load("compare_runs")

ATTACK = ("Block", "Challenge")
# CRS bookkeeping rules: they fire on every blocked request or only add up scores,
# so they are not a detection family.
NON_FAMILY = {"949", "959", "980", "901", "905"}
RUN_NAME = re.compile(r"^(modsecurity|coraza)-pl(\d)-t(\d+)$")


def load_run(path):
    """{rel: (label, blocked, verdict, status)} from a replay CSV."""
    with open(path, newline="", encoding="utf-8") as f:
        return {r["rel"]: (int(r["label"]), r["verdict"] == "blocked", r["verdict"], r["status"])
                for r in csv.DictReader(f)}


def load_library(path):
    with open(path, newline="", encoding="utf-8") as f:
        return {r["rel"]: (int(r["label"]), r["lib_verdict"] in ATTACK, r["lib_verdict"], "")
                for r in csv.DictReader(f)}


def metrics(run, rows):
    m = rx.confusion([(run[k][0], "blocked" if run[k][1] else "passed") for k in rows])
    failed = {}
    for k in rows:
        label, _b, verdict, status = run[k]
        if verdict == "failed":
            key = f"{'malicious' if label else 'benign'}:{status or 'io'}"
            failed[key] = failed.get(key, 0) + 1
    m["failed"] = dict(sorted(failed.items()))
    return m


def mcnemar(a, b, rows):
    """Per class: b = blocked by `a` only, c = blocked by `b` only, exact two-sided p."""
    out = {}
    for label, name in ((1, "malicious"), (0, "benign")):
        x = y = 0
        for k in rows:
            if a[k][0] != label:
                continue
            if a[k][1] and not b[k][1]:
                x += 1
            elif b[k][1] and not a[k][1]:
                y += 1
        out[name] = {"b": x, "c": y, "p": cr.mcnemar_p(x, y)}
    return out


def families(rule_ids):
    return sorted({r[:3] for r in rule_ids if len(r) == 6 and r[:3] not in NON_FAMILY})


def fp_families(run, rules, rows):
    """CRS false positives by rule family (first three digits of the rule id), summary counts only."""
    fp = [k for k in rows if run[k][0] == 0 and run[k][1]]
    fired, solo, by_rule = {}, {}, {}
    no_rules = only_920 = with_920 = 0
    for k in fp:
        fams = families(rules.get(k, []))
        if not fams:
            no_rules += 1
            continue
        for r in rules[k]:
            if r[:3] not in NON_FAMILY:
                by_rule[r] = by_rule.get(r, 0) + 1
        for f in fams:
            fired[f] = fired.get(f, 0) + 1
        if len(fams) == 1:
            solo[fams[0]] = solo.get(fams[0], 0) + 1
        if "920" in fams:
            with_920 += 1
            if fams == ["920"]:
                only_920 += 1
    return {
        "fp_rows": len(fp),
        "fp_rows_without_joined_rules": no_rules,
        "rows_where_family_fired": dict(sorted(fired.items(), key=lambda kv: (-kv[1], kv[0]))),
        "rows_where_family_is_the_only_one": dict(sorted(solo.items(), key=lambda kv: (-kv[1], kv[0]))),
        "fp_rows_with_920": with_920,
        "fp_rows_920_only": only_920,
        "fp_rows_without_920": len(fp) - with_920 - no_rules,
        "top_rules": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:10]),
    }


def nearest(settings, target):
    """The setting whose FP rate is closest to `target` (ties: higher recall)."""
    return min(settings, key=lambda s: (abs(s[1]["fp_rate"] - target), -s[1]["recall"]))


def build(runs_dir, library_csv, expected=None):
    runs_dir = Path(runs_dir)
    lib = load_library(library_csv)
    runs = {}
    for p in sorted(runs_dir.glob("*.csv")):
        if RUN_NAME.match(p.stem) or p.stem == "vft-serve":
            runs[p.stem] = load_run(p)
    shared = set(lib)
    for r in runs.values():
        shared &= set(r)
    rows = sorted(shared)
    report = {"rows_shared": len(rows),
              "rows_shared_by_label": {"malicious": sum(1 for k in rows if lib[k][0] == 1),
                                       "benign": sum(1 for k in rows if lib[k][0] == 0)},
              "rows_only_in_library": len(set(lib) - shared)}
    if expected:
        want = [l.strip() for l in Path(expected).read_text(encoding="utf-8-sig").splitlines()
                if l.strip().endswith((".white", ".black"))]
        report["corpus_expected"] = len(want)
        report["corpus_missing"] = sorted(set(want) - set(lib))
    vft_full = metrics(lib, sorted(lib))
    report["vft_library_full_corpus"] = vft_full
    engines = {"vft-library": metrics(lib, rows)}
    for name, run in runs.items():
        engines[name] = metrics(run, rows)
        if name != "vft-serve":
            engines[name]["mcnemar_vs_vft_library"] = mcnemar(run, lib, rows)
            if "vft-serve" in runs:
                engines[name]["mcnemar_vs_vft_serve"] = mcnemar(run, runs["vft-serve"], rows)
            rules_path = runs_dir / f"rules-{name}.json"
            if rules_path.exists():
                rules = json.loads(rules_path.read_text(encoding="utf-8"))
                engines[name]["fp_by_family"] = fp_families(run, rules, rows)
            summary_path = runs_dir / f"{name}.json"
            if summary_path.exists():
                s = json.loads(summary_path.read_text(encoding="utf-8"))
                engines[name]["run"] = {k: s.get(k) for k in ("env", "effective_crs_setup", "io_errors", "statuses",
                                                               "replayed", "not_replayable", "unreadable",
                                                               "sent_sha256", "wall_s", "audit_records_joined")}
    if "vft-serve" in runs:
        s = runs["vft-serve"]
        engines["vft-serve"]["disagree_with_library"] = {
            "blocked_serve_only": sum(1 for k in rows if s[k][1] and not lib[k][1]),
            "blocked_library_only": sum(1 for k in rows if lib[k][1] and not s[k][1]),
            "blocked_library_only_failed_in_serve": sum(1 for k in rows if lib[k][1] and s[k][2] == "failed"),
        }
        engines["vft-serve"]["mcnemar_vs_vft_library"] = mcnemar(s, lib, rows)
        p = runs_dir / "vft-serve.json"
        if p.exists():
            js = json.loads(p.read_text(encoding="utf-8"))
            engines["vft-serve"]["run"] = {k: js.get(k) for k in ("io_errors", "statuses", "replayed", "sent_sha256", "wall_s")}
    report["engines"] = engines
    target = vft_full["fp_rate"]
    matched = {}
    for engine in ("modsecurity", "coraza"):
        settings = [(n, m) for n, m in engines.items() if n.startswith(engine + "-")]
        if settings:
            n, m = nearest(settings, target)
            matched[engine] = {"setting": n, "fp_rate": m["fp_rate"], "recall": m["recall"],
                               "recall_ci95": m["recall_ci95"], "fp_rate_ci95": m["fp_rate_ci95"]}
    report["matched_fpr"] = {"vft_fp_rate_full_corpus": target, "vft_recall_full_corpus": vft_full["recall"],
                             "vft_recall_shared_rows": engines["vft-library"]["recall"],
                             "vft_fp_rate_shared_rows": engines["vft-library"]["fp_rate"], "nearest": matched}
    if "modsecurity-pl1-t5" in runs and "coraza-pl1-t5" in runs:
        report["mcnemar_modsecurity_vs_coraza_pl1_t5"] = mcnemar(runs["modsecurity-pl1-t5"], runs["coraza-pl1-t5"], rows)
    return report


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--vft-library", required=True)
    ap.add_argument("--expected", help="file listing every corpus rel path the corpus should hold")
    a = ap.parse_args(argv)
    json.dump(build(a.runs, a.vft_library, a.expected), sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
