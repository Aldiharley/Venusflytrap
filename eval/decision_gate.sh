#!/usr/bin/env bash
# Serve-mode decision gate.
#   eval/decision_gate.sh capture <dir>  # write the baseline CSVs and JSON reports
#   eval/decision_gate.sh check <dir>    # re-run into <dir>/now-* and require identical decisions
#   eval/decision_gate.sh diff <dir>     # re-run into <dir>/now-* and list every changed decision
# Needs VFT_CORPUS (the labelled corpus testcases directory). check compares, per
# file: label, lib_verdict, serve_verdict, score, banned (eval/compare_runs.py).
# diff prints, for distinct and pooled:100, every row whose lib_verdict,
# serve_verdict or banned changed, with the new cause, field, top and top_field,
# then the new run's bans_from_allowed and invariant_violations
# (eval/changes.py gate). diff exits 0 when both counters are 0 in both runs,
# 1 otherwise, 2 on invalid input.
set -euo pipefail
: "${VFT_CORPUS:?set VFT_CORPUS to the labelled corpus testcases directory}"
mode=${1:?capture, check or diff}
dir=${2:?output directory}
case "$mode" in capture) prefix="" ;; check|diff) prefix="now-" ;; *) echo "mode must be capture, check or diff" >&2; exit 2 ;; esac
PY=${PY:-py -I -X utf8}
mkdir -p "$dir"
cargo build --release -p vft-cli
bin=target/release/venusflytrap
for sources in distinct pooled:100; do
  tag=${sources/:/}
  "$bin" eval --corpus "$VFT_CORPUS" --mode serve --sources "$sources" \
    --out "$dir/${prefix}serve-$tag.csv" > "$dir/${prefix}serve-$tag.json"
done
if [ "$mode" = check ]; then
  for tag in distinct pooled100; do
    $PY eval/compare_runs.py "$dir/serve-$tag.csv" "$dir/now-serve-$tag.csv"
  done
  echo "decision gate: identical"
fi
if [ "$mode" = diff ]; then
  status=0
  for tag in distinct pooled100; do
    rc=0
    $PY eval/changes.py gate --tag "$tag" "$dir/serve-$tag.csv" "$dir/now-serve-$tag.csv" "$dir/now-serve-$tag.json" || rc=$?
    if [ "$rc" -eq 2 ]; then exit 2; fi
    if [ "$rc" -ne 0 ]; then status=1; fi
  done
  if [ "$status" -eq 0 ]; then
    echo "decision gate diff: bans_from_allowed 0, invariant_violations 0"
  else
    echo "decision gate diff: FAIL (bans_from_allowed or invariant_violations is not 0)"
  fi
  exit "$status"
fi
