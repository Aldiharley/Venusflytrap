#!/usr/bin/env bash
# Decision-equivalence gate for changes that must not move any decision.
#   eval/decision_gate.sh capture <dir>  # write the baseline CSVs and JSON reports
#   eval/decision_gate.sh check <dir>    # re-run into <dir>/now-* and compare with the baseline
# Needs VFT_CORPUS (the blazehttp testcases directory). Compares, per file:
# label, lib_verdict, serve_verdict, score, banned (eval/compare_runs.py).
set -euo pipefail
: "${VFT_CORPUS:?set VFT_CORPUS to the blazehttp testcases directory}"
mode=${1:?capture or check}
dir=${2:?output directory}
case "$mode" in capture) prefix="" ;; check) prefix="now-" ;; *) echo "mode must be capture or check" >&2; exit 2 ;; esac
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
