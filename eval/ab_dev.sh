#!/usr/bin/env bash
# Dev-half A/B for one DQ2 step: library mode on the dev rows of the split, run twice.
#   eval/ab_dev.sh <step> "<flags A>" "<flags B>" [binA] [binB]
# binA and binB default to ./target/release/venusflytrap; this script does not
# build. Each flags string is split into words and passed to `venusflytrap eval`
# (for example "--disable gate.cmd-position"); "" passes nothing.
# Writes $VFT_RUNS/<step>-a.{csv,json}, $VFT_RUNS/<step>-b.{csv,json} and
# $VFT_RUNS/<step>-ab.txt (eval/changes.py ab, then eval/clusters.py --top 15
# for each run), and prints the -ab.txt.
# Needs VFT_CORPUS, VFT_MANIFEST and VFT_RUNS. Exit status: 0 written, 2 invalid
# input or a failed run.
set -euo pipefail
: "${VFT_CORPUS:?set VFT_CORPUS to the corpus testcases directory}"
: "${VFT_MANIFEST:?set VFT_MANIFEST to the split manifest}"
: "${VFT_RUNS:?set VFT_RUNS to the runs directory}"
if [ $# -lt 3 ] || [ $# -gt 5 ]; then
  echo 'usage: eval/ab_dev.sh <step> "<flags A>" "<flags B>" [binA] [binB]' >&2
  exit 2
fi
step=$1
flags_a=$2
flags_b=$3
bin_a=${4:-./target/release/venusflytrap}
bin_b=${5:-./target/release/venusflytrap}
PY=${PY:-py -I -X utf8}
mkdir -p "$VFT_RUNS"
r="$VFT_RUNS/$step"

run_side() { # run_side <a|b> <binary> <flags>
  local side=$1 bin=$2 flags=$3
  # shellcheck disable=SC2086 # the flags string is split into words on purpose
  if ! "$bin" eval --corpus "$VFT_CORPUS" --mode library --manifest "$VFT_MANIFEST" --side dev $flags \
    --out "$r-$side.csv" > "$r-$side.json"; then
    echo "ab_dev: run $side failed ($bin $flags)" >&2
    exit 2
  fi
}

run_side a "$bin_a" "$flags_a"
run_side b "$bin_b" "$flags_b"
{
  echo "step: $step"
  echo "a: $bin_a $flags_a"
  echo "b: $bin_b $flags_b"
  $PY eval/changes.py ab "$r-a.csv" "$r-a.json" "$r-b.csv" "$r-b.json"
  echo
  echo "== clusters a"
  $PY eval/clusters.py "$r-a.csv" --manifest "$VFT_MANIFEST" --side dev --top 15
  echo
  echo "== clusters b"
  $PY eval/clusters.py "$r-b.csv" --manifest "$VFT_MANIFEST" --side dev --top 15
} > "$r-ab.txt"
cat "$r-ab.txt"
