# SP1 measurement log

Real blazehttp corpus (33,877 requests: 33,219 benign, 658 malicious). "lib" = `Shield::inspect` via
`bench_http` on the Python-parsed JSONL; "serve" = `venusflytrap eval --mode serve` on raw files.
Mutation = 22 seeds → 660 mutants (eval/mutate.py, seed 1337).

| Task | Change | Path | TP | FP | FN | Recall | Precision | FP rate | Seeds | Mutants | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | baseline (command-position `$(` fix) | lib | 282 | 268 | 376 | 42.86% | 51.27% | 0.81% | 19/22 | 548/660 | measured 2026-10-25 |
| 1 | per-field contributions (refactor) | lib | 282 | 268 | 376 | 42.86% | 51.27% | 0.81% | – | – | byte-identical verdicts |
| 2 | decision-driven chain, ban policy, time passed in | lib | 282 | 268 | 376 | 42.86% | 51.27% | 0.81% | – | – | stateless verdicts byte-identical; C1 fixed (unit tests) |
| 3 | H4 + M1 scoring fixes (AI emits None not Safe; per-field conflict with band floor; corroboration deduped per (field, construct), capped at 15) | lib | 283 | 268 | 375 | 43.01% | 51.36% | 0.81% | 19/22 (86.36%) | 548/660 (83.03%) | mutation retention 96.1% (83.03/86.36), unchanged vs row 0; verdict flips vs row 0: 1 (an XXE malicious request Monitor to Challenge, score 67 to 75); 676 score changes (550 up, 126 down); no regression |
