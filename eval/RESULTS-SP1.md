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
| 4 | canonical path for honeypot/intent (percent-decode up to 3 layers, dot segments, matrix params, slash collapse; H5) | lib | 283 | 268 | 375 | 43.01% | 51.36% | 0.81% | 19/22 (86.36%) | 548/660 (83.03%) | mutation retention 96.1% (83.03/86.36), unchanged; verdicts, scores and miss lists identical to row 3 on corpus, seeds and mutants (0 diffs): the corpus has no encoded or dotted recon paths the old raw-path checks missed, and no benign path that canonicalisation newly maps onto a decoy or sensitive prefix. H5 is fixed per unit tests only, not visible in these numbers |
| 6 | adapter inspects every forwarded header byte (non-UTF-8 decoded lossily + `limit.header-non-utf8` evidence, C4); `Host` now inspected, raw `Cookie` header skipped (parsed cookies cover it, L4) | lib | 283 | 268 | 375 | 43.01% | 51.36% | 0.81% | 19/22 (86.36%) | 548/660 (83.03%) | mutation retention 96.1% (83.03/86.36), unchanged; 0 verdict flips and 0 miss-list changes vs row 4 on corpus, seeds and mutants. Only 9 benign corpus requests changed score (+2 or +3, all still Allow/Monitor): every one has `Host: s.union.360.cn`, where the `union` host label now scores as a weak SQL keyword token. The corpus JSONL has Host on all 33,877 requests but no raw Cookie header (204 requests carry parsed cookies), so L4 double-counting and C4 non-UTF-8 handling are fixed per unit tests only (the lib bench path never sees non-UTF-8 bytes) |

## Throughput (Task 7, H3)

`Pipeline::decide` (64-shard chain store, no lock held during inspection) versus stateless `Shield::inspect`,
8 threads x 50 requests, 8 distinct source IPs per thread, release build
(`cargo test --release -p vft-proxy --lib decide_throughput -- --ignored --nocapture`). Request: a ~64 KB query
(4 fields of `a%3Bb%20` x 2000) with Chrome headers; the brief's 6-field query was 96 KB and exceeds the
65,534-byte URI limit of the `http` crate, so the fixture uses 4 fields. One discarded warm-up round of each mode
runs before the timed pair.

| Run | stateless | decide | ratio (stateless / decide) |
|---|---|---|---|
| 1 | 0.193 s | 0.189 s | 1.02 |
| 2 | 0.191 s | 0.193 s | 0.99 |
| 3 | 0.186 s | 0.185 s | 1.00 |

Acceptance is ratio >= 0.75 (decide at least 0.75x stateless throughput). It is met: after warm-up the stateful
path runs at parity with the stateless one (ratio 0.99 to 1.02), i.e. the sharded chain store adds no measurable
serialisation. (Before the warm-up was added the first measurement read 1.41 to 1.52, which was warm-up cost
charged to the stateless pass, not a speed-up.)
