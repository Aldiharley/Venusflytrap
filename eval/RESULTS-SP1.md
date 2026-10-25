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
| 10 lib (raw Rust parser) | `venusflytrap eval --mode library` (stateless `Shield::inspect`, raw Cookie header kept) | lib | 283 | 269 | 373 | 43.14% (of 656 scored) | 51.27% | 0.81% | – | – | raw corpus, Rust lenient parser (`venusflytrap eval`), 33,877 files of which 33,875 scored: 2 malicious files were unreadable (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`: os error 5 Access is denied from this host; the Python parser read them earlier), counted in `read_failures` and not scored (FN would be 375 against the 658 malicious, recall 43.01%); parse_failures 0 (one request line without a leading `/`, `ff/67/62b331a3e94507a5759d1f9bcb8a.black`, is rooted by the parser; without that rule it was the only parse failure); skipped_headers 0; invariant_violations 0; latency p50/p95/p99 77/217/765 us (inspect only, excludes parse). Versus row 6 (Python-parsed JSONL, 283/268/375): TP identical; FP +1; 33,649 of 33,875 scored requests have identical score, 222 are +1, one +2, one +3, one +67. The single verdict flip is benign `eb/c3/0dc87d6db1c36991b86d3693f646.white` (Block 100 here, Allow 33 in row 6; an 83 KB JSON body with non-ASCII bytes, constructs shell-meta, quote-breakout), consistent with the Python path decoding the body latin-1 and the Rust path UTF-8-lossy; the one +1 case inspected (`02/4b/7e19a3a2e319704e739778c0cac0.white`) has a gzip binary body. The other 221 are not individually traced. The libinjection baseline still reads the Python-parsed JSONL (input-fairness gap) |
| 10 serve distinct | `venusflytrap eval --mode serve --sources distinct` (`Pipeline::decide`, one source per request, 100 ms synthetic step) | serve | 283 | 269 | 373 | 43.14% (of 656 scored) | 51.27% | 0.81% | – | – | raw corpus, Rust lenient parser (`venusflytrap eval`), 33,877 files of which 33,875 scored: 2 malicious files were unreadable (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`: os error 5 Access is denied from this host; the Python parser read them earlier), counted in `read_failures` and not scored (FN would be 375 against the 658 malicious, recall 43.01%); parse_failures 0 (one request line without a leading `/`, `ff/67/62b331a3e94507a5759d1f9bcb8a.black`, is rooted by the parser; without that rule it was the only parse failure); skipped_headers 0; verdicts identical to library for every request (distinct sources: no ban ever affects a later request); benign_sources 33,219; benign_sources_banned 72 (sources whose own benign request was blocked and then banned); collateral_fp 0; bans_from_allowed 0; invariant_violations 0; latency p50/p95/p99 94/269/884 us (`decide` only) |
| 10 serve pooled:100 | `venusflytrap eval --mode serve --sources pooled:100` (100 shared sources, hashed by file name, 100 ms synthetic step) | serve | 446 | 15847 | 210 | 67.99% (of 656 scored) | 2.74% | 47.70% | – | – | raw corpus, Rust lenient parser (`venusflytrap eval`), 33,877 files of which 33,875 scored: 2 malicious files were unreadable (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`: os error 5 Access is denied from this host; the Python parser read them earlier), counted in `read_failures` and not scored (FN would be 375 against the 658 malicious, recall 43.01%); parse_failures 0 (one request line without a leading `/`, `ff/67/62b331a3e94507a5759d1f9bcb8a.black`, is rooted by the parser; without that rule it was the only parse failure); skipped_headers 0; benign_sources 100; benign_sources_banned 80; collateral_fp 15,578 (benign requests blocked in serve that library allowed, i.e. blocked because their pooled source was already banned); bans_from_allowed 0; invariant_violations 0; latency p50/p95/p99 44/179/410 us. This is the cost of per-source banning when many benign clients share a source (NAT, unconfigured trusted proxy): 80 of 100 shared sources get banned within the corpus and then every later request from them is rejected. Reported as measured, nothing tuned |

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

## TCP replay equivalence (Task 11)

`venusflytrap eval --mode tcp --limit 1000` starts the real proxy (`serve_listener`, enforce on, audit off) on
loopback in front of a stub upstream and replays the first 1,000 raw corpus samples (sorted by path; 16 of them
are `.black`) over sockets: own `X-Forwarded-For` per sample (`proxy.trusted_proxies = [127.0.0.1]`),
`Connection: close`, exact `Content-Length`. The in-process `Pipeline::decide` runs on an identically configured
pipeline immediately before each send; 403 must equal Block/Challenge and 200 must equal Allow/Monitor.

| Run | replayed | matched | proxy_rejected | not_replayable | mismatched |
|---|---|---|---|---|---|
| first 1,000 (distinct sources) | 992 | 991 | 1 | 8 | 0 |

`not_replayable` (8): Transfer-Encoding or Upgrade samples, or requests the lenient parser cannot read after
normalisation. `proxy_rejected` (1): `00/06/005a52981dd324c40488a1a588f9.white` answered 400 by hyper because its
request target holds raw `<` and `>`; the lenient in-process parser percent-encodes them. This is a known
front-end difference, not an engine mismatch. Caveat: the 1,000-sample prefix holds only 16 attack samples, so the
403 path is exercised far less than the 200 path.
