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
| 6 | adapter inspects every forwarded header *value* (correction: at this point `Accept-Encoding` was still skipped and query keys and cookie names were not inspected; fixed in "Final review fix wave" below) (non-UTF-8 decoded lossily + `limit.header-non-utf8` evidence, C4); `Host` now inspected, raw `Cookie` header skipped (parsed cookies cover it, L4) | lib | 283 | 268 | 375 | 43.01% | 51.36% | 0.81% | 19/22 (86.36%) | 548/660 (83.03%) | mutation retention 96.1% (83.03/86.36), unchanged; 0 verdict flips and 0 miss-list changes vs row 4 on corpus, seeds and mutants. Only 9 benign corpus requests changed score (+2 or +3, all still Allow/Monitor): every one has `Host: s.union.360.cn`, where the `union` host label now scores as a weak SQL keyword token. The corpus JSONL has Host on all 33,877 requests but no raw Cookie header (204 requests carry parsed cookies), so L4 double-counting and C4 non-UTF-8 handling are fixed per unit tests only (the lib bench path never sees non-UTF-8 bytes) |
| 10 lib (raw Rust parser) | `venusflytrap eval --mode library` (stateless `Shield::inspect`, raw Cookie header kept) | lib | 283 | 269 | 373 | 43.14% (of 656 scored) | 51.27% | 0.81% | – | – | raw corpus, Rust lenient parser (`venusflytrap eval`), 33,877 files of which 33,875 scored: 2 malicious files were unreadable (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`: os error 5 Access is denied from this host; the Python parser read them earlier), counted in `read_failures` and not scored (FN would be 375 against the 658 malicious, recall 43.01%); parse_failures 0 (one request line without a leading `/`, `ff/67/62b331a3e94507a5759d1f9bcb8a.black`, is rooted by the parser; without that rule it was the only parse failure); skipped_headers 0; invariant_violations 0; latency p50/p95/p99 77/217/765 us (inspect only, excludes parse). Versus row 6 (Python-parsed JSONL, 283/268/375): TP identical; FP +1; 33,649 of 33,875 scored requests have identical score, 222 are +1, one +2, one +3, one +67. The single verdict flip is benign `eb/c3/0dc87d6db1c36991b86d3693f646.white` (Block 100 here, Allow 33 in row 6; an 83 KB JSON body with non-ASCII bytes, constructs shell-meta, quote-breakout), consistent with the Python path decoding the body latin-1 and the Rust path UTF-8-lossy; the one +1 case inspected (`02/4b/7e19a3a2e319704e739778c0cac0.white`) has a gzip binary body. The other 221 are not individually traced. The libinjection baseline still reads the Python-parsed JSONL (input-fairness gap) |
| 10 serve distinct | `venusflytrap eval --mode serve --sources distinct` (`Pipeline::decide`, one source per request, 100 ms synthetic step) | serve | 283 | 269 | 373 | 43.14% (of 656 scored) | 51.27% | 0.81% | – | – | raw corpus, Rust lenient parser (`venusflytrap eval`), 33,877 files of which 33,875 scored: 2 malicious files were unreadable (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`: os error 5 Access is denied from this host; the Python parser read them earlier), counted in `read_failures` and not scored (FN would be 375 against the 658 malicious, recall 43.01%); parse_failures 0 (one request line without a leading `/`, `ff/67/62b331a3e94507a5759d1f9bcb8a.black`, is rooted by the parser; without that rule it was the only parse failure); skipped_headers 0; block/allow decisions identical to library for every request (distinct sources: no ban ever affects a later request; 10 requests are Challenge in the library and Block in serve, from the chain-stage bonus, so verdict labels are not identical); benign_sources 33,219; benign_sources_banned 72 (sources whose own benign request was blocked and then banned); collateral_fp 0; bans_from_allowed 0; invariant_violations 0; latency p50/p95/p99 94/269/884 us (`decide` only) |
| 10 serve pooled:100 | `venusflytrap eval --mode serve --sources pooled:100` (100 shared sources, hashed by file name, 100 ms synthetic step) | serve | 446 | 15847 | 210 | 67.99% (of 656 scored) | 2.74% | 47.70% | – | – | raw corpus, Rust lenient parser (`venusflytrap eval`), 33,877 files of which 33,875 scored: 2 malicious files were unreadable (`3e/f0/ba59dd0840009f5b678663dbb1bd.black`, `d5/65/2dcdd89317f10d43500014509120.black`: os error 5 Access is denied from this host; the Python parser read them earlier), counted in `read_failures` and not scored (FN would be 375 against the 658 malicious, recall 43.01%); parse_failures 0 (one request line without a leading `/`, `ff/67/62b331a3e94507a5759d1f9bcb8a.black`, is rooted by the parser; without that rule it was the only parse failure); skipped_headers 0; benign_sources 100; benign_sources_banned 80; collateral_fp 15,578 (benign requests blocked in serve that library allowed, i.e. blocked because their pooled source was already banned); bans_from_allowed 0; invariant_violations 0; latency p50/p95/p99 44/179/410 us. This is the cost of per-source banning when many benign clients share a source (NAT, unconfigured trusted proxy): 80 of 100 shared sources get banned within the corpus and then every later request from them is rejected. Reported as measured, nothing tuned |

## Throughput (Task 7, H3)

`Pipeline::decide` (64-shard chain store, no lock held during inspection) versus stateless `Shield::inspect`,
8 threads x 50 requests, 50 distinct source IPs per thread (400 total), release build
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

| Run | replayed | matched_block (403) | matched_allow (200) | proxy_rejected | not_replayable | mismatched |
|---|---|---|---|---|---|---|
| first 1,000 (distinct sources) | 992 | 20 | 971 | 1 | 8 | 0 |

`not_replayable` (8): Transfer-Encoding or Upgrade samples, or requests the lenient parser cannot read after
normalisation. `proxy_rejected` (1): `00/06/005a52981dd324c40488a1a588f9.white` answered 400 by hyper because its
request target holds raw `<` and `>`; the lenient in-process parser percent-encodes them. This is a known
front-end difference, not an engine mismatch. Caveat: the 1,000-sample prefix holds only 16 `.black` samples (20 requests were blocked in total, counting
benign false positives), so the 403 path is exercised far less than the 200 path. A connect failure, a stalled
write with no reply, or a reply without a status line counts as a mismatch, never an abort.

## Final measurement (Task 12)

Release build of the final tree, all outputs in `$EVAL/sp1/final-*.{json,csv}`. Recall is given over the 656
scored malicious files and over all 658 (the two unreadable `.black` files counted as missed).

| Run | Path | TP | FP | FN (656 / 658) | Recall (656 / 658) | Precision | F1 (656 / 658) | FP rate | Latency p50/p95/p99 (us) |
|---|---|---|---|---|---|---|---|---|---|
| final library | lib (raw corpus) | 283 | 269 | 373 / 375 | 43.14% / 43.01% | 51.27% | 0.4685 / 0.4678 | 0.81% | 72 / 210 / 718 |
| final serve distinct | serve | 283 | 269 | 373 / 375 | 43.14% / 43.01% | 51.27% | 0.4685 / 0.4678 | 0.81% | 71 / 208 / 713 |
| final serve pooled:100 | serve | 446 | 15,847 | 210 / 212 | 67.99% / 67.78% | 2.74% | 0.0526 / 0.0526 | 47.70% | 42 / 160 / 368 |
| final bench_http corpus (Python-parsed JSONL) | lib | 283 | 268 | 375 | 43.01% (of 658) | 51.36% | 0.4682 | 0.81% | 68 / 202 / 743 |
| libinjection (Python-parsed JSONL) | baseline | 214 | 93 | 444 | 32.52% | 69.71% | 0.4435 | 0.28% | 15 / 58 / 131 |
| regex baseline (Python-parsed JSONL) | baseline | 127 | 126 | 531 | 19.30% | 50.20% | 0.2788 | 0.38% | 10 / 199 / 1421 |

Serve distinct: block/allow decisions identical to library (10 Challenge-vs-Block label differences from the chain-stage bonus); benign_sources 33,219, benign_sources_banned 72, collateral_fp 0,
bans_from_allowed 0, invariant_violations 0. Serve pooled:100: benign_sources 100, benign_sources_banned 80,
collateral_fp 15,578, bans_from_allowed 0, invariant_violations 0. **Acceptance check "collateral FP <= request-level
FP" FAILS for pooled:100 (15,578 vs 269 library FP; serve FP rate 47.70%).** Cause: one blocked exfiltration
request bans a shared source for 1 h; with 100 shared sources, 80 were banned. Ban-policy redesign is a planned
follow-up; no policy or config changed. Baselines read the Python-parsed JSONL, a different input from the Rust eval.

Mutation (bench_http on `seeds.jsonl` / `mutants.jsonl`): seeds 19/22 (86.36%), mutants 548/660 (83.03%),
retention 96.1%, identical to Task 0. libinjection and regex retention (57% and 54%) are from the original run,
not re-measured.

Throughput (`decide_throughput`, 3 runs, ratio stateless / stateful): 0.185 s / 0.188 s = 0.99; 0.175 s / 0.179 s =
0.98; 0.185 s / 0.184 s = 1.01 (acceptance >= 0.75, met).

### TCP replay

| Run | replayed | matched_block | matched_allow | proxy_rejected | not_replayable | mismatched |
|---|---|---|---|---|---|---|
| first 1,000 (re-run on final tree) | 992 | 20 | 971 | 1 | 8 | 0 |
| full corpus (`--limit 40000`, exit 3) | 33,711 | 550 | 32,207 | 5 | 166 | 949 |

Full-corpus run is NOT clean (949 mismatched). All 20 listed mismatches are `502` on benign samples with
`in_process_block=false`: the proxy made the same Allow decision, then failed to reach the stub upstream (harness
failure, not an engine/proxy disagreement). The other 929 were not individually examined; their cause is inferred, not
established. Likely cause:
ephemeral-port exhaustion on Windows (two `Connection: close` loopback sockets per request; 16,384-port dynamic
range; 8,107 sockets in TIME_WAIT right after the run). A separate fast replay of 24,000 small benign samples
reproduced it (6,437 mismatches, listed ones all 502/Allow, first ~17k clean, dense from `88/*`). The four earliest
mismatches (`09/8a` 573 KB, `11/27` 858 KB, `1b/12` 66 KB, `30/56` 74 KB) are large bodies; the first two reproduce
a 502 in isolation because the stub upstream reads once and closes without draining. `88/58` (1 KB) mismatched in the
full run but passes in a small corpus (load-dependent). proxy_rejected 5:
400 x4 and 413 x1. matched_block 550 shows the block path was exercised on the full corpus. None of the 20 examined mismatches shows a
differing decision; the other 929 were not examined, so full-corpus equivalence is not demonstrated. No engine or
proxy code was changed for this.

## Final review fix wave

Code changes measured here: query keys and cookie names became inspected fields, `Accept-Encoding` is no
longer skipped, and the raw `Cookie` header is also inspected when any segment is not `token=value` (C1,
C2); Recon stages a source only at verdict Monitor or above (F1); the proxy runs the ban fast-track before
reading the body, gives Challenge its own 403 body, keeps every `X-Forwarded-For` line and drops
client-sent `x-venusflytrap-*` headers (I3, I4, I8); the TCP replay buckets mismatches by direction (I6).
Release build; outputs in `$EVAL/sp1/fw-*.{json,csv}`. Deltas are against the Task 12 rows above.

| Run | Path | TP | FP | FN (656 / 658) | Recall (656 / 658) | Precision | F1 (656 / 658) | FP rate | Delta vs Task 12 |
|---|---|---|---|---|---|---|---|---|---|
| fw library | lib (raw corpus) | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% | TP +1, FP +2 |
| fw serve distinct | serve | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% | TP +1, FP +2 |
| fw serve pooled:100 | serve | 446 | 15,848 | 210 / 212 | 67.99% / 67.78% | 2.74% | 0.0526 / 0.0526 | 47.71% | TP 0, FP +1, collateral -1 |
| fw bench_http corpus (Python-parsed JSONL) | lib | 284 | 270 | 374 (of 658) | 43.16% | 51.26% | 0.4686 | 0.81% | TP +1, FP +2 |

Cause of every change (a pre-fix binary built from `eca014d` was run on the same corpus with `--out` and
diffed per request; a throwaway diagnostic, not committed, listed which newly inspected field carried
threat evidence in each request):

- **Query keys account for every verdict and score change.** 735 requests changed score (729 benign, 6
  malicious), all upwards: 668 by +3, 62 by +2, 2 by +4, 2 by +64, 1 by +67. Every one of them carries
  threat evidence on a query-key field. The common case is a key that is not a name at all: analytics
  beacons send a JSON blob or a URL as the whole query string without `=`, so the blob is the key; 721
  benign requests get `shell-meta` Suspicious on such a key (+2 or +3, nearly all still Allow). 61 benign
  requests moved Allow to Monitor (60 `shell-meta`, 1 `sql-keyword` on a key); Monitor is still
  forwarded and does not count as blocked.
- **Three block/allow flips, all Allow to Block, all from query keys.** TP +1:
  `f1/e6/04a2a6bd968eeccacc3492bb9a54.black` (`/?nice%20?%3Cscript%3Ealert(11)%3C/script%3E...=123.txt`, the
  XSS payload is in the key; `script-tag`, `alert-script`). FP +2: `2e/9e/6e45189445311af775b7868122a0.white`
  and `3a/06/14c72ccb93096a235d5717fc261e.white`, analytics beacons whose JSON-blob key contains a logged
  search URL with the text `binary<script is incorrect` (`script-tag` Dangerous); the same text in a value
  would have fired before.
- **Cookie names: no evidence on this corpus.** No cookie name carries threat evidence in any request.
  One malicious request (`e9/fb/0f57b1c282be9e43ab4140bb8844.black`) has a cookie name with `%20/%20`,
  which is not an RFC 6265 token, so its raw `Cookie` header is now inspected as well (`shell-meta`
  Suspicious, score up, verdict unchanged); no benign request has a malformed `Cookie` header.
- **`Accept-Encoding`: no evidence on this corpus.** It is now inspected on every request that carries
  it; no value scored.
- Serve distinct: block/allow decisions identical to library for every request; the same 10
  Challenge-vs-Block label differences (chain-stage bonus) as before; benign_sources 33,219,
  benign_sources_banned 72, collateral_fp 0, bans_from_allowed 0, invariant_violations 0. Pooled:100:
  benign_sources 100, benign_sources_banned 80, collateral_fp 15,577 (of the two new library FPs, `2e/9e` was
  already blocked by its banned pooled source, so it moves from collateral to request-level FP, and `3a/06` is a
  new serve FP; the new library TP `f1/e6` was already blocked by its banned source, so pooled TP is unchanged), bans_from_allowed 0, invariant_violations 0.
  **The acceptance check "collateral FP <= request-level FP" still FAILS for pooled:100 (15,577 vs 271).**
- F1 (Recon gated on verdict) changes nothing measurable here: invariant_violations was already 0.
- The proxy changes (I3, I4, I8) do not affect `decide` verdicts; they are covered by tests only.

Mutation (bench_http): seeds 19/22 (86.36%), mutants 548/660 (83.03%), retention 96.1%; predictions and
scores identical to Task 12 per request (the payloads sit in the value of key `q`).

Latency (us, p50/p95/p99). The first fw runs read library 79/249/744, serve distinct 106/328/891, pooled
47/214/458, bench_http 87/281/852, but the machine was noisy then (a same-session pre-fix serve run read
63/184/663). An interleaved A/B on one machine state, pre-fix binary vs fix-wave binary, two rounds:

| Path | pre-fix round 1 | fix wave round 1 | pre-fix round 2 | fix wave round 2 |
|---|---|---|---|---|
| library (`inspect`) | 64 / 191 / 653 | 72 / 224 / 659 | 63 / 190 / 659 | 70 / 213 / 645 |
| serve distinct (`decide`) | 63 / 187 / 642 | 70 / 217 / 641 | 63 / 187 / 669 | 73 / 233 / 715 |

The fix wave costs about +10% at p50 and +12% to +25% at p95 (more fields per request); p99 is within
run-to-run noise.

Throughput (`decide_throughput`, 3 runs, stateless / stateful): 0.494 / 0.407 s = 1.21; 0.548 / 0.482 s
= 1.14; 0.286 / 0.305 s = 0.94. Acceptance >= 0.75 met in every run. These runs are slower and noisier
than Task 12's (about 0.18 s per pass, ratio 0.98 to 1.01); not investigated further.

### TCP replay, bucketed (I6)

| Run | replayed | matched_block | matched_allow | proxy_rejected | not_replayable | block_vs_proxy_allow | allow_vs_proxy_403 | upstream_5xx | io | other | mismatched |
|---|---|---|---|---|---|---|---|---|---|---|---|
| first 1,000 | 992 | 20 | 971 | 1 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| full corpus (`--limit 40000`, exit 3) | 33,711 | 553 | 32,377 | 5 | 166 | **0** | **0** | 767 | 9 | 0 | 776 |

Versus Task 12's full run (550 / 32,207 / 5 / 166, 949 mismatched, 929 of them unexamined): both
decision-disagreement buckets are 0, so no in-process Block/Challenge was answered 200 and no in-process
Allow/Monitor was answered 403. All 555 in-process blocks are accounted for (553 matched 403, plus
`00/06/005a52981dd324c40488a1a588f9.white` and `ec/98/75af1332f120a05581069320ad6f.black`, Block in
process, refused 400 by hyper for raw `<`/`>` in the target), equal to the serve-distinct blocked count
(284 + 271). `upstream_5xx` 767: every listed example is 502 with in-process Allow; a 502 is only
produced after the proxy has decided to forward, so these are the same decision followed by a stub
upstream failure. The first two listed are the large bodies `09/8a` (573 KB) and `11/27` (858 KB) seen
before; the next nine listed (`29/1a` 69 KB, `2c/5b` 599 B, `3a/e9` 219 KB, `3d/85` 708 B, `6c/cf` 896 B,
`73/08` 733 B, `78/1f` 539 B, `79/a1` 1.5 KB, `7e/14` 1.1 KB) come before the port-exhaustion window and
are unexplained; the last nine listed are from `81/*` onward. `io` 9: all `connect timeout` from the
replay client, in-process Allow, `82/*` to `87/*`; no proxy decision observed. 33,244 sockets were in
`TIME_WAIT` right after the run (16,384-port dynamic range), consistent with loopback port exhaustion as
the cause of the 502s from `81/*` on and the connect timeouts; inferred, not confirmed, and the 747
unlisted 502s were not examined. The run took 3.5 minutes.
proxy_rejected 5: 400 x4, 413 x1 (unchanged). No engine or proxy code was changed for this.

## Ban policy redesign (successor log)

Follow-up to SP1. Spec: `docs/superpowers/specs/2026-10-26-ban-policy-redesign-design.md`. Change: every automatic
ban (honeypot, exfiltration, repeated exploitation) also needs hostile requests to be at least
`chain.ban_policy.min_hostile_share` (new, default 0.5) of the source's requests in the last `within_secs` (600 s,
tallied in 10 buckets). `on_exfiltration_block` now defaults to false, so a single exfiltration block no longer bans;
exfiltration blocks still count toward the 3-in-600 s rule. TTLs and manual bans are unchanged. Library path, scoring,
`event_for`, `Pipeline` and the eval harness are unchanged. Release build, default config (no `--config`); outputs in
the session scratchpad `m/final-*.{json,csv}`.

### Candidates measured before choosing (pooled serve runs, SP1 release build or an uncommitted prototype)

Library FP is 271 in every run; bans_from_allowed and invariant_violations are 0 in every run. "Banned" =
benign_sources_banned. "–" = not run.

| Candidate | pooled:10 collateral | pooled:100 collateral / banned | pooled:1000 collateral | distinct banned |
|---|---|---|---|---|
| SP1 defaults | 31,969 | 15,577 / 80 | 1,723 | 72 |
| first TTL 300 s | – | 5,230 / 80 | – | – |
| first TTL 60 s | – | 1,943 / 80 | – | – |
| no single-exfil ban | 31,678 | 9,366 / 57 | – | – |
| no single-exfil ban, TTL 60 s | – | 898 / 57 | – | – |
| no single-exfil ban, 5 blocks in 600 s | 29,923 | 0 / 1 | 0 | 0 |
| honeypot only | – | 0 / 0 | – | – |
| no bans at all | – | 0 / 0 | – | – |
| hostile share >= 0.05 / 0.10 / 0.25 / 0.5, single-exfil ban kept | – | 7,698 / 46; 1,258 / 4; 327 / 1; 327 / 1 | – | – |
| hostile share >= 0.25, no single-exfil ban | – | 0 / 0 | – | – |
| **hostile share >= 0.5, no single-exfil ban (chosen)** | **0** | **0 / 0** | **8** | **0** |

Shorter TTLs alone stay above 271. A count threshold (5 blocks) passes pooled:100 but not pooled:10. Honeypot-only
passes because the corpus has no honeypot hits, so it measures nothing about honeypot bans. With the single-exfil ban
kept, a pooled source whose first request is an exfiltration block has share 1/1 and is banned (327 collateral).
Keys that add the User-Agent were not built: 33,398 of the 33,875 readable files (98.6%) carry one User-Agent
string (191 distinct), so such a key would barely split the pooled sources.

### Result (shipped defaults)

| Run | Path | TP | FP | FN (656 / 658) | Recall (656 / 658) | Precision | F1 (656 / 658) | FP rate |
|---|---|---|---|---|---|---|---|---|
| library | lib (raw corpus) | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% |
| serve distinct | serve | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% |
| serve pooled:10 | serve | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% |
| serve pooled:100 | serve | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% |
| serve pooled:1000 | serve | 284 | 279 | 372 / 374 | 43.29% / 43.16% | 50.44% | 0.4660 / 0.4652 | 0.84% |

| Run | benign sources | benign sources banned (SP1 -> now) | collateral FP (SP1 -> now) | bans_from_allowed | invariant_violations |
|---|---|---|---|---|---|
| serve distinct | 33,219 | 72 -> 0 | 0 -> 0 | 0 | 0 |
| serve pooled:10 | 10 | 10 -> 0 | 31,969 -> 0 | 0 | 0 |
| serve pooled:100 | 100 | 80 -> 0 | 15,577 -> 0 | 0 | 0 |
| serve pooled:1000 | 1,000 | 107 -> 1 | 1,723 -> 8 | 0 | 0 |

- **The acceptance check "collateral FP <= request-level FP" now passes for pooled:100: 0 against 271.** Pooled:100
  serve makes the same block/allow decision as the library for every request.
- Pooled:1000: one source was banned by its third exploitation block within 10 minutes (the third was the
  malicious `b1/71/3c058c3be65f080c2443252dab2b.black`), with too little benign traffic to dilute it; the 1 h ban then blocked 8
  later benign requests from that source. The ban caught no extra malicious request (serve TP 284 = library TP).
- **Regression, stated plainly: pooled serve TP falls from 446 (SP1) to 284 at pooled:100.** Those 162 extra true
  positives came only from bans rejecting everything a shared source sent after it was banned, at the cost of
  15,577 benign requests. In this corpus no ban now adds a true positive.
- Serve distinct: block/allow decisions identical to library for every request; the same 10 Challenge-vs-Block label
  differences (chain-stage bonus) as SP1; serve verdicts identical to SP1's fix-wave run for every request.
  benign_sources_banned falls from 72 to 0: those were single benign requests that were false positives and were
  banned by the removed single-exfiltration trigger. bans_from_allowed 0, invariant_violations 0.
- Library verdicts are identical to SP1's fix-wave run for all 33,875 scored files (the library path never touches
  the chain). Read failures 2 (the same two files), parse failures 0.
- Mutation (bench_http on `seeds.jsonl` / `mutants.jsonl`): seeds 19/22 (86.36%), mutants 548/660 (83.03%),
  retention 96.1%; label/prediction/score columns identical to SP1's fix-wave outputs per sample.
- What gets worse beyond the numbers (covered by unit tests, not by this corpus): a single exfiltration request from
  a fresh address is blocked but no longer bans it; an attacker who sends at least one benign request per hostile one,
  or who sits behind a busy NAT, is never banned automatically; a honeypot hit on a busy source no longer bans it
  (the corpus has no honeypot hits, so this is unmeasured here).
- Latency: the five runs above ran concurrently on one machine, so their latencies (p50 72 to 74 us, p95 223 to
  227 us, p99 658 to 681 us) are not comparable with SP1's single-run figures and are not published as a result.
