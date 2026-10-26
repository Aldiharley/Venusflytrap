# Venusflytrap: Benchmark Results

All numbers here come from one real labelled HTTP corpus (plus one small mutation set). They are
measured on a single Windows 11 machine with the release build, and nothing is tuned to the corpus after
the fact. The full history, including per-task deltas and regressions, is in
[`eval/RESULTS-SP1.md`](../eval/RESULTS-SP1.md).

The built-in `venusflytrap bench` command is a synthetic smoke test. It checks that nothing is broken
and it is not a result; its output goes to `target/bench/` and is not published here.

## 1. Corpus and method

- **Corpus:** blazehttp test cases, commit `afc88a94`: 33,877 raw HTTP requests, 33,219 benign
  (`.white`) and 658 malicious (`.black`).
- **Two files could not be read** on the measuring machine (OS error 5, access denied):
  `3e/f0/ba59dd0840009f5b678663dbb1bd.black` and `d5/65/2dcdd89317f10d43500014509120.black`. They are
  counted as `read_failures` and not scored. Recall is therefore stated both ways below: over the
  **656 scored** malicious files, and over **all 658** counting the two as missed. Precision, FP and
  FP rate are unaffected.
- **Library path:** stateless `Shield::inspect` on each request. The Rust eval parses the raw files
  with a lenient parser and keeps the raw `Cookie` header.
- **Serve path:** `Pipeline::decide`, the function the proxy calls for every request. It is stateful
  (attack chains, bans, honeypot), reads the raw `Cookie` header, and runs on a synthetic clock that
  advances 100 ms per request. Two source models:
  - `distinct`: every request has its own source address, so a ban can never affect a later request.
  - `pooled:100`: requests are hashed by file name onto 100 shared source addresses. This models many
    benign clients behind a NAT or an unconfigured trusted proxy.
- **TCP replay:** the real proxy (`serve_listener`, enforcement on) on loopback in front of a stub
  upstream. The replay was run twice: over the first 1,000 samples (sorted by path) and over the whole corpus (33,877 samples). Every replayable sample is sent over a socket, and the proxy's answer
  (403 or 200) is compared with the in-process `Pipeline::decide` run on an identically configured
  pipeline.
- **Verdict mapping:** Block and Challenge count as blocked; Allow and Monitor count as allowed.
- **Baselines:** libinjection (the reference C library, loaded as a DLL) and a regex signature
  baseline, run by `eval/baselines.py`. **They read the Python-parsed JSONL of the same corpus, not the
  raw files the Rust eval reads**, and all 658 malicious files were readable there. The two inputs
  differ slightly (header and body decoding), so the baseline rows are close to, but not exactly,
  like-for-like with the Venusflytrap rows.

## 2. Library vs serve

Recall, FN and F1 for Venusflytrap are given over 656 scored malicious files / over all 658 (two
unreadable files counted as missed). The baselines read all 658 and have one figure.

| Engine | TP | FP | FN (656 / 658) | Recall (656 / 658) | Precision | F1 (656 / 658) | FP rate |
|---|---|---|---|---|---|---|---|
| Venusflytrap, library | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% |
| Venusflytrap, serve, distinct | 284 | 271 | 372 / 374 | 43.29% / 43.16% | 51.17% | 0.4690 / 0.4683 | 0.82% |
| Venusflytrap, serve, pooled:100 | 446 | 15,848 | 210 / 212 | 67.99% / 67.78% | 2.74% | 0.0526 / 0.0526 | 47.71% |
| libinjection (Python-parsed input) | 214 | 93 | 444 | 32.52% | 69.71% | 0.4435 | 0.28% |
| Regex baseline (Python-parsed input) | 127 | 126 | 531 | 19.30% | 50.20% | 0.2788 | 0.38% |

These rows are from the tree after the final-review fix wave, which made query keys, cookie names and
`Accept-Encoding` inspected fields (they were forwarded but not inspected before). Against the previous
measurement (283 TP / 269 FP library) that added one true positive and two false positives, all three
from query keys; details in `eval/RESULTS-SP1.md`, "Final review fix wave".

How to read this:

- The engine detects about 43% of this corpus's malicious requests, and about half of what it blocks is
  benign. That is a weak result in absolute terms. It finds more attacks than libinjection (284 vs 214
  true positives) but raises more false positives (271 vs 93), so libinjection has the higher precision.
- **Serve-distinct makes the same block/allow decision as library**, request for request. With one
  source per request, state never changes a block/allow decision, which is the expected check. The
  verdict labels are not all identical: 10 malicious requests are Challenge in the library and Block in
  serve, because the first exploitation event from a source adds the chain-stage bonus.
- **Serve-pooled:100 is not a better detector.** Its extra true positives (446 vs 284) and its 47.71%
  FP rate both come from bans: once a shared source is banned, every later request from it is rejected,
  malicious or benign.

## 3. Ban effects

| Run | benign sources | benign sources banned | collateral FP | bans from allowed requests | invariant violations |
|---|---|---|---|---|---|
| serve, distinct | 33,219 | 72 | 0 | 0 | 0 |
| serve, pooled:100 | 100 | 80 | 15,577 | 0 | 0 |

- `benign_sources_banned`: sources that sent at least one benign request and were banned. In the
  distinct run these are 72 sources whose own benign request was blocked (a false positive) and then
  banned.
- `collateral_fp`: benign requests blocked in the serve run that the library path allowed, i.e. blocked
  only because their shared source was already banned.
- `bans_from_allowed` is 0: no request that was allowed ever caused a ban.
- `invariant_violations` is 0: every Allow in the corpus is recorded as benign in the attack chain.

**Failed acceptance check.** The SP1 check "collateral FP is no larger than request-level FP" **fails**
for pooled:100: collateral FP is 15,577 against 271 request-level false positives on the library path.
The cause is that a single blocked exfiltration request bans a shared source for one hour, and with 100
shared sources, 80 were banned. Redesigning the ban policy is a planned follow-up; this run changes no
policy or configuration.

## 4. Mutation robustness

22 hand-written seed attacks (14 SQL injection, 8 XSS) are each mutated 30 times into 660 variants
(`eval/mutate.py`, seed 1337; each variant applies 1 to 4 random mutations from: case swap, whitespace
substitution, comment injection, URL-encoding, operator swap, logic suffix). This set has no benign
traffic, so only recall is meaningful. Retention is mutant recall divided by seed recall.

| Engine | Seeds detected | Mutants detected | Retention |
|---|---|---|---|
| Venusflytrap, final tree | 19 / 22 (86.36%) | 548 / 660 (83.03%) | 96.1% |
| Venusflytrap, start of SP1 (Task 0) | 19 / 22 (86.36%) | 548 / 660 (83.03%) | 96.1% |
| libinjection (original run) | not re-measured | not re-measured | 57% |
| Regex baseline (original run) | not re-measured | not re-measured | 54% |

The libinjection and regex retentions are carried over from the original measurement run and were not
re-run for this document. SP1, including the final-review fix wave, left Venusflytrap's mutation
robustness unchanged (the mutation set carries its payloads in query values, which were already inspected). With 22 seeds the seed
recall is a coarse number: one seed is 4.5 points.

## 5. Latency

Per-request latency in microseconds, release build, one thread, on the full corpus; raw-file parsing
is excluded. The rows do not time the same call, so they are not strictly like-for-like: the library
row times `Shield::inspect` only, while the serve rows time `Pipeline::decide`, which adds adapting
the hyper request (`adapt::from_parts`), the ban lookup, and the chain `observe`/`finalize` around the
same inspection.

| Path | p50 | p95 | p99 |
|---|---|---|---|
| Library (`Shield::inspect`), run 1 / run 2 | 72 / 70 | 224 / 213 | 659 / 645 |
| Serve, distinct (`Pipeline::decide`), run 1 / run 2 | 70 / 73 | 217 / 233 | 641 / 715 |
| Serve, pooled:100 (not comparable) | 47 | 214 | 458 |

The library and serve-distinct rows come from an A/B run on one machine state, interleaving the binary
from before the final-review fix wave with the current one. The earlier binary measured 64 / 191 / 653
and 63 / 190 / 659 (library) and 63 / 187 / 642 and 63 / 187 / 669 (serve distinct) in the same session,
so the fix wave costs about 10% at p50 and 12 to 25% at p95: query keys, cookie names and
`Accept-Encoding` are now inspected fields. The pooled row is a single run; it is lower only because
requests from banned sources are rejected before inspection.

**Throughput.** `Pipeline::decide` (64-shard chain store, no lock held during inspection) against
stateless `Shield::inspect`: 8 threads x 50 requests, each request from its own source (50 distinct
sources per thread, 400 in total), a request with a ~64 KB query, after one discarded warm-up round of
each mode. Ratio stateless / stateful over three runs of the current tree: 1.21, 1.14 and 0.94
(stateless 0.494, 0.548, 0.286 s; stateful 0.407, 0.482, 0.305 s). These runs were noisier and slower in
absolute terms than the earlier ones (ratios 0.99, 0.98, 1.01 at about 0.18 s per pass); every run is
above the 0.75 acceptance floor, and no run shows the stateful path slower than 0.94x stateless.

## 6. TCP replay equivalence

Every replayed sample's proxy answer is compared with the in-process decision: 403 must equal
Block/Challenge and 200 must equal Allow/Monitor. A 400, 413, 431 or 501 from the proxy's HTTP front end
is counted as `proxy_rejected`, not as a mismatch. Each sample uses its own source (`X-Forwarded-For`
from a trusted loopback peer), `Connection: close`, and an exact `Content-Length`. Mismatches are
counted by direction:

- `block_vs_proxy_allow`: in-process Block/Challenge, proxy 200. A request the engine stops reached
  the upstream. This is the bucket that matters for safety.
- `allow_vs_proxy_403`: in-process Allow/Monitor, proxy 403.
- `upstream_5xx`: in-process Allow/Monitor, proxy 502/504. The proxy only answers 502/504 after it has
  decided to forward (a stopped request gets its 403 first), so these are the same Allow decision
  followed by a failure to reach the stub upstream.
- `io`: the replay client could not connect, write or read a status; no proxy decision was observed.
- `other`: anything else.

| Run | replayed | matched_block (403) | matched_allow (200) | proxy_rejected | not_replayable | block_vs_proxy_allow | allow_vs_proxy_403 | upstream_5xx | io | other |
|---|---|---|---|---|---|---|---|---|---|---|
| First 1,000 samples | 992 | 20 | 971 | 1 | 8 | **0** | 0 | 0 | 0 | 0 |
| Full corpus (33,877 samples) | 33,711 | 553 | 32,377 | 5 | 166 | **0** | **0** | 767 | 9 | 0 |

**No request that the engine stops was let through, and no observed allowed request was refused.** Both
decision-disagreement buckets are 0 over the full corpus. Every in-process Block/Challenge is accounted
for: 553 answered 403 and 2 more (`00/06/...`, `ec/98/...`) were refused with 400 by the HTTP front end
before inspection; 555 is also the serve-distinct blocked count (284 TP + 271 FP).

The run is still not clean in the harness sense: 776 samples did not produce a 200 that could be
compared directly.

- **767 `upstream_5xx`**, all 502 with in-process Allow in the 20 listed examples. As argued above, a
  502 means the proxy had already decided to forward. Two of the listed ones are the large bodies
  (`09/8a/...` 573 KB, `11/27/...` 858 KB) that reproduced a 502 in isolation in the earlier
  investigation (the stub upstream reads once and closes without draining the body). Nine more listed
  ones come before the port-exhaustion window and are **unexplained**: `29/1a` (69 KB), `2c/5b`
  (599 B), `3a/e9` (219 KB), `3d/85` (708 B), `6c/cf` (896 B), `73/08` (733 B), `78/1f` (539 B),
  `79/a1` (1.5 KB) and `7e/14` (1.1 KB); most are small, so neither cause above covers them. The last
  nine listed are from `81/*` onwards, where loopback port exhaustion is the likely cause: 33,244 sockets
  were in `TIME_WAIT` right after the run, against a 16,384-port Windows dynamic range. That cause is
  inferred, not confirmed by capturing the upstream connect error, and the unlisted 747 were not examined.
- **9 `io`**, all `connect timeout` from the replay client to the proxy, in-process Allow, listed from
  `82/*` to `87/*`: the same port-exhaustion window on the client side. No proxy decision was observed
  for these 9.

So block/allow equivalence over sockets is shown for every in-process block and for 32,377 + 767
allowed requests; it is not observed for the 9 `io` samples or the 5 front-end rejections. The previous
run of this replay (before the fix wave, without direction buckets) had 949 unexamined mismatches; the
bucketed re-run replaces it. Making the harness immune to port exhaustion and large-body resets is not
part of this document's scope.

## 7. What this does not show

- **One corpus.** Every detection number comes from the same labelled corpus. Quality on other traffic
  is unmeasured, and the false-positive rate on real production traffic will differ.
- **Random mutation is a lower bound.** The mutation test applies random formatting and encoding
  changes to 22 seeds; it is not an adaptive adversary searching for evasions.
- **Attack families not modelled:** XXE, SSRF, deserialization and template injection have no dedicated
  detectors, so their detection here is incidental at best.
- **Baselines read different input** than the Rust eval (Python-parsed JSONL vs raw files).
- **Two malicious files are unscored** because they were unreadable on the measuring machine.
- **Pooled sources are a model.** Real shared-source behaviour depends on the deployment's
  trusted-proxy configuration, which this benchmark does not vary.

**Known open fail-opens and uninspected input.** The current tree forwards these to the upstream
without inspecting them. Read every "inspected" claim elsewhere with this list:

- **Field content past `shield.max_payload`** (65,536 characters per field by default). The normalizer
  truncates each field silently, so the rest of a long field is forwarded uninspected. In practice this
  is a request body: the proxy accepts bodies up to `limits.max_body` (1 MiB). Owned by the recall-lift
  effort (C3, fail-closed truncation).
- **Tokens past the graph cap** (4,096 per field): the taint graph is built from the first 4,096 tokens
  only. Owned by recall-lift (C2).
- **One-layer percent-decode failure**: a percent-encoded layer whose decoded bytes are not valid UTF-8
  is not peeled, so that field is analysed with the layer still encoded. Owned by recall-lift (H1).
- **`Content-Length`** is forwarded but not inspected (the HTTP front end has already validated it as a
  length). **`Connection`** is not inspected; it is hop-by-hop and never forwarded.
- A raw `Cookie` header whose every segment is `token=value` is inspected through its parsed cookie
  names and values rather than a second time as a header. Any other `Cookie` header is inspected both
  ways.

**Ban storage (implementation note).** Bans are kept in their own map inside each of the 64 chain
shards (separate capacity `chain.ban_policy.max_bans`, never evicted by the source LRU), not in a
separate `BanStore` as the SP1 design sketched. This is an intentional simplification. A banned source is
answered from the request head (`Pipeline::fast_track`) before its body is read.
