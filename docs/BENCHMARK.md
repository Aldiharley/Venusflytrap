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
| Venusflytrap, library | 283 | 269 | 373 / 375 | 43.14% / 43.01% | 51.27% | 0.4685 / 0.4678 | 0.81% |
| Venusflytrap, serve, distinct | 283 | 269 | 373 / 375 | 43.14% / 43.01% | 51.27% | 0.4685 / 0.4678 | 0.81% |
| Venusflytrap, serve, pooled:100 | 446 | 15,847 | 210 / 212 | 67.99% / 67.78% | 2.74% | 0.0526 / 0.0526 | 47.70% |
| libinjection (Python-parsed input) | 214 | 93 | 444 | 32.52% | 69.71% | 0.4435 | 0.28% |
| Regex baseline (Python-parsed input) | 127 | 126 | 531 | 19.30% | 50.20% | 0.2788 | 0.38% |

How to read this:

- The engine detects about 43% of this corpus's malicious requests, and about half of what it blocks is
  benign. That is a weak result in absolute terms. It finds more attacks than libinjection (283 vs 214
  true positives) but raises more false positives (269 vs 93), so libinjection has the higher precision.
- **Serve-distinct equals library**, request for request. With one source per request, state never
  changes a verdict, which is the expected check.
- **Serve-pooled:100 is not a better detector.** Its extra true positives (446 vs 283) and its 47.70%
  FP rate both come from bans: once a shared source is banned, every later request from it is rejected,
  malicious or benign.

## 3. Ban effects

| Run | benign sources | benign sources banned | collateral FP | bans from allowed requests | invariant violations |
|---|---|---|---|---|---|
| serve, distinct | 33,219 | 72 | 0 | 0 | 0 |
| serve, pooled:100 | 100 | 80 | 15,578 | 0 | 0 |

- `benign_sources_banned`: sources that sent at least one benign request and were banned. In the
  distinct run these are 72 sources whose own benign request was blocked (a false positive) and then
  banned.
- `collateral_fp`: benign requests blocked in the serve run that the library path allowed, i.e. blocked
  only because their shared source was already banned.
- `bans_from_allowed` is 0: no request that was allowed ever caused a ban.
- `invariant_violations` is 0: every Allow in the corpus is recorded as benign in the attack chain.

**Failed acceptance check.** The SP1 check "collateral FP is no larger than request-level FP" **fails**
for pooled:100: collateral FP is 15,578 against 269 request-level false positives on the library path.
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
re-run for this document. SP1 left Venusflytrap's mutation robustness unchanged. With 22 seeds the seed
recall is a coarse number: one seed is 4.5 points.

## 5. Latency

Per-request latency of the detection call only (parsing excluded), microseconds, release build, one
thread, on the full corpus.

| Path | p50 | p95 | p99 |
|---|---|---|---|
| Library (`Shield::inspect`) | 72 | 210 | 718 |
| Serve, distinct (`Pipeline::decide`) | 71 | 208 | 713 |
| Serve, pooled:100 (not comparable) | 42 | 160 | 368 |

The pooled row is lower only because requests from banned sources are rejected before inspection.

**Throughput.** `Pipeline::decide` (64-shard chain store, no lock held during inspection) against
stateless `Shield::inspect`: 8 threads x 50 requests, each request from its own source (50 distinct sources per thread, 400 in
total), a request with a ~64 KB query, after one discarded warm-up round of each mode. Ratio stateless / stateful over three runs of the final tree: 0.99, 0.98 and 1.01
(stateless 0.185, 0.175, 0.185 s; stateful 0.188, 0.179, 0.184 s). The stateful path runs at parity
with the stateless one; the acceptance floor was 0.75.

## 6. TCP replay equivalence

Every replayed sample's proxy answer is compared with the in-process decision: 403 must equal
Block/Challenge and 200 must equal Allow/Monitor. A 400, 413, 431 or 501 from the proxy's HTTP front end
is counted as `proxy_rejected`, not as a mismatch. Each sample uses its own source (`X-Forwarded-For`
from a trusted loopback peer), `Connection: close`, and an exact `Content-Length`.

| Run | replayed | matched_block (403) | matched_allow (200) | proxy_rejected | not_replayable | mismatched |
|---|---|---|---|---|---|---|
| First 1,000 samples | 992 | 20 | 971 | 1 | 8 | **0** |
| Full corpus (33,877 samples) | 33,711 | 550 | 32,207 | 5 | 166 | **949** |

**The full-corpus run is not clean: 949 samples mismatched.** The 20 mismatches the tool lists are all
`502` responses on benign samples that the in-process decision also allowed (`in_process_block=false`).
For those 20, the proxy reached the same Allow decision and then failed to reach the stub upstream: a
failure of the test harness, not a disagreement between the proxy and the engine. Only the first 20
mismatches are listed by the tool. The other 929 were not individually examined, and their cause
(ephemeral-port exhaustion and undrained stub bodies, below) is inferred from the 20 listed ones and from
the reproduction below, not established. What was observed:

- Apart from the large-body ones below, the failures start roughly 17,000 samples into the run and are
  dense from there (the next listed mismatch is `88/58`, then a run of `89/*` samples). A separate replay
  of 24,000 small benign samples at full speed reproduced the pattern: mismatches began at the same
  point in the corpus (first listed `81/d4`, `86/ca`, `87/be`, then dense from `88/*`), all listed ones
  `502` with in-process Allow, 6,437 in total.
- 8,107 sockets were still in `TIME_WAIT` right after the full run, and the Windows dynamic port range is
  16,384 ports. Two loopback sockets per request (client to proxy, proxy to upstream) with
  `Connection: close` make ephemeral-port exhaustion the likely cause. This is inferred from that
  evidence; it was not confirmed by capturing the connect error.
- The four earliest mismatches (`09/8a/...` 573 KB, `11/27/...` 858 KB, `1b/12/...` 66 KB,
  `30/56/...` 74 KB) are larger request bodies; the first two reproduce a 502 in isolation. The stub
  upstream reads once and closes without draining the body, which probably resets the connection while the proxy
  is still sending it. That is also a harness limitation, and it is a separate cause from the port
  exhaustion.
- Samples such as `88/58/...` (1 KB) that mismatched in the full run pass when replayed in a small
  corpus, so those failures depend on load, not on request content.

`matched_block` 550 shows the block path was exercised on the whole corpus (the 1,000-sample prefix holds
only 20 blocked requests). Among the 20 examined mismatches, none shows the proxy and the engine deciding
differently. The other 929 were not examined, so this run does not demonstrate full-corpus equivalence. Making the replay immune to port exhaustion and large-body resets is not part of this
document's scope.

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
