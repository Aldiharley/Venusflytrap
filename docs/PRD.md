# Venusflytrap — Product Requirements Document

*A semantic, taint-graph WAF + honeypot engine in Rust — an open, measurable
engine that reasons about what a payload can do. Date: 2026-10-22*

## 1. Problem
Signature/regex WAFs collapse under encoding, case, comment and fragmentation
mutations; naive AST parsers fail open on malformed input. Defenders need an
engine that reasons about **what a payload can do** (does tainted input reach a
dangerous sink?) rather than what it textually looks like, and that is **honest
about its false-positive rate** instead of asserting perfection.

## 2. Goals
- **G1** Detect SQLi / XSS / command-injection / path-traversal / SSRF-ish and
  scanner/recon probes via normalization + token-graph taint reachability.
- **G2** Be substantially more mutation-robust than a regex baseline and at least
  competitive with a tokenizer baseline, measured on an open corpus.
- **G3** Arbitrate multiple detectors through a four-valued evidence lattice;
  emit a calibrated 0–100 score and a verdict (ALLOW/MONITOR/CHALLENGE/BLOCK).
- **G4** Provide deception: honeypot path/response signaling and cross-request
  attack-chain (kill-chain stage) inference with per-IP state.
- **G5** Ship reproducible benchmarks with a full confusion matrix and latency
  percentiles — no unverifiable headline numbers.
- **G6** Usable three ways: Rust library, CLI (`venusflytrap scan`), and a
  reverse-proxy mode.

## 3. Non-goals (v1)
- Not a drop-in enterprise WAF / not a SafeLine replacement.
- No trained ML model shipped; the "AI" detector is a pluggable **trait** with a
  deterministic heuristic default (so results are reproducible and offline).
- No live external threat-intel fetching by default (feeds are file-backed and
  optional; network fetch is opt-in and out of v1 scope).
- Not a TLS terminator; proxy mode is plain HTTP for local/eval use.

## 4. Users
- Dennis (operator/researcher): runs the benchmark, tunes weights, embeds the lib.
- Downstream dev: puts proxy mode in front of a local app to observe verdicts.

## 5. Functional requirements
- **FR1 Normalizer**: iterative decode to fixpoint (URL, HTML entity,
  unicode-escape, base64-looking, mixed) with a hard depth cap; Unicode NFKC +
  UTS#39 confusable skeleton folding; full-width→ASCII; comment/whitespace
  canonicalization. Records how many layers were peeled and flags "deep nesting"
  as a signal.
- **FR2 Token-graph taint engine**: tokenize normalized payload; build a graph
  (adjacency + typed edges); mark tainted sources (the raw request field) and
  dangerous sinks (SQL/HTML/shell/path constructs); report reachability + the
  matched structural pattern (e.g. tautology, union-select, comment-terminator,
  stacked query, event-handler XSS, `;`/`|`/`$()` command chaining, `../`
  traversal).
- **FR3 Detectors** (each returns a four-valued evidence verdict + weight):
  graph/taint, structural-signature, intent/behavior (path, method, empty-payload
  recon), API-safety, and a pluggable AI trait (heuristic default).
- **FR4 Arbitration (lattice)**: combine detector evidence in Belnap's knowledge
  order; resolve conflict (one says safe, another dangerous) by configured weight
  arbitration; produce score ∈ [0,100] and verdict band.
- **FR5 Honeypot**: match configured decoy paths; empty-payload probing of
  sensitive paths raises intent score; honeypot hits emit a high-confidence
  signal and are recorded.
- **FR6 Chain inference**: per-source (IP) sliding-window state machine mapping
  events to stages (recon → enumeration → exploitation → exfiltration); escalate
  verdict/score when stages advance; support permanent ban decision.
- **FR7 Threat intel (file-backed)**: IP/ASN allow/deny lists, scanner/C2 UA
  fingerprints, known-exploit fingerprints; contribute evidence, never sole basis
  for block unless deny-listed.
- **FR8 Config**: YAML files mirroring the article (`shield`, `scoring`, `chain`,
  `honeypot`, `audit`) with sane built-in defaults so it runs with zero config.
- **FR9 Interfaces**: library API `Shield::inspect(&Request) -> Judgment`; CLI;
  reverse proxy with `X-Venusflytrap-*` decision headers + JSONL audit log.
- **FR10 Audit/log**: structured JSONL per decision (scores per engine, verdict,
  matched patterns, chain stage) — the format shown in the article's "battle log."

## 6. Non-functional requirements
- **NFR1 Performance**: p95 inspection latency < 1 ms on typical (<4 KB) payloads
  on a modern laptop core; measured and reported (article claims 0.38 ms — we
  verify).
- **NFR2 Safety/DoS**: all decode/graph work bounded (payload size cap, decode
  depth cap, node/edge caps, time budget) — malformed input must never hang or
  OOM; never panic on attacker input (fuzz-checked).
- **NFR3 Determinism**: no network, no clock-dependent logic in the detection
  path; same input → same judgment.
- **NFR4 No dependencies bloat**: small, audited crate set; `#![forbid(unsafe_code)]`.
- **NFR5 Honesty**: benchmark output always includes FP count and rate.

## 7. Success metrics (to be earned by the benchmark, not asserted)
- Detection (recall) on obfuscated attack set **> 70%** and strictly **>>** regex
  baseline under mutation.
- False-positive rate on benign corpus **< 1%** (report the actual number; do not
  claim zero).
- p95 latency **< 1 ms** on the eval corpus.
- Zero panics across the fuzz/property suite.

## 8. Risks & mitigations
| Risk | Mitigation |
|---|---|
| Parser differential (WAFFLED-style) | Normalize-first, canonical re-serialize; document that proxy must match backend parsing |
| Adversarial mutation (WAF-A-MoLE) | Graph/taint over tokens, not literals; include mutated samples in corpus; treat robustness as measured, not absolute |
| FP honesty | Benchmark forces confusion matrix; "zero FP" explicitly rejected as a goal |
| DoS via decode bombs | Hard caps + time budget + fuzzing |
| Overclaiming vs article | All numbers reproduced locally; RESEARCH.md states what is unverifiable |

## 9. Acceptance
`cargo test` green, `cargo clippy -D warnings` clean, `venusflytrap bench`
produces `docs/BENCHMARK.md` with a confusion matrix + latency table, and proxy
mode returns correct decision headers against a local target.
