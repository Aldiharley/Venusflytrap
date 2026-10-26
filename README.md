# Venusflytrap 🪰

A semantic, **taint-graph** web-application-firewall engine with a honeypot and
cross-request attack-chain inference — written in Rust, with **no unsafe code**.

The thesis: don't guess *what a payload looks like* (regex signatures that break
on encoding, or AST parsers that fail open on malformed input) — reason about
*what it can do* by normalizing the input, building a token graph, and checking
whether attacker-controlled data reaches a dangerous construct.

> **Honesty note.** Every design claim is grounded in published work in
> [`docs/RESEARCH.md`](docs/RESEARCH.md), and any headline number is treated as a
> *target to measure*, not a result to assume. In particular, Venusflytrap does
> **not** claim "zero false positives" as a property — it reports the measured
> false-positive count on a stated corpus.

## Pipeline

```
request → normalize → token-graph taint → detectors → four-valued lattice → score/verdict
              │             │                 │              │
         14-layer      source→sink        graph/taint    Belnap logic:
         decode +      reachability       signature      None/Safe/
         UTS#39        (mutation-         intent/recon   Suspicious/
         confusables   robust)            api-safety     Dangerous
         folding                          AI (pluggable) + arbitration
                                                              │
                          honeypot ── intel ── chain (kill-chain stages) ──┘
```

## Measured results

Measured on a real labelled corpus (33,877 HTTP requests: 33,219 benign, 658 malicious), through both the
stateless library path and the stateful serve path that the proxy runs. Recall is over the 656 malicious
files that were readable on the measuring machine (43.77% if the two unreadable files count as missed).
Full method, ban effects, mutation robustness, latency and limits are in
[`docs/BENCHMARK.md`](docs/BENCHMARK.md). That includes the shared-source ban check, which failed under
the first ban policy and passes after the ban-policy redesign.

| Engine | TP | FP | Recall | Precision | FP rate |
|---|---|---|---|---|---|
| Venusflytrap, library | 288 | 278 | 43.90% | 50.88% | 0.84% |
| Venusflytrap, serve (distinct sources) | 288 | 278 | 43.90% | 50.88% | 0.84% |
| Venusflytrap, serve (100 shared sources) | 288 | 278 | 43.90% | 50.88% | 0.84% |
| libinjection | 214 | 93 | 32.52% | 69.71% | 0.28% |

These are modest numbers and they are reported as measured. The baseline reads a slightly different
parse of the same corpus. `venusflytrap bench` is a synthetic smoke test, not a result.

## Usage

```bash
# Inspect one request (exit code 2 if blocked)
venusflytrap scan --path "/items" --query "1 union select password from users"

# Synthetic smoke test (writes target/bench/BENCHMARK-synthetic.md; not a result)
venusflytrap bench --seed 1337 --n 2000

# Real-corpus evaluation (library path, or serve path through Pipeline::decide)
venusflytrap eval --corpus path/to/testcases --mode library
venusflytrap eval --corpus path/to/testcases --mode serve --sources pooled:100

# Reverse proxy in front of a local app (observation mode with --monitor-only)
venusflytrap serve --bind 127.0.0.1:8080 --upstream http://127.0.0.1:3000 --audit audit.jsonl
```

As a library:

```rust
use vft_core::{Shield, Config, Request, Verdict};

let shield = Shield::new(Config::default());
let mut req = Request::get("/items");
req.query.push(("id".into(), "1 union select password from users".into()));
assert_eq!(shield.inspect(&req).verdict, Verdict::Block);
```

## Workspace

- `crates/vft-core` — the engine (normalize, graph/taint, lattice, detectors,
  honeypot, chain, intel). No I/O, no network, deterministic.
- `crates/vft-proxy` — hyper reverse proxy, decision headers, JSONL audit log.
- `crates/vft-cli` — `scan` / `bench` / `serve` plus the benchmark corpus and
  baselines.

## Documents

- [`docs/RESEARCH.md`](docs/RESEARCH.md) — claim-by-claim feasibility review.
- [`docs/PRD.md`](docs/PRD.md) — requirements and non-goals.
- [`docs/TECH_SPEC.md`](docs/TECH_SPEC.md) — architecture and data model.
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — build phases.
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md) — real-corpus results, library and serve side by side.

## Safety & limits

- `#![forbid(unsafe_code)]`; all decode/graph work is bounded (payload cap,
  decode-depth cap, node cap) and fuzz-tested to never panic or hang.
- This is a **research-grade reference implementation**, not a drop-in
  enterprise WAF. The "AI" detector is a deterministic heuristic by default
  (pluggable via the `AiOracle` trait); threat intel is file-backed/offline.
- Known hard problems it does not magically solve: parser-differential evasion
  (WAFFLED-style) and adversarial mutation (WAF-A-MoLE) — see RESEARCH.md.
- **Known open fail-opens (forwarded uninspected today):** field content past
  `shield.max_payload` (65,536 characters per field; in practice the rest of a
  request body up to the 1 MiB body limit), tokens past the 4,096-token graph
  cap, and a percent-encoded layer that does not decode to valid UTF-8 (left
  encoded). Fixes are planned. The `Content-Length` header is forwarded without
  inspection (it is validated as a length); `Connection` is not inspected and
  never forwarded. Details: [`docs/BENCHMARK.md`](docs/BENCHMARK.md) section 7.

## License

Apache-2.0.
