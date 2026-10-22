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

From `venusflytrap bench` on an open, deterministic synthetic corpus (6,000
samples; see [`docs/BENCHMARK.md`](docs/BENCHMARK.md)):

| Engine | Recall (obfuscated) | Precision | FP rate | p95 latency |
|---|---|---|---|---|
| Regex baseline | 17.8% | 100% | 0% | <1 µs |
| Tokenizer baseline | 100% | 85.2% | 34.7% | 5 µs |
| **Venusflytrap (full)** | **96.1%** | **100%** | **0.0%** | **9 µs** |

The regex baseline collapses under encoding/case/comment mutation; the naive
tokenizer recovers recall but is noisy (high FP); the full engine keeps
obfuscated recall high **and** false positives low — because the graph/taint
reachability step separates a formed attack from a coincidental keyword. That is
the whole point of the architecture, shown rather than asserted. (0% FP is this
corpus's measured number, not a guarantee — real traffic will differ.)

## Usage

```bash
# Inspect one request (exit code 2 if blocked)
venusflytrap scan --path "/items" --query "1 union select password from users"

# Reproduce the benchmark
venusflytrap bench --seed 1337 --n 2000 --out docs/BENCHMARK.md

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
- [`docs/BENCHMARK.md`](docs/BENCHMARK.md) — generated results.

## Safety & limits

- `#![forbid(unsafe_code)]`; all decode/graph work is bounded (payload cap,
  decode-depth cap, node cap) and fuzz-tested to never panic or hang.
- This is a **research-grade reference implementation**, not a drop-in
  enterprise WAF. The "AI" detector is a deterministic heuristic by default
  (pluggable via the `AiOracle` trait); threat intel is file-backed/offline.
- Known hard problems it does not magically solve: parser-differential evasion
  (WAFFLED-style) and adversarial mutation (WAF-A-MoLE) — see RESEARCH.md.

## License

Apache-2.0.
