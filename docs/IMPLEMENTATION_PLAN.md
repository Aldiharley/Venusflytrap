# Venusflytrap — Implementation Plan

*Date: 2026-10-22. Execute top to bottom; each phase ends green
(`cargo test` + `cargo clippy -D warnings`).*

## Phase 0 — Scaffold
- [ ] Workspace `Cargo.toml`; crates `vft-core`, `vft-cli`, `vft-proxy`.
- [ ] `#![forbid(unsafe_code)]`, pinned deps, `.gitignore` (`/target`).
- [ ] `request.rs`, `judgment.rs`, `config.rs` (+ `Default`), error types.

## Phase 1 — Normalizer (FR1)
- [ ] `decode_fixpoint` (URL/entity/`\x\u`/base64) with depth cap + layer count.
- [ ] `fold_unicode` (NFKC, full-width fold, confusable skeleton subset table,
      mixed-script flag).
- [ ] `canonicalize_ws_comments` (+ `/*! */` flagging).
- [ ] Tests: encoded `UNION SELECT`, full-width, Cyrillic homoglyph, nested
      double-encode, decode-bomb bounded.

## Phase 2 — Token graph + taint (FR2)
- [ ] Multi-grammar `tokenize`.
- [ ] `Graph` build with node/edge caps + truncation flag.
- [ ] Sink detectors (SQL tautology/union/stacked/comment-term, XSS
      tag+handler+proto, shell meta/subst, path `../`).
- [ ] BFS reachability source→sink → `Reachable{family,pattern}`.
- [ ] Tests: each family positive; benign lookalikes negative.

## Phase 3 — Detectors + lattice + score (FR3/FR4)
- [ ] `FourValued` + knowledge-order join + conflict surface (`lattice.rs`).
- [ ] Detectors: graph/taint, signature, intent (CRS restricted-files set),
      api-safety, `AiOracle` trait + `HeuristicOracle`.
- [ ] `arbitrate` → score+verdict with `scoring.yaml` weights/bands; hard-pin
      rules (deny-list, honeypot).
- [ ] Tests: conflict case (AI safe vs taint dangerous → Block), band edges.

## Phase 4 — Honeypot, chain, intel (FR5/FR6/FR7)
- [ ] `honeypot.rs` decoy/sensitive-path + empty-payload rule.
- [ ] `chain.rs` per-IP windowed stage machine + ban decision (bounded LRU).
- [ ] `intel.rs` file-backed + embedded-default lists/fingerprints.
- [ ] `shield.rs` orchestrator wiring all engines; `inspect` + `inspect_stateful`.
- [ ] Tests: honeypot hit → Block; recon→exploit escalation; deny-list pin.

## Phase 5 — Config + data files (FR8)
- [ ] `config/*.yaml` mirroring article; loader falls back to embedded defaults.
- [ ] `fingerprints/*`, `threat_intel/*` sample files.
- [ ] Test: zero-config run == embedded-default run.

## Phase 6 — CLI + proxy (FR9/FR10)
- [ ] `vft-cli`: `scan` (stdin/JSON), `serve`, `bench`.
- [ ] `vft-proxy`: hyper service, verdict→action, decision headers, JSONL audit.
- [ ] Smoke test: proxy in front of a tiny local echo upstream; blocked vs allowed.

## Phase 7 — Corpus + benchmark (G5)
- [ ] `corpus` generator: 100k-scale is optional; default eval set a few k
      benign + attack + obfuscated (documented, deterministic seed). Make size a
      flag so the article's 200k run is reproducible on demand.
- [ ] `bench` runs regex/tokenizer/full; writes `docs/BENCHMARK.md` (confusion
      matrix + latency p50/p95/p99).

## Phase 8 — Verify + harden
- [ ] `proptest` no-panic/termination; `criterion` inspect micro-bench.
- [ ] Full `cargo test` + `cargo clippy --all-targets -- -D warnings`.
- [ ] Independent review pass (separate reviewer agent, unseen-by-author) on
      correctness/FP/DoS; fix findings.
- [ ] README with honest metrics + link to RESEARCH.md caveats.

## Phase 9 — Ship
- [ ] Commit (conventional-commit messages), push to `main`.
- [ ] Report results + measured numbers to Dennis.

## Validation gates (every push)
`cargo test` green · `cargo clippy -D warnings` clean · `bench` regenerates
`docs/BENCHMARK.md` · proxy smoke test passes · zero panics in fuzz suite.
