# Venusflytrap — Technical Specification

*Date: 2026-10-22. Companion to PRD.md and IMPLEMENTATION_PLAN.md.*

## 1. Workspace layout
Cargo workspace, `#![forbid(unsafe_code)]` in every crate.

```
venusflytrap/
├── Cargo.toml                 # [workspace] members
├── crates/
│   ├── vft-core/              # the engine (library, no I/O, no network)
│   │   ├── normalize/         # FR1  decoder + unicode folding
│   │   ├── graph/             # FR2  tokenizer + token-graph + taint reachability
│   │   ├── detect/            # FR3  detectors -> Evidence
│   │   ├── lattice.rs         # FR4  Belnap four-valued logic + arbitration
│   │   ├── score.rs           # FR4  evidence -> 0..100 -> Verdict
│   │   ├── honeypot.rs        # FR5
│   │   ├── chain.rs           # FR6  per-source kill-chain state
│   │   ├── intel.rs           # FR7  file-backed lists/fingerprints
│   │   ├── config.rs          # FR8  serde structs + defaults
│   │   ├── request.rs         # input model
│   │   ├── judgment.rs        # output model
│   │   └── shield.rs          # FR9  orchestrator: Shield::inspect
│   ├── vft-cli/               # `venusflytrap scan|bench|serve`
│   └── vft-proxy/             # reverse proxy (hyper)
├── corpus/                    # generated benign/attack/obfuscated samples
├── config/                    # shield.yaml scoring.yaml chain.yaml honeypot.yaml audit.yaml
├── fingerprints/  threat_intel/   # data files (defaults embedded too)
└── docs/
```

Dependencies (pinned, minimal): `serde`,`serde_yaml`,`serde_json`,
`percent-encoding`,`unicode-normalization`,`base64`,`regex` (baseline only),
`clap`,`hyper`+`tokio` (proxy), `anyhow`/`thiserror`. Dev: `proptest`,`criterion`.

## 2. Core data model

```rust
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: &'a [u8],
    pub src_ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
}

pub struct Field { pub loc: Location, pub name: String, pub raw: String }
// Location = Path | Query | Header | Body | Cookie

pub struct Judgment {
    pub verdict: Verdict,              // Allow | Monitor | Challenge | Block
    pub score: u8,                     // 0..=100
    pub engines: Vec<EngineReport>,    // per-detector score+evidence+patterns
    pub chain_stage: Option<Stage>,
    pub matched: Vec<Pattern>,
    pub normalized_layers: u8,
    pub reason: String,
}
```

## 3. FR1 — Normalizer (`normalize/`)
- `decode_fixpoint(raw, cap) -> Decoded { text, layers, flags }`:
  loop up to `cap` (default 14): try URL-decode, HTML-entity, `\xNN`/`\uNNNN`,
  and conservative base64 (only when the whole token decodes to valid
  printable/UTF-8 and changes the string); stop when a pass is a no-op.
  Record `layers`; set `DeepNesting` flag if `layers >= deep_threshold`.
- `fold_unicode(s)`: NFKC → full-width/half-width ASCII fold → UTS#39 confusable
  skeleton (bundled subset table mapping common Cyrillic/Greek homoglyphs to
  Latin) → lowercase for matching copy (original kept for logging). Set
  `MixedScript` flag when ≥2 scripts seen before folding.
- `canonicalize_ws_comments(s)`: collapse whitespace, strip SQL comments
  `/*..*/`, `--`, `#`, and MySQL conditional comments `/*!..*/` (flag their
  presence as a signal rather than silently dropping).
- Bounds: input truncated to `max_payload` (default 64 KiB) before work.

## 4. FR2 — Token graph + taint (`graph/`)
- `tokenize(s) -> Vec<Token>`: lightweight multi-grammar lexer emitting token
  kinds across SQL/HTML/shell/path families: `Keyword(sql)`, `Operator`,
  `Quote`, `Comment`, `Number`, `Ident`, `Punct`, `Tag`, `Attr`, `EventHandler`,
  `Proto(js:/data:)`, `ShellMeta(;|&$()\`)`, `PathSeg(../)`, `Whitespace`.
- `Graph`: nodes = tokens; edges = `Adjacent`, `SameQuote` (tokens inside one
  quoted span), `Boundary` (quote/paren open→close), `Flow` (ident→operator→
  value). Node/edge caps (default 4096) — excess ⇒ `GraphTruncated` flag (itself
  a mild signal).
- **Taint**: source = the whole decoded field (attacker-controlled by
  definition at the WAF boundary). Sink nodes = structural danger markers:
  - SQL: tautology (`<op> <num|str> = <same>`), `UNION … SELECT`, stacked `;`,
    comment-terminator after a quote, boolean/opaque-true (`OR 1=1`, `OR 'a'='a'`).
  - XSS: `<script>`, event-handler attr, `javascript:`/`data:` proto, `<svg
    onload>`-style tag+handler adjacency.
  - Shell: `;|&` chaining, `$(...)`/backtick substitution, `||`/`&&`.
  - Path: `../` / `..\\` segments crossing a boundary; sensitive suffixes.
- **Reachability**: BFS from source span to any sink node along edges; a
  connected source→sink path ⇒ `Reachable { family, pattern }`. This is the
  "tainted data reaches dangerous function" check — mutation-robust because it is
  over token structure, not literal strings.

## 5. FR3 — Detectors (`detect/`)
Each implements `trait Detector { fn assess(&self, ctx: &Ctx) -> Evidence; }`
returning `Evidence { value: FourValued, weight: f32, patterns, note }`.
- `GraphTaintDetector` — Dangerous if `Reachable`, Suspicious if sinks present
  but unreached, else None.
- `SignatureDetector` — curated high-confidence structural signatures (few,
  precise) → Dangerous/Suspicious.
- `IntentDetector` — path recon (CRS restricted-files set: `.env`,`.git/`,
  `.npmrc`,`/actuator/*`,`info.php`,`phpinfo`…), empty-payload + sensitive path,
  dangerous method/path combos → Suspicious/Dangerous.
- `ApiSafetyDetector` — type/shape violations (numeric field carrying SQL),
  oversized/encoded header smuggling hints.
- `AiDetector` (trait `AiOracle`, default `HeuristicOracle`) — bounded feature
  score; pluggable so a real model can be injected without touching the lattice.

## 6. FR4 — Lattice + scoring
```rust
pub enum FourValued { None, Safe, Suspicious, Dangerous } // Belnap: ⊥, F-ish, mid, T-ish
```
- Knowledge-order **join** `⊔` accumulates evidence monotonically; explicit
  **conflict** (`Safe` with high weight vs `Dangerous` with high weight) is
  surfaced as arbitration, not averaged away.
- `arbitrate(&[Evidence], &Scoring) -> (u8, Verdict)`:
  weighted sum of evidence mapped to [0,100] with per-engine weights and caps
  from `scoring.yaml`; honeypot/deny-list evidence can hard-pin to BLOCK; chain
  escalation adds a stage bonus. Bands (defaults): `>=90 Block`, `70..90
  Challenge`, `40..70 Monitor`, `<40 Allow`.
- Design note: arbitration is deterministic and documented; the article's "AI
  says safe but deep semantics say dangerous → weight arbitration" is exactly the
  conflict case, resolved by configured weights favoring the taint-graph verdict.

## 7. FR5/FR6/FR7
- `honeypot.rs`: `HoneypotSet` from config/defaults; `check(path) -> Option<Hit>`;
  empty-body probe of decoy/sensitive path ⇒ Dangerous evidence w/ high weight.
- `chain.rs`: `ChainTracker { window: Duration, per-ip ring of events }`;
  `observe(ip, event) -> Option<Stage>`; stages
  `Recon<Enum<Exploit<Exfil`; advancing stages raise score; `should_ban(ip)` when
  Exploit/Exfil reached or honeypot tripped. In-memory, bounded LRU of sources.
  (Pure library state; proxy owns the instance.)
- `intel.rs`: load allow/deny IP+ASN, scanner/C2 UA, exploit fingerprints from
  files if present else embedded defaults; `lookup` returns evidence.

## 8. FR9 — Interfaces
- Library: `Shield::from_config(Config) ; shield.inspect(&Request) -> Judgment`
  (optionally `inspect_stateful(&mut self, ...)` to feed the chain tracker).
- CLI: `scan` (one request/stdin/JSON), `bench` (runs corpus, writes
  `docs/BENCHMARK.md`), `serve` (proxy).
- Proxy (`vft-proxy`): hyper service; on each request build `Request`, inspect,
  then Allow→forward / Block→403 canned page / Challenge→403+marker /
  Monitor→forward; always add `X-Venusflytrap-Score`,`-Verdict`,`-Stage` and
  append JSONL to the audit log. Upstream target via `--upstream`.

## 9. Benchmark harness (`vft-cli bench`)
- Loads `corpus/{benign,attack,obfuscated}.jsonl`.
- Runs three engines over identical inputs: **regex baseline** (a handful of
  classic signatures), **tokenizer baseline** (structural sink presence only, no
  graph), and **Venusflytrap full**.
- Emits per-engine confusion matrix (TP/FP/TN/FN, precision/recall/F1) and
  latency p50/p95/p99 (via `Instant`), written to `docs/BENCHMARK.md`.

## 10. Testing & safety
- Unit tests per module; table-driven detection tests (known payloads → expected
  family/verdict); FP tests (benign lookalikes: `comment='I like 1=1 math'`,
  SELECT in prose, paths containing `..` legitimately).
- `proptest`: random bytes & structured mutations never panic and always
  terminate within the time budget (NFR2/NFR4).
- `criterion` micro-bench for `inspect`.
- CI-style gate: `cargo test` + `cargo clippy --all-targets -- -D warnings`.

## 11. Explicit honesty constraints
- Benchmark output must print the FP count even if zero; README must not claim
  "zero false positives" as a property — only report the measured number with the
  corpus it came from.
- RESEARCH.md's unverifiable-claims section is linked from the README.
