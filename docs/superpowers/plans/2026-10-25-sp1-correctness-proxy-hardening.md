# SP1 — Correctness, Proxy Hardening, Honest Serve-Path Eval — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Venusflytrap's reverse proxy safe to put in front of real traffic, and measure the proxy path with the same code it serves, so library and serve numbers can be published side by side.

**Architecture:** `vft-core` stays a pure engine. Its stateful API splits into `inspect` (pure, no lock) → `chain observe` (a pure state machine; time is passed in) → `finalize` (never lowers a verdict). The kill chain and bans consume only decision-grade evidence (the verdict plus per-field `Contribution`s), never latent patterns. `vft-proxy` gains an adapter (every forwarded byte is inspected), a sharded `ChainStore`, `Pipeline::decide` (the single function used by the proxy handler and by the eval), and a hardened hyper front end with limits, timeouts, hop-by-hop stripping and an async audit sink. `vft-cli` gains `eval` (library / serve / tcp modes) over the raw blazehttp files, and `config validate`.

**Tech Stack:** Rust 2021 (rustc 1.96), hyper 1.12 + hyper-util 0.1.21 + http-body-util, tokio 1.54, serde/serde_yaml/serde_json, clap 4. Python 3.13 is used only by the existing libinjection baseline.

**Spec:** `docs/superpowers/specs/2026-10-25-operable-service-design.md` §5.2–§5.5 and §6 SP1.

## Global Constraints

- `#![forbid(unsafe_code)]` in every crate.
- `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` green at the end of every task.
- `vft-core` stays I/O-free and deterministic: no clock, no file or network access in the detection path. Time enters as `now_ms: u64`.
- No `unwrap()`/`expect()` on attacker-reachable paths in non-test code. Recover poisoned mutexes with `PoisonError::into_inner`.
- Every bounded queue drops and counts; nothing on the request path blocks on disk or on a slow consumer.
- Honest measurement: never quote the synthetic-corpus result as a result. Record every measured number in `eval/RESULTS-SP1.md`. Report regressions plainly.
- Do not associate Venusflytrap with outside project names in code, docs or commit messages.
- Commits go on branch `sp1-serve-hardening` in a separate worktree. The owner has to approve committing per task before execution starts (Task 0). Never push and never touch `main` without explicit approval.
- Recall-lift owns: body structuring (`body.rs`), normalizer decoders (incl. the H1 lossy percent-decode), graph sink registry, C2/C3 truncation fail-closed, and detection constructs (M4, M5). This plan must not change those areas beyond what is listed here.

## Eval data locations (this machine)

```bash
EVAL=C:/Users/DENNIS~1/AppData/Local/Temp/claude/C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu/da1b01dd-cef6-4b76-bba8-0e55e99fd9e4/scratchpad
# raw corpus:            $EVAL/ext/blazehttp/testcases   (33,219 .white + 658 .black)
# parsed JSONL:          $EVAL/run0/corpus.jsonl         (from eval/parse_corpus.py)
# mutation seeds/mutants:$EVAL/run0/seeds.jsonl, $EVAL/run0/mutants.jsonl
# current-tree baseline: $EVAL/run2/pred.csv             (command-position $( fix; 282 TP / 268 FP / 376 FN)
# libinjection DLL:      $EVAL/ext/libinjection.dll
```

Run Python as `py -I -X utf8`. The "neutrality check" used by several tasks:

```bash
cargo build --release -p vft-cli --example bench_http
./target/release/examples/bench_http "$EVAL/run0/corpus.jsonl" "$EVAL/sp1/pred-taskN.csv"
diff <(cut -d, -f1-3 "$EVAL/run2/pred.csv") <(cut -d, -f1-3 "$EVAL/sp1/pred-taskN.csv") && echo NEUTRAL
```

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `crates/vft-core/src/judgment.rs` | `FieldRef`, `Contribution`, `Verdict::rank`, `Family::Limit`, `Judgment.contributions` | 1, 6 |
| `crates/vft-core/src/score.rs` | `Scored`, `arbitrate`, `band`, dedup + cap + per-field conflict | 1, 2, 3 |
| `crates/vft-core/src/shield.rs` | `Recorder`; `inspect` (pure), `finalize`, `banned_judgment`, `inspect_stateful(now_ms)` | 1, 2, 3, 6 |
| `crates/vft-core/src/chain.rs` | pure chain: `event_for`, `SourceKey`, `BanRecord`, `ChainOutcome`, `ChainTracker` | 2 |
| `crates/vft-core/src/config.rs` | `BanPolicy`, `corroboration_cap`, `ProxyConfig`, `LimitsConfig`, `validate`, `load` | 2, 3, 5, 7, 8 |
| `crates/vft-core/src/detect.rs` | AI detector emits `None` for no signal; intent reads the canonical path | 3, 4 |
| `crates/vft-core/src/request.rs` | `canonical_path`, `non_utf8_headers`, field skip list | 4, 6 |
| `crates/vft-core/src/honeypot.rs` | reads the canonical path | 4 |
| `crates/vft-proxy/src/adapt.rs` (new) | hyper parts → `Request`; lossy header decoding | 6 |
| `crates/vft-proxy/src/pipeline.rs` (new) | `ChainStore`, `Pipeline::decide`, `client_ip` | 7 |
| `crates/vft-proxy/src/lib.rs` | hardened server: limits, forwarder, hop-by-hop, accept loop | 7, 8 |
| `crates/vft-proxy/src/audit.rs` | async JSONL sink with rotation and counters | 9 |
| `crates/vft-proxy/tests/hardening.rs` (new) | end-to-end proxy tests over real sockets | 8 |
| `crates/vft-cli/src/eval.rs` (new) | raw corpus loader, lenient parser, library/serve/tcp eval | 10, 11 |
| `crates/vft-cli/src/main.rs` | `eval`, `config validate`, `bench` default output | 5, 10, 11, 12 |
| `crates/vft-cli/examples/bench_http.rs` | struct-literal update only | 6 |
| `config/shield.yaml` | new keys with their defaults | 5, 8 |
| `eval/RESULTS-SP1.md` (new) | measurement log, one row per measured task | 1–12 |
| `README.md`, `docs/BENCHMARK.md` | real-corpus numbers, library vs serve | 12 |

---

### Task 0: Branch, worktree, baseline commit

**Files:**
- Modify: `.gitignore`
- Create: `eval/RESULTS-SP1.md`

- [ ] **Step 1: Ask the owner** to approve (a) a worktree at `M:/Projects/venusflytrap-sp1` on a new branch `sp1-serve-hardening`, and (b) one commit per task on that branch. Stop if not approved.

- [ ] **Step 2: Create the worktree** (use the using-git-worktrees skill):

```bash
cd /m/Projects/venusflytrap
git worktree add ../venusflytrap-sp1 -b sp1-serve-hardening HEAD
```

- [ ] **Step 3: Bring over the uncommitted baseline** (eval harness + command-position `$(` fix). The main checkout keeps its copies untouched.

```bash
cd /m/Projects/venusflytrap
mkdir -p ../venusflytrap-sp1/eval ../venusflytrap-sp1/crates/vft-cli/examples ../venusflytrap-sp1/docs/superpowers/specs ../venusflytrap-sp1/docs/superpowers/plans
cp eval/parse_corpus.py eval/baselines.py eval/mutate.py ../venusflytrap-sp1/eval/
cp crates/vft-cli/examples/bench_http.rs ../venusflytrap-sp1/crates/vft-cli/examples/
cp crates/vft-core/src/graph/mod.rs ../venusflytrap-sp1/crates/vft-core/src/graph/mod.rs
cp docs/superpowers/specs/2026-10-25-operable-service-design.md ../venusflytrap-sp1/docs/superpowers/specs/
cp docs/superpowers/plans/2026-10-25-sp1-correctness-proxy-hardening.md ../venusflytrap-sp1/docs/superpowers/plans/
```

- [ ] **Step 4: Ignore research material** (it names outside projects and must not be committed). Append to `.gitignore`:

```
/research_notes/
/reports/
```

- [ ] **Step 5: Create `eval/RESULTS-SP1.md`**

```markdown
# SP1 measurement log

Real blazehttp corpus (33,877 requests: 33,219 benign, 658 malicious). "lib" = `Shield::inspect` via
`bench_http` on the Python-parsed JSONL; "serve" = `venusflytrap eval --mode serve` on raw files.
Mutation = 22 seeds → 660 mutants (eval/mutate.py, seed 1337).

| Task | Change | Path | TP | FP | FN | Recall | Precision | FP rate | Seeds | Mutants | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | baseline (command-position `$(` fix) | lib | 282 | 268 | 376 | 42.86% | 51.27% | 0.81% | 19/22 | 548/660 | measured 2026-10-25 |
```

- [ ] **Step 6: Verify and commit**

```bash
cd /m/Projects/venusflytrap-sp1
cargo test --workspace 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-targets -- -D warnings 2>&1 | tail -1
git add -A && git commit -m "chore: real-corpus eval harness, command-position \$( fix, SP1 spec and plan"
```

Expected: every `test result: ok`; clippy `Finished`.

---

### Task 1: Per-field contributions (detection-neutral refactor)

Adds `FieldRef`/`Contribution` to `Judgment` and a `Scored` input type for `arbitrate`, without changing any score.

**Files:**
- Modify: `crates/vft-core/src/request.rs` (derive `Hash` on `Location`)
- Modify: `crates/vft-core/src/judgment.rs`
- Modify: `crates/vft-core/src/score.rs`
- Modify: `crates/vft-core/src/shield.rs`
- Modify: `crates/vft-core/src/lib.rs`

**Interfaces:**
- Produces: `vft_core::judgment::{FieldRef, Contribution}`; `Judgment.contributions: Vec<Contribution>`; `vft_core::score::Scored { engine: String, engine_weight: f32, field: Option<FieldRef>, evidence: Evidence }`; `arbitrate(items: &[Scored], cfg, hard_block: bool, extra: u8) -> (u8, Verdict, bool)`; `Verdict::rank(self) -> u8`.

- [ ] **Step 1: Write the failing test** in `crates/vft-core/src/shield.rs` `mod tests`:

```rust
    #[test]
    fn contributions_carry_field_and_construct() {
        let mut req = Request::get("/items");
        req.query.push(("id".into(), "1 union select password from users".into()));
        let j = shield().inspect(&req);
        let c = j
            .contributions
            .iter()
            .find(|c| c.construct.as_deref() == Some("union-select"))
            .expect("union-select contribution");
        assert_eq!(c.field, Some(FieldRef { loc: Location::Query, name: "id".into() }));
        assert_eq!(c.family, Some(Family::Sqli));
        assert_eq!(c.value, FourValued::Dangerous);
    }
```

Add `use crate::judgment::FieldRef; use crate::lattice::FourValued; use crate::request::Location;` to the test module's imports.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p vft-core --lib contributions_carry_field_and_construct`
Expected: compile error, `no field 'contributions'` / `cannot find type FieldRef`.

- [ ] **Step 3: Implement**

`crates/vft-core/src/request.rs` — change the `Location` derive to:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Location {
```

`crates/vft-core/src/judgment.rs` — add after the `Verdict` enum:

```rust
impl Verdict {
    /// Severity order: Allow < Monitor < Challenge < Block.
    pub fn rank(self) -> u8 {
        match self {
            Verdict::Allow => 0,
            Verdict::Monitor => 1,
            Verdict::Challenge => 2,
            Verdict::Block => 3,
        }
    }
}

/// Which field of the request a piece of evidence is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldRef {
    pub loc: crate::request::Location,
    pub name: String,
}

impl FieldRef {
    pub fn of(f: &crate::request::Field) -> Self {
        FieldRef { loc: f.loc, name: f.name.clone() }
    }
    pub fn path() -> Self {
        FieldRef { loc: crate::request::Location::Path, name: "<path>".into() }
    }
    pub fn header(name: &str) -> Self {
        FieldRef { loc: crate::request::Location::Header, name: name.to_ascii_lowercase() }
    }
}

/// One piece of non-`None` evidence about one field, with the construct that
/// produced it. Decision-grade input for the kill chain and the "why" panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub engine: String,
    pub field: Option<FieldRef>,
    /// Construct name (today's pattern name; stable dotted ids arrive with the
    /// construct registry).
    pub construct: Option<String>,
    pub family: Option<Family>,
    pub value: crate::lattice::FourValued,
    pub weight: f32,
    /// Points added to the score. Filled in SP2; 0.0 until then.
    pub points: f32,
}
```

Add the field to `Judgment` (after `matched`) and to `Judgment::allow()`:

```rust
    pub contributions: Vec<Contribution>,
```
```rust
            contributions: Vec::new(),
```

`crates/vft-core/src/score.rs` — replace the `arbitrate` signature and loop (the math stays identical: the old running "previous top becomes corroboration" equals 0.1 × (sum − top)):

```rust
use crate::judgment::FieldRef;

/// One weighted evidence item, tagged with its engine and field.
#[derive(Debug, Clone)]
pub struct Scored {
    pub engine: String,
    pub engine_weight: f32,
    pub field: Option<FieldRef>,
    pub evidence: Evidence,
}

pub fn arbitrate(
    items: &[Scored],
    cfg: &ScoringConfig,
    hard_block: bool,
    extra: u8,
) -> (u8, Verdict, bool) {
    if hard_block {
        return (100, Verdict::Block, true);
    }
    let evid_only: Vec<Evidence> = items.iter().map(|s| s.evidence.clone()).collect();
    let is_conflict = conflict(&evid_only, cfg.conflict_threshold);

    let points: Vec<f32> = items
        .iter()
        .filter(|s| s.evidence.value.is_threat())
        .map(|s| value_points(s.evidence.value) * s.evidence.weight * s.engine_weight)
        .collect();
    let top = points.iter().copied().fold(0.0f32, f32::max);
    let corroboration = (points.iter().sum::<f32>() - top) * 0.1;

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        score *= 0.9;
    }
    score = (score + extra as f32).min(100.0);
    let s = score.round() as u8;
    (s, band(s, cfg), is_conflict)
}

/// Map a 0..=100 score onto the configured verdict bands.
pub fn band(score: u8, cfg: &ScoringConfig) -> Verdict {
    if score >= cfg.block_at {
        Verdict::Block
    } else if score >= cfg.challenge_at {
        Verdict::Challenge
    } else if score >= cfg.monitor_at {
        Verdict::Monitor
    } else {
        Verdict::Allow
    }
}
```

Update the four existing tests in `score.rs` to build `Scored` values with a helper:

```rust
    fn sc(w: f32, e: Evidence) -> Scored {
        Scored { engine: "t".into(), engine_weight: w, field: None, evidence: e }
    }
```

For example, `let ev = vec![sc(1.0, Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint"))]; let (s, v, _) = arbitrate(&ev, &cfg, false, 0);`.

`crates/vft-core/src/shield.rs` — replace the free `record` function with a `Recorder`:

```rust
use crate::judgment::{Contribution, FieldRef};
use crate::lattice::FourValued;
use crate::score::Scored;

#[derive(Default)]
struct Recorder {
    engines: Vec<EngineReport>,
    scored: Vec<Scored>,
    matched: Vec<Pattern>,
    contributions: Vec<Contribution>,
}

impl Recorder {
    fn record(&mut self, name: &str, engine_weight: f32, field: Option<FieldRef>, e: Evidence) {
        for p in &e.patterns {
            if !self.matched.contains(p) {
                self.matched.push(p.clone());
            }
        }
        if e.value != FourValued::None {
            if e.patterns.is_empty() {
                self.contributions.push(Contribution {
                    engine: name.to_string(),
                    field: field.clone(),
                    construct: None,
                    family: None,
                    value: e.value,
                    weight: e.weight,
                    points: 0.0,
                });
            }
            for p in &e.patterns {
                self.contributions.push(Contribution {
                    engine: name.to_string(),
                    field: field.clone(),
                    construct: Some(p.name.clone()),
                    family: Some(p.family),
                    value: e.value,
                    weight: e.weight,
                    points: 0.0,
                });
            }
        }
        self.engines.push(EngineReport {
            engine: name.to_string(),
            value: e.value,
            weight: e.weight,
            score_contribution: 0.0,
            patterns: e.patterns.clone(),
            note: e.note.clone(),
        });
        self.scored.push(Scored { engine: name.to_string(), engine_weight, field, evidence: e });
    }
}
```

In `inspect_inner`, replace the three vectors `engines`/`weighted`/`matched` with `let mut rec = Recorder::default();` and change each call site:

- per field: `let fref = FieldRef::of(&field);` then `rec.record(det.name(), *w, Some(fref.clone()), det.assess(&ctx));` and `rec.record(ai.name(), self.cfg.scoring.weight_ai, Some(fref), ai.assess(&ctx));`
- path graph: `rec.record("graph-taint", self.cfg.scoring.weight_graph, Some(FieldRef::path()), e);`
- intent: `rec.record("intent", self.cfg.scoring.weight_intent, Some(FieldRef::path()), intent);`
- intel UA: `rec.record("intel", self.cfg.scoring.weight_intent, Some(FieldRef::header("user-agent")), ua_e);`
- honeypot: `rec.record("honeypot", 1.0, Some(FieldRef::path()), e);`
- chain block: `let families: Vec<Family> = rec.matched.iter().map(|p| p.family).collect();` and `classify_event(&rec.matched, honeypot)`
- `arbitrate(&rec.scored, &self.cfg.scoring, hard_block, extra)`
- `build_reason(&rec.matched, conflict, banned_source, hard_block)`
- the returned `Judgment` uses `engines: rec.engines, matched: rec.matched, contributions: rec.contributions`.

`crates/vft-core/src/lib.rs` — extend the judgment re-export:

```rust
pub use judgment::{Contribution, EngineReport, Family, FieldRef, Judgment, Pattern, Stage, Verdict};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"` then `cargo clippy --all-targets -- -D warnings`
Expected: all pass, including `contributions_carry_field_and_construct`.

- [ ] **Step 5: Neutrality check** (see "Eval data locations"; use `pred-task1.csv`)
Expected: `NEUTRAL`. If not, the refactor changed scoring — fix before continuing.

- [ ] **Step 6: Log and commit**

Append to `eval/RESULTS-SP1.md`: `| 1 | per-field contributions (refactor) | lib | 282 | 268 | 376 | 42.86% | 51.27% | 0.81% | – | – | byte-identical verdicts |`

```bash
git add -A && git commit -m "refactor(core): per-field contributions and Scored arbitration input"
```

---

### Task 2: Pure kill chain driven by the decision (C1, M2, M3, H3 core)

**Files:**
- Rewrite: `crates/vft-core/src/chain.rs`
- Modify: `crates/vft-core/src/config.rs` (`ChainConfig`, new `BanPolicy`)
- Modify: `crates/vft-core/src/shield.rs` (`inspect`, `finalize`, `banned_judgment`, `inspect_stateful`)
- Modify: `crates/vft-core/src/score.rs` (drop the `extra` parameter)
- Modify: `crates/vft-core/src/lib.rs`
- Modify: `crates/vft-proxy/src/lib.rs` (call site only)

**Interfaces:**
- Consumes: `Judgment.contributions`, `Verdict::rank`, `score::band` (Task 1).
- Produces (re-exported from `vft_core`):
  - `pub fn event_for(j: &Judgment) -> Event`
  - `pub struct SourceKey(IpAddr)` with `SourceKey::new(ip: IpAddr, ipv6_prefix: u8) -> SourceKey`, `.ip() -> IpAddr`
  - `pub enum BanCause { Honeypot, Exfiltration, RepeatedExploitation, Manual }`
  - `pub struct BanRecord { since_ms: u64, until_ms: u64, cause: BanCause, offences: u32 }` with `.active(now_ms) -> bool`
  - `pub struct ChainOutcome { stage_before: Option<Stage>, stage_after: Option<Stage>, advanced: bool, new_ban: Option<BanRecord> }`
  - `ChainTracker::new(&ChainConfig)`, `.active_ban(key, now_ms) -> Option<BanRecord>`, `.observe(key, ev, now_ms, may_ban: bool) -> ChainOutcome`, `.ban(key, cause, now_ms) -> BanRecord`, `.lift(key) -> bool`, `.tracked_sources() -> usize`, `.ban_count() -> usize`
  - `Shield::inspect(&self, &Request) -> Judgment` (pure), `Shield::finalize(&self, Judgment, &ChainOutcome) -> Judgment`, `Shield::banned_judgment(&self, &BanRecord) -> Judgment`, `Shield::inspect_stateful(&self, &Request, &mut ChainTracker, now_ms: u64) -> Judgment`, `Shield::intel(&self) -> &Intel`
  - `arbitrate(items, cfg, hard_block) -> (u8, Verdict, bool)` (no `extra`)
  - `ChainConfig { window_secs, max_sources, events_per_source, ipv6_prefix: u8, ban_policy: BanPolicy }`, `BanPolicy { on_honeypot, on_exfiltration_block, exploitation_blocks: u32, within_secs, ttl_secs, ttl_max_secs, max_bans: usize }`

- [ ] **Step 1: Write the failing tests**

Replace the `mod tests` in `crates/vft-core/src/chain.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChainConfig;
    use std::net::Ipv4Addr;

    fn key(n: u8) -> SourceKey {
        SourceKey::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)), 64)
    }
    const MIN: u64 = 60_000;

    #[test]
    fn honeypot_bans_immediately() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let o = t.observe(key(1), Event::Honeypot, 0, true);
        assert_eq!(o.new_ban.map(|b| b.cause), Some(BanCause::Honeypot));
        assert!(t.active_ban(key(1), 1).is_some());
    }

    #[test]
    fn one_exploitation_does_not_ban_three_in_ten_minutes_do() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        assert!(t.observe(key(2), Event::Exploitation, 0, true).new_ban.is_none());
        assert!(t.observe(key(2), Event::Exploitation, MIN, true).new_ban.is_none());
        let o = t.observe(key(2), Event::Exploitation, 2 * MIN, true);
        assert_eq!(o.new_ban.map(|b| b.cause), Some(BanCause::RepeatedExploitation));
    }

    #[test]
    fn exploitation_spread_beyond_window_does_not_ban() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        for i in 0..3 {
            assert!(t.observe(key(3), Event::Exploitation, i * 6 * MIN, true).new_ban.is_none());
        }
    }

    #[test]
    fn stage_decays_after_window() {
        let cfg = ChainConfig::default();
        let window = cfg.window_secs * 1000;
        let mut t = ChainTracker::new(&cfg);
        let o1 = t.observe(key(4), Event::Recon, 0, true);
        assert_eq!(o1.stage_after, Some(Stage::Recon));
        assert!(o1.advanced);
        let o2 = t.observe(key(4), Event::Recon, 1, true);
        assert!(!o2.advanced, "same stage again must not count as an advance (M2)");
        let o3 = t.observe(key(4), Event::Benign, window + 2, true);
        assert_eq!(o3.stage_after, None, "stage must decay outside the window (M2)");
    }

    #[test]
    fn ban_expires_and_reoffence_doubles_ttl_up_to_cap() {
        let cfg = ChainConfig::default();
        let ttl = cfg.ban_policy.ttl_secs * 1000;
        let mut t = ChainTracker::new(&cfg);
        let b1 = t.ban(key(5), BanCause::Honeypot, 0);
        assert_eq!(b1.until_ms, ttl);
        assert!(t.active_ban(key(5), ttl - 1).is_some());
        assert!(t.active_ban(key(5), ttl).is_none());
        let b2 = t.ban(key(5), BanCause::Honeypot, ttl + 1);
        assert_eq!(b2.until_ms - b2.since_ms, 2 * ttl);
        let mut last = b2;
        for _ in 0..10 {
            last = t.ban(key(5), BanCause::Honeypot, last.until_ms + 1);
        }
        assert_eq!(last.until_ms - last.since_ms, cfg.ban_policy.ttl_max_secs * 1000);
    }

    #[test]
    fn allowlisted_source_is_never_banned() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        assert!(t.observe(key(6), Event::Honeypot, 0, false).new_ban.is_none());
        assert!(t.active_ban(key(6), 1).is_none());
    }

    #[test]
    fn bans_survive_source_lru_eviction() {
        // M3: spraying other sources must not flush a ban.
        let cfg = ChainConfig { max_sources: 64, ..ChainConfig::default() };
        let mut t = ChainTracker::new(&cfg);
        t.ban(key(7), BanCause::Honeypot, 0);
        for n in 0..5_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0B00_0000 | n));
            t.observe(SourceKey::new(ip, 64), Event::Recon, 1, true);
        }
        assert!(t.tracked_sources() <= 64);
        assert!(t.active_ban(key(7), 2).is_some());
    }

    #[test]
    fn source_keys_aggregate_ipv6_prefix_and_unmap_ipv4() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(SourceKey::new(a, 64), SourceKey::new(b, 64));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(SourceKey::new(mapped, 64).ip(), "192.0.2.7".parse::<IpAddr>().unwrap());
    }
}
```

Replace `chain_escalates_and_bans` in `crates/vft-core/src/shield.rs` tests, and add the C1 regression:

```rust
    fn browser(path: &str, ip: IpAddr) -> Request {
        let mut r = Request::get(path);
        r.src_ip = Some(ip);
        r.headers.push(("User-Agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36".into()));
        r.headers.push(("Accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into()));
        r.headers.push(("Accept-Language".into(), "en-US,en;q=0.9".into()));
        r
    }

    #[test]
    fn browser_is_never_staged_or_banned() {
        // C1 regression: latent shell-meta from ';' in browser headers must not
        // advance the chain.
        let s = shield();
        let mut chain = ChainTracker::new(&s.config().chain);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));
        for i in 0..5 {
            let j = s.inspect_stateful(&browser("/index.html", ip), &mut chain, i * 1000);
            assert_eq!(j.verdict, Verdict::Allow, "request {i}: {}", j.reason);
            assert!(!j.banned_source);
            assert_eq!(j.chain_stage, None);
        }
    }

    #[test]
    fn repeated_exploitation_bans_then_fast_tracks() {
        let s = shield();
        let mut chain = ChainTracker::new(&s.config().chain);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let mut xss = Request::get("/p");
        xss.src_ip = Some(ip);
        xss.query.push(("q".into(), "<script>alert(1)</script>".into()));
        let j1 = s.inspect_stateful(&xss, &mut chain, 0);
        assert_eq!(j1.verdict, Verdict::Block);
        assert!(!j1.banned_source);
        let _ = s.inspect_stateful(&xss, &mut chain, 1_000);
        let j3 = s.inspect_stateful(&xss, &mut chain, 2_000);
        assert!(j3.banned_source, "third exploitation block within 10 min bans");
        let benign = browser("/index.html", ip);
        let j4 = s.inspect_stateful(&benign, &mut chain, 3_000);
        assert_eq!(j4.verdict, Verdict::Block);
        assert!(j4.banned_source);
    }

    #[test]
    fn chain_bonus_applies_only_on_advance() {
        let s = shield();
        let mut chain = ChainTracker::new(&s.config().chain);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let mut recon = Request::get("/.env");
        recon.src_ip = Some(ip);
        let j1 = s.inspect_stateful(&recon, &mut chain, 0);
        let j2 = s.inspect_stateful(&recon, &mut chain, 1_000);
        assert_eq!(j1.chain_stage, Some(Stage::Recon));
        assert!(j2.score < j1.score, "no bonus without an advance (M2): {} vs {}", j2.score, j1.score);
    }
```

Add `use crate::chain::ChainTracker; use crate::judgment::Stage;` to the test imports if missing.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-core --lib chain`
Expected: compile errors (`SourceKey`, `BanCause` and the new `observe` signature don't exist).

- [ ] **Step 3: Implement**

`crates/vft-core/src/config.rs` — replace `ChainConfig` and its `Default`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChainConfig {
    /// Events older than this no longer count toward a source's stage.
    pub window_secs: u64,
    /// Bounded LRU of tracked sources (bans are tracked separately).
    pub max_sources: usize,
    pub events_per_source: usize,
    /// IPv6 sources are aggregated to this prefix length.
    pub ipv6_prefix: u8,
    pub ban_policy: BanPolicy,
}

impl Default for ChainConfig {
    fn default() -> Self {
        ChainConfig {
            window_secs: 3600,
            max_sources: 4096,
            events_per_source: 64,
            ipv6_prefix: 64,
            ban_policy: BanPolicy::default(),
        }
    }
}

/// When a source gets banned, and for how long.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BanPolicy {
    pub on_honeypot: bool,
    pub on_exfiltration_block: bool,
    /// Ban after this many exploitation blocks within `within_secs`.
    pub exploitation_blocks: u32,
    pub within_secs: u64,
    /// First ban length; doubles on each re-offence up to `ttl_max_secs`.
    pub ttl_secs: u64,
    pub ttl_max_secs: u64,
    pub max_bans: usize,
}

impl Default for BanPolicy {
    fn default() -> Self {
        BanPolicy {
            on_honeypot: true,
            on_exfiltration_block: true,
            exploitation_blocks: 3,
            within_secs: 600,
            ttl_secs: 3600,
            ttl_max_secs: 86_400,
            max_bans: 100_000,
        }
    }
}
```

`crates/vft-core/src/chain.rs` — replace everything above `mod tests` with:

```rust
//! FR6 — Cross-request attack-chain inference as a pure state machine.
//!
//! Chain events come from the *decision* (verdict + decision-grade
//! contributions), never from latent evidence, so a request the engine allows
//! cannot advance a source. Stage is the maximum over events inside the window
//! and therefore decays. Bans are a separate policy with TTLs and are never
//! evicted by the source LRU. Time is passed in (`now_ms`) — no clock here.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::config::ChainConfig;
use crate::judgment::{Family, Judgment, Stage, Verdict};
use crate::lattice::FourValued;

/// What a single decision told us about a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Benign,
    Recon,
    Enumeration,
    Exploitation,
    Exfiltration,
    Honeypot,
}

impl Event {
    fn to_stage(self) -> Option<Stage> {
        match self {
            Event::Benign => None,
            Event::Recon => Some(Stage::Recon),
            Event::Enumeration => Some(Stage::Enumeration),
            Event::Exploitation | Event::Honeypot => Some(Stage::Exploitation),
            Event::Exfiltration => Some(Stage::Exfiltration),
        }
    }
    fn is_exploit(self) -> bool {
        matches!(self, Event::Exploitation | Event::Exfiltration)
    }
}

/// Constructs whose Dangerous presence in a blocked request means data exfiltration.
const EXFIL_CONSTRUCTS: &[&str] = &["union-select", "union-all-select", "schema-enum", "load_file"];
const ATTACK_FAMILIES: &[Family] =
    &[Family::Sqli, Family::Xss, Family::CommandInjection, Family::PathTraversal];

/// Derive the chain event from a decision. Suspicious or latent evidence never
/// stages a source.
pub fn event_for(j: &Judgment) -> Event {
    let dangerous = |f: Family| {
        j.contributions
            .iter()
            .any(|c| c.value == FourValued::Dangerous && c.family == Some(f))
    };
    if dangerous(Family::Honeypot) {
        return Event::Honeypot;
    }
    if j.verdict.rank() >= Verdict::Challenge.rank() {
        let exfil = j.contributions.iter().any(|c| {
            c.value == FourValued::Dangerous
                && c.construct.as_deref().is_some_and(|n| EXFIL_CONSTRUCTS.contains(&n))
        });
        if exfil {
            return Event::Exfiltration;
        }
        if ATTACK_FAMILIES.iter().any(|f| dangerous(*f)) {
            return Event::Exploitation;
        }
    }
    if dangerous(Family::Recon) {
        return Event::Recon;
    }
    let scanner = j
        .contributions
        .iter()
        .any(|c| c.family == Some(Family::Intel) && c.value.is_threat());
    if scanner && j.verdict.rank() >= Verdict::Monitor.rank() {
        return Event::Enumeration;
    }
    Event::Benign
}

/// A tracked source: an IPv4 address, or an IPv6 address masked to a prefix.
/// IPv4-mapped IPv6 is canonicalized to IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceKey(IpAddr);

impl SourceKey {
    pub fn new(ip: IpAddr, ipv6_prefix: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => SourceKey(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return SourceKey(IpAddr::V4(v4));
                }
                let p = u32::from(ipv6_prefix.min(128));
                let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                SourceKey(IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask)))
            }
        }
    }
    pub fn ip(&self) -> IpAddr {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BanCause {
    Honeypot,
    Exfiltration,
    RepeatedExploitation,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanRecord {
    pub since_ms: u64,
    pub until_ms: u64,
    pub cause: BanCause,
    /// 1 for a first ban; each re-offence doubles the TTL.
    pub offences: u32,
}

impl BanRecord {
    pub fn active(&self, now_ms: u64) -> bool {
        now_ms < self.until_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChainOutcome {
    pub stage_before: Option<Stage>,
    pub stage_after: Option<Stage>,
    /// True only when the stage strictly increased with this event.
    pub advanced: bool,
    pub new_ban: Option<BanRecord>,
}

struct SourceState {
    events: VecDeque<(u64, Event)>,
    last_seen: u64,
}

fn stage_of(events: &VecDeque<(u64, Event)>) -> Option<Stage> {
    events.iter().filter_map(|(_, e)| e.to_stage()).max()
}

/// Single-threaded chain + ban store. The proxy shards several of these.
pub struct ChainTracker {
    cfg: ChainConfig,
    sources: HashMap<SourceKey, SourceState>,
    bans: HashMap<SourceKey, BanRecord>,
}

impl ChainTracker {
    pub fn new(cfg: &ChainConfig) -> Self {
        ChainTracker { cfg: cfg.clone(), sources: HashMap::new(), bans: HashMap::new() }
    }

    pub fn active_ban(&self, key: SourceKey, now_ms: u64) -> Option<BanRecord> {
        self.bans.get(&key).copied().filter(|b| b.active(now_ms))
    }

    /// Record one decision's event. `may_ban` is false for allow-listed sources.
    pub fn observe(&mut self, key: SourceKey, ev: Event, now_ms: u64, may_ban: bool) -> ChainOutcome {
        let window_ms = self.cfg.window_secs.saturating_mul(1000);
        let cap = self.cfg.events_per_source.max(1);
        let within_ms = self.cfg.ban_policy.within_secs.saturating_mul(1000);

        let st = self
            .sources
            .entry(key)
            .or_insert_with(|| SourceState { events: VecDeque::new(), last_seen: now_ms });
        st.last_seen = now_ms;
        while st.events.front().is_some_and(|(t, _)| now_ms.saturating_sub(*t) > window_ms) {
            st.events.pop_front();
        }
        let stage_before = stage_of(&st.events);
        if ev != Event::Benign {
            st.events.push_back((now_ms, ev));
            while st.events.len() > cap {
                st.events.pop_front();
            }
        }
        let stage_after = stage_of(&st.events);
        let recent_exploits = st
            .events
            .iter()
            .filter(|(t, e)| e.is_exploit() && now_ms.saturating_sub(*t) <= within_ms)
            .count();

        let bp = &self.cfg.ban_policy;
        let cause = if !may_ban {
            None
        } else if ev == Event::Honeypot && bp.on_honeypot {
            Some(BanCause::Honeypot)
        } else if ev == Event::Exfiltration && bp.on_exfiltration_block {
            Some(BanCause::Exfiltration)
        } else if ev.is_exploit() && recent_exploits >= bp.exploitation_blocks.max(1) as usize {
            Some(BanCause::RepeatedExploitation)
        } else {
            None
        };
        let new_ban = cause.map(|c| self.ban(key, c, now_ms));
        self.evict();
        ChainOutcome { stage_before, stage_after, advanced: stage_after > stage_before, new_ban }
    }

    /// Ban (or re-ban) a source. A previous record, even expired, counts as an offence.
    pub fn ban(&mut self, key: SourceKey, cause: BanCause, now_ms: u64) -> BanRecord {
        let bp = &self.cfg.ban_policy;
        let offences = self.bans.get(&key).map_or(1, |b| b.offences.saturating_add(1));
        let factor = 1u64 << (offences - 1).min(20);
        let ttl_s = bp.ttl_secs.saturating_mul(factor).min(bp.ttl_max_secs.max(bp.ttl_secs));
        let rec = BanRecord {
            since_ms: now_ms,
            until_ms: now_ms.saturating_add(ttl_s.saturating_mul(1000)),
            cause,
            offences,
        };
        self.bans.insert(key, rec);
        rec
    }

    pub fn lift(&mut self, key: SourceKey) -> bool {
        self.bans.remove(&key).is_some()
    }
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }
    pub fn ban_count(&self) -> usize {
        self.bans.len()
    }

    fn evict(&mut self) {
        if self.sources.len() > self.cfg.max_sources {
            let target = (self.cfg.max_sources * 9) / 10;
            let mut by_recency: Vec<(SourceKey, u64)> =
                self.sources.iter().map(|(k, v)| (*k, v.last_seen)).collect();
            by_recency.sort_by_key(|(_, t)| *t);
            let remove = self.sources.len() - target;
            for (k, _) in by_recency.into_iter().take(remove) {
                self.sources.remove(&k);
            }
        }
        if self.bans.len() > self.cfg.ban_policy.max_bans {
            // Evict soonest-expiring first; offence memory is lost for those.
            let target = (self.cfg.ban_policy.max_bans * 9) / 10;
            let mut by_expiry: Vec<(SourceKey, u64)> =
                self.bans.iter().map(|(k, b)| (*k, b.until_ms)).collect();
            by_expiry.sort_by_key(|(_, u)| *u);
            let remove = self.bans.len() - target;
            for (k, _) in by_expiry.into_iter().take(remove) {
                self.bans.remove(&k);
            }
        }
    }
}
```

`crates/vft-core/src/score.rs` — remove the `extra: u8` parameter and the `score = (score + extra as f32).min(100.0);` line. Update the four tests to call `arbitrate(&ev, &cfg, false)` / `arbitrate(&[], &cfg, true)`.

`crates/vft-core/src/shield.rs`:
- Delete `classify_event`, the `use std::time::Instant;` import and the `chain_stage`/`banned_source`/`extra` block inside `inspect_inner`. Rename `inspect_inner(&self, req, chain)` to the body of `pub fn inspect(&self, req: &Request) -> Judgment` (no chain parameter). Its tail becomes:

```rust
        let (score, verdict, conflict) = arbitrate(&rec.scored, &self.cfg.scoring, hard_block);
        let reason = build_reason(&rec.matched, conflict, false, hard_block);
        Judgment {
            verdict,
            score,
            engines: rec.engines,
            matched: rec.matched,
            contributions: rec.contributions,
            chain_stage: None,
            normalized_layers: max_layers,
            banned_source: false,
            reason,
        }
```

- Add these methods to `impl Shield`:

```rust
    pub fn intel(&self) -> &Intel {
        &self.intel
    }

    /// Apply a chain outcome to a judgment. Never lowers the verdict.
    pub fn finalize(&self, mut j: Judgment, o: &ChainOutcome) -> Judgment {
        j.chain_stage = o.stage_after;
        if o.advanced && o.stage_after.is_some() {
            let bumped = j.score.saturating_add(self.cfg.scoring.chain_stage_bonus).min(100);
            let v = crate::score::band(bumped, &self.cfg.scoring);
            if v.rank() > j.verdict.rank() {
                j.verdict = v;
            }
            j.score = j.score.max(bumped);
        }
        if let Some(b) = o.new_ban {
            j.banned_source = true;
            j.verdict = Verdict::Block;
            j.score = 100;
            j.reason = format!(
                "{} (source banned: {:?}, {} s)",
                j.reason,
                b.cause,
                (b.until_ms - b.since_ms) / 1000
            );
        }
        j
    }

    /// The judgment for a request from an actively banned source (no inspection).
    pub fn banned_judgment(&self, ban: &BanRecord) -> Judgment {
        Judgment {
            verdict: Verdict::Block,
            score: 100,
            engines: Vec::new(),
            matched: Vec::new(),
            contributions: vec![Contribution {
                engine: "chain".into(),
                field: None,
                construct: Some("chain.ban".into()),
                family: None,
                value: FourValued::Dangerous,
                weight: 1.0,
                points: 0.0,
            }],
            chain_stage: None,
            normalized_layers: 0,
            banned_source: true,
            reason: format!("source banned ({:?}) until t={} ms", ban.cause, ban.until_ms),
        }
    }

    /// Single-threaded stateful inspection: ban fast-track, pure inspect,
    /// chain observe, finalize. The proxy runs the same steps over a sharded store.
    pub fn inspect_stateful(&self, req: &Request, chain: &mut ChainTracker, now_ms: u64) -> Judgment {
        let Some(ip) = req.src_ip else {
            return self.inspect(req);
        };
        let key = SourceKey::new(ip, self.cfg.chain.ipv6_prefix);
        if let Some(b) = chain.active_ban(key, now_ms) {
            return self.banned_judgment(&b);
        }
        let j = self.inspect(req);
        let may_ban = !self.intel.is_allowed(&ip);
        let o = chain.observe(key, event_for(&j), now_ms, may_ban);
        self.finalize(j, &o)
    }
```

with imports `use crate::chain::{event_for, BanRecord, ChainOutcome, ChainTracker, SourceKey};` and `use crate::intel::Intel;`. `build_reason`'s `banned` parameter stays (always `false` from `inspect`).

`crates/vft-core/src/lib.rs`:

```rust
pub use chain::{event_for, BanCause, BanRecord, ChainOutcome, ChainTracker, Event, SourceKey};
pub use config::{BanPolicy, Config};
```

`crates/vft-proxy/src/lib.rs` — temporary call-site update (Task 7 replaces it):

```rust
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn judge(state: &ProxyState, req: &VftRequest) -> Judgment {
    let mut chain = state.chain.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.shield.inspect_stateful(req, &mut chain, now_ms())
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"`; `cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Neutrality check** (`pred-task2.csv`) — the stateless path must be unchanged.
Expected: `NEUTRAL`.

- [ ] **Step 6: Log and commit**

Append: `| 2 | decision-driven chain, ban policy, time passed in | lib | 282 | 268 | 376 | 42.86% | 51.27% | 0.81% | – | – | stateless verdicts byte-identical; C1 fixed (unit tests) |`

```bash
git add -A && git commit -m "fix(core): drive kill chain from decisions, TTL ban policy, pure chain state (C1, M2, M3)"
```

---

### Task 3: Scoring fixes — no Safe from silence, per-field conflict, capped corroboration (H4, M1)

This task changes measured numbers on purpose. Measure and record them; do not tune toward a target.

**Files:**
- Modify: `crates/vft-core/src/detect.rs` (AI detector)
- Modify: `crates/vft-core/src/score.rs`
- Modify: `crates/vft-core/src/config.rs` (`ScoringConfig.corroboration_cap`)
- Modify: `config/shield.yaml`
- Test: `crates/vft-core/src/score.rs`, `crates/vft-core/src/shield.rs`

**Interfaces:**
- Consumes: `Scored` (Task 1), `band` (Task 1).
- Produces: `ScoringConfig.corroboration_cap: f32` (default 15.0).

- [ ] **Step 1: Write the failing tests**

In `crates/vft-core/src/shield.rs` tests:

```rust
    #[test]
    fn clean_header_does_not_damp_attack() {
        // H4: an unrelated clean field must not pull a Block down to Challenge.
        let mut req = Request::get("/items");
        req.query.push(("id".into(), "1 union select password from users".into()));
        req.headers.push(("Accept-Language".into(), "en".into()));
        let j = shield().inspect(&req);
        assert_eq!(j.verdict, Verdict::Block, "score {} {}", j.score, j.reason);
    }

    #[test]
    fn env_probe_not_damped_below_challenge() {
        let mut req = Request::get("/.env");
        req.headers.push(("Accept-Language".into(), "en".into()));
        let j = shield().inspect(&req);
        assert!(j.verdict.rank() >= Verdict::Challenge.rank(), "{:?} {}", j.verdict, j.score);
    }

    #[test]
    fn many_weak_signals_cannot_reach_block() {
        // M1: 25 values of `red;blue` must not add up to a Block.
        let mut req = Request::get("/form");
        for i in 0..25 {
            req.query.push((format!("c{i}"), "red;blue".into()));
        }
        let j = shield().inspect(&req);
        assert!(j.score < shield().config().scoring.block_at, "score {}", j.score);
        assert_ne!(j.verdict, Verdict::Block);
    }
```

In `crates/vft-core/src/score.rs` tests:

```rust
    fn scf(w: f32, field: &str, e: Evidence) -> Scored {
        Scored {
            engine: "t".into(),
            engine_weight: w,
            field: Some(FieldRef { loc: crate::request::Location::Query, name: field.into() }),
            evidence: e,
        }
    }

    #[test]
    fn corroboration_is_capped() {
        let cfg = ScoringConfig::default();
        let mut ev = vec![scf(1.0, "a", Evidence::new(FourValued::Dangerous, 0.5, vec![], "x"))];
        for i in 0..50 {
            ev.push(scf(1.0, &format!("f{i}"), Evidence::new(FourValued::Suspicious, 0.5, vec![], "w")));
        }
        let (s, _, _) = arbitrate(&ev, &cfg, false);
        assert!(s as f32 <= 50.0 + cfg.corroboration_cap + 0.5, "score {s}");
    }

    #[test]
    fn duplicate_construct_on_same_field_counts_once() {
        let cfg = ScoringConfig::default();
        let p = vec![crate::judgment::Pattern::new(crate::judgment::Family::CommandInjection, "shell-meta")];
        let one = vec![scf(1.0, "a", Evidence::new(FourValued::Suspicious, 0.5, p.clone(), "w"))];
        let two = vec![
            scf(1.0, "a", Evidence::new(FourValued::Suspicious, 0.5, p.clone(), "w")),
            scf(1.0, "a", Evidence::new(FourValued::Suspicious, 0.5, p, "w")),
        ];
        assert_eq!(arbitrate(&one, &cfg, false).0, arbitrate(&two, &cfg, false).0);
    }

    #[test]
    fn conflict_is_scoped_per_field_and_floored() {
        let cfg = ScoringConfig::default();
        // Safe on another field: no conflict.
        let ev = vec![
            scf(1.0, "id", Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint")),
            scf(1.0, "lang", Evidence::new(FourValued::Safe, 0.9, vec![], "ai")),
        ];
        let (_, v, c) = arbitrate(&ev, &cfg, false);
        assert!(!c);
        assert_eq!(v, Verdict::Block);
        // Safe on the same field: conflict, but never below the band the danger reaches alone.
        let ev2 = vec![
            scf(1.0, "id", Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint")),
            scf(1.0, "id", Evidence::new(FourValued::Safe, 0.9, vec![], "ai")),
        ];
        let (_, v2, c2) = arbitrate(&ev2, &cfg, false);
        assert!(c2);
        assert_eq!(v2, Verdict::Block);
    }
```

Add `use crate::judgment::FieldRef;` to the score test module.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-core --lib -- clean_header_does_not_damp many_weak corroboration duplicate_construct conflict_is_scoped`
Expected: compile error for `corroboration_cap`; after a stub field, `clean_header_does_not_damp_attack` fails with Challenge 87 and `many_weak_signals_cannot_reach_block` fails with score ≥ 90.

- [ ] **Step 3: Implement**

`crates/vft-core/src/config.rs` — add to `ScoringConfig` (struct and `Default`):

```rust
    /// Upper bound on the total points corroborating signals may add.
    pub corroboration_cap: f32,
```
```rust
            corroboration_cap: 15.0,
```

`crates/vft-core/src/detect.rs` — in `AiDetector::assess`, replace the `(value, weight)` block and its comment:

```rust
        // Absence of evidence is Belnap's None, not Safe: a clean field says
        // nothing about another field's attack (H4).
        let (value, weight) = if s >= 0.6 {
            (FourValued::Dangerous, s)
        } else if s >= 0.35 {
            (FourValued::Suspicious, s)
        } else {
            (FourValued::None, 0.0)
        };
```

`crates/vft-core/src/score.rs` — replace the body of `arbitrate` after the `hard_block` early return:

```rust
    let is_conflict = field_conflict(items, cfg.conflict_threshold);

    // One contribution per (field, construct): repeating the same weak signal
    // on one field does not corroborate itself (M1).
    let mut seen: std::collections::HashSet<(Option<FieldRef>, String)> = Default::default();
    let mut points: Vec<f32> = Vec::new();
    for s in items.iter().filter(|s| s.evidence.value.is_threat()) {
        let construct = s
            .evidence
            .patterns
            .first()
            .map_or_else(|| s.engine.clone(), |p| p.name.clone());
        if !seen.insert((s.field.clone(), construct)) {
            continue;
        }
        points.push(value_points(s.evidence.value) * s.evidence.weight * s.engine_weight);
    }
    let top = points.iter().copied().fold(0.0f32, f32::max);
    let corroboration = ((points.iter().sum::<f32>() - top) * 0.1).min(cfg.corroboration_cap);

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        // Damp, but never below the band the strongest danger reaches alone.
        score = (score * 0.9).max(band_floor(top, cfg));
    }
    let s = score.round().clamp(0.0, 100.0) as u8;
    (s, band(s, cfg), is_conflict)
}

/// A strong Safe and a strong Dangerous about the *same* field.
fn field_conflict(items: &[Scored], threshold: f32) -> bool {
    items
        .iter()
        .filter(|d| d.evidence.value == FourValued::Dangerous && d.evidence.weight >= threshold)
        .any(|d| {
            items.iter().any(|o| {
                o.field == d.field
                    && o.evidence.value == FourValued::Safe
                    && o.evidence.weight >= threshold
            })
        })
}

fn band_floor(points: f32, cfg: &ScoringConfig) -> f32 {
    [cfg.block_at, cfg.challenge_at, cfg.monitor_at]
        .into_iter()
        .map(f32::from)
        .find(|t| points >= *t)
        .unwrap_or(0.0)
}
```

Remove the now-unused `use crate::lattice::conflict` import from `score.rs` (keep `lattice::conflict` itself; its own tests still use it).

`config/shield.yaml` — under `scoring:` add:

```yaml
  corroboration_cap: 15   # max points corroborating weak signals may add in total
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"`; `cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Measure (numbers will change)**

```bash
cargo build --release -p vft-cli --example bench_http
B=./target/release/examples/bench_http
$B "$EVAL/run0/corpus.jsonl" "$EVAL/sp1/pred-task3.csv"
$B "$EVAL/run0/seeds.jsonl" "$EVAL/sp1/s-task3.csv"
$B "$EVAL/run0/mutants.jsonl" "$EVAL/sp1/m-task3.csv"
```

Record all three `engine=venusflytrap …` lines in `eval/RESULTS-SP1.md` as row 3 ("H4 + M1 scoring fixes"), with the mutation retention (mutant recall / seed recall). If mutation retention drops below 96% or mutant recall below 83.0%, note it as a regression in the row and tell the owner before continuing.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "fix(core): no Safe from silence, per-field conflict with band floor, capped corroboration (H4, M1)"
```

---

### Task 4: Canonical path for honeypot and recon (H5)

**Files:**
- Modify: `crates/vft-core/src/request.rs`
- Modify: `crates/vft-core/src/honeypot.rs`
- Modify: `crates/vft-core/src/detect.rs` (`intent_evidence`)

**Interfaces:**
- Produces: `pub fn canonical_path(raw: &str) -> String` and `Request::canonical_path(&self) -> String` in `vft_core::request`.

- [ ] **Step 1: Write the failing tests**

In `crates/vft-core/src/request.rs` add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_cases() {
        for (raw, want) in [
            ("/.git/config", "/.git/config"),
            ("/%2egit/config", "/.git/config"),
            ("//.git//config", "/.git/config"),
            ("/.%65nv", "/.env"),
            ("/a/b/../../.git/config", "/.git/config"),
            ("/x/..;/.git/config", "/.git/config"),
            ("/a\\..\\.env", "/.env"),
            ("/%252egit/config", "/.git/config"),
            ("/phpmyadmin/", "/phpmyadmin/"),
            ("/", "/"),
            ("", "/"),
            ("/../../..", "/"),
        ] {
            assert_eq!(canonical_path(raw), want, "raw {raw:?}");
        }
    }
}
```

In `crates/vft-core/src/honeypot.rs` tests:

```rust
    #[test]
    fn encoded_and_dotted_decoys_still_hit() {
        // H5
        let hp = Honeypot::new(&HoneypotConfig::default());
        for p in ["/%2egit/config", "//.git/config", "/a/../.git/config", "/x/..;/.git/config"] {
            assert!(hp.check(&Request::get(p)).is_some(), "missed {p}");
        }
    }
```

In `crates/vft-core/src/detect.rs` tests:

```rust
    #[test]
    fn intent_flags_encoded_env_probe() {
        let cfg = Config::default();
        for p in ["/.%65nv", "/%2eenv", "//.env"] {
            let e = intent_evidence(&Request::get(p), &cfg);
            assert_eq!(e.value, FourValued::Dangerous, "missed {p}");
        }
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-core --lib -- canonical_path encoded_and_dotted intent_flags_encoded`
Expected: compile error (`canonical_path` not found).

- [ ] **Step 3: Implement**

`crates/vft-core/src/request.rs` — add below `impl Request`:

```rust
/// Percent-decode to bytes, then UTF-8 lossily (never skips a layer on bad
/// UTF-8). Private stand-in until the recall-lift decoder
/// (`normalize::percent_decode_lossy`) lands — replace this then.
fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The path as a backend would resolve it: percent-decoded (up to 3 layers),
/// backslashes as slashes, matrix parameters (`;x`) dropped per segment, empty
/// and `.` segments removed, `..` resolved (RFC 3986 §5.2.4), trailing slash
/// kept. Used by honeypot and recon checks (H5). The path graph keeps the raw
/// path, because dot segments are the traversal evidence.
pub fn canonical_path(raw: &str) -> String {
    let mut s = raw.to_string();
    for _ in 0..3 {
        let d = percent_decode_lossy(&s);
        if d == s {
            break;
        }
        s = d;
    }
    let s = s.replace('\\', "/");
    let mut segs: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg.split(';').next().unwrap_or("") {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            other => segs.push(other),
        }
    }
    let mut out = String::with_capacity(s.len() + 1);
    for seg in &segs {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() || (s.ends_with('/') && !segs.is_empty()) {
        out.push('/');
    }
    out
}
```

and inside `impl Request`:

```rust
    pub fn canonical_path(&self) -> String {
        canonical_path(&self.path)
    }
```

`crates/vft-core/src/honeypot.rs` — in `check`, replace `let path = req.path.to_lowercase();` with:

```rust
        let path = req.canonical_path().to_lowercase();
```

`crates/vft-core/src/detect.rs` — in `intent_evidence`, replace `let path = req.path.to_lowercase();` with:

```rust
    let path = req.canonical_path().to_lowercase();
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"`; `cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Measure** (as in Task 3 Step 5, files `*-task4.csv`). Log row 4 "canonical path for honeypot/intent". Note the change in FP and TP from row 3 and say where it came from (the miss file lists the patterns).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "fix(core): canonical path for honeypot and recon checks (H5)"
```

---

### Task 5: Config validation and `config validate` (M6)

**Files:**
- Modify: `crates/vft-core/src/config.rs`
- Modify: `crates/vft-cli/src/main.rs`
- Modify: `config/shield.yaml`

**Interfaces:**
- Produces: `ConfigIssue { key: String, message: String }`; `Config::validate(&self) -> Result<(), Vec<ConfigIssue>>`; `Config::load(path: &Path) -> Result<Config, ConfigError>`; `ConfigError::Invalid(Vec<ConfigIssue>)`; `Config::load_or_default(Option<&Path>)` now errors on a missing explicit path. Later tasks add rules for their own sections to `validate`.

- [ ] **Step 1: Write the failing tests** — append to `crates/vft-core/src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn issues(yaml: &str) -> Vec<ConfigIssue> {
        let cfg: Config = serde_yaml::from_str(yaml).expect("parses");
        cfg.validate().err().unwrap_or_default()
    }

    #[test]
    fn defaults_and_shipped_yaml_validate() {
        assert!(Config::default().validate().is_ok());
        let shipped: Config =
            serde_yaml::from_str(include_str!("../../../config/shield.yaml")).expect("shipped yaml parses");
        assert!(shipped.validate().is_ok(), "{:?}", shipped.validate());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let r: Result<Config, _> = serde_yaml::from_str("scoring:\n  blok_at: 10\n");
        assert!(r.is_err(), "typo must not be silently ignored");
    }

    #[test]
    fn bad_values_report_their_key() {
        assert!(issues("scoring:\n  block_at: 0\n").iter().any(|i| i.key == "scoring.block_at"));
        assert!(issues("scoring:\n  weight_ai: .nan\n").iter().any(|i| i.key == "scoring.weight_ai"));
        assert!(issues("shield:\n  max_payload: 0\n").iter().any(|i| i.key == "shield.max_payload"));
        assert!(issues("chain:\n  ban_policy:\n    ttl_max_secs: 1\n")
            .iter()
            .any(|i| i.key == "chain.ban_policy.ttl_max_secs"));
    }

    #[test]
    fn missing_explicit_file_is_an_error() {
        let r = Config::load_or_default(Some(std::path::Path::new("Z:/definitely/not/here.yaml")));
        assert!(r.is_err());
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-core --lib config::tests`
Expected: compile error (`validate`, `ConfigIssue` missing).

- [ ] **Step 3: Implement**

`crates/vft-core/src/config.rs`:
- Change every `#[serde(default)]` on a config struct (`Config`, `ShieldConfig`, `ScoringConfig`, `ChainConfig`, `BanPolicy`, `HoneypotConfig`) to `#[serde(default, deny_unknown_fields)]`.
- Replace `ConfigError` and the `impl Config` loader with:

```rust
/// One problem with one option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    pub key: String,
    pub message: String,
}

impl std::fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid config: {}", .0.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<ConfigIssue>),
}

impl Config {
    /// Load and validate a YAML file. A missing file is an error.
    pub fn load(path: &std::path::Path) -> Result<Config, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&s)?;
        cfg.validate().map_err(ConfigError::Invalid)?;
        Ok(cfg)
    }

    /// `None` means built-in defaults; `Some(path)` must exist and validate.
    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Config, ConfigError> {
        match path {
            Some(p) => Config::load(p),
            None => Ok(Config::default()),
        }
    }

    /// Per-key bounds and cross-field rules. Every issue names its option key.
    pub fn validate(&self) -> Result<(), Vec<ConfigIssue>> {
        let mut v: Vec<ConfigIssue> = Vec::new();
        let mut bad = |key: &str, message: String| v.push(ConfigIssue { key: key.into(), message });

        let sh = &self.shield;
        if sh.max_payload < 1024 {
            bad("shield.max_payload", format!("must be >= 1024, got {}", sh.max_payload));
        }
        if !(1..=32).contains(&sh.decode_cap) {
            bad("shield.decode_cap", format!("must be in 1..=32, got {}", sh.decode_cap));
        }
        if sh.deep_threshold == 0 || sh.deep_threshold > sh.decode_cap {
            bad("shield.deep_threshold", format!("must be in 1..=decode_cap, got {}", sh.deep_threshold));
        }

        let s = &self.scoring;
        for (key, w) in [
            ("scoring.weight_graph", s.weight_graph),
            ("scoring.weight_signature", s.weight_signature),
            ("scoring.weight_intent", s.weight_intent),
            ("scoring.weight_api", s.weight_api),
            ("scoring.weight_ai", s.weight_ai),
        ] {
            if !w.is_finite() || !(0.0..=2.0).contains(&w) {
                bad(key, format!("must be a finite number in [0, 2], got {w}"));
            }
        }
        if !s.conflict_threshold.is_finite() || !(0.0..=1.0).contains(&s.conflict_threshold) {
            bad("scoring.conflict_threshold", format!("must be in [0, 1], got {}", s.conflict_threshold));
        }
        if !s.corroboration_cap.is_finite() || !(0.0..=50.0).contains(&s.corroboration_cap) {
            bad("scoring.corroboration_cap", format!("must be in [0, 50], got {}", s.corroboration_cap));
        }
        if s.monitor_at == 0 {
            bad("scoring.monitor_at", "must be >= 1 (0 would flag every request)".into());
        }
        if !(s.monitor_at < s.challenge_at && s.challenge_at < s.block_at && s.block_at <= 100) {
            bad(
                "scoring.block_at",
                format!(
                    "bands must satisfy monitor_at < challenge_at < block_at <= 100, got {}/{}/{}",
                    s.monitor_at, s.challenge_at, s.block_at
                ),
            );
        }

        let c = &self.chain;
        if c.window_secs == 0 {
            bad("chain.window_secs", "must be >= 1".into());
        }
        if c.max_sources < 64 {
            bad("chain.max_sources", format!("must be >= 64, got {}", c.max_sources));
        }
        if c.events_per_source == 0 {
            bad("chain.events_per_source", "must be >= 1".into());
        }
        if !(1..=128).contains(&c.ipv6_prefix) {
            bad("chain.ipv6_prefix", format!("must be in 1..=128, got {}", c.ipv6_prefix));
        }
        let b = &c.ban_policy;
        if b.exploitation_blocks == 0 {
            bad("chain.ban_policy.exploitation_blocks", "must be >= 1".into());
        }
        if b.within_secs == 0 {
            bad("chain.ban_policy.within_secs", "must be >= 1".into());
        }
        if b.ttl_secs == 0 {
            bad("chain.ban_policy.ttl_secs", "must be >= 1".into());
        }
        if b.ttl_max_secs < b.ttl_secs {
            bad("chain.ban_policy.ttl_max_secs", format!("must be >= ttl_secs ({}), got {}", b.ttl_secs, b.ttl_max_secs));
        }
        if b.max_bans < 64 {
            bad("chain.ban_policy.max_bans", format!("must be >= 64, got {}", b.max_bans));
        }

        for (key, list) in [
            ("honeypot.decoy_paths", &self.honeypot.decoy_paths),
            ("honeypot.sensitive_paths", &self.honeypot.sensitive_paths),
        ] {
            if let Some(p) = list.iter().find(|p| !p.starts_with('/')) {
                bad(key, format!("paths must start with '/', got {p:?}"));
            }
        }

        if v.is_empty() {
            Ok(())
        } else {
            Err(v)
        }
    }
}
```

`config/shield.yaml` — under `chain:` add the new keys with their defaults:

```yaml
  ipv6_prefix: 64         # IPv6 sources are aggregated to this prefix
  ban_policy:
    on_honeypot: true
    on_exfiltration_block: true
    exploitation_blocks: 3  # ban after this many exploitation blocks ...
    within_secs: 600        # ... within this many seconds
    ttl_secs: 3600          # first ban length; doubles on re-offence
    ttl_max_secs: 86400
    max_bans: 100000
```

`crates/vft-cli/src/main.rs` — add the subcommand:

```rust
    /// Configuration tools.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
```
```rust
#[derive(Subcommand)]
enum ConfigCmd {
    /// Parse and validate a config file; exit 1 and list every issue if invalid.
    Validate { file: PathBuf },
}
```
```rust
        Command::Config { action: ConfigCmd::Validate { file } } => match Config::load(&file) {
            Ok(_) => println!("{}: ok", file.display()),
            Err(e) => {
                eprintln!("{}: {e}", file.display());
                std::process::exit(1);
            }
        },
```

- [ ] **Step 4: Run the tests and the CLI**

```bash
cargo test --workspace 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-targets -- -D warnings
cargo run -q -p vft-cli -- config validate config/shield.yaml
printf 'scoring:\n  block_at: 0\n' > "$EVAL/sp1/bad.yaml"; cargo run -q -p vft-cli -- config validate "$EVAL/sp1/bad.yaml"; echo "exit=$?"
```

Expected: tests pass; `config/shield.yaml: ok`; the bad file prints `scoring.block_at: bands must satisfy …` and `exit=1`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(config): reject unknown keys, validate bounds and bands, config validate (M6)"
```

---

### Task 6: Adapter — inspect every forwarded byte (C4, L4)

**Files:**
- Create: `crates/vft-proxy/src/adapt.rs`
- Modify: `crates/vft-proxy/src/lib.rs` (use the adapter; re-export `hyper::http`)
- Modify: `crates/vft-core/src/request.rs` (`non_utf8_headers`, skip list)
- Modify: `crates/vft-core/src/judgment.rs` (`Family::Limit`)
- Modify: `crates/vft-core/src/shield.rs` (limit evidence)
- Modify: `crates/vft-cli/examples/bench_http.rs` (struct literal)

**Interfaces:**
- Produces: `vft_proxy::adapt::from_parts(parts: &http::request::Parts, body: &[u8], src_ip: Option<IpAddr>) -> vft_core::Request`; `Request.non_utf8_headers: Vec<String>`; `Family::Limit`; construct name `limit.header-non-utf8`; `pub use hyper::http;` from `vft_proxy`.

- [ ] **Step 1: Write the failing tests** — new file `crates/vft-proxy/src/adapt.rs` starts with its tests at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::{self, HeaderValue};
    use vft_core::{Config, Shield, Verdict};

    fn parts_with_cookie(raw: &[u8]) -> http::request::Parts {
        http::Request::builder()
            .uri("/x?a=1")
            .header("cookie", HeaderValue::from_bytes(raw).unwrap())
            .header("host", "example.test")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn non_utf8_cookie_is_still_inspected() {
        // C4: one obs-text byte must not hide the cookie from inspection.
        let parts = parts_with_cookie(b"id=1 union select password from users; z=\xff");
        let req = from_parts(&parts, b"", None);
        assert_eq!(req.non_utf8_headers, vec!["cookie".to_string()]);
        assert!(req.cookies.iter().any(|(k, v)| k == "id" && v.contains("union select")));
        let j = Shield::new(Config::default()).inspect(&req);
        assert_eq!(j.verdict, Verdict::Block, "{} {}", j.score, j.reason);
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.header-non-utf8")));
    }

    #[test]
    fn host_is_inspected_and_raw_cookie_not_double_counted() {
        // L4
        let parts = parts_with_cookie(b"a=1; b=2");
        let req = from_parts(&parts, b"", None);
        let names: Vec<String> = req.fields().iter().map(|f| f.name.to_ascii_lowercase()).collect();
        assert!(names.contains(&"host".to_string()));
        assert!(!names.contains(&"cookie".to_string()), "raw Cookie header must not be inspected twice");
        assert_eq!(req.cookies.len(), 2);
    }

    #[test]
    fn query_and_percent_decoding() {
        let q = form_urlencoded_parse("x=1%20union&y=2");
        assert_eq!(q[0].1, "1 union");
        assert_eq!(percent_decode("%EF%BC%B3"), "\u{ff33}");
        assert_eq!(percent_decode("100%done"), "100%done");
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-proxy --lib adapt`
Expected: compile error (module not declared / `from_parts` missing).

- [ ] **Step 3: Implement**

`crates/vft-core/src/request.rs`:
- Add to `Request` (after `src_ip`):

```rust
    /// Names of headers whose bytes were not valid UTF-8. Their values are
    /// decoded lossily and still inspected; the fact itself is evidence (C4).
    pub non_utf8_headers: Vec<String>,
```

- In `fields()`, change the skip list so `Host` is inspected and the raw `Cookie` header is not counted twice (parsed cookies cover it):

```rust
            if matches!(
                k.to_ascii_lowercase().as_str(),
                "connection" | "content-length" | "accept-encoding" | "cookie"
            ) {
```

`crates/vft-core/src/judgment.rs` — add `Limit` to `Family` (after `Intel`):

```rust
    /// The request hit an inspection limit or carried bytes that could not be
    /// decoded as-is.
    Limit,
```

`crates/vft-core/src/shield.rs` — in `inspect`, after the per-field loop:

```rust
        if let Some(first) = req.non_utf8_headers.first() {
            rec.record(
                "adapter",
                self.cfg.scoring.weight_api,
                Some(FieldRef::header(first)),
                Evidence::new(
                    FourValued::Suspicious,
                    0.6,
                    vec![Pattern::new(Family::Limit, "limit.header-non-utf8")],
                    format!("non-UTF-8 bytes in header(s): {}", req.non_utf8_headers.join(", ")),
                ),
            );
        }
```

`crates/vft-cli/examples/bench_http.rs` — in the `Request { … }` literal add `non_utf8_headers: Vec::new(),` after `src_ip: None,`.

`crates/vft-proxy/src/adapt.rs` — above the tests:

```rust
//! Hyper request parts → `vft_core::Request`. Every header that is forwarded
//! is also inspected: bytes that are not valid UTF-8 are decoded lossily and
//! recorded in `non_utf8_headers`, which the engine turns into evidence (C4).

use std::net::IpAddr;

use hyper::http::request::Parts;
use vft_core::Request as VftRequest;

pub fn from_parts(parts: &Parts, body: &[u8], src_ip: Option<IpAddr>) -> VftRequest {
    let mut req = VftRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        body: body.to_vec(),
        src_ip,
        ..Default::default()
    };
    if let Some(q) = parts.uri.query() {
        req.query = form_urlencoded_parse(q);
    }
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        let value = match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                req.non_utf8_headers.push(name.to_string());
                String::from_utf8_lossy(v.as_bytes()).into_owned()
            }
        };
        if name.eq_ignore_ascii_case("cookie") {
            req.cookies.extend(parse_cookies(&value));
        }
        req.headers.push((name.to_string(), value));
    }
    req
}

pub(crate) fn form_urlencoded_parse(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

/// Decode to bytes first, then UTF-8 lossily, so percent-encoded UTF-8 keeps
/// its real code points for the engine's confusable folding.
pub(crate) fn percent_decode(s: &str) -> String {
    let replaced = s.replace('+', " ");
    let b = replaced.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                bytes.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn parse_cookies(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?.trim().to_string();
            let v = it.next().unwrap_or("").trim().to_string();
            (!k.is_empty()).then_some((k, v))
        })
        .collect()
}
```

`crates/vft-proxy/src/lib.rs`:
- Add `pub mod adapt;` and `pub use hyper::http;`.
- Delete `to_vft`, `form_urlencoded_parse`, `percent_decode`, `parse_cookies` and the tests `cookie_and_query_parse` and `percent_decode_preserves_utf8` (they now live in `adapt.rs`).
- In `handle`, replace `let vreq = to_vft(&parts, &collected, peer);` with `let vreq = adapt::from_parts(&parts, &collected, peer.map(|p| p.ip()));`.
- In the test `fullwidth_encoded_sqli_not_evaded`, call `adapt::form_urlencoded_parse`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"`; `cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Measure** (as in Task 3 Step 5, files `*-task6.csv`). The library path now also inspects `Host`. Log row 6 and say how FP/TP moved.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "fix(proxy): inspect every forwarded header byte; inspect Host; no cookie double count (C4, L4)"
```

---

### Task 7: Sharded chain store and `Pipeline::decide` (H3)

**Files:**
- Create: `crates/vft-proxy/src/pipeline.rs`
- Modify: `crates/vft-proxy/src/lib.rs`
- Modify: `crates/vft-core/src/config.rs` (`ProxyConfig { trusted_proxies }` + validation)
- Modify: `crates/vft-cli/src/main.rs` (serve wiring)

**Interfaces:**
- Consumes: `ChainTracker`, `SourceKey`, `event_for`, `Shield::{inspect, finalize, banned_judgment, intel}` (Task 2); `adapt::from_parts` (Task 6).
- Produces:
  - `vft_core::config::ProxyConfig { trusted_proxies: Vec<String> }` at `Config.proxy`
  - `vft_proxy::pipeline::ChainStore::new(&ChainConfig)`, `.active_ban(SourceKey, u64) -> Option<BanRecord>`, `.observe(SourceKey, Event, u64, bool) -> ChainOutcome`, `.lift(SourceKey) -> bool`
  - `vft_proxy::pipeline::Pipeline::new(shield: Arc<Shield>) -> Pipeline`, `.client_ip(peer: IpAddr, headers: &HeaderMap) -> IpAddr`, `.decide(&Parts, &[u8], peer: Option<IpAddr>, now_ms: u64) -> Decision`, `.shield() -> &Shield`
  - `pub struct Decision { pub request: vft_core::Request, pub judgment: Judgment, pub src: Option<SourceKey> }`
  - `vft_proxy::now_ms() -> u64`

- [ ] **Step 1: Write the failing tests** — at the bottom of the new `crates/vft-proxy/src/pipeline.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::{self, HeaderValue};
    use vft_core::{Config, Verdict};

    const CHROME: &[(&str, &str)] = &[
        ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        ("accept-language", "en-US,en;q=0.9"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("sec-ch-ua", "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\""),
        ("cookie", "_ga=GA1.1.123.456; session=abc; theme=dark"),
    ];
    const FIREFOX: &[(&str, &str)] = &[
        ("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
    ];
    const SAFARI: &[(&str, &str)] = &[
        ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("accept-language", "en-GB,en;q=0.9"),
    ];

    fn parts(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = http::Request::builder().uri(uri).header("host", "shop.example");
        for (k, v) in headers {
            b = b.header(*k, HeaderValue::from_str(v).unwrap());
        }
        b.body(()).unwrap().into_parts().0
    }

    fn pipeline() -> Pipeline {
        Pipeline::new(Arc::new(Shield::new(Config::default())))
    }

    #[test]
    fn real_browsers_are_never_banned() {
        // C1 acceptance: Chrome, Firefox, Safari default header sets.
        let p = pipeline();
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        for (name, hs) in [("chrome", CHROME), ("firefox", FIREFOX), ("safari", SAFARI)] {
            for i in 0..10 {
                let d = p.decide(&parts("/products?page=2", hs), b"", Some(peer), i * 500);
                assert_eq!(d.judgment.verdict, Verdict::Allow, "{name} #{i}: {}", d.judgment.reason);
                assert!(!d.judgment.banned_source, "{name} #{i} banned");
                assert_eq!(vft_core::event_for(&d.judgment), vft_core::Event::Benign);
            }
        }
    }

    #[test]
    fn exfiltration_block_bans_and_fast_tracks() {
        let p = pipeline();
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let d1 = p.decide(&parts("/items?id=1%20union%20select%20password%20from%20users", CHROME), b"", Some(peer), 0);
        assert!(d1.judgment.banned_source);
        let d2 = p.decide(&parts("/", CHROME), b"", Some(peer), 1_000);
        assert!(d2.judgment.banned_source);
        assert_eq!(d2.judgment.verdict, Verdict::Block);
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(p.decide(&parts("/", CHROME), b"", Some(other), 1_000).judgment.verdict, Verdict::Allow);
    }

    #[test]
    fn client_ip_trusts_xff_only_from_trusted_proxies() {
        let mut cfg = Config::default();
        cfg.proxy.trusted_proxies = vec!["10.0.0.1".into()];
        let p = Pipeline::new(Arc::new(Shield::new(cfg)));
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1, 10.0.0.1"));
        assert_eq!(p.client_ip("10.0.0.1".parse().unwrap(), &h), "198.51.100.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.client_ip("192.0.2.5".parse().unwrap(), &h), "192.0.2.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    #[ignore = "throughput measurement; run with --ignored --release"]
    fn decide_throughput_close_to_stateless_inspect() {
        // H3 acceptance: 8-thread decide >= 0.75x 8-thread stateless inspect.
        let p = Arc::new(pipeline());
        let mut q = String::from("/search?");
        for i in 0..6 {
            q.push_str(&format!("f{i}={}&", "a%3Bb%20".repeat(2000)));
        }
        let work = Arc::new(parts(&q, CHROME));
        let run = |stateful: bool| {
            let t = std::time::Instant::now();
            let hs: Vec<_> = (0..8)
                .map(|n| {
                    let (p, w) = (p.clone(), work.clone());
                    std::thread::spawn(move || {
                        for i in 0..50u64 {
                            let ip = IpAddr::from([10, 9, n as u8, i as u8]);
                            if stateful {
                                let _ = p.decide(&w, b"", Some(ip), i);
                            } else {
                                let _ = p.shield().inspect(&adapt::from_parts(&w, b"", Some(ip)));
                            }
                        }
                    })
                })
                .collect();
            hs.into_iter().for_each(|h| h.join().unwrap());
            t.elapsed().as_secs_f64()
        };
        let (stateless, stateful) = (run(false), run(true));
        eprintln!("stateless {stateless:.3}s stateful {stateful:.3}s ratio {:.2}", stateless / stateful);
        assert!(stateless / stateful >= 0.75);
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-proxy --lib pipeline`
Expected: compile error (module missing).

- [ ] **Step 3: Implement**

`crates/vft-core/src/config.rs`:

```rust
/// Data-plane settings that the engine itself does not use.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Peers whose `X-Forwarded-For` is trusted (exact IPs).
    pub trusted_proxies: Vec<String>,
}
```

Add `pub proxy: ProxyConfig,` to `Config`, and to `validate`:

```rust
        for p in &self.proxy.trusted_proxies {
            if p.parse::<std::net::IpAddr>().is_err() {
                bad("proxy.trusted_proxies", format!("not an IP address: {p:?}"));
            }
        }
```

`crates/vft-proxy/src/pipeline.rs` — above the tests:

```rust
//! The data-plane decision function shared by the proxy handler and the eval:
//! ban fast-track → adapt → pure inspect (no lock) → sharded chain observe →
//! finalize. No lock is held during inspection (H3).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use hyper::http::request::Parts;
use hyper::http::HeaderMap;
use vft_core::config::ChainConfig;
use vft_core::{
    event_for, BanRecord, ChainOutcome, ChainTracker, Event, Judgment, Request as VftRequest, Shield,
    SourceKey,
};

use crate::adapt;

const SHARDS: usize = 64;

pub struct ChainStore {
    shards: Vec<Mutex<ChainTracker>>,
}

impl ChainStore {
    pub fn new(cfg: &ChainConfig) -> Self {
        let mut per = cfg.clone();
        per.max_sources = (cfg.max_sources / SHARDS).max(1);
        per.ban_policy.max_bans = (cfg.ban_policy.max_bans / SHARDS).max(1);
        ChainStore { shards: (0..SHARDS).map(|_| Mutex::new(ChainTracker::new(&per))).collect() }
    }

    fn shard(&self, key: &SourceKey) -> MutexGuard<'_, ChainTracker> {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        let i = (h.finish() as usize) % SHARDS;
        self.shards[i].lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn active_ban(&self, key: SourceKey, now_ms: u64) -> Option<BanRecord> {
        self.shard(&key).active_ban(key, now_ms)
    }

    pub fn observe(&self, key: SourceKey, ev: Event, now_ms: u64, may_ban: bool) -> ChainOutcome {
        self.shard(&key).observe(key, ev, now_ms, may_ban)
    }

    pub fn lift(&self, key: SourceKey) -> bool {
        self.shard(&key).lift(key)
    }
}

pub struct Decision {
    pub request: VftRequest,
    pub judgment: Judgment,
    pub src: Option<SourceKey>,
}

pub struct Pipeline {
    shield: Arc<Shield>,
    chain: ChainStore,
    trusted: Vec<IpAddr>,
}

impl Pipeline {
    pub fn new(shield: Arc<Shield>) -> Self {
        let cfg = shield.config();
        let trusted = cfg.proxy.trusted_proxies.iter().filter_map(|s| s.parse().ok()).collect();
        let chain = ChainStore::new(&cfg.chain);
        Pipeline { shield, chain, trusted }
    }

    pub fn shield(&self) -> &Shield {
        &self.shield
    }

    pub fn chain(&self) -> &ChainStore {
        &self.chain
    }

    /// The client address: the peer, unless the peer is a trusted proxy, in
    /// which case the right-most untrusted `X-Forwarded-For` hop.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let canon = |ip: IpAddr| SourceKey::new(ip, 128).ip();
        if !self.trusted.contains(&canon(peer)) {
            return peer;
        }
        let mut hops: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        while let Some(ip) = hops.pop() {
            if !self.trusted.contains(&canon(ip)) {
                return ip;
            }
        }
        peer
    }

    pub fn decide(&self, parts: &Parts, body: &[u8], peer: Option<IpAddr>, now_ms: u64) -> Decision {
        let ip = peer.map(|p| self.client_ip(p, &parts.headers));
        let request = adapt::from_parts(parts, body, ip);
        let Some(ip) = ip else {
            let judgment = self.shield.inspect(&request);
            return Decision { request, judgment, src: None };
        };
        let key = SourceKey::new(ip, self.shield.config().chain.ipv6_prefix);
        if let Some(ban) = self.chain.active_ban(key, now_ms) {
            let judgment = self.shield.banned_judgment(&ban);
            return Decision { request, judgment, src: Some(key) };
        }
        let judgment = self.shield.inspect(&request);
        let may_ban = !self.shield.intel().is_allowed(&ip);
        let outcome = self.chain.observe(key, event_for(&judgment), now_ms, may_ban);
        let judgment = self.shield.finalize(judgment, &outcome);
        Decision { request, judgment, src: Some(key) }
    }
}
```

`crates/vft-proxy/src/lib.rs`:
- Add `pub mod pipeline;`, make `now_ms` `pub`.
- Replace `ProxyState` and its constructor:

```rust
pub struct ProxyState {
    pub pipeline: pipeline::Pipeline,
    pub upstream: String,
    pub audit: audit::AuditLog,
    /// If true, Block/Challenge are stopped; otherwise everything is forwarded.
    pub enforce: bool,
}

impl ProxyState {
    pub fn new(shield: Shield, upstream: String, audit_path: Option<String>, enforce: bool) -> Self {
        ProxyState {
            pipeline: pipeline::Pipeline::new(std::sync::Arc::new(shield)),
            upstream,
            audit: audit::AuditLog::new(audit_path),
            enforce,
        }
    }
}
```

- Delete `judge` and the `ChainTracker`/`Mutex` imports. In `handle`:

```rust
    let decision = state.pipeline.decide(&parts, &collected, peer.map(|p| p.ip()), now_ms());
    state.audit.record(&decision.request, &decision.judgment);
    let judgment = decision.judgment;
```

- Rewrite the remaining lib tests to go through the pipeline:

```rust
    #[test]
    fn judges_sqli_as_block() {
        let st = state();
        let parts = hyper::http::Request::builder()
            .uri("/x?id=1%20union%20select%20a,b")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let d = st.pipeline.decide(&parts, b"", None, 0);
        assert_eq!(d.judgment.verdict, Verdict::Block);
    }
```

  For `fullwidth_encoded_sqli_not_evaded`, build parts with `.uri(format!("/x?id={enc}"))` and assert on `st.pipeline.decide(&parts, b"", None, 0).judgment`.

- [ ] **Step 4: Run the tests, including the throughput measurement**

```bash
cargo test --workspace 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-targets -- -D warnings
cargo test --release -p vft-proxy --lib decide_throughput -- --ignored --nocapture
```

Expected: all pass; the ignored test prints a ratio ≥ 0.75. Record the ratio in `eval/RESULTS-SP1.md` under a "Throughput" note.

If `real_browsers_are_never_banned` fails on a verdict (not a ban), that is a real false positive on stock browser headers. Do **not** edit the fixture to make it pass. Record which header and construct fired, and stop and report it to the owner.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(proxy): Pipeline::decide with sharded chain store, no lock during inspection (H3)"
```

---

### Task 8: Hardened proxy front end (H2, H6, M9, L1, L3)

**Files:**
- Modify: `crates/vft-core/src/config.rs` (`LimitsConfig`, `ProxyConfig.decision_headers`, validation)
- Rewrite: `crates/vft-proxy/src/lib.rs` (server, forwarder)
- Modify: `crates/vft-proxy/Cargo.toml` (tokio `time` in normal deps)
- Create: `crates/vft-proxy/tests/hardening.rs`
- Modify: `config/shield.yaml`

**Interfaces:**
- Consumes: `Pipeline::decide`, `now_ms` (Task 7).
- Produces:
  - `LimitsConfig { max_body: usize, max_headers: usize, max_connections: usize, header_read_timeout_ms: u64, body_read_timeout_ms: u64, upstream_connect_timeout_ms: u64, upstream_response_timeout_ms: u64 }` at `Config.limits`
  - `DecisionHeaders { Off, Upstream }` at `ProxyConfig.decision_headers`
  - `vft_proxy::serve(state, bind)` and `vft_proxy::serve_listener(state: Arc<ProxyState>, listener: TcpListener) -> anyhow::Result<()>`

- [ ] **Step 1: Write the failing tests** — `crates/vft-proxy/tests/hardening.rs`:

```rust
//! End-to-end proxy hardening tests over real loopback sockets, with short
//! configured timeouts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vft_core::{Config, Shield};
use vft_proxy::{serve_listener, ProxyState};

struct Stub {
    addr: std::net::SocketAddr,
    conns: Arc<AtomicUsize>,
    last: Arc<Mutex<Vec<u8>>>,
}

/// Upstream stub. `respond = false` accepts and then never answers.
async fn stub(respond: bool) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(Vec::new()));
    let (c, la) = (conns.clone(), last.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let la = la.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = s.read(&mut buf).await.unwrap_or(0);
                *la.lock().unwrap() = buf[..n].to_vec();
                if respond {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                } else {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }
    });
    Stub { addr, conns, last }
}

async fn proxy(cfg: Config, upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    let state = Arc::new(ProxyState::new(Shield::new(cfg), format!("http://{upstream}"), None, true));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve_listener(state, l));
    addr
}

fn short_cfg() -> Config {
    let mut c = Config::default();
    c.limits.max_body = 64 * 1024;
    c.limits.header_read_timeout_ms = 300;
    c.limits.body_read_timeout_ms = 300;
    c.limits.upstream_response_timeout_ms = 300;
    c
}

async fn send(addr: std::net::SocketAddr, raw: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    // The proxy may answer (e.g. 413) and close before the whole body is sent.
    let _ = s.write_all(raw).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn oversized_body_is_413_before_upstream() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let body = vec![b'a'; 200 * 1024];
    let mut raw = format!("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    raw.extend_from_slice(&body);
    let resp = send(p, &raw).await;
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_utf8_cookie_attack_is_blocked_and_never_forwarded() {
    // C4 end to end
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let mut raw = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nCookie: id=1 union select password from users; z=".to_vec();
    raw.push(0xff);
    raw.extend_from_slice(b"\r\n\r\n");
    let resp = send(p, &raw).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped_and_forwarding_headers_added() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let raw = b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close, X-Internal-Auth\r\nX-Internal-Auth: s3cret\r\nKeep-Alive: timeout=5\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nTE: trailers\r\n\r\n";
    let resp = send(p, raw).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let fwd = String::from_utf8_lossy(&up.last.lock().unwrap()).to_ascii_lowercase();
    for h in ["x-internal-auth", "keep-alive:", "proxy-authorization", "\r\nte:"] {
        assert!(!fwd.contains(h), "forwarded {h}: {fwd}");
    }
    assert!(fwd.contains("x-forwarded-for: 127.0.0.1"), "{fwd}");
    assert!(fwd.contains("via: 1.1 venusflytrap"), "{fwd}");
}

#[tokio::test]
async fn upgrade_is_refused() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let resp = send(p, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, close\r\nUpgrade: h2c\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn hung_upstream_is_504() {
    let up = stub(false).await;
    let p = proxy(short_cfg(), up.addr).await;
    let t = Instant::now();
    let resp = send(p, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 504"), "{resp}");
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn slowloris_connection_is_closed() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let mut s = TcpStream::connect(p).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    assert!(r.is_ok(), "connection still open after header-read timeout");
}

#[tokio::test]
async fn no_decision_headers_or_error_text_reach_the_client() {
    // L1, L3: upstream down → generic 502, no score oracle.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let p = proxy(short_cfg(), dead).await;
    let resp = send(p, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.to_ascii_lowercase();
    assert!(resp.starts_with("http/1.1 502"), "{resp}");
    assert!(!resp.contains("x-venusflytrap"), "{resp}");
    assert!(!resp.contains("error"), "{resp}");
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-proxy --test hardening`
Expected: compile errors (`serve_listener`, `limits` missing).

- [ ] **Step 3: Implement**

`crates/vft-proxy/Cargo.toml` — make the normal tokio dependency:

```toml
tokio = { version = "1.41.0", features = ["rt-multi-thread", "net", "macros", "sync", "io-util", "time"] }
```

`crates/vft-core/src/config.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionHeaders {
    /// Never emit decision headers.
    #[default]
    Off,
    /// Add X-Venusflytrap-* to the forwarded request only (never to the client).
    Upstream,
}

/// Request-level limits on the data plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_body: usize,
    pub max_headers: usize,
    pub max_connections: usize,
    pub header_read_timeout_ms: u64,
    pub body_read_timeout_ms: u64,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_response_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_body: 1024 * 1024,
            max_headers: 100,
            max_connections: 1024,
            header_read_timeout_ms: 10_000,
            body_read_timeout_ms: 30_000,
            upstream_connect_timeout_ms: 5_000,
            upstream_response_timeout_ms: 30_000,
        }
    }
}
```

Add `pub decision_headers: DecisionHeaders,` to `ProxyConfig`, `pub limits: LimitsConfig,` to `Config`, and to `validate`:

```rust
        let l = &self.limits;
        if l.max_body < 1024 {
            bad("limits.max_body", format!("must be >= 1024, got {}", l.max_body));
        }
        if !(8..=1000).contains(&l.max_headers) {
            bad("limits.max_headers", format!("must be in 8..=1000, got {}", l.max_headers));
        }
        if l.max_connections == 0 {
            bad("limits.max_connections", "must be >= 1".into());
        }
        for (key, ms) in [
            ("limits.header_read_timeout_ms", l.header_read_timeout_ms),
            ("limits.body_read_timeout_ms", l.body_read_timeout_ms),
            ("limits.upstream_connect_timeout_ms", l.upstream_connect_timeout_ms),
            ("limits.upstream_response_timeout_ms", l.upstream_response_timeout_ms),
        ] {
            if ms == 0 {
                bad(key, "must be >= 1".into());
            }
        }
```

`config/shield.yaml` — append:

```yaml
proxy:
  trusted_proxies: []       # peers whose X-Forwarded-For is trusted (exact IPs)
  decision_headers: off     # off | upstream (never sent to clients)

limits:
  max_body: 1048576         # bytes; larger bodies get 413 before any upstream connection
  max_headers: 100
  max_connections: 1024
  header_read_timeout_ms: 10000
  body_read_timeout_ms: 30000
  upstream_connect_timeout_ms: 5000
  upstream_response_timeout_ms: 30000
```

`crates/vft-proxy/src/lib.rs` — replace everything except `pub mod adapt; pub mod audit; pub mod pipeline; pub use hyper::http; now_ms()` and the `ProxyState` fields with:

```rust
//! FR9/FR10 — Hardened reverse proxy. Every request runs through
//! `Pipeline::decide`; Allow/Monitor forward through one pooled client with
//! timeouts, hop-by-hop headers stripped and forwarding headers added;
//! Block/Challenge get a generic 403. Decision headers never reach clients.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use vft_core::config::{DecisionHeaders, LimitsConfig};
use vft_core::{Judgment, Shield, Verdict};

pub mod adapt;
pub mod audit;
pub mod pipeline;
pub use hyper::http;

type Body = BoxBody<Bytes, hyper::Error>;

pub struct ProxyState {
    pub pipeline: pipeline::Pipeline,
    pub upstream: String,
    pub audit: audit::AuditLog,
    pub enforce: bool,
    client: Client<HttpConnector, Full<Bytes>>,
    limits: LimitsConfig,
    decision_headers: DecisionHeaders,
}

impl ProxyState {
    pub fn new(shield: Shield, upstream: String, audit_path: Option<String>, enforce: bool) -> Self {
        let limits = shield.config().limits.clone();
        let decision_headers = shield.config().proxy.decision_headers;
        let mut conn = HttpConnector::new();
        conn.set_connect_timeout(Some(Duration::from_millis(limits.upstream_connect_timeout_ms)));
        let client = Client::builder(TokioExecutor::new()).build(conn);
        ProxyState {
            pipeline: pipeline::Pipeline::new(Arc::new(shield)),
            upstream,
            audit: audit::AuditLog::new(audit_path),
            enforce,
            client,
            limits,
            decision_headers,
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn text(status: StatusCode, msg: &'static str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from_static(msg.as_bytes())).map_err(|n| match n {}).boxed());
    *r.status_mut() = status;
    r
}

/// RFC 9110 §7.6.1 hop-by-hop headers, plus any header named in `Connection`.
fn strip_hop_by_hop(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in [
        "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade",
    ] {
        h.remove(n);
    }
}

fn wants_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(hyper::header::UPGRADE)
        || h.get_all(hyper::header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
}

async fn handle(state: Arc<ProxyState>, peer: SocketAddr, req: HyperReq<Incoming>) -> Result<Response<Body>, hyper::Error> {
    let lim = &state.limits;
    if req.headers().len() > lim.max_headers {
        return Ok(text(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "Request header fields too large.\n"));
    }
    if wants_upgrade(req.headers()) {
        return Ok(text(StatusCode::NOT_IMPLEMENTED, "Protocol upgrade is not supported.\n"));
    }
    let declared_len = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared_len.is_some_and(|n| n > lim.max_body) {
        return Ok(text(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large.\n"));
    }

    let (parts, body) = req.into_parts();
    let read = Limited::new(body, lim.max_body).collect();
    let collected = match tokio::time::timeout(Duration::from_millis(lim.body_read_timeout_ms), read).await {
        Err(_) => return Ok(text(StatusCode::REQUEST_TIMEOUT, "Request timeout.\n")),
        Ok(Err(e)) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
            return Ok(text(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large.\n"))
        }
        Ok(Err(_)) => return Ok(text(StatusCode::BAD_REQUEST, "Bad request.\n")),
        Ok(Ok(c)) => c.to_bytes(),
    };

    let decision = state.pipeline.decide(&parts, &collected, Some(peer.ip()), now_ms());
    state.audit.record(&decision.request, &decision.judgment);
    let j = decision.judgment;

    if state.enforce && matches!(j.verdict, Verdict::Block | Verdict::Challenge) {
        return Ok(text(StatusCode::FORBIDDEN, "Request blocked.\n"));
    }
    Ok(forward(&state, &parts, collected, peer, &j).await)
}

async fn forward(state: &ProxyState, parts: &http::request::Parts, body: Bytes, peer: SocketAddr, j: &Judgment) -> Response<Body> {
    let path_q = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", state.upstream.trim_end_matches('/'), path_q);
    let mut headers = parts.headers.clone();
    strip_hop_by_hop(&mut headers);
    headers.remove(hyper::header::HOST);
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(prev) => format!("{prev}, {}", peer.ip()),
        None => peer.ip().to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    headers.append(hyper::header::VIA, HeaderValue::from_static("1.1 venusflytrap"));
    if state.decision_headers == DecisionHeaders::Upstream {
        headers.insert("x-venusflytrap-score", HeaderValue::from(u16::from(j.score)));
        if let Ok(v) = HeaderValue::from_str(&format!("{:?}", j.verdict)) {
            headers.insert("x-venusflytrap-verdict", v);
        }
        if let Some(stage) = j.chain_stage.and_then(|s| HeaderValue::from_str(&format!("{s:?}")).ok()) {
            headers.insert("x-venusflytrap-stage", stage);
        }
    }
    let mut out = match HyperReq::builder().method(parts.method.clone()).uri(url).body(Full::new(body)) {
        Ok(r) => r,
        Err(_) => return text(StatusCode::BAD_GATEWAY, "Bad gateway.\n"),
    };
    *out.headers_mut() = headers;

    let wait = Duration::from_millis(state.limits.upstream_response_timeout_ms);
    match tokio::time::timeout(wait, state.client.request(out)).await {
        Err(_) => text(StatusCode::GATEWAY_TIMEOUT, "Gateway timeout.\n"),
        Ok(Err(_)) => text(StatusCode::BAD_GATEWAY, "Bad gateway.\n"),
        Ok(Ok(resp)) => {
            let (mut rp, rb) = resp.into_parts();
            strip_hop_by_hop(&mut rp.headers);
            Response::from_parts(rp, rb.boxed())
        }
    }
}

/// Bind and serve until the process is killed.
pub async fn serve(state: Arc<ProxyState>, bind: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    eprintln!("venusflytrap proxy listening on http://{bind} -> {} (enforce={})", state.upstream, state.enforce);
    serve_listener(state, listener).await
}

/// Serve on an already-bound listener. Accept errors never end the loop (M9).
pub async fn serve_listener(state: Arc<ProxyState>, listener: TcpListener) -> anyhow::Result<()> {
    let slots = Arc::new(Semaphore::new(state.limits.max_connections));
    let mut backoff = Duration::from_millis(10);
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (stream, peer) = match listener.accept().await {
            Ok(x) => {
                backoff = Duration::from_millis(10);
                x
            }
            Err(e) => {
                eprintln!("accept error: {e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let st = state.clone();
        let header_ms = state.limits.header_read_timeout_ms;
        let max_headers = state.limits.max_headers;
        tokio::spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |req| handle(st.clone(), peer, req));
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(header_ms))
                .max_headers(max_headers);
            let _ = b.serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}
```

Keep the `#[cfg(test)] mod tests` from Task 7 (`judges_sqli_as_block`, `fullwidth_encoded_sqli_not_evaded`).

- [ ] **Step 4: Run the tests**

```bash
cargo test --workspace 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-targets -- -D warnings
```

Expected: all pass, including the seven `hardening` tests.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(proxy): body/header limits, timeouts, hop-by-hop stripping, pooled client, resilient accept (H2, H6, M9, L1, L3)"
```

---

### Task 9: Async JSONL audit sink (L2)

**Files:**
- Rewrite: `crates/vft-proxy/src/audit.rs`
- Modify: `crates/vft-proxy/src/lib.rs` (field type and call site)
- Modify: `crates/vft-cli/src/main.rs` (`--audit-max-mb`)

**Interfaces:**
- Produces: `AuditSink::new(path: Option<PathBuf>, max_bytes: u64) -> AuditSink` (writes to stdout when `None`), `AuditSink::off() -> AuditSink`, `.record(&self, req: &Request, j: &Judgment, ts_ms: u64, request_id: u64)`, `.dropped() -> u64`, `.write_errors() -> u64`, `.close(self)`. `ProxyState::new(shield, upstream, audit: AuditSink, enforce)`.

- [ ] **Step 1: Write the failing tests** — bottom of `audit.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use vft_core::{Config, Shield};

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("vft-audit-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("1"));
        p
    }

    #[test]
    fn lines_carry_timestamp_and_request_id() {
        let p = tmp("ts.jsonl");
        let sink = AuditSink::new(Some(p.clone()), 10 * 1024 * 1024);
        let mut req = Request::get("/x");
        req.query.push(("id".into(), "1 union select a".into()));
        let j = Shield::new(Config::default()).inspect(&req);
        sink.record(&req, &j, 1_700_000_000_000, 7);
        sink.close();
        let line = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(v["ts_ms"], 1_700_000_000_000u64);
        assert_eq!(v["request_id"], 7);
        assert!(v["contributions"].as_array().unwrap().iter().any(|c| c["construct"] == "union-select"));
    }

    #[test]
    fn rotates_at_max_bytes() {
        let p = tmp("rot.jsonl");
        let sink = AuditSink::new(Some(p.clone()), 300);
        let req = Request::get("/rotate");
        let j = Shield::new(Config::default()).inspect(&req);
        for i in 0..20 {
            sink.record(&req, &j, i, i);
        }
        sink.close();
        assert!(p.with_extension("1").exists(), "rotated file missing");
        let current = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        assert!(current < 300 + 400, "current file should have been restarted, len {current}");
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-proxy --lib audit`
Expected: compile error (`AuditSink` missing).

- [ ] **Step 3: Implement** — replace `crates/vft-proxy/src/audit.rs` above the tests with:

```rust
//! FR10 — JSONL audit sink. The request path only does a non-blocking
//! `try_send`; a dedicated thread owns the file, batches writes, rotates at a
//! size cap and counts drops and write errors (L2).

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::Serialize;
use vft_core::{Judgment, Request};

#[derive(Serialize)]
struct ContribLine<'a> {
    construct: Option<&'a str>,
    field: Option<String>,
    value: String,
}

#[derive(Serialize)]
struct AuditLine<'a> {
    ts_ms: u64,
    request_id: u64,
    method: &'a str,
    path: &'a str,
    src_ip: Option<String>,
    verdict: String,
    score: u8,
    stage: Option<String>,
    banned: bool,
    layers: u8,
    contributions: Vec<ContribLine<'a>>,
    reason: &'a str,
}

pub struct AuditSink {
    tx: Option<SyncSender<String>>,
    worker: Option<JoinHandle<()>>,
    dropped: Arc<AtomicU64>,
    write_errors: Arc<AtomicU64>,
    enabled: bool,
}

impl AuditSink {
    /// `None` writes to stdout.
    pub fn new(path: Option<PathBuf>, max_bytes: u64) -> Self {
        let (tx, rx) = sync_channel::<String>(4096);
        let write_errors = Arc::new(AtomicU64::new(0));
        let errs = write_errors.clone();
        let worker = std::thread::spawn(move || {
            let mut out: Box<dyn Write> = match &path {
                Some(p) => match open(p) {
                    Some(f) => Box::new(BufWriter::new(f)),
                    None => {
                        errs.fetch_add(1, Ordering::Relaxed);
                        Box::new(std::io::sink())
                    }
                },
                None => Box::new(BufWriter::new(std::io::stdout())),
            };
            let mut size = path.as_ref().and_then(|p| std::fs::metadata(p).ok()).map_or(0, |m| m.len());
            loop {
                match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(line) => {
                        if writeln!(out, "{line}").is_err() {
                            errs.fetch_add(1, Ordering::Relaxed);
                        }
                        size += line.len() as u64 + 1;
                        if let Some(p) = path.as_ref().filter(|_| size >= max_bytes) {
                            let _ = out.flush();
                            drop(out);
                            if std::fs::rename(p, p.with_extension("1")).is_err() {
                                errs.fetch_add(1, Ordering::Relaxed);
                            }
                            out = match open(p) {
                                Some(f) => Box::new(BufWriter::new(f)),
                                None => {
                                    errs.fetch_add(1, Ordering::Relaxed);
                                    Box::new(std::io::sink())
                                }
                            };
                            size = 0;
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        if out.flush().is_err() {
                            errs.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        let _ = out.flush();
                        return;
                    }
                }
            }
        });
        AuditSink {
            tx: Some(tx),
            worker: Some(worker),
            dropped: Arc::new(AtomicU64::new(0)),
            write_errors,
            enabled: true,
        }
    }

    /// A sink that records nothing.
    pub fn off() -> Self {
        AuditSink {
            tx: None,
            worker: None,
            dropped: Arc::new(AtomicU64::new(0)),
            write_errors: Arc::new(AtomicU64::new(0)),
            enabled: false,
        }
    }

    pub fn record(&self, req: &Request, j: &Judgment, ts_ms: u64, request_id: u64) {
        let Some(tx) = self.tx.as_ref().filter(|_| self.enabled) else {
            return;
        };
        let line = AuditLine {
            ts_ms,
            request_id,
            method: &req.method,
            path: &req.path,
            src_ip: req.src_ip.map(|i| i.to_string()),
            verdict: format!("{:?}", j.verdict),
            score: j.score,
            stage: j.chain_stage.map(|s| format!("{s:?}")),
            banned: j.banned_source,
            layers: j.normalized_layers,
            contributions: j
                .contributions
                .iter()
                .map(|c| ContribLine {
                    construct: c.construct.as_deref(),
                    field: c.field.as_ref().map(|f| format!("{:?}:{}", f.loc, f.name)),
                    value: format!("{:?}", c.value),
                })
                .collect(),
            reason: &j.reason,
        };
        let Ok(json) = serde_json::to_string(&line) else {
            return;
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(json) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
    pub fn write_errors(&self) -> u64 {
        self.write_errors.load(Ordering::Relaxed)
    }

    /// Flush and stop the writer thread.
    pub fn close(mut self) {
        self.tx.take();
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

fn open(p: &std::path::Path) -> Option<File> {
    OpenOptions::new().create(true).append(true).open(p).ok()
}
```

`crates/vft-proxy/src/lib.rs`:
- `ProxyState` field `pub audit: audit::AuditSink,`, plus `request_seq: std::sync::atomic::AtomicU64,`.
- `ProxyState::new(shield: Shield, upstream: String, audit: audit::AuditSink, enforce: bool)` stores `audit` and `request_seq: AtomicU64::new(0)`.
- In `handle`:

```rust
    let id = state.request_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.audit.record(&decision.request, &decision.judgment, now_ms(), id);
```

- Update `crates/vft-proxy/tests/hardening.rs` `proxy()` to pass `vft_proxy::audit::AuditSink::off()`, and the lib tests' `state()` likewise.

`crates/vft-cli/src/main.rs` — `Serve` gains `#[arg(long, default_value_t = 100)] audit_max_mb: u64,` and builds:

```rust
            let sink = vft_proxy::audit::AuditSink::new(audit.map(PathBuf::from), audit_max_mb * 1024 * 1024);
            let state = Arc::new(vft_proxy::ProxyState::new(shield, upstream, sink, !monitor_only));
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"`; `cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(proxy): async JSONL audit sink with timestamps, request ids, rotation and counters (L2)"
```

---

### Task 10: `venusflytrap eval` over raw files — library and serve modes (M8)

**Files:**
- Create: `crates/vft-cli/src/eval.rs`
- Modify: `crates/vft-cli/src/main.rs`

**Interfaces:**
- Consumes: `vft_proxy::{adapt, pipeline::Pipeline, http}` (Tasks 6–7), `vft_core::{event_for, Event, SourceKey}`.
- Produces: `eval::load_corpus(&Path) -> anyhow::Result<Vec<Sample>>`; `eval::parse_raw(&[u8]) -> Result<Parsed, String>`; `eval::Sources::{Distinct, Pooled(u32)}` with `FromStr`; `eval::run(cfg: Config, samples: &[Sample], serve: bool, sources: Sources, step_ms: u64, csv: Option<&Path>) -> anyhow::Result<Report>`; `Report` is `Serialize`.

- [ ] **Step 1: Write the failing tests** — bottom of `eval.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lf_only_and_raw_payload_targets() {
        let raw = b"GET /p?q=<script>alert(1)</script> HTTP/1.1\nHost: x\nCookie: a=1\n\n";
        let p = parse_raw(raw).expect("parses");
        assert_eq!(p.parts.uri.path(), "/p");
        assert!(p.parts.uri.query().unwrap().contains("%3Cscript%3E"));
        assert_eq!(p.parts.headers.get("cookie").unwrap(), "a=1");
    }

    #[test]
    fn keeps_obs_text_header_bytes_and_body() {
        let mut raw = b"POST /f HTTP/1.1\r\nHost: x\r\nX-T: a".to_vec();
        raw.push(0xe9);
        raw.extend_from_slice(b"\r\n\r\nname=1");
        let p = parse_raw(&raw).expect("parses");
        assert_eq!(p.parts.headers.get("x-t").unwrap().as_bytes(), b"a\xe9");
        assert_eq!(p.body, b"name=1");
    }

    #[test]
    fn sources_parse_and_are_deterministic() {
        assert!(matches!("distinct".parse::<Sources>(), Ok(Sources::Distinct)));
        assert!(matches!("pooled:100".parse::<Sources>(), Ok(Sources::Pooled(100))));
        assert!("pooled:x".parse::<Sources>().is_err());
        let s = Sources::Pooled(10);
        assert_eq!(s.ip_for(0, "a/b.white"), s.ip_for(99, "a/b.white"));
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p vft-cli eval`
Expected: compile error (module missing).

- [ ] **Step 3: Implement** — `crates/vft-cli/src/eval.rs` above the tests:

```rust
//! Real-corpus evaluation over raw HTTP files. `library` mode scores
//! `Shield::inspect` statelessly; `serve` mode runs the exact function the
//! proxy serves (`Pipeline::decide`) statefully, with the raw Cookie header,
//! and reports ban effects. Both modes share one lenient raw-request parser.

use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use vft_core::{event_for, Config, Event, Shield, SourceKey, Verdict};
use vft_proxy::http::{self, HeaderName, HeaderValue, Method, Uri};
use vft_proxy::{adapt, pipeline::Pipeline};

pub struct Sample {
    pub rel: String,
    pub label: u8,
    pub raw: Vec<u8>,
}

pub fn load_corpus(dir: &Path) -> anyhow::Result<Vec<Sample>> {
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<Sample>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            walk(root, &p, out)?;
            continue;
        }
        let label = match p.extension().and_then(|e| e.to_str()) {
            Some("white") => 0,
            Some("black") => 1,
            _ => continue,
        };
        let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
        out.push(Sample { rel, label, raw: std::fs::read(&p)? });
    }
    Ok(())
}

pub struct Parsed {
    pub parts: http::request::Parts,
    pub body: Vec<u8>,
    pub skipped_headers: u32,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Percent-encode bytes that a URI target may not carry raw (the corpus holds
/// payloads exactly as an attacker would send them).
fn sanitize_target(t: &[u8]) -> String {
    let mut s = String::with_capacity(t.len());
    for (i, &b) in t.iter().enumerate() {
        let plain = b.is_ascii_alphanumeric() || b"-._~:/?@!$&'()*+,;=".contains(&b);
        let pct = b == b'%' && t.len() > i + 2 && t[i + 1].is_ascii_hexdigit() && t[i + 2].is_ascii_hexdigit();
        if plain || pct {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    if s.is_empty() {
        s.push('/');
    }
    s
}

/// Lenient raw HTTP/1.x parser (LF or CRLF; obs-text header bytes kept).
pub fn parse_raw(raw: &[u8]) -> Result<Parsed, String> {
    let (head, body) = if let Some(i) = find(raw, b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = find(raw, b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &raw[raw.len()..])
    };
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let reqline = lines.next().ok_or("empty request")?;
    let sp = reqline.iter().position(|&b| b == b' ').ok_or("no method")?;
    let method = Method::from_bytes(&reqline[..sp]).map_err(|e| e.to_string())?;
    let rest = &reqline[sp + 1..];
    let target = match rest.iter().rposition(|&b| b == b' ') {
        Some(i) if rest[i + 1..].starts_with(b"HTTP/") => &rest[..i],
        _ => rest,
    };
    let uri: Uri = sanitize_target(target).parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let mut builder = http::Request::builder().method(method).uri(uri);
    let mut skipped = 0u32;
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            if !line.trim_ascii().is_empty() {
                skipped += 1;
            }
            continue;
        };
        match (
            HeaderName::from_bytes(line[..colon].trim_ascii()),
            HeaderValue::from_bytes(line[colon + 1..].trim_ascii()),
        ) {
            (Ok(n), Ok(v)) => builder = builder.header(n, v),
            _ => skipped += 1,
        }
    }
    let (parts, ()) = builder.body(()).map_err(|e| e.to_string())?.into_parts();
    Ok(Parsed { parts, body: body.to_vec(), skipped_headers: skipped })
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Sources {
    Distinct,
    Pooled(u32),
}

impl FromStr for Sources {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "distinct" {
            return Ok(Sources::Distinct);
        }
        s.strip_prefix("pooled:")
            .and_then(|n| n.parse().ok())
            .filter(|n| *n > 0)
            .map(Sources::Pooled)
            .ok_or_else(|| format!("expected 'distinct' or 'pooled:<N>', got {s:?}"))
    }
}

impl Sources {
    /// A 10.0.0.0/8 source address for sample `i`.
    pub fn ip_for(&self, i: usize, rel: &str) -> IpAddr {
        let n = match self {
            Sources::Distinct => i as u32,
            Sources::Pooled(k) => {
                let mut h: u32 = 0x811c_9dc5;
                for b in rel.bytes() {
                    h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
                }
                h % k
            }
        };
        IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | (n & 0x00FF_FFFF)))
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Metrics {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
    pub recall: f64,
    pub precision: f64,
    pub f1: f64,
    pub fp_rate: f64,
}

impl Metrics {
    fn add(&mut self, predicted_attack: bool, label: u8) {
        match (predicted_attack, label) {
            (true, 1) => self.tp += 1,
            (true, _) => self.fp += 1,
            (false, 0) => self.tn += 1,
            (false, _) => self.fn_ += 1,
        }
    }
    fn finish(mut self) -> Self {
        let r = self.tp as f64 / (self.tp + self.fn_).max(1) as f64;
        let p = self.tp as f64 / (self.tp + self.fp).max(1) as f64;
        self.recall = r;
        self.precision = p;
        self.f1 = if r + p > 0.0 { 2.0 * r * p / (r + p) } else { 0.0 };
        self.fp_rate = self.fp as f64 / (self.fp + self.tn).max(1) as f64;
        self
    }
}

#[derive(Debug, Serialize)]
pub struct ServeMetrics {
    pub metrics: Metrics,
    pub benign_sources: usize,
    /// Benign sources answered with a ban (from their own FP or a pooled neighbour).
    pub benign_sources_banned: usize,
    /// Benign requests blocked in serve mode that the stateless library allowed.
    pub collateral_fp: u64,
    /// Bans triggered by a request whose library verdict was Allow (the C1 class; must be 0).
    pub bans_from_allowed: u64,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    pub sources: Sources,
    pub samples: usize,
    pub parse_failures: u64,
    pub skipped_headers: u64,
    pub library: Metrics,
    pub serve: Option<ServeMetrics>,
    /// Library judgments with verdict Allow whose chain event is not Benign (must be 0).
    pub invariant_violations: u64,
    pub latency_us_p50_p95_p99: [u64; 3],
}

fn attack(v: Verdict) -> bool {
    matches!(v, Verdict::Block | Verdict::Challenge)
}

pub fn run(cfg: Config, samples: &[Sample], serve: bool, sources: Sources, step_ms: u64, csv: Option<&Path>) -> anyhow::Result<Report> {
    let shield = Arc::new(Shield::new(cfg));
    let pipeline = Pipeline::new(shield.clone());
    let mut csv_out = match csv {
        Some(p) => {
            let mut f = std::io::BufWriter::new(std::fs::File::create(p)?);
            writeln!(f, "rel,label,lib_verdict,serve_verdict,score,banned,constructs")?;
            Some(f)
        }
        None => None,
    };
    let (mut lib, mut srv) = (Metrics::default(), Metrics::default());
    let (mut parse_failures, mut skipped_headers, mut invariant_violations) = (0u64, 0u64, 0u64);
    let (mut collateral_fp, mut bans_from_allowed) = (0u64, 0u64);
    let mut benign_sources: HashSet<SourceKey> = HashSet::new();
    let mut benign_banned: HashSet<SourceKey> = HashSet::new();
    let mut lat: Vec<u64> = Vec::with_capacity(samples.len());

    for (i, s) in samples.iter().enumerate() {
        let Ok(p) = parse_raw(&s.raw) else {
            parse_failures += 1;
            continue;
        };
        skipped_headers += u64::from(p.skipped_headers);
        let ip = sources.ip_for(i, &s.rel);
        let req = adapt::from_parts(&p.parts, &p.body, Some(ip));
        let t = Instant::now();
        let lj = shield.inspect(&req);
        if lj.verdict == Verdict::Allow && event_for(&lj) != Event::Benign {
            invariant_violations += 1;
        }
        lib.add(attack(lj.verdict), s.label);

        let mut serve_verdict = String::new();
        let mut banned = false;
        if serve {
            let t2 = Instant::now();
            let d = pipeline.decide(&p.parts, &p.body, Some(ip), i as u64 * step_ms);
            lat.push(t2.elapsed().as_micros() as u64);
            let sj = &d.judgment;
            srv.add(attack(sj.verdict), s.label);
            banned = sj.banned_source;
            let fresh_ban = sj.banned_source && !sj.contributions.iter().any(|c| c.construct.as_deref() == Some("chain.ban"));
            if fresh_ban && lj.verdict == Verdict::Allow {
                bans_from_allowed += 1;
            }
            if s.label == 0 {
                let key = SourceKey::new(ip, 64);
                benign_sources.insert(key);
                if sj.banned_source {
                    benign_banned.insert(key);
                }
                if attack(sj.verdict) && !attack(lj.verdict) {
                    collateral_fp += 1;
                }
            }
            serve_verdict = format!("{:?}", sj.verdict);
        } else {
            lat.push(t.elapsed().as_micros() as u64);
        }
        if let Some(f) = csv_out.as_mut() {
            let constructs: Vec<&str> = lj.contributions.iter().filter_map(|c| c.construct.as_deref()).collect();
            writeln!(f, "{},{},{:?},{},{},{},{}", s.rel, s.label, lj.verdict, serve_verdict, lj.score, banned, constructs.join("|"))?;
        }
    }
    lat.sort_unstable();
    let pct = |q: f64| lat.get(((lat.len().max(1) - 1) as f64 * q).round() as usize).copied().unwrap_or(0);
    Ok(Report {
        mode: if serve { "serve" } else { "library" },
        sources,
        samples: samples.len(),
        parse_failures,
        skipped_headers,
        library: lib.finish(),
        serve: serve.then(|| ServeMetrics {
            metrics: srv.finish(),
            benign_sources: benign_sources.len(),
            benign_sources_banned: benign_banned.len(),
            collateral_fp,
            bans_from_allowed,
        }),
        invariant_violations,
        latency_us_p50_p95_p99: [pct(0.5), pct(0.95), pct(0.99)],
    })
}
```

`crates/vft-cli/src/main.rs` — add `mod eval;` and:

```rust
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum EvalMode {
    Library,
    Serve,
}
```
```rust
    /// Evaluate on a raw labeled corpus (*.white benign, *.black malicious).
    Eval {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long, value_enum, default_value_t = EvalMode::Serve)]
        mode: EvalMode,
        /// distinct | pooled:<N>
        #[arg(long, default_value = "distinct")]
        sources: String,
        /// Synthetic clock step between requests.
        #[arg(long, default_value_t = 100)]
        step_ms: u64,
        /// Optional per-sample CSV.
        #[arg(long)]
        out: Option<PathBuf>,
    },
```
```rust
        Command::Eval { corpus, mode, sources, step_ms, out } => {
            let cfg = load_config(cli.config.as_ref())?;
            let sources: eval::Sources = sources.parse().map_err(anyhow::Error::msg)?;
            let samples = eval::load_corpus(&corpus)?;
            let report = eval::run(cfg, &samples, mode == EvalMode::Serve, sources, step_ms, out.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.invariant_violations > 0 || report.serve.as_ref().is_some_and(|s| s.bans_from_allowed > 0) {
                std::process::exit(3);
            }
        }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"`; `cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 5: Run the real evaluation**

```bash
cargo build --release -p vft-cli
V=./target/release/venusflytrap
C="$EVAL/ext/blazehttp/testcases"
$V eval --corpus "$C" --mode library --out "$EVAL/sp1/eval-lib.csv"            > "$EVAL/sp1/eval-lib.json"
$V eval --corpus "$C" --mode serve --sources distinct                          > "$EVAL/sp1/eval-serve-distinct.json"
$V eval --corpus "$C" --mode serve --sources pooled:100                        > "$EVAL/sp1/eval-serve-pooled100.json"
```

Expected: exit code 0 for all three (no invariant violations, `bans_from_allowed` = 0); `samples` = 33877. Check `parse_failures` and `skipped_headers`: if `parse_failures` > 0, list the failing files (`rel` paths) in the results log rather than hiding them.

Add rows to `eval/RESULTS-SP1.md`: "10 lib (raw Rust parser)", "10 serve distinct", "10 serve pooled:100", with TP/FP/FN/recall/precision/FP rate, and in Notes: parse failures, `benign_sources_banned`, `collateral_fp`, latency triple. Note the input-fairness gap: the libinjection baseline still reads the Python-parsed JSONL.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(cli): eval over raw corpus through the serve path, with ban and collateral metrics (M8)"
```

---

### Task 11: TCP replay equivalence (serve over sockets == in-process decide)

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`run_tcp`, `rewrite_for_replay`)
- Modify: `crates/vft-cli/src/main.rs` (`EvalMode::Tcp`, `--limit`)

**Interfaces:**
- Consumes: `vft_proxy::{serve_listener, ProxyState, audit::AuditSink}` (Tasks 8–9), `parse_raw`, `Pipeline` (Tasks 7, 10).
- Produces: `eval::rewrite_for_replay(raw: &[u8], xff: IpAddr) -> Option<Vec<u8>>`; `eval::run_tcp(cfg: Config, samples: &[Sample], limit: usize) -> anyhow::Result<TcpReport>`.

- [ ] **Step 1: Write the failing test** (in `eval.rs` tests):

```rust
    #[test]
    fn replay_rewrite_sets_framing_and_xff() {
        let raw = b"POST /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nContent-Length: 999\r\nX-Forwarded-For: 1.2.3.4\r\n\r\nab";
        let out = rewrite_for_replay(raw, "10.0.0.5".parse().unwrap()).unwrap();
        let s = String::from_utf8_lossy(&out).to_ascii_lowercase();
        assert!(s.contains("x-forwarded-for: 10.0.0.5\r\n"));
        assert!(!s.contains("1.2.3.4"));
        assert!(s.contains("connection: close\r\n"));
        assert!(s.contains("content-length: 2\r\n"));
        assert!(s.ends_with("\r\n\r\nab"));
        let chunked = b"POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(rewrite_for_replay(chunked, "10.0.0.5".parse().unwrap()).is_none());
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p vft-cli replay_rewrite`
Expected: compile error.

- [ ] **Step 3: Implement** — add to `eval.rs`:

```rust
/// Normalize framing for a socket replay: CRLF line endings, our own
/// `X-Forwarded-For`, `Connection: close`, an exact `Content-Length`. Samples
/// that use Transfer-Encoding or Upgrade are not replayable (`None`).
pub fn rewrite_for_replay(raw: &[u8], xff: IpAddr) -> Option<Vec<u8>> {
    let (head, body) = if let Some(i) = find(raw, b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = find(raw, b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &raw[raw.len()..])
    };
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let mut out = lines.next()?.to_vec();
    out.extend_from_slice(b"\r\n");
    for line in lines {
        let name = line.split(|&b| b == b':').next().unwrap_or(b"").trim_ascii().to_ascii_lowercase();
        match name.as_slice() {
            b"transfer-encoding" | b"upgrade" => return None,
            b"connection" | b"content-length" | b"x-forwarded-for" | b"keep-alive" | b"proxy-connection" => continue,
            _ => {}
        }
        if !line.is_empty() {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(format!("X-Forwarded-For: {xff}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Some(out)
}

#[derive(Debug, Default, Serialize)]
pub struct TcpReport {
    pub replayed: u64,
    pub not_replayable: u64,
    pub matched: u64,
    /// The proxy refused the request at the HTTP layer (400/413/431/501) while
    /// the lenient in-process parser accepted it.
    pub proxy_rejected: u64,
    pub mismatched: u64,
    pub mismatch_examples: Vec<String>,
}

pub fn run_tcp(cfg: Config, samples: &[Sample], limit: usize) -> anyhow::Result<TcpReport> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cfg = cfg;
    cfg.proxy.trusted_proxies = vec!["127.0.0.1".into()];
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1 << 20];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                });
            }
        });
        let state = Arc::new(vft_proxy::ProxyState::new(
            Shield::new(cfg.clone()),
            format!("http://{up_addr}"),
            vft_proxy::audit::AuditSink::off(),
            true,
        ));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = l.local_addr()?;
        tokio::spawn(vft_proxy::serve_listener(state, l));
        let local = Pipeline::new(Arc::new(Shield::new(cfg)));
        let loopback: IpAddr = "127.0.0.1".parse()?;

        let mut r = TcpReport::default();
        for (i, s) in samples.iter().take(limit).enumerate() {
            let ip = Sources::Distinct.ip_for(i, &s.rel);
            let Some(raw) = rewrite_for_replay(&s.raw, ip) else {
                r.not_replayable += 1;
                continue;
            };
            let Ok(p) = parse_raw(&raw) else {
                r.not_replayable += 1;
                continue;
            };
            let d = local.decide(&p.parts, &p.body, Some(loopback), vft_proxy::now_ms());
            let mut sock = tokio::net::TcpStream::connect(proxy_addr).await?;
            sock.write_all(&raw).await?;
            let mut resp = Vec::new();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), sock.read_to_end(&mut resp)).await;
            let status: u16 = std::str::from_utf8(&resp)
                .ok()
                .and_then(|t| t.split_whitespace().nth(1))
                .and_then(|c| c.parse().ok())
                .unwrap_or(0);
            r.replayed += 1;
            match (status, attack(d.judgment.verdict)) {
                (403, true) | (200, false) => r.matched += 1,
                (400 | 413 | 431 | 501, _) => r.proxy_rejected += 1,
                (code, blocked) => {
                    r.mismatched += 1;
                    if r.mismatch_examples.len() < 20 {
                        r.mismatch_examples.push(format!("{} status={code} in_process_block={blocked}", s.rel));
                    }
                }
            }
        }
        Ok(r)
    })
}
```

`crates/vft-cli/src/main.rs` — add `Tcp` to `EvalMode`, `#[arg(long, default_value_t = 1000)] limit: usize,` to `Eval`, and dispatch before the library/serve path:

```rust
            if mode == EvalMode::Tcp {
                let r = eval::run_tcp(cfg, &samples, limit)?;
                println!("{}", serde_json::to_string_pretty(&r)?);
                if r.mismatched > 0 {
                    std::process::exit(3);
                }
                return Ok(());
            }
```

In `crates/vft-cli/Cargo.toml`, replace the tokio line with:

```toml
tokio = { version = "1.41.0", features = ["rt-multi-thread", "net", "io-util", "time", "macros"] }
```

- [ ] **Step 4: Run the tests and the replay**

```bash
cargo test --workspace 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-targets -- -D warnings
cargo build --release -p vft-cli
./target/release/venusflytrap eval --corpus "$EVAL/ext/blazehttp/testcases" --mode tcp --limit 1000 > "$EVAL/sp1/eval-tcp.json"; echo "exit=$?"
```

Expected: `exit=0` and `mismatched` = 0. Record `replayed`, `matched`, `proxy_rejected` and `not_replayable` in the results log. Investigate any `proxy_rejected` > 0: list the files and the status, and state it as a known front-end difference, not an engine mismatch.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "test(cli): TCP replay equivalence between the live proxy and in-process decide"
```

---

### Task 12: Honest docs, final measurement, Claude Doc update (L6)

**Files:**
- Modify: `README.md`
- Rewrite: `docs/BENCHMARK.md`
- Modify: `crates/vft-cli/src/main.rs` (`bench` default output)
- Modify: `crates/vft-cli/src/bench.rs` (report wording)
- Modify: `eval/RESULTS-SP1.md`

- [ ] **Step 1: `bench` no longer overwrites the docs.** In `main.rs`, change `Bench.out`'s default to `target/bench/BENCHMARK-synthetic.md`. In `bench.rs`, the report heading becomes `# Synthetic smoke benchmark (not a result)` with the line `This corpus is ~20 benign templates and the payloads the detectors were written against. It checks that nothing is broken; it does not measure detection quality. Real-corpus results: docs/BENCHMARK.md.`, and the sentence "The full engine should keep obfuscated recall high **and** FP low" is removed.

- [ ] **Step 2: Final measurement run** (all from the release build):

```bash
./target/release/venusflytrap eval --corpus "$EVAL/ext/blazehttp/testcases" --mode library  > "$EVAL/sp1/final-lib.json"
./target/release/venusflytrap eval --corpus "$EVAL/ext/blazehttp/testcases" --mode serve --sources distinct   > "$EVAL/sp1/final-serve-distinct.json"
./target/release/venusflytrap eval --corpus "$EVAL/ext/blazehttp/testcases" --mode serve --sources pooled:100 > "$EVAL/sp1/final-serve-pooled.json"
./target/release/venusflytrap eval --corpus "$EVAL/ext/blazehttp/testcases" --mode tcp --limit 1000          > "$EVAL/sp1/final-tcp.json"
./target/release/examples/bench_http "$EVAL/run0/corpus.jsonl"  "$EVAL/sp1/final-bench.csv"
./target/release/examples/bench_http "$EVAL/run0/seeds.jsonl"   "$EVAL/sp1/final-s.csv"
./target/release/examples/bench_http "$EVAL/run0/mutants.jsonl" "$EVAL/sp1/final-m.csv"
py -I -X utf8 eval/baselines.py "$EVAL/run0/corpus.jsonl" "$EVAL/sp1/final-baselines.json" "$EVAL/ext/libinjection.dll"
cargo test --release -p vft-proxy --lib decide_throughput -- --ignored --nocapture
```

- [ ] **Step 3: Rewrite `docs/BENCHMARK.md`** with exactly these sections, filled only with numbers from Step 2:
  1. *Corpus and method:* blazehttp, 33,877 requests (33,219 benign / 658 malicious), commit `afc88a94`; library = stateless `Shield::inspect`; serve = `Pipeline::decide`, stateful, raw Cookie header, synthetic 100 ms clock; sources distinct and pooled:100; TCP replay of 1,000 samples.
  2. *Library vs serve* table: TP, FP, FN, recall, precision, F1, FP rate for library, serve-distinct, serve-pooled:100, plus libinjection and regex from `final-baselines.json`, with a note that the baselines read the Python-parsed JSONL.
  3. *Ban effects:* `benign_sources_banned`, `collateral_fp`, `bans_from_allowed` (expected 0), `invariant_violations` (expected 0).
  4. *Mutation robustness:* seed vs mutant recall and retention for Venusflytrap (with the Task 0 numbers alongside for comparison) and the libinjection/regex numbers from the original run.
  5. *Latency:* p50/p95/p99 for library and serve, plus the throughput ratio.
  6. *What this does not show:* single corpus; random-mutation lower bound; the attack families not modelled (XXE, SSRF, deserialization, template injection).

- [ ] **Step 4: README.** Replace the "Measured results" section with a short paragraph and a 3-row table (library, serve-distinct, libinjection) copied from `docs/BENCHMARK.md`, linking to it. Delete every mention of the synthetic 96%/0-FP result as a result.

- [ ] **Step 5: Update the Claude Doc** (`https://claude.ai/artifact/RNL7nDCgA7Qawz2pe8kM3s`, via the docs connector, reading with `sinceRev` first): add a "Library vs serve path (SP1)" table after the real-corpus table, update the latency paragraph, and add one sentence to the error analysis on C1 (browser bans), and how the serve-path eval now measures it. Use only numbers from Step 2.

- [ ] **Step 6: Full gate**

```bash
cargo test --workspace 2>&1 | grep -E "^test result|FAILED"
cargo clippy --all-targets -- -D warnings
grep -rn "96\.\|0 FP\|zero false" README.md docs/BENCHMARK.md
```

Expected: tests and clippy green; the grep shows no synthetic result presented as a result.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "docs: publish real-corpus library and serve-path results; synthetic bench is a smoke test (L6)"
```

---

## SP1 acceptance checklist (from the spec)

| Spec acceptance item | Where it is verified |
|---|---|
| Chrome/Firefox/Safari: Allow, `event_for == Benign`, no ban | Task 7 `real_browsers_are_never_banned`; Task 2 `browser_is_never_staged_or_banned` |
| Every corpus Allow has `event_for == Benign` | Task 10 `invariant_violations` (exit 3 if > 0) |
| Serve distinct: bans from Allowed requests = 0; FP-driven bans reported | Task 10 `bans_from_allowed`, `benign_sources_banned` |
| Pooled:100 reports request FP, benign-source ban rate, collateral FP; collateral ≤ request-level FP | Task 10 / Task 12 `final-serve-pooled.json` (compare `collateral_fp` with `serve.metrics.fp`) |
| BENCHMARK.md + Claude Doc publish library and serve side by side | Task 12 Steps 3, 5 |
| C1/C4/H4/H5/M1 repros are regression tests | Tasks 2, 6, 3, 4, 3 |
| Cookie `union select` + `\xff` → 403, upstream receives nothing | Task 8 `non_utf8_cookie_attack_is_blocked_and_never_forwarded` |
| H2: oversized body 413 with zero upstream connections; slowloris closed; hung upstream 504 | Task 8 hardening tests |
| H3: 8-thread decide ≥ 0.75× stateless inspect | Task 7 ignored throughput test |
| TCP replay of 1,000 samples matches in-process 1:1 | Task 11 (`mismatched` = 0) |
| Mutation robustness re-run, changes reported | Tasks 3, 4, 6, 12 |
| `cargo test --workspace` + clippy `-D warnings` green; proptest unchanged | every task, Task 12 Step 6 |
