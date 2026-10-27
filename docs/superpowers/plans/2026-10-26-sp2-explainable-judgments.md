# SP2 — Explainable Judgments and Option Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every judgment names the one setting that decided it (`decided_by`), every contribution carries the points it actually added, and every config leaf has a hand-written descriptor that drives per-key validation, base + override layering and generated TypeScript types — with corpus decisions byte-identical to main.

**Architecture:** All new logic is pure and lives in `vft-core`: `options.rs` (descriptor registry, per-key tree checker, layering), `Cause`/`CauseKind` in `judgment.rs`, points from `score::arbitrate`, cause selection in `shield.rs`. `vft-proxy` and `vft-cli` only migrate off the legacy judgment fields. A committed decision gate (`eval/decision_gate.sh`) re-runs the real corpus after every behaviour-touching task and diffs every decision against a baseline captured from main before any change.

**Tech Stack:** Rust 2021 workspace (vft-core, vft-proxy, vft-cli), serde / serde_json / serde_yaml, proptest, ts-rs 12.0.1 (optional, `ts` feature), Python 3 for `eval/compare_runs.py`, Git Bash for the gate script.

**Spec:** `docs/superpowers/specs/2026-10-25-operable-service-design.md` §4 (principles 1, 5, 6), §5.2, §5.4 (staging note), §5.6, §5.10 (Types), §6 SP2, §7, §10. Detail source: `research_notes/Portmaster lessons for Venusflytrap/architecture_review.md` §SP2 and the key-types block.

## Global Constraints

- `#![forbid(unsafe_code)]` stays in every crate; `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` are green after every task.
- The core stays pure: no I/O, clock or locks in `vft-core` library code. Tests may read and write files.
- **No detection change.** After every task marked *Gate*, `eval/decision_gate.sh check` must report identical decisions (`label, lib_verdict, serve_verdict, score, banned`) for `--sources distinct` and `--sources pooled:100` against the baseline captured in Task 1 from main `b2f82ff`.
- `decided_by` order is fixed: ban → honeypot → intel deny → fail-closed limit → the band threshold crossed (`scoring.block_at` / `scoring.challenge_at` / `scoring.monitor_at`) with the top contribution's construct and field → `NoEvidence` (`scoring.monitor_at`). An allow-listed source whose verdict is Allow gets `Allowlisted` (`intel.allow_ips`) in place of `NoEvidence`. A chain bonus that raises the band gives `ChainEscalation` (`scoring.chain_stage_bonus`).
- Every `decided_by.option_key` exists in `options::REGISTRY`. Option keys are the dotted config paths (`scoring.block_at`): one key names one setting in config, `decided_by`, the API, the settings screen and deep links.
- `Σ contribution.points` reproduces `score` within ±1.
- Construct ids are stable dotted ids, never reused. `chain.ban` and `chain.stage-advance` record chain decisions and are deliberately **not** in the construct registry.
- `Config.version` is `1`; `deny_unknown_fields` stays on every config struct.
- `ts-rs = "12.0.1"` is optional behind the `ts` feature of `vft-core`; the default build gains no dependency.
- The synthetic corpus result is never quoted as a result.
- Commits: one per task, on branch `sp2-explainable-judgments` in a worktree, only after the owner has approved executing this plan. No push and no change to `main` without the owner's approval.

## Decisions this plan takes (owner to confirm before execution)

| # | Decision | Why |
|---|---|---|
| D1 | `Judgment` loses `engines`, `matched`, `reason`, `banned_source`, `chain_stage` (Task 8). Replacements: `decided_by.msg`, `contributions`, `Judgment::banned()`, `Judgment::stage()`, `chain: Option<ChainOutcome>`. `EngineReport` is deleted. `Judgment` becomes `Serialize`-only (nothing deserializes it). | Spec §5.2 shape; `contributions` replaces engines + matched. |
| D2 | New config section `intel: { deny_ips: [], allow_ips: [] }` (exact IPs, seeded into `Intel` by `Shield::new`), and a new construct `intel.deny-listed` recorded on a deny pin. The Enumeration rule matches `intel.scanner-ua` by id instead of by family. | `IntelDeny` and `Allowlisted` causes need real registry keys; without the id match a deny pin would start staging Enumeration. |
| D3 | New `Family::Anomaly` and constructs `ai.anomaly-score` and `api.oversized-header`, emitted by the two detectors that today emit pattern-less evidence. | "Every non-Allow has a construct" fails for AI-only Monitor verdicts otherwise. Scores are unchanged: the dedup key per field stays one per detector. |
| D4 | Ban cause keys: Honeypot → `chain.ban_policy.on_honeypot`; Exfiltration → `chain.ban_policy.on_exfiltration_block`; RepeatedExploitation → `chain.ban_policy.exploitation_blocks`; Manual → `chain.ban_policy.ttl_secs` (the option that sets a manual ban's length). | Spec gives `chain.ban_policy`, which is a section, not a leaf. |
| D5 | Points: the top item keeps its raw points, the others share the (capped) corroboration in proportion, then every item is scaled by the 100-clamp and conflict damping, so Σ equals the unrounded score. On a hard pin the deciding pin (honeypot, then deny, then limit) carries 100 and everything else 0. A chain bonus adds a `chain.stage-advance` contribution; a new ban adds `chain.ban` with the remainder to 100. | Exact sum by construction; the score expression itself is untouched. |
| D6 | Per-key bounds move out of hand-written `validate()` into the registry; `validate()` = registry tree check + cross-field rules. Unknown keys and type errors in YAML become per-key `ConfigIssue`s (`Config::from_yaml_str`). Message wording changes; keys do not. | Spec M6: each bad input yields a per-key issue; bounds live in one place. |
| D7 | `Apply::Restart` for `version`, all `proxy.*`, all `limits.*`, `chain.max_sources`, `chain.events_per_source`, `chain.ipv6_prefix`, `chain.ban_policy.max_bans`; everything else `Live`. Nothing is `sensitive` yet. | Conservative until SP3 implements reload. |
| D8 | `vft-cli/examples/bench_http.rs` (the owner's harness) changes two expressions: `j.matched` → constructs from `j.contributions`, `j.reason` → `j.decided_by.msg`. Its output columns are unchanged. | It reads two removed fields. |

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `eval/decision_gate.sh` (new) | Capture / check corpus decisions against a baseline | 1 |
| `crates/vft-core/src/config.rs` | `version`, `IntelConfig`, `validate` = tree check + cross-field, `from_yaml_str`, `from_tree` | 1, 2, 3 |
| `config/shield.yaml` | Shipped defaults: `version: 1`, `intel:` section | 1, 2 |
| `crates/vft-core/src/options.rs` (new) | `OptionDescriptor`, `REGISTRY`, `lookup`, `check_value`, `check_tree`, `yaml_tree`, `Source`, `Layered`, `layer` | 3, 4 |
| `crates/vft-core/src/graph/sinks/mod.rs` | New constructs `intel.deny-listed`, `ai.anomaly-score`, `api.oversized-header` | 2, 5 |
| `crates/vft-core/src/judgment.rs` | `Family::Anomaly`, `CauseKind`, `Cause`, new `Judgment` shape, helpers | 5, 7, 8 |
| `crates/vft-core/src/detect.rs` | AI and API detectors emit their constructs | 5 |
| `crates/vft-core/src/score.rs` | `Arbitration` with per-item points | 6 |
| `crates/vft-core/src/shield.rs` | Intel seeding and deny pin, points assignment, `cause_for`, `finalize` / `banned_judgment` causes | 2, 6, 7, 8 |
| `crates/vft-core/src/chain.rs` | `event_for` reads `decided_by`; scanner rule by id; `ChainOutcome: Serialize` | 2, 7 |
| `crates/vft-core/tests/points.rs` (new) | Property: Σ points within ±1 of score | 6 |
| `crates/vft-core/tests/ts_bindings.rs` (new), `ui/src/gen/*.ts` (new) | Drift check / bless for generated wire types | 9 |
| `crates/vft-proxy/src/{audit,lib,pipeline,adapt}.rs` | Migrate off legacy fields; audit line gains cause and points | 8 |
| `crates/vft-cli/src/{main,eval}.rs`, `crates/vft-cli/examples/bench_http.rs` | `config validate --overrides`; eval migration, `cause` CSV column, explain counters | 4, 8, 10 |
| `eval/RESULTS-SP2.md` (new) | Measured acceptance results | 10 |

## Environment for every task

```bash
# Git Bash, from the worktree root.
export VFT_CORPUS="C:/Users/DENNIS~1/AppData/Local/Temp/claude/C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu/da1b01dd-cef6-4b76-bba8-0e55e99fd9e4/scratchpad/ext/blazehttp/testcases"
export VFT_BASELINE="$(git rev-parse --show-toplevel)/.superpowers/sp2/baseline"   # git-ignored
```

If `VFT_CORPUS` does not exist on this machine, stop and ask the owner for the blazehttp `testcases` path; do not substitute another corpus.

---

### Task 1: Decision gate, baseline, `Config.version`

**Files:**
- Create: `eval/decision_gate.sh`
- Modify: `crates/vft-core/src/config.rs` (struct `Config`, its `Default`, `validate`, tests)
- Modify: `config/shield.yaml` (top)

**Interfaces:**
- Produces: `eval/decision_gate.sh capture|check <dir>`; `Config.version: u32` (default 1).

- [ ] **Step 1: Write the gate script**

```bash
#!/usr/bin/env bash
# Decision-equivalence gate for changes that must not move any decision.
#   eval/decision_gate.sh capture <dir>  # write the baseline CSVs and JSON reports
#   eval/decision_gate.sh check <dir>    # re-run into <dir>/now-* and compare with the baseline
# Needs VFT_CORPUS (the blazehttp testcases directory). Compares, per file:
# label, lib_verdict, serve_verdict, score, banned (eval/compare_runs.py).
set -euo pipefail
: "${VFT_CORPUS:?set VFT_CORPUS to the blazehttp testcases directory}"
mode=${1:?capture or check}
dir=${2:?output directory}
case "$mode" in capture) prefix="" ;; check) prefix="now-" ;; *) echo "mode must be capture or check" >&2; exit 2 ;; esac
PY=${PY:-py -I -X utf8}
mkdir -p "$dir"
cargo build --release -p vft-cli
bin=target/release/venusflytrap
for sources in distinct pooled:100; do
  tag=${sources/:/}
  "$bin" eval --corpus "$VFT_CORPUS" --mode serve --sources "$sources" \
    --out "$dir/${prefix}serve-$tag.csv" > "$dir/${prefix}serve-$tag.json"
done
if [ "$mode" = check ]; then
  for tag in distinct pooled100; do
    $PY eval/compare_runs.py "$dir/serve-$tag.csv" "$dir/now-serve-$tag.csv"
  done
  echo "decision gate: identical"
fi
```

- [ ] **Step 2: Capture the baseline on the unchanged tree**

Run: `git log -1 --format=%h` → Expected: `b2f82ff` (or the commit the worktree was cut from; record it in the ledger).
Run: `bash eval/decision_gate.sh capture "$VFT_BASELINE"`
Expected: four files in `$VFT_BASELINE`; `serve-distinct.json` shows `"tp": 288`, `"fp": 278`, `"fn": 368` in both `library` and `serve`, `invariant_violations: 0`. If the counts differ, stop and report: the baseline is not main.

- [ ] **Step 3: Write the failing test** (append to `mod tests` in `config.rs`)

```rust
    #[test]
    fn version_defaults_to_one_and_other_versions_are_rejected() {
        assert_eq!(Config::default().version, 1);
        assert!(issues("version: 1\n").is_empty());
        assert!(issues("version: 2\n").iter().any(|i| i.key == "version"));
        let shipped: Config =
            serde_yaml::from_str(include_str!("../../../config/shield.yaml")).expect("shipped yaml parses");
        assert_eq!(shipped.version, 1);
    }
```

- [ ] **Step 4: Run it to see it fail**

Run: `cargo test -p vft-core version_defaults_to_one`
Expected: compile error, `no field 'version' on type 'Config'`.

- [ ] **Step 5: Implement**

In `config.rs`, replace the `Config` struct and add a manual `Default` (remove `Default` from its derive list):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Config schema version. Only 1 exists.
    pub version: u32,
    pub shield: ShieldConfig,
    pub scoring: ScoringConfig,
    pub chain: ChainConfig,
    pub honeypot: HoneypotConfig,
    pub proxy: ProxyConfig,
    pub limits: LimitsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 1,
            shield: ShieldConfig::default(),
            scoring: ScoringConfig::default(),
            chain: ChainConfig::default(),
            honeypot: HoneypotConfig::default(),
            proxy: ProxyConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}
```

At the top of `validate()`, after `let mut bad = ...;`:

```rust
        if self.version != 1 {
            bad("version", format!("must be 1, got {}", self.version));
        }
```

At the top of `config/shield.yaml`, after the comment block:

```yaml
version: 1                # config schema version
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p vft-core config::` → Expected: all pass.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 7: Commit**

```bash
git add eval/decision_gate.sh crates/vft-core/src/config.rs config/shield.yaml
git commit -m "feat(config): schema version 1 and a corpus decision gate"
```

---

### Task 2: `intel` config section and the deny-pin construct *(Gate)*

**Files:**
- Modify: `crates/vft-core/src/config.rs` (new `IntelConfig`, `Config.intel`, `validate`, tests)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (new static + registry entry)
- Modify: `crates/vft-core/src/shield.rs` (`with_oracle`, `inspect_counting`, tests)
- Modify: `crates/vft-core/src/chain.rs` (`event_for` scanner rule)
- Modify: `config/shield.yaml`

**Interfaces:**
- Produces: `Config.intel: IntelConfig { deny_ips: Vec<String>, allow_ips: Vec<String> }`; `sinks::INTEL_DENY_LISTED` (id `intel.deny-listed`, family `Intel`, kind `Signature`). A deny-pinned request carries a Dangerous `intel.deny-listed` contribution (engine `intel`, field `None`).

- [ ] **Step 1: Write the failing tests**

In `shield.rs` `mod tests`:

```rust
    #[test]
    fn deny_and_allow_lists_come_from_config() {
        let mut cfg = Config::default();
        cfg.intel.deny_ips = vec!["192.0.2.9".into(), "192.0.2.10".into()];
        cfg.intel.allow_ips = vec!["192.0.2.10".into()];
        let s = Shield::new(cfg);
        let mut r = Request::get("/index.html");
        r.src_ip = Some("::ffff:192.0.2.9".parse().unwrap());
        let j = s.inspect(&r);
        assert_eq!(j.verdict, Verdict::Block);
        assert!(has_construct(&j, "intel.deny-listed"));
        assert_eq!(crate::chain::event_for(&j), crate::chain::Event::Benign, "a deny pin is not a kill-chain event");
        r.src_ip = Some("192.0.2.10".parse().unwrap());
        assert_eq!(s.inspect(&r).verdict, Verdict::Allow, "the allow-list suppresses the deny pin");
    }

    #[test]
    fn disabling_the_deny_construct_removes_the_pin() {
        let mut cfg = Config::default();
        cfg.intel.deny_ips = vec!["192.0.2.9".into()];
        cfg.shield.disabled = vec!["intel.deny-listed".into()];
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(Shield::new(cfg).inspect(&r).verdict, Verdict::Allow);
    }
```

In `config.rs` `mod tests`:

```rust
    #[test]
    fn intel_lists_must_be_ip_addresses() {
        assert!(issues("intel:\n  deny_ips: [\"1.2.3.4\", \"nope\"]\n").iter().any(|i| i.key == "intel.deny_ips"));
        assert!(issues("intel:\n  allow_ips: [\"10.0.0.1:80\"]\n").iter().any(|i| i.key == "intel.allow_ips"));
        assert!(issues("intel:\n  deny_ips: [\"::1\"]\n  allow_ips: [\"192.0.2.1\"]\n").is_empty());
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-core intel_lists deny_and_allow disabling_the_deny`
Expected: compile errors (`no field 'intel'`).

- [ ] **Step 3: Implement**

`config.rs` — add after `ProxyConfig`:

```rust
/// Source lists checked before inspection. Exact addresses; an IPv4-mapped
/// IPv6 entry is matched as IPv4.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {
    /// Sources always answered with Block (a hard pin), unless also allow-listed.
    pub deny_ips: Vec<String>,
    /// Sources never banned and never deny-pinned. They are still inspected.
    pub allow_ips: Vec<String>,
}
```

Add `pub intel: IntelConfig,` as the last field of `Config` and `intel: IntelConfig::default(),` in its `Default`. In `validate()`, after the `proxy.trusted_proxies` loop:

```rust
        for (key, list) in [("intel.deny_ips", &self.intel.deny_ips), ("intel.allow_ips", &self.intel.allow_ips)] {
            if let Some(p) = list.iter().find(|p| p.parse::<std::net::IpAddr>().is_err()) {
                bad(key, format!("not an IP address: {p:?}"));
            }
        }
```

`sinks/mod.rs` — after `INTEL_SCANNER_UA`:

```rust
pub static INTEL_DENY_LISTED: ConstructInfo = ConstructInfo { id: "intel.deny-listed", family: Some(Family::Intel), kind: ConstructKind::Signature, summary: "source address is on intel.deny_ips" };
```

and add `&INTEL_DENY_LISTED,` to `REGISTRY` directly after `&INTEL_SCANNER_UA,`.

`shield.rs` — in `with_oracle`, replace `let intel = Intel::with_defaults();` with:

```rust
        let mut intel = Intel::with_defaults();
        for ip in cfg.intel.deny_ips.iter().filter_map(|s| s.parse().ok()) {
            intel.add_deny_ip(canonical(ip));
        }
        for ip in cfg.intel.allow_ips.iter().filter_map(|s| s.parse().ok()) {
            intel.add_allow_ip(canonical(ip));
        }
```

In `inspect_counting`, replace the `// Honeypot.` block's first line `let mut honeypot_or_deny = denied;` with:

```rust
        let deny_pin = denied && !self.disabled.is(&sinks::INTEL_DENY_LISTED);
        if deny_pin {
            rec.record(
                "intel",
                1.0,
                None,
                Evidence::new(
                    FourValued::Dangerous,
                    1.0,
                    vec![sinks::INTEL_DENY_LISTED.pattern()],
                    "source is on intel.deny_ips",
                ),
            );
        }
        let mut honeypot_or_deny = deny_pin;
```

`chain.rs` — in `event_for`, replace the scanner closure body:

```rust
    let scanner = j
        .contributions
        .iter()
        .any(|c| c.construct.as_deref() == Some(sinks::INTEL_SCANNER_UA.id) && c.value.is_threat());
```

(`sinks` is already imported in `chain.rs` for `EXFIL_CONSTRUCTS`; if not, add `use crate::graph::sinks;`.)

`config/shield.yaml` — append after the `proxy:` section:

```yaml
intel:
  deny_ips: []              # sources always blocked (exact IPs), unless also allow-listed
  allow_ips: []             # sources never banned or deny-pinned; still inspected
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green (including `defaults_and_shipped_yaml_validate`, `scanner_fingerprint_stages_enumeration_only_at_challenge_or_above`).

- [ ] **Step 5: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical`.

- [ ] **Step 6: Commit**

```bash
git add crates/vft-core/src/config.rs crates/vft-core/src/graph/sinks/mod.rs crates/vft-core/src/shield.rs crates/vft-core/src/chain.rs config/shield.yaml
git commit -m "feat(intel): deny/allow lists in config with an intel.deny-listed pin"
```

---

### Task 3: Option registry and per-key validation

**Files:**
- Create: `crates/vft-core/src/options.rs`
- Modify: `crates/vft-core/src/lib.rs` (add `pub mod options;`)
- Modify: `crates/vft-core/src/config.rs` (`validate`, new `cross_field_issues`, `from_yaml_str`, `from_tree`, `load`, tests)

**Interfaces:**
- Produces (in `vft_core::options`):
  - `pub enum OptionKind { Int { min: i64, max: i64 }, Float { min: f64, max: f64 }, Bool, Choice { values: &'static [&'static str] }, Paths, Ips, ConstructIds }`
  - `pub enum Expertise { Basic, Advanced, Expert }`, `pub enum Apply { Live, Restart }`
  - `pub struct OptionDescriptor { pub key: &'static str, pub kind: OptionKind, pub section: &'static str, pub help: &'static str, pub level: Expertise, pub apply: Apply, pub sensitive: bool }`
  - `pub static REGISTRY: &[OptionDescriptor]`, `pub fn lookup(key: &str) -> Option<&'static OptionDescriptor>`
  - `pub fn check_value(d: &OptionDescriptor, v: &serde_json::Value) -> Option<String>`
  - `pub fn check_tree(root: &serde_json::Value) -> Vec<ConfigIssue>`
  - `pub(crate) fn yaml_tree(s: &str) -> Result<serde_json::Value, ConfigError>`
- Produces (in `vft_core::config`): `Config::from_yaml_str(s: &str) -> Result<Config, ConfigError>`, `pub(crate) fn from_tree(tree: serde_json::Value) -> Result<Config, ConfigError>`.

- [ ] **Step 1: Write `options.rs` with its tests first (tests fail until the registry is complete)**

```rust
//! Option descriptor registry: one hand-written entry per config leaf, keyed
//! by its dotted path (`scoring.block_at`). The same key names the setting in
//! YAML, in `decided_by`, in the API, in the settings screen and in deep links.
//! Per-key bounds live here; `Config::validate` adds the cross-field rules.

use std::net::IpAddr;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::{ConfigError, ConfigIssue};

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OptionKind {
    Int { min: i64, max: i64 },
    Float { min: f64, max: f64 },
    Bool,
    Choice { values: &'static [&'static str] },
    /// A list of absolute URL paths.
    Paths,
    /// A list of exact IP addresses.
    Ips,
    /// A list of registered construct ids (`graph::sinks::constructs()`).
    ConstructIds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Expertise {
    Basic,
    Advanced,
    Expert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Apply {
    /// Takes effect on the next request after a reload.
    Live,
    /// Saved, but only takes effect after a restart.
    Restart,
}

#[derive(Debug, Serialize)]
pub struct OptionDescriptor {
    pub key: &'static str,
    pub kind: OptionKind,
    pub section: &'static str,
    /// Markdown.
    pub help: &'static str,
    pub level: Expertise,
    pub apply: Apply,
    /// Redacted in API responses, logs and debug bundles.
    pub sensitive: bool,
}

const MAX: i64 = i64::MAX;

const fn opt(key: &'static str, kind: OptionKind, section: &'static str, help: &'static str, level: Expertise, apply: Apply) -> OptionDescriptor {
    OptionDescriptor { key, kind, section, help, level, apply, sensitive: false }
}

use Apply::{Live, Restart};
use Expertise::{Advanced, Basic, Expert};
use OptionKind::{Bool, ConstructIds, Float, Int, Ips, Paths};

pub static REGISTRY: &[OptionDescriptor] = &[
    opt("version", Int { min: 1, max: 1 }, "general", "Config schema version. Only `1` exists.", Expert, Restart),
    // shield
    opt("shield.max_payload", Int { min: 1024, max: MAX }, "shield", "Characters of one field normalized as one chunk; longer fields are inspected in overlapping chunks.", Expert, Live),
    opt("shield.decode_cap", Int { min: 1, max: 32 }, "shield", "Most decode layers peeled from one field before stopping.", Expert, Live),
    opt("shield.deep_threshold", Int { min: 1, max: 32 }, "shield", "Decode depth at or above which a field counts as deeply nested. Must not exceed `shield.decode_cap`.", Expert, Live),
    opt("shield.max_graph_windows", Int { min: 1, max: 1024 }, "shield", "Token windows analyzed per field; past it the field is reported as `limit.graph-truncated`.", Expert, Live),
    opt("shield.max_inspect_bytes", Int { min: 1024, max: MAX }, "shield", "Bytes of one request inspected; past it the request hard-blocks as `limit.payload-truncated`. Must be at least `shield.max_payload`.", Expert, Live),
    opt("shield.max_normalize_work", Int { min: 1024, max: MAX }, "shield", "Folded characters all normalizations of one request may produce; reaching it hard-blocks as `limit.payload-truncated`. Must be at least `shield.max_payload`.", Expert, Live),
    opt("shield.disabled", ConstructIds, "shield", "Construct, decoder or limit ids switched off. Unknown ids are rejected.", Advanced, Live),
    // scoring
    opt("scoring.weight_graph", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of the taint-graph engine.", Advanced, Live),
    opt("scoring.weight_signature", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of literal signatures.", Advanced, Live),
    opt("scoring.weight_intent", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of request intent (sensitive-path recon) and scanner fingerprints.", Advanced, Live),
    opt("scoring.weight_api", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of API-safety checks and inspection limits.", Advanced, Live),
    opt("scoring.weight_ai", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of the heuristic anomaly oracle.", Advanced, Live),
    opt("scoring.block_at", Int { min: 1, max: 100 }, "scoring", "Score at or above which a request is blocked.", Basic, Live),
    opt("scoring.challenge_at", Int { min: 1, max: 100 }, "scoring", "Score at or above which a request is challenged (answered 403 in enforce mode).", Basic, Live),
    opt("scoring.monitor_at", Int { min: 1, max: 100 }, "scoring", "Score at or above which a request is forwarded but flagged.", Basic, Live),
    opt("scoring.conflict_threshold", Float { min: 0.0, max: 1.0 }, "scoring", "Evidence weight above which Safe against Dangerous on one field is a real conflict.", Expert, Live),
    opt("scoring.chain_stage_bonus", Int { min: 0, max: 100 }, "scoring", "Points added when a source advances a kill-chain stage.", Advanced, Live),
    opt("scoring.corroboration_cap", Float { min: 0.0, max: 50.0 }, "scoring", "Most points that corroborating weaker signals may add in total.", Expert, Live),
    // chain
    opt("chain.window_secs", Int { min: 1, max: MAX }, "chain", "Seconds a source's events count toward its stage.", Advanced, Live),
    opt("chain.max_sources", Int { min: 640, max: MAX }, "chain", "Sources tracked at once (least recently seen are evicted; bans are kept separately).", Expert, Restart),
    opt("chain.events_per_source", Int { min: 1, max: MAX }, "chain", "Events remembered per source.", Expert, Restart),
    opt("chain.ipv6_prefix", Int { min: 1, max: 128 }, "chain", "IPv6 sources are grouped by this prefix length.", Expert, Restart),
    opt("chain.ban_policy.on_honeypot", Bool, "chain", "Ban a source that hits a honeypot decoy.", Basic, Live),
    opt("chain.ban_policy.on_exfiltration_block", Bool, "chain", "Ban a source on a single exfiltration block.", Advanced, Live),
    opt("chain.ban_policy.exploitation_blocks", Int { min: 1, max: u32::MAX as i64 }, "chain", "Ban after this many exploitation blocks within `chain.ban_policy.within_secs`.", Advanced, Live),
    opt("chain.ban_policy.within_secs", Int { min: 1, max: MAX }, "chain", "Window for counting exploitation blocks and the hostile share.", Advanced, Live),
    opt("chain.ban_policy.ttl_secs", Int { min: 1, max: MAX }, "chain", "Length of a first ban (and of a manual ban); doubles on each re-offence.", Advanced, Live),
    opt("chain.ban_policy.ttl_max_secs", Int { min: 1, max: MAX }, "chain", "Longest automatic ban. Must be at least `chain.ban_policy.ttl_secs`.", Advanced, Live),
    opt("chain.ban_policy.max_bans", Int { min: 640, max: MAX }, "chain", "Bans held at once; the soonest to expire are evicted first.", Expert, Restart),
    opt("chain.ban_policy.min_hostile_share", Float { min: 0.0, max: 1.0 }, "chain", "Share of a source's recent requests that must be hostile before any automatic ban; `0` turns the check off.", Advanced, Live),
    // honeypot
    opt("honeypot.decoy_paths", Paths, "honeypot", "Decoy paths no legitimate client requests; a hit hard-blocks.", Basic, Live),
    opt("honeypot.sensitive_paths", Paths, "honeypot", "Path prefixes whose probing counts as recon.", Basic, Live),
    // proxy
    opt("proxy.trusted_proxies", Ips, "proxy", "Peers whose `X-Forwarded-For` is trusted.", Basic, Restart),
    opt("proxy.decision_headers", OptionKind::Choice { values: &["off", "upstream"] }, "proxy", "`upstream` adds `X-Venusflytrap-*` headers to forwarded requests; never sent to clients.", Advanced, Restart),
    // limits
    opt("limits.max_body", Int { min: 1024, max: MAX }, "limits", "Largest request body in bytes; larger bodies get 413 before any upstream connection.", Basic, Restart),
    opt("limits.max_headers", Int { min: 8, max: 1000 }, "limits", "Most request headers accepted.", Advanced, Restart),
    opt("limits.max_connections", Int { min: 1, max: MAX }, "limits", "Concurrent client connections.", Advanced, Restart),
    opt("limits.header_read_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed to receive the request head.", Advanced, Restart),
    opt("limits.body_read_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed to receive the request body.", Advanced, Restart),
    opt("limits.upstream_connect_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed to connect to the upstream.", Advanced, Restart),
    opt("limits.upstream_response_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed for the upstream response head.", Advanced, Restart),
    opt("limits.response_idle_timeout_ms", Int { min: 1, max: MAX }, "limits", "Longest gap between upstream response-body chunks.", Advanced, Restart),
    opt("limits.max_connection_ms", Int { min: 1, max: MAX }, "limits", "Hard cap on one client connection's lifetime.", Advanced, Restart),
    // intel
    opt("intel.deny_ips", Ips, "intel", "Sources always blocked, unless also allow-listed.", Basic, Live),
    opt("intel.allow_ips", Ips, "intel", "Sources never banned or deny-listed; still inspected.", Basic, Live),
];

pub fn lookup(key: &str) -> Option<&'static OptionDescriptor> {
    REGISTRY.iter().find(|d| d.key == key)
}

/// True if `key` is a strict prefix section of some registered key (`chain`,
/// `chain.ban_policy`).
fn is_section(key: &str) -> bool {
    REGISTRY
        .iter()
        .any(|d| d.key.len() > key.len() && d.key.starts_with(key) && d.key.as_bytes()[key.len()] == b'.')
}

/// The problem with `v` as a value of `d`, if any.
pub fn check_value(d: &OptionDescriptor, v: &Value) -> Option<String> {
    match d.kind {
        OptionKind::Int { min, max } => match v.as_i64() {
            Some(n) if (min..=max).contains(&n) => None,
            _ if max == MAX => Some(format!("must be an integer >= {min}, got {v}")),
            _ => Some(format!("must be an integer in {min}..={max}, got {v}")),
        },
        OptionKind::Float { min, max } => match v.as_f64() {
            Some(x) if x.is_finite() && (min..=max).contains(&x) => None,
            _ => Some(format!("must be a finite number in [{min}, {max}], got {v}")),
        },
        OptionKind::Bool => (!v.is_boolean()).then(|| format!("must be true or false, got {v}")),
        OptionKind::Choice { values } => match v.as_str() {
            Some(s) if values.contains(&s) => None,
            _ => Some(format!("must be one of {}, got {v}", values.join(", "))),
        },
        OptionKind::Paths => strings(v, "a list of paths", |s| {
            (!s.starts_with('/')).then(|| format!("paths must start with '/', got {s:?}"))
        }),
        OptionKind::Ips => strings(v, "a list of IP addresses", |s| {
            s.parse::<IpAddr>().is_err().then(|| format!("not an IP address: {s:?}"))
        }),
        OptionKind::ConstructIds => strings(v, "a list of construct ids", |s| {
            crate::graph::sinks::lookup(s).is_none().then(|| format!("unknown construct id {s:?}"))
        }),
    }
}

fn strings(v: &Value, what: &str, bad: impl Fn(&str) -> Option<String>) -> Option<String> {
    let Some(items) = v.as_array() else {
        return Some(format!("must be {what}, got {v}"));
    };
    for item in items {
        let Some(s) = item.as_str() else {
            return Some(format!("must be {what}, got {v}"));
        };
        if let Some(m) = bad(s) {
            return Some(m);
        }
    }
    None
}

/// Every per-key problem in a config tree: unknown keys, wrong types, values
/// out of bounds. A `Null` root is an empty config.
pub fn check_tree(root: &Value) -> Vec<ConfigIssue> {
    let mut out = Vec::new();
    match root {
        Value::Null => {}
        Value::Object(m) => walk("", m, &mut out),
        _ => out.push(ConfigIssue { key: "<config>".into(), message: "must be a mapping of sections".into() }),
    }
    out
}

fn walk(prefix: &str, m: &Map<String, Value>, out: &mut Vec<ConfigIssue>) {
    for (k, v) in m {
        let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        if let Some(d) = lookup(&key) {
            if let Some(message) = check_value(d, v) {
                out.push(ConfigIssue { key, message });
            }
        } else if is_section(&key) {
            match v {
                Value::Object(c) => walk(&key, c, out),
                _ => out.push(ConfigIssue { key, message: "must be a mapping".into() }),
            }
        } else {
            out.push(ConfigIssue { key, message: "unknown option".into() });
        }
    }
}

/// Parse YAML into the JSON tree the checker reads. An empty document is `Null`.
pub(crate) fn yaml_tree(s: &str) -> Result<Value, ConfigError> {
    if s.trim().is_empty() {
        return Ok(Value::Null);
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(s)?;
    serde_json::to_value(yaml).map_err(|e| {
        ConfigError::Invalid(vec![ConfigIssue { key: "<config>".into(), message: format!("not a plain mapping: {e}") }])
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn leaves(prefix: &str, v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, c) in m {
                    let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    leaves(&p, c, out);
                }
            }
            _ => out.push(prefix.to_string()),
        }
    }

    #[test]
    fn every_config_leaf_has_exactly_one_descriptor() {
        let mut keys = Vec::new();
        leaves("", &serde_json::to_value(Config::default()).expect("serializes"), &mut keys);
        for k in &keys {
            assert_eq!(REGISTRY.iter().filter(|d| d.key == k).count(), 1, "leaf {k} needs exactly one descriptor");
        }
        for d in REGISTRY {
            assert!(keys.iter().any(|k| k == d.key), "descriptor {} is not a config leaf", d.key);
        }
    }

    #[test]
    fn sections_and_help_are_filled_in() {
        for d in REGISTRY {
            let want = d.key.split_once('.').map_or("general", |(s, _)| s);
            assert_eq!(d.section, want, "{}", d.key);
            assert!(!d.help.is_empty(), "{} has no help", d.key);
        }
    }

    #[test]
    fn defaults_pass_the_tree_check() {
        let tree = serde_json::to_value(Config::default()).expect("serializes");
        assert_eq!(check_tree(&tree), Vec::new());
    }

    #[test]
    fn check_value_reports_type_and_bounds() {
        let d = lookup("scoring.block_at").unwrap();
        assert!(check_value(d, &serde_json::json!(90)).is_none());
        assert!(check_value(d, &serde_json::json!(0)).is_some());
        assert!(check_value(d, &serde_json::json!("ninety")).is_some());
        let w = lookup("scoring.weight_ai").unwrap();
        assert!(check_value(w, &Value::Null).is_some(), "NaN serializes as null");
        assert!(check_value(w, &serde_json::json!(1)).is_none(), "an integer is a valid float");
        let c = lookup("proxy.decision_headers").unwrap();
        assert!(check_value(c, &serde_json::json!("upstream")).is_none());
        assert!(check_value(c, &serde_json::json!("client")).is_some());
    }

    #[test]
    fn unknown_keys_and_non_mappings_are_per_key() {
        let tree = serde_json::json!({ "scoring": { "blok_at": 10 }, "chain": 5, "nonsense": 1 });
        let mut keys: Vec<String> = check_tree(&tree).into_iter().map(|i| i.key).collect();
        keys.sort();
        assert_eq!(keys, vec!["chain", "nonsense", "scoring.blok_at"]);
    }
}
```

Add `pub mod options;` to `lib.rs` after `pub mod normalize;`.

- [ ] **Step 2: Run the registry tests**

Run: `cargo test -p vft-core options::` → Expected: all five pass. If `every_config_leaf_has_exactly_one_descriptor` fails, the message names the missing or extra key; fix the table, not the test.

- [ ] **Step 3: Write the failing M6 tests** (append to `config.rs` `mod tests`)

```rust
    #[test]
    fn m6_bad_inputs_yield_per_key_issues() {
        for (yaml, key) in [
            ("scoring:\n  blok_at: 10\n", "scoring.blok_at"),
            ("scoring:\n  block_at: 0\n", "scoring.block_at"),
            ("scoring:\n  weight_ai: .nan\n", "scoring.weight_ai"),
            ("shield:\n  max_payload: 0\n", "shield.max_payload"),
            ("shield:\n  decode_cap: banana\n", "shield.decode_cap"),
            ("nonsense: 1\n", "nonsense"),
        ] {
            match Config::from_yaml_str(yaml) {
                Err(ConfigError::Invalid(issues)) => {
                    assert!(issues.iter().any(|i| i.key == key), "{yaml:?}: {issues:?}")
                }
                other => panic!("{yaml:?}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn empty_and_shipped_files_load() {
        assert!(Config::from_yaml_str("").is_ok());
        assert!(Config::from_yaml_str(include_str!("../../../config/shield.yaml")).is_ok());
    }

    #[test]
    fn cross_field_rules_still_apply() {
        assert!(issues("shield:\n  decode_cap: 4\n  deep_threshold: 5\n").iter().any(|i| i.key == "shield.deep_threshold"));
        assert!(issues("scoring:\n  monitor_at: 80\n").iter().any(|i| i.key == "scoring.block_at"));
    }
```

- [ ] **Step 4: Run them to see them fail**

Run: `cargo test -p vft-core m6_bad_inputs empty_and_shipped cross_field_rules`
Expected: compile error, `no function 'from_yaml_str'`.

- [ ] **Step 5: Rewrite `validate`, add `from_yaml_str` / `from_tree`, route `load` through them**

Replace the whole `impl Config { ... }` block in `config.rs` with:

```rust
impl Config {
    /// Load and validate a YAML file. A missing file is an error.
    pub fn load(path: &std::path::Path) -> Result<Config, ConfigError> {
        Config::from_yaml_str(&std::fs::read_to_string(path)?)
    }

    /// `None` means built-in defaults; `Some(path)` must exist and validate.
    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Config, ConfigError> {
        match path {
            Some(p) => Config::load(p),
            None => Ok(Config::default()),
        }
    }

    /// Parse and validate YAML. Unknown keys, wrong types and out-of-bounds
    /// values are reported per key, all at once.
    pub fn from_yaml_str(s: &str) -> Result<Config, ConfigError> {
        from_tree(crate::options::yaml_tree(s)?)
    }

    /// Per-key bounds (from `options::REGISTRY`) and cross-field rules. Every
    /// issue names its option key.
    pub fn validate(&self) -> Result<(), Vec<ConfigIssue>> {
        let mut v = match serde_json::to_value(self) {
            Ok(tree) => crate::options::check_tree(&tree),
            Err(e) => vec![ConfigIssue { key: "<config>".into(), message: e.to_string() }],
        };
        v.extend(self.cross_field_issues());
        if v.is_empty() {
            Ok(())
        } else {
            Err(v)
        }
    }

    fn cross_field_issues(&self) -> Vec<ConfigIssue> {
        let mut v: Vec<ConfigIssue> = Vec::new();
        let mut bad = |key: &str, message: String| v.push(ConfigIssue { key: key.into(), message });
        let sh = &self.shield;
        if sh.deep_threshold > sh.decode_cap {
            bad("shield.deep_threshold", format!("must be <= shield.decode_cap ({}), got {}", sh.decode_cap, sh.deep_threshold));
        }
        if sh.max_inspect_bytes < sh.max_payload {
            bad("shield.max_inspect_bytes", format!("must be >= shield.max_payload ({}), got {}", sh.max_payload, sh.max_inspect_bytes));
        }
        if sh.max_normalize_work < sh.max_payload {
            bad("shield.max_normalize_work", format!("must be >= shield.max_payload ({}), got {}", sh.max_payload, sh.max_normalize_work));
        }
        let s = &self.scoring;
        if !(s.monitor_at < s.challenge_at && s.challenge_at < s.block_at && s.block_at <= 100) {
            bad(
                "scoring.block_at",
                format!(
                    "bands must satisfy monitor_at < challenge_at < block_at <= 100, got {}/{}/{}",
                    s.monitor_at, s.challenge_at, s.block_at
                ),
            );
        }
        let b = &self.chain.ban_policy;
        if b.ttl_max_secs < b.ttl_secs {
            bad("chain.ban_policy.ttl_max_secs", format!("must be >= ttl_secs ({}), got {}", b.ttl_secs, b.ttl_max_secs));
        }
        v
    }
}

/// Check a config tree per key, deserialize it, then apply the cross-field rules.
pub(crate) fn from_tree(tree: serde_json::Value) -> Result<Config, ConfigError> {
    let issues = crate::options::check_tree(&tree);
    if !issues.is_empty() {
        return Err(ConfigError::Invalid(issues));
    }
    let tree = if tree.is_null() { serde_json::Value::Object(Default::default()) } else { tree };
    let cfg: Config = serde_json::from_value(tree)
        .map_err(|e| ConfigError::Invalid(vec![ConfigIssue { key: "<config>".into(), message: e.to_string() }]))?;
    cfg.validate().map_err(ConfigError::Invalid)?;
    Ok(cfg)
}
```

The per-key checks deleted from the old `validate` (version, every `shield.*` bound, weights, `conflict_threshold`, `corroboration_cap`, `monitor_at == 0`, chain and ban-policy minimums, `min_hostile_share`, trusted proxies, intel lists, limits, honeypot paths, `shield.disabled`) are now in `REGISTRY`; the existing tests in `config.rs` keep passing because they assert keys, not messages.

- [ ] **Step 6: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green. `cargo run -p vft-cli -- config validate config/shield.yaml` → Expected: `config/shield.yaml: ok`.

- [ ] **Step 7: Commit**

```bash
git add crates/vft-core/src/options.rs crates/vft-core/src/lib.rs crates/vft-core/src/config.rs
git commit -m "feat(options): descriptor registry drives per-key config validation"
```

---

### Task 4: Base + override layering and `config validate --overrides`

**Files:**
- Modify: `crates/vft-core/src/options.rs` (append `Source`, `Layered`, `layer`, helpers, tests)
- Modify: `crates/vft-cli/src/main.rs` (`ConfigCmd::Validate`)

**Interfaces:**
- Consumes: `check_tree`, `check_value`, `lookup`, `yaml_tree` (Task 3); `config::from_tree` (Task 3).
- Produces: `pub enum Source { Default, Base, Override }` (serde lowercase); `pub struct Layered { pub config: Config, pub sources: BTreeMap<&'static str, Source> }`; `pub fn layer(base_yaml: Option<&str>, overrides_yaml: Option<&str>) -> Result<Layered, ConfigError>`. Overrides are a flat YAML map of dotted keys; scalars override, lists replace.

- [ ] **Step 1: Write the failing tests** (append to `options.rs` `mod tests`)

```rust
    #[test]
    fn overrides_replace_scalars_and_lists_and_report_sources() {
        let base = "scoring:\n  block_at: 95\nhoneypot:\n  decoy_paths: [/a, /b]\n";
        let ov = "scoring.challenge_at: 60\nhoneypot.decoy_paths: [/c]\n";
        let l = layer(Some(base), Some(ov)).expect("valid");
        assert_eq!(l.config.scoring.block_at, 95);
        assert_eq!(l.config.scoring.challenge_at, 60);
        assert_eq!(l.config.honeypot.decoy_paths, vec!["/c".to_string()], "lists replace");
        assert_eq!(l.sources["scoring.block_at"], Source::Base);
        assert_eq!(l.sources["scoring.challenge_at"], Source::Override);
        assert_eq!(l.sources["honeypot.decoy_paths"], Source::Override);
        assert_eq!(l.sources["scoring.monitor_at"], Source::Default);
        assert_eq!(l.sources.len(), REGISTRY.len());
    }

    #[test]
    fn bad_overrides_are_per_key() {
        let err = |ov: &str| match layer(None, Some(ov)) {
            Err(ConfigError::Invalid(i)) => i.into_iter().map(|i| i.key).collect::<Vec<_>>(),
            other => panic!("{ov:?}: expected Invalid, got {other:?}"),
        };
        assert_eq!(err("scoring.blok_at: 1\n"), vec!["scoring.blok_at"]);
        assert_eq!(err("scoring.block_at: banana\n"), vec!["scoring.block_at"]);
        assert_eq!(err("scoring.monitor_at: 95\n"), vec!["scoring.block_at"], "cross-field rules see the merged config");
        assert_eq!(err("- not a map\n"), vec!["<overrides>"]);
    }

    #[test]
    fn no_layers_is_the_default_config() {
        let l = layer(None, None).expect("defaults are valid");
        assert_eq!(l.config.scoring.block_at, Config::default().scoring.block_at);
        assert!(l.sources.values().all(|s| *s == Source::Default));
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-core options::tests::overrides` → Expected: compile error, `cannot find function 'layer'`.

- [ ] **Step 3: Implement** (append to `options.rs`, above `#[cfg(test)]`)

First widen the imports at the top of `options.rs`: add `use std::collections::BTreeMap;` and change the config import to `use crate::config::{Config, ConfigError, ConfigIssue};` (then drop the now-redundant `use crate::config::Config;` from its `mod tests`).

```rust
/// Where an option's effective value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Default,
    Base,
    Override,
}

/// The effective config and, for every registered key, which layer set it.
#[derive(Debug)]
pub struct Layered {
    pub config: Config,
    pub sources: BTreeMap<&'static str, Source>,
}

/// Apply a sparse override map (`scoring.block_at: 85`) on top of the
/// operator's base YAML. Scalars override, lists replace. Every problem in
/// either layer is reported per key; nothing is applied unless all is valid.
pub fn layer(base_yaml: Option<&str>, overrides_yaml: Option<&str>) -> Result<Layered, ConfigError> {
    let mut tree = match base_yaml {
        Some(s) => yaml_tree(s)?,
        None => Value::Null,
    };
    let mut issues = check_tree(&tree);
    if !tree.is_object() {
        tree = Value::Object(Map::new());
    }
    let in_base: Vec<&'static str> = REGISTRY.iter().filter(|d| get_path(&tree, d.key).is_some()).map(|d| d.key).collect();

    let overrides = match overrides_yaml {
        Some(s) => yaml_tree(s)?,
        None => Value::Null,
    };
    let mut overridden: Vec<&'static str> = Vec::new();
    match &overrides {
        Value::Null => {}
        Value::Object(m) => {
            for (k, v) in m {
                match lookup(k) {
                    None => issues.push(ConfigIssue { key: k.clone(), message: "unknown option (in overrides)".into() }),
                    Some(d) => match check_value(d, v) {
                        Some(msg) => issues.push(ConfigIssue { key: k.clone(), message: format!("{msg} (in overrides)") }),
                        None => {
                            set_path(&mut tree, d.key, v.clone());
                            overridden.push(d.key);
                        }
                    },
                }
            }
        }
        _ => issues.push(ConfigIssue {
            key: "<overrides>".into(),
            message: "must be a flat mapping of option keys to values".into(),
        }),
    }
    if !issues.is_empty() {
        return Err(ConfigError::Invalid(issues));
    }
    let config = crate::config::from_tree(tree)?;
    let sources = REGISTRY
        .iter()
        .map(|d| {
            let s = if overridden.contains(&d.key) {
                Source::Override
            } else if in_base.contains(&d.key) {
                Source::Base
            } else {
                Source::Default
            };
            (d.key, s)
        })
        .collect();
    Ok(Layered { config, sources })
}

fn get_path<'a>(tree: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.').try_fold(tree, |node, part| node.get(part))
}

fn set_path(tree: &mut Value, key: &str, v: Value) {
    let mut node = tree;
    let mut parts = key.split('.').peekable();
    while let Some(part) = parts.next() {
        if !node.is_object() {
            *node = Value::Object(Map::new());
        }
        let Value::Object(m) = node else { return };
        if parts.peek().is_none() {
            m.insert(part.to_string(), v);
            return;
        }
        node = m.entry(part.to_string()).or_insert_with(|| Value::Object(Map::new()));
    }
}
```

In `crates/vft-cli/src/main.rs`, change the subcommand:

```rust
enum ConfigCmd {
    /// Parse and validate a config file, optionally with an overrides file on top;
    /// exit 1 and list every issue if invalid.
    Validate {
        file: PathBuf,
        /// Sparse `key: value` overrides applied on top of FILE (lists replace).
        #[arg(long)]
        overrides: Option<PathBuf>,
    },
}
```

and its arm:

```rust
        Command::Config { action: ConfigCmd::Validate { file, overrides } } => {
            let base = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let ov = match overrides.as_ref() {
                Some(p) => Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?),
                None => None,
            };
            match vft_core::options::layer(Some(&base), ov.as_deref()) {
                Ok(l) => {
                    println!("{}: ok", file.display());
                    for (key, src) in &l.sources {
                        if *src == vft_core::options::Source::Override {
                            println!("  {key}: override");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}: {e}", file.display());
                    std::process::exit(1);
                }
            }
        }
```

- [ ] **Step 4: Run the tests and a manual check**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.
Run: `printf 'scoring.block_at: 85\n' > target/ov.yaml && cargo run -q -p vft-cli -- config validate config/shield.yaml --overrides target/ov.yaml`
Expected: `config/shield.yaml: ok` then `  scoring.block_at: override`.

- [ ] **Step 5: Commit**

```bash
git add crates/vft-core/src/options.rs crates/vft-cli/src/main.rs
git commit -m "feat(options): base + override layering with per-key sources"
```

---

### Task 5: Constructs for pattern-less evidence *(Gate)*

**Files:**
- Modify: `crates/vft-core/src/judgment.rs` (`Family::Anomaly`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (two statics, registry entries)
- Modify: `crates/vft-core/src/detect.rs` (`ApiSafetyDetector`, `AiDetector`, tests)

**Interfaces:**
- Produces: `Family::Anomaly`; `sinks::AI_ANOMALY_SCORE` (`ai.anomaly-score`) and `sinks::API_OVERSIZED_HEADER` (`api.oversized-header`), both family `Anomaly`, kind `Signature`. After this task every non-`None` evidence carries at least one pattern.

- [ ] **Step 1: Write the failing test** (in `detect.rs` `mod tests`; it goes through `Shield` so it needs no `FieldCtx` fixture):

```rust
    #[test]
    fn every_threat_evidence_names_a_construct() {
        let shield = crate::Shield::new(crate::Config::default());
        let mut r = crate::Request::get("/p");
        r.query.push(("q".into(), "%27%22%3E%3C!--{{}}$$((;;||&&".into()));
        r.headers.push(("X-Big".into(), "a".repeat(5000)));
        let j = shield.inspect(&r);
        for c in &j.contributions {
            assert!(c.construct.is_some(), "{} on {:?} has no construct", c.engine, c.field);
        }
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("api.oversized-header")));
    }
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p vft-core every_threat_evidence_names_a_construct`
Expected: FAIL, `api-safety on Some(..) has no construct`.

- [ ] **Step 3: Implement**

`judgment.rs` — add to `Family` after `Limit`:

```rust
    /// A heuristic anomaly signal that belongs to no attack family.
    Anomaly,
```

`sinks/mod.rs` — after `API_TYPE_VIOLATION`:

```rust
pub static API_OVERSIZED_HEADER: ConstructInfo = ConstructInfo { id: "api.oversized-header", family: Some(Family::Anomaly), kind: ConstructKind::Signature, summary: "a header value longer than 4096 bytes" };
pub static AI_ANOMALY_SCORE: ConstructInfo = ConstructInfo { id: "ai.anomaly-score", family: Some(Family::Anomaly), kind: ConstructKind::Signature, summary: "the heuristic anomaly oracle scored the field at or above 0.35" };
```

and in `REGISTRY` after `&API_TYPE_VIOLATION,`: `&API_OVERSIZED_HEADER,` and `&AI_ANOMALY_SCORE,`.

`detect.rs` — in `ApiSafetyDetector::assess`, change the oversized-header branch to:

```rust
        if ctx.field.loc == Location::Header
            && ctx.field.raw.len() > 4096
            && !ctx.disabled.is(&sinks::API_OVERSIZED_HEADER)
        {
            return Evidence::new(
                FourValued::Suspicious,
                0.3,
                vec![sinks::API_OVERSIZED_HEADER.pattern()],
                "oversized header value",
            );
        }
```

In `AiDetector::assess`, replace the last line:

```rust
        if value == FourValued::None || ctx.disabled.is(&sinks::AI_ANOMALY_SCORE) {
            return Evidence::none(format!("ai score {s:.2}"));
        }
        Evidence::new(value, weight, vec![sinks::AI_ANOMALY_SCORE.pattern()], format!("ai score {s:.2}"))
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 5: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (scores included: the per-field dedup key stays one per detector).

- [ ] **Step 6: Commit**

```bash
git add crates/vft-core/src/judgment.rs crates/vft-core/src/graph/sinks/mod.rs crates/vft-core/src/detect.rs
git commit -m "feat(sinks): anomaly constructs for the AI and oversized-header signals"
```

---

### Task 6: Real points *(Gate)*

**Files:**
- Modify: `crates/vft-core/src/score.rs` (`Arbitration`, `arbitrate`, tests)
- Modify: `crates/vft-core/src/shield.rs` (`Recorder`, `inspect_counting`, tests)
- Create: `crates/vft-core/tests/points.rs`

**Interfaces:**
- Produces: `pub struct Arbitration { pub score: u8, pub verdict: Verdict, pub conflict: bool, pub points: Vec<f32> }`; `pub fn arbitrate(items: &[Scored], cfg: &ScoringConfig, hard_block: bool) -> Arbitration`. `points[i]` belongs to `items[i]`; on a hard pin all are 0 and the caller credits the pin. After this task `Σ contribution.points` is within ±1 of `score` for every `inspect` result.

- [ ] **Step 1: Write the failing tests**

`crates/vft-core/tests/points.rs`:

```rust
//! Σ contribution points reproduces the score (SP2 acceptance).

use proptest::prelude::*;
use vft_core::{Config, Judgment, Request, Shield};

fn sum(j: &Judgment) -> f32 {
    j.contributions.iter().map(|c| c.points).sum()
}

fn assert_adds_up(j: &Judgment, what: &str) {
    assert!((sum(j) - f32::from(j.score)).abs() <= 1.0, "{what}: Σ points {} vs score {}", sum(j), j.score);
}

#[test]
fn points_add_up_on_known_requests() {
    let s = Shield::new(Config::default());
    assert_adds_up(&s.inspect(&Request::get("/.git/config")), "honeypot");
    assert_adds_up(&s.inspect(&Request::get("/.env")), "recon");
    assert_adds_up(&s.inspect(&Request::get("/index.html")), "benign");
    let mut q = Request::get("/items");
    q.query.push(("id".into(), "1 union select password from users".into()));
    assert_adds_up(&s.inspect(&q), "sqli");
    let mut x = Request::get("/p");
    x.query.push(("q".into(), "<img src=x onerror=alert(1)>".into()));
    for i in 0..30 {
        x.query.push((format!("c{i}"), "red;blue".into()));
    }
    assert_adds_up(&s.inspect(&x), "xss plus capped corroboration");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn points_add_up_on_arbitrary_values(v in ".{0,300}", h in ".{0,100}") {
        let s = Shield::new(Config::default());
        let mut r = Request::get("/p");
        r.query.push(("q".into(), v));
        r.headers.push(("X-Test".into(), h));
        let j = s.inspect(&r);
        prop_assert!((sum(&j) - f32::from(j.score)).abs() <= 1.0, "Σ {} vs {}", sum(&j), j.score);
    }
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-core --test points` → Expected: FAIL (`Σ points 0 vs score 100`).

- [ ] **Step 3: Implement `Arbitration`** — replace `arbitrate` in `score.rs` (keep `value_points`, `Scored`, `field_conflict`, `band_floor`, `band` unchanged):

```rust
/// The outcome of combining one request's evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct Arbitration {
    pub score: u8,
    pub verdict: Verdict,
    pub conflict: bool,
    /// Points each input item added, aligned with `items`. Their sum is the
    /// score before rounding. All zero for a hard pin; the caller credits it.
    pub points: Vec<f32>,
}

/// Combine evidence into a score and a verdict. Hard-pin inputs (deny-list,
/// honeypot, fail-closed limit) are passed via `hard_block`.
pub fn arbitrate(items: &[Scored], cfg: &ScoringConfig, hard_block: bool) -> Arbitration {
    if hard_block {
        return Arbitration { score: 100, verdict: Verdict::Block, conflict: false, points: vec![0.0; items.len()] };
    }

    // Weighted max-style aggregation: the strongest well-weighted threat drives
    // the score, with smaller corroborating signals nudging it up. This avoids
    // diluting a single strong detection by averaging in silent detectors.
    let is_conflict = field_conflict(items, cfg.conflict_threshold);

    // One contribution per (field, construct): repeating the same weak signal
    // on one field does not corroborate itself (M1).
    let mut seen: std::collections::HashSet<(Option<FieldRef>, String)> = Default::default();
    // (item index, raw points) for each counted threat item.
    let mut counted: Vec<(usize, f32)> = Vec::new();
    for (i, s) in items.iter().enumerate().filter(|(_, s)| s.evidence.value.is_threat()) {
        let construct = s
            .evidence
            .patterns
            .first()
            .map_or_else(|| s.engine.clone(), |p| p.name.clone());
        if !seen.insert((s.field.clone(), construct)) {
            continue;
        }
        counted.push((i, value_points(s.evidence.value) * s.evidence.weight * s.engine_weight));
    }
    let top = counted.iter().map(|c| c.1).fold(0.0f32, f32::max);
    let rest = counted.iter().map(|c| c.1).sum::<f32>() - top;
    let corroboration = (rest * 0.1).min(cfg.corroboration_cap);

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        // Damp, but never below the band the strongest danger reaches alone.
        score = (score * 0.9).max(band_floor(top, cfg));
    }

    // Points: the first maximal item keeps its raw points, the rest share the
    // corroboration in proportion; clamping and damping then scale every item
    // alike, so the points sum to the unrounded score.
    let mut points = vec![0.0f32; items.len()];
    let mut top_n: Option<usize> = None;
    let mut best = 0.0f32;
    for (n, c) in counted.iter().enumerate() {
        if c.1 > best {
            best = c.1;
            top_n = Some(n);
        }
    }
    let share = if rest > 0.0 { corroboration / rest } else { 0.0 };
    for (n, &(i, raw)) in counted.iter().enumerate() {
        points[i] = if Some(n) == top_n { raw } else { raw * share };
    }
    let unscaled = top + corroboration;
    if unscaled > 0.0 {
        let k = score / unscaled;
        for p in &mut points {
            *p *= k;
        }
    }

    let s = score.round().clamp(0.0, 100.0) as u8;
    Arbitration { score: s, verdict: band(s, cfg), conflict: is_conflict, points }
}
```

Note the score expression is the old one term for term (`rest` is the old `points.iter().sum::<f32>() - top`); do not reorder it.

Update every `score.rs` unit test from tuple destructuring to fields, e.g. `let (s, v, _) = arbitrate(&ev, &cfg, false);` → `let a = arbitrate(&ev, &cfg, false); let (s, v) = (a.score, a.verdict);`, `arbitrate(..).0` → `arbitrate(..).score`, `let (_, v, c) = ...` → `let a = ...; let (v, c) = (a.verdict, a.conflict);`. Add one unit test:

```rust
    #[test]
    fn points_sum_to_the_unrounded_score() {
        let cfg = ScoringConfig::default();
        let mut ev = vec![scf(1.0, "a", Evidence::new(FourValued::Dangerous, 0.95, vec![], "x"))];
        for i in 0..40 {
            ev.push(scf(1.0, &format!("f{i}"), Evidence::new(FourValued::Suspicious, 0.5, vec![], "w")));
        }
        let a = arbitrate(&ev, &cfg, false);
        let sum: f32 = a.points.iter().sum();
        assert!((sum - f32::from(a.score)).abs() <= 0.5, "Σ {sum} vs {}", a.score);
        assert!(a.points[0] > a.points[1], "the top item keeps the most points");
    }
```

- [ ] **Step 4: Credit points to contributions in `shield.rs`**

In `Recorder`, add a field `first_contrib: Vec<Option<usize>>` (aligned with `scored`). In `record`, before the `if e.value != FourValued::None` block insert `let first = (e.value != FourValued::None).then_some(self.contributions.len());` and after the `self.scored.push(..)` line add `self.first_contrib.push(first);`.

In `inspect_counting`, replace `let (score, verdict, conflict) = arbitrate(&rec.scored, &self.cfg.scoring, hard_block);` with:

```rust
        let arb = arbitrate(&rec.scored, &self.cfg.scoring, hard_block);
        let (score, verdict, conflict) = (arb.score, arb.verdict, arb.conflict);
        for (i, p) in arb.points.iter().enumerate() {
            if let Some(ci) = rec.first_contrib[i] {
                rec.contributions[ci].points += p;
            }
        }
        if hard_block {
            // The deciding pin carries the whole score, in decided_by order.
            let pin = [sinks::HONEYPOT_DECOY_HIT.id, sinks::INTEL_DENY_LISTED.id, sinks::LIMIT_PAYLOAD_TRUNCATED.id]
                .into_iter()
                .find_map(|id| rec.contributions.iter().position(|c| c.construct.as_deref() == Some(id)));
            if let Some(ci) = pin {
                rec.contributions[ci].points = 100.0;
            }
        }
```

`banned_judgment` sets its `chain.ban` contribution's `points: 100.0`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green, including `tests/points.rs`.

- [ ] **Step 6: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical`.

- [ ] **Step 7: Commit**

```bash
git add crates/vft-core/src/score.rs crates/vft-core/src/shield.rs crates/vft-core/tests/points.rs
git commit -m "feat(score): contributions carry the points they added"
```

---

### Task 7: `Cause` and `decided_by`; `event_for` reads it *(Gate)*

**Files:**
- Modify: `crates/vft-core/src/judgment.rs` (`CauseKind`, `Cause`, `FieldRef::label`, `Judgment` gains `decided_by` and `chain`, drops `Deserialize`)
- Modify: `crates/vft-core/src/chain.rs` (`ChainOutcome: Serialize`; `event_for` honeypot rule; test builder)
- Modify: `crates/vft-core/src/shield.rs` (`Pins`, `cause_for`, `band_key`, `ban_cause`, `chain_contribution`, `inspect_counting`, `finalize`, `banned_judgment`, tests)
- Modify: `crates/vft-core/src/lib.rs` (re-export `Cause`, `CauseKind`)

**Interfaces:**
- Produces:
  - `pub enum CauseKind { NoEvidence, Detection, Honeypot, IntelDeny, Ban, ChainEscalation, Limit, Allowlisted }` (Debug, Clone, Copy, PartialEq, Eq, Serialize)
  - `pub struct Cause { pub kind: CauseKind, pub option_key: &'static str, pub construct: Option<String>, pub field: Option<FieldRef>, pub msg: String }` (Debug, Clone, Serialize)
  - `Judgment.decided_by: Cause`, `Judgment.chain: Option<ChainOutcome>` (set by `finalize`; `None` for stateless `inspect` and for a fast-track ban)
  - `FieldRef::label(&self) -> String` → `"query:id"`
  - Option keys used: `honeypot.decoy_paths`, `intel.deny_ips`, `intel.allow_ips`, `shield.max_inspect_bytes`, `shield.max_normalize_work`, `shield.max_payload`, `scoring.block_at`, `scoring.challenge_at`, `scoring.monitor_at`, `scoring.chain_stage_bonus`, and the four ban keys of D4.
  - Contribution ids `chain.stage-advance` and `chain.ban` (engine `chain`, not in the construct registry).

- [ ] **Step 1: Write the failing tests** (in `shield.rs` `mod tests`; add `use crate::judgment::CauseKind; use crate::chain::ChainOutcome;` to the module's imports)

```rust
    #[test]
    fn decided_by_follows_the_fixed_order() {
        let s = shield();
        let j = s.inspect(&Request::get("/.git/config"));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Honeypot, "honeypot.decoy_paths"));
        let mut q = Request::get("/items");
        q.query.push(("id".into(), "1 union select password from users".into()));
        let j = s.inspect(&q);
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Detection, "scoring.block_at"));
        assert!(j.decided_by.construct.is_some());
        assert_eq!(j.decided_by.field.as_ref().map(|f| f.name.as_str()), Some("id"));
        assert!(j.decided_by.msg.contains("scoring.block_at"), "{}", j.decided_by.msg);
        let j = s.inspect(&Request::get("/index.html"));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::NoEvidence, "scoring.monitor_at"));
    }

    #[test]
    fn intel_causes_name_their_lists() {
        let mut cfg = Config::default();
        cfg.intel.deny_ips = vec!["192.0.2.9".into()];
        cfg.intel.allow_ips = vec!["192.0.2.10".into()];
        let s = Shield::new(cfg);
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(s.inspect(&r).decided_by.kind, CauseKind::IntelDeny);
        assert_eq!(s.inspect(&r).decided_by.option_key, "intel.deny_ips");
        r.src_ip = Some("192.0.2.10".parse().unwrap());
        let j = s.inspect(&r);
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Allowlisted, "intel.allow_ips"));
    }

    #[test]
    fn limit_cause_names_the_budget_that_stopped_inspection() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let j = Shield::new(cfg).inspect(&query_req("a".repeat(200_000)));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Limit, "shield.max_inspect_bytes"));
        let (j, _) = Shield::new(Config::default()).inspect_counting(&fdfa_body(1 << 20));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Limit, "shield.max_normalize_work"));
    }

    #[test]
    fn chain_causes_name_their_option() {
        let s = shield();
        let mut chain = ChainTracker::new(&s.config().chain);
        let ip: IpAddr = "10.0.0.20".parse().unwrap();
        let mut hp = Request::get("/.git/config");
        hp.src_ip = Some(ip);
        let j1 = s.inspect_stateful(&hp, &mut chain, 0);
        assert_eq!((j1.decided_by.kind, j1.decided_by.option_key), (CauseKind::Ban, "chain.ban_policy.on_honeypot"));
        assert!(j1.chain.and_then(|o| o.new_ban).is_some());
        let sum: f32 = j1.contributions.iter().map(|c| c.points).sum();
        assert!((sum - 100.0).abs() <= 1.0, "Σ {sum}");
        let j2 = s.inspect_stateful(&browser("/index.html", ip), &mut chain, 1_000);
        assert_eq!(j2.decided_by.kind, CauseKind::Ban);
        assert!(j2.chain.is_none(), "a fast-track ban observes nothing");
    }

    #[test]
    fn a_chain_bonus_that_crosses_a_band_is_the_cause() {
        let s = shield();
        let mut j = Judgment::allow();
        j.score = 30;
        let o = ChainOutcome { stage_before: None, stage_after: Some(Stage::Recon), advanced: true, new_ban: None };
        let j = s.finalize(j, &o);
        assert_eq!(j.verdict, Verdict::Monitor);
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::ChainEscalation, "scoring.chain_stage_bonus"));
        assert!(j
            .contributions
            .iter()
            .any(|c| c.construct.as_deref() == Some("chain.stage-advance") && (c.points - 15.0).abs() < 1e-3));
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p vft-core decided_by_follows` → Expected: compile error, `no field 'decided_by'`.

- [ ] **Step 3: Add the types** (`judgment.rs`)

```rust
/// What kind of thing decided a judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CauseKind {
    NoEvidence,
    Detection,
    Honeypot,
    IntelDeny,
    Ban,
    ChainEscalation,
    Limit,
    Allowlisted,
}

/// The one setting that decided a judgment, with the construct and field behind it.
#[derive(Debug, Clone, Serialize)]
pub struct Cause {
    pub kind: CauseKind,
    /// A key of `options::REGISTRY`, e.g. "scoring.block_at".
    pub option_key: &'static str,
    pub construct: Option<String>,
    pub field: Option<FieldRef>,
    /// One human sentence.
    pub msg: String,
}
```

Add to `impl FieldRef`:

```rust
    /// `query:id`, `header:user-agent`, `path:<path>`.
    pub fn label(&self) -> String {
        let loc = format!("{:?}", self.loc).to_ascii_lowercase();
        format!("{loc}:{}", self.name)
    }
```

Change `Judgment`'s derive to `#[derive(Debug, Clone, Serialize)]` and add two fields after `contributions`:

```rust
    pub decided_by: Cause,
    /// The chain observation applied by `Shield::finalize`.
    pub chain: Option<crate::chain::ChainOutcome>,
```

In `Judgment::allow()` add:

```rust
            decided_by: Cause {
                kind: CauseKind::NoEvidence,
                option_key: "scoring.monitor_at",
                construct: None,
                field: None,
                msg: "no evidence".into(),
            },
            chain: None,
```

Re-export in `lib.rs`: `pub use judgment::{Cause, CauseKind, Contribution, EngineReport, Family, FieldRef, Judgment, Pattern, Stage, Verdict};`

`chain.rs`: add `Serialize` to `ChainOutcome`'s derive (`use serde::Serialize` is already imported for `BanRecord`). Replace the test builder:

```rust
    fn judgment(verdict: Verdict, contributions: Vec<Contribution>) -> Judgment {
        let mut j = Judgment::allow();
        j.verdict = verdict;
        j.contributions = contributions;
        j
    }
```

- [ ] **Step 4: Select the cause in `shield.rs`**

Add above `#[derive(Default)] struct Recorder`:

```rust
/// Hard pins found during inspection.
struct Pins {
    honeypot: bool,
    deny: bool,
    limit: Option<&'static str>,
}

/// The option key and threshold of the band a verdict sits in (`None` for Allow).
fn band_key(v: Verdict, cfg: &crate::config::ScoringConfig) -> Option<(&'static str, u8)> {
    match v {
        Verdict::Block => Some(("scoring.block_at", cfg.block_at)),
        Verdict::Challenge => Some(("scoring.challenge_at", cfg.challenge_at)),
        Verdict::Monitor => Some(("scoring.monitor_at", cfg.monitor_at)),
        Verdict::Allow => None,
    }
}

/// The contribution that added the most points (the first one on a tie).
fn top_contribution(cs: &[Contribution]) -> Option<&Contribution> {
    let mut best: Option<&Contribution> = None;
    for c in cs {
        if best.map_or(c.points > 0.0, |b| c.points > b.points) {
            best = Some(c);
        }
    }
    best
}

/// Spec §5.2: honeypot → intel deny → fail-closed limit → band → no evidence
/// (bans are applied later, by `finalize` and `banned_judgment`).
fn cause_for(
    contributions: &[Contribution],
    verdict: Verdict,
    score: u8,
    cfg: &crate::config::ScoringConfig,
    pins: &Pins,
    allowlisted: bool,
) -> Cause {
    if pins.honeypot {
        let field = contributions
            .iter()
            .find(|c| c.construct.as_deref() == Some(sinks::HONEYPOT_DECOY_HIT.id))
            .and_then(|c| c.field.clone());
        return Cause {
            kind: CauseKind::Honeypot,
            option_key: "honeypot.decoy_paths",
            construct: Some(sinks::HONEYPOT_DECOY_HIT.id.into()),
            field,
            msg: "hard-block: request hit a honeypot decoy path".into(),
        };
    }
    if pins.deny {
        return Cause {
            kind: CauseKind::IntelDeny,
            option_key: "intel.deny_ips",
            construct: Some(sinks::INTEL_DENY_LISTED.id.into()),
            field: None,
            msg: "hard-block: source is on intel.deny_ips".into(),
        };
    }
    if let Some(key) = pins.limit {
        return Cause {
            kind: CauseKind::Limit,
            option_key: key,
            construct: Some(sinks::LIMIT_PAYLOAD_TRUNCATED.id.into()),
            field: None,
            msg: format!("hard-block: limit.payload-truncated (request not fully inspected; {key})"),
        };
    }
    let Some((key, threshold)) = band_key(verdict, cfg) else {
        return if allowlisted {
            Cause {
                kind: CauseKind::Allowlisted,
                option_key: "intel.allow_ips",
                construct: None,
                field: None,
                msg: format!("source is on intel.allow_ips; score {score} < scoring.monitor_at {}", cfg.monitor_at),
            }
        } else {
            Cause {
                kind: CauseKind::NoEvidence,
                option_key: "scoring.monitor_at",
                construct: None,
                field: None,
                msg: format!("score {score} < scoring.monitor_at {}", cfg.monitor_at),
            }
        };
    };
    let top = top_contribution(contributions);
    let construct = top.and_then(|c| c.construct.clone());
    let field = top.and_then(|c| c.field.clone());
    let what = match (&construct, &field) {
        (Some(c), Some(f)) => format!("{c} in {}", f.label()),
        (Some(c), None) => c.clone(),
        (None, _) => "evidence".into(),
    };
    Cause {
        kind: CauseKind::Detection,
        option_key: key,
        construct,
        field,
        msg: format!("score {score} >= {key} {threshold}: {what}"),
    }
}

/// The cause of a ban, keyed by the option that triggered it (D4).
fn ban_cause(b: &BanRecord, msg: String) -> Cause {
    let option_key = match b.cause {
        BanCause::Honeypot => "chain.ban_policy.on_honeypot",
        BanCause::Exfiltration => "chain.ban_policy.on_exfiltration_block",
        BanCause::RepeatedExploitation => "chain.ban_policy.exploitation_blocks",
        BanCause::Manual => "chain.ban_policy.ttl_secs",
    };
    Cause { kind: CauseKind::Ban, option_key, construct: Some("chain.ban".into()), field: None, msg }
}

/// A chain decision recorded as a contribution so the points still add up.
/// `chain.*` ids are deliberately not in the construct registry.
fn chain_contribution(id: &str, points: f32) -> Contribution {
    Contribution {
        engine: "chain".into(),
        field: None,
        construct: Some(id.into()),
        family: None,
        value: FourValued::Dangerous,
        weight: 1.0,
        points,
    }
}
```

Update imports at the top of `shield.rs`: `use crate::chain::{event_for, BanCause, BanRecord, ChainOutcome, ChainTracker, SourceKey};` and `use crate::judgment::{Cause, CauseKind, Contribution, EngineReport, FieldRef, Judgment, Pattern, Verdict};`.

In `inspect_counting`:

1. Declare `let mut budget_hit = false;` next to `let mut payload_truncated = false;`, and set `budget_hit = true;` on the line before `payload_truncated = true;` inside the `if added > budget` branch.
2. After `let hard_block = honeypot_or_deny || limit_block;` add:

```rust
        let pins = Pins {
            honeypot: honeypot_seen,
            deny: deny_pin,
            limit: limit_block.then_some(if budget_hit {
                "shield.max_inspect_bytes"
            } else if work.exhausted {
                "shield.max_normalize_work"
            } else {
                "shield.max_payload"
            }),
        };
        let allowlisted = req.src_ip.is_some_and(|ip| self.intel.is_allowed(&canonical(ip)));
```

   `honeypot_hit` is moved by `if let Some(e) = honeypot_hit`, so add `let honeypot_seen = honeypot_hit.is_some();` on the line before that `if let`, and write `honeypot: honeypot_seen,` in `Pins`.

3. After the points block from Task 6, compute `let decided_by = cause_for(&rec.contributions, verdict, score, &self.cfg.scoring, &pins, allowlisted);` and add `decided_by, chain: None,` to the `Judgment { .. }` literal.

Replace `finalize`:

```rust
    /// Apply a chain outcome to a judgment. Never lowers the verdict.
    pub fn finalize(&self, mut j: Judgment, o: &ChainOutcome) -> Judgment {
        j.chain_stage = o.stage_after;
        j.chain = Some(*o);
        let sc = &self.cfg.scoring;
        if o.advanced && o.stage_after.is_some() {
            let bumped = j.score.saturating_add(sc.chain_stage_bonus).min(100);
            let v = crate::score::band(bumped, sc);
            let raised = v.rank() > j.verdict.rank();
            if raised {
                j.verdict = v;
            }
            let before = j.score;
            j.score = j.score.max(bumped);
            if j.score > before {
                j.contributions.push(chain_contribution("chain.stage-advance", f32::from(j.score - before)));
            }
            if let (true, Some((key, threshold))) = (raised, band_key(v, sc)) {
                j.decided_by = Cause {
                    kind: CauseKind::ChainEscalation,
                    option_key: "scoring.chain_stage_bonus",
                    construct: j.decided_by.construct.clone(),
                    field: j.decided_by.field.clone(),
                    msg: format!(
                        "kill-chain stage advance (+{} scoring.chain_stage_bonus) raised the score to {} >= {key} {threshold}; before: {}",
                        sc.chain_stage_bonus, j.score, j.decided_by.msg
                    ),
                };
            }
        }
        if let Some(b) = o.new_ban {
            j.banned_source = true;
            j.verdict = Verdict::Block;
            let before = j.score;
            j.score = 100;
            if before < 100 {
                j.contributions.push(chain_contribution("chain.ban", f32::from(100 - before)));
            }
            j.reason = format!("{} (source banned: {:?}, {} s)", j.reason, b.cause, (b.until_ms - b.since_ms) / 1000);
            let msg = format!("{}; source banned ({:?}) for {} s", j.decided_by.msg, b.cause, (b.until_ms - b.since_ms) / 1000);
            j.decided_by = ban_cause(&b, msg);
        }
        j
    }
```

In `banned_judgment`, add to the literal:

```rust
            decided_by: ban_cause(ban, format!("source banned ({:?}) until t={} ms", ban.cause, ban.until_ms)),
            chain: None,
```

`chain.rs` — in `event_for`, replace the honeypot rule:

```rust
    if j.decided_by.kind == CauseKind::Honeypot {
        return Event::Honeypot;
    }
```

with `use crate::judgment::CauseKind;` added. If the `dangerous` closure is now only used for attack families, keep it.

Update any `event_for` unit test in `chain.rs` that builds a honeypot judgment from a contribution alone: set `j.decided_by.kind = CauseKind::Honeypot` on it as well (grep `Family::Honeypot` in the `chain.rs` tests).

- [ ] **Step 5: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green.

- [ ] **Step 6: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (this pins "event_for switches to `decided_by` with no change in behaviour").

- [ ] **Step 7: Commit**

```bash
git add crates/vft-core/src/judgment.rs crates/vft-core/src/chain.rs crates/vft-core/src/shield.rs crates/vft-core/src/lib.rs
git commit -m "feat(judgment): decided_by names the option behind every decision"
```

---

### Task 8: Retire the legacy judgment fields *(Gate)*

**Files:**
- Modify: `crates/vft-core/src/judgment.rs`, `shield.rs`, `chain.rs`, `lib.rs`, `tests/fuzz_props.rs`
- Modify: `crates/vft-proxy/src/audit.rs`, `lib.rs`, `pipeline.rs`, `adapt.rs`
- Modify: `crates/vft-cli/src/eval.rs`, `crates/vft-cli/examples/bench_http.rs`

**Interfaces:**
- Consumes: `Cause`, `Judgment.chain` (Task 7).
- Produces: `Judgment { verdict, score, contributions, decided_by, chain, normalized_layers }`; `Judgment::banned(&self) -> bool` (`decided_by.kind == Ban`); `Judgment::stage(&self) -> Option<Stage>` (`chain.and_then(|o| o.stage_after)`); `Contribution.engine: &'static str`, `Contribution` is `Serialize`-only. `EngineReport` and `build_reason` no longer exist.

- [ ] **Step 1: Write the failing test** (`judgment.rs`, new `#[cfg(test)] mod tests`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_read_cause_and_chain() {
        let mut j = Judgment::allow();
        assert!(!j.banned());
        assert_eq!(j.stage(), None);
        j.decided_by.kind = CauseKind::Ban;
        j.chain = Some(crate::chain::ChainOutcome { stage_after: Some(Stage::Recon), ..Default::default() });
        assert!(j.banned());
        assert_eq!(j.stage(), Some(Stage::Recon));
    }
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p vft-core helpers_read_cause_and_chain` → Expected: compile error, `no method named 'banned'`.

- [ ] **Step 3: Reshape `Judgment`** (`judgment.rs`)

Delete `EngineReport`. Replace `Judgment` and its `impl`:

```rust
/// The engine's decision about a single request.
#[derive(Debug, Clone, Serialize)]
pub struct Judgment {
    pub verdict: Verdict,
    pub score: u8,
    pub contributions: Vec<Contribution>,
    pub decided_by: Cause,
    /// The chain observation applied by `Shield::finalize`.
    pub chain: Option<crate::chain::ChainOutcome>,
    pub normalized_layers: u8,
}

impl Judgment {
    pub fn allow() -> Self {
        Judgment {
            verdict: Verdict::Allow,
            score: 0,
            contributions: Vec::new(),
            decided_by: Cause {
                kind: CauseKind::NoEvidence,
                option_key: "scoring.monitor_at",
                construct: None,
                field: None,
                msg: "no evidence".into(),
            },
            chain: None,
            normalized_layers: 0,
        }
    }

    /// The source is banned: by this request (`chain.new_ban`) or already (fast-track).
    pub fn banned(&self) -> bool {
        self.decided_by.kind == CauseKind::Ban
    }

    /// The source's kill-chain stage after this request, when a chain was observed.
    pub fn stage(&self) -> Option<Stage> {
        self.chain.and_then(|o| o.stage_after)
    }
}
```

`Contribution`: derive `#[derive(Debug, Clone, Serialize)]`, field `pub engine: &'static str,`, and update its points doc to `/// Points this contribution added to the score.` Update the `lib.rs` re-export to drop `EngineReport`.

- [ ] **Step 4: Migrate `shield.rs`**

- `Recorder`: remove `engines` and `matched` and the code that fills them; `record(&mut self, name: &'static str, ...)`; contributions use `engine: name`.
- Delete `build_reason` and the `let reason = ...` line; drop `engines`, `matched`, `chain_stage`, `banned_source`, `reason` from both `Judgment` literals.
- `finalize`: delete `j.chain_stage = ...;`, `j.banned_source = true;` and the `j.reason = format!(...)` line.
- `chain_contribution` and `banned_judgment`: `engine: "chain"`.
- `inspect_stateful` unchanged.
- Tests: `.banned_source` → `.banned()`; `.chain_stage` → `.stage()`; a `.reason` used only inside an assertion message → `.decided_by.msg`; `assert_eq!(j.reason, LIMIT_REASON)` → `assert_eq!(j.decided_by.kind, CauseKind::Limit)`; delete `const LIMIT_REASON`. Replace `honeypot_and_deny_list_reasons_are_unchanged` with:

```rust
    #[test]
    fn honeypot_outranks_deny_and_limit() {
        assert_eq!(shield().inspect(&Request::get("/.git/config")).decided_by.kind, CauseKind::Honeypot);
        let mut s = shield();
        s.intel_mut().add_deny_ip("192.0.2.9".parse().unwrap());
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(s.inspect(&r).decided_by.kind, CauseKind::IntelDeny);
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let mut r = Request::get("/.git/config");
        r.query.push(("q".into(), "a".repeat(200_000)));
        let j = Shield::new(cfg).inspect(&r);
        assert_eq!(j.decided_by.kind, CauseKind::Honeypot);
        assert!(has_limit(&j), "the limit is still recorded as a contribution");
    }
```

- `chain.rs` tests: contributions built with `engine: "intel".into()` → `engine: "intel"` (same for `"intent"`).
- `tests/fuzz_props.rs` line asserting the limit reason → `assert_eq!(j.decided_by.kind, vft_core::CauseKind::Limit);`; the `eprintln!` using `j.reason` → `j.decided_by.msg`.

- [ ] **Step 5: Migrate `vft-proxy`**

`audit.rs` — `ContribLine` gains `points: f32` (`points: c.points`); `AuditLine` gains `cause: String` and `option_key: &'a str` after `reason`. Build with:

```rust
            stage: j.stage().map(|s| format!("{s:?}")),
            banned: j.banned(),
            ...
            reason: &j.decided_by.msg,
            cause: format!("{:?}", j.decided_by.kind),
            option_key: j.decided_by.option_key,
```

`lib.rs` — `j.chain_stage.and_then(...)` → `j.stage().and_then(...)`.
`pipeline.rs`, `adapt.rs` tests — `.banned_source` → `.banned()`, `.reason` → `.decided_by.msg`.
If an audit test asserts the JSON line's keys, add `cause` and `option_key` to its expectation.

- [ ] **Step 6: Migrate `vft-cli`**

`eval.rs` in `run`:

```rust
            banned = sj.banned();
            let fresh_ban = sj.chain.and_then(|o| o.new_ban).is_some();
```

and `if sj.banned_source {` → `if sj.banned() {`.

`examples/bench_http.rs` — replace the `fams` expression and the `reason` argument:

```rust
            let mut fams: Vec<String> = Vec::new();
            for c in &j.contributions {
                if let (Some(f), Some(n)) = (c.family, c.construct.as_deref()) {
                    let s = format!("{f:?}:{n}");
                    if !fams.contains(&s) {
                        fams.push(s);
                    }
                }
            }
```

and `j.reason.replace(['\t', '\n'], " ")` → `j.decided_by.msg.replace(['\t', '\n'], " ")`.

- [ ] **Step 7: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings` → Expected: green. `grep -rnE '\.(banned_source|chain_stage|matched|engines)\b|EngineReport|\.reason\b' crates` → Expected: no matches.

- [ ] **Step 8: Gate**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical`.

- [ ] **Step 9: Commit**

```bash
git add crates
git commit -m "refactor(judgment): contributions and decided_by replace the legacy fields"
```

---

### Task 9: Generated TypeScript wire types (`ts` feature)

**Files:**
- Modify: `crates/vft-core/Cargo.toml`
- Modify: `crates/vft-core/src/{judgment,lattice,request,chain,options}.rs` (derive attributes)
- Create: `crates/vft-core/tests/ts_bindings.rs`
- Create: `ui/src/gen/*.ts` (generated, committed)

**Interfaces:**
- Produces: `cargo test -p vft-core --features ts --test ts_bindings` fails when any file in `ui/src/gen/` differs from the Rust types; `VFT_BLESS_TS=1` rewrites them. Exported types: `Judgment, Cause, CauseKind, Contribution, FieldRef, Location, FourValued, Verdict, Family, Stage, ChainOutcome, BanRecord, BanCause, OptionDescriptor, OptionKind, Expertise, Apply, Source`. Large integers map to `number`.

- [ ] **Step 1: Add the feature** (`crates/vft-core/Cargo.toml`)

```toml
[features]
# Derive ts_rs::TS on wire types; `cargo test -p vft-core --features ts` checks ui/src/gen.
ts = ["dep:ts-rs"]

[dependencies]
# ...existing...
ts-rs = { version = "12.0.1", optional = true }
```

- [ ] **Step 2: Write the drift test** (`crates/vft-core/tests/ts_bindings.rs`)

```rust
//! The console's wire types in ui/src/gen must match the Rust types.
//! Check: cargo test -p vft-core --features ts --test ts_bindings
//! Bless: VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings
#![cfg(feature = "ts")]

use std::path::PathBuf;
use ts_rs::{Config, TS};
use vft_core::chain::{BanCause, BanRecord, ChainOutcome};
use vft_core::options::{Apply, Expertise, OptionDescriptor, OptionKind, Source};
use vft_core::{Cause, CauseKind, Contribution, Family, FieldRef, FourValued, Judgment, Location, Stage, Verdict};

fn gen_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ui/src/gen")
}

fn check<T: TS + 'static>(cfg: &Config, stale: &mut Vec<String>) {
    let rel = T::output_path().expect("derived types have an output path");
    let path = gen_dir().join(&rel);
    let want = T::export_to_string(cfg).expect("type renders");
    if std::env::var_os("VFT_BLESS_TS").is_some() {
        std::fs::create_dir_all(gen_dir()).expect("create ui/src/gen");
        std::fs::write(&path, &want).expect("write binding");
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(have) if have.replace("\r\n", "\n") == want => {}
        _ => stale.push(rel.display().to_string()),
    }
}

#[test]
fn generated_types_are_current() {
    let cfg = Config::new().with_large_int("number");
    let mut stale = Vec::new();
    check::<Judgment>(&cfg, &mut stale);
    check::<Cause>(&cfg, &mut stale);
    check::<CauseKind>(&cfg, &mut stale);
    check::<Contribution>(&cfg, &mut stale);
    check::<FieldRef>(&cfg, &mut stale);
    check::<Location>(&cfg, &mut stale);
    check::<FourValued>(&cfg, &mut stale);
    check::<Verdict>(&cfg, &mut stale);
    check::<Family>(&cfg, &mut stale);
    check::<Stage>(&cfg, &mut stale);
    check::<ChainOutcome>(&cfg, &mut stale);
    check::<BanRecord>(&cfg, &mut stale);
    check::<BanCause>(&cfg, &mut stale);
    check::<OptionDescriptor>(&cfg, &mut stale);
    check::<OptionKind>(&cfg, &mut stale);
    check::<Expertise>(&cfg, &mut stale);
    check::<Apply>(&cfg, &mut stale);
    check::<Source>(&cfg, &mut stale);
    assert!(stale.is_empty(), "stale bindings in ui/src/gen (re-run with VFT_BLESS_TS=1): {stale:?}");
}
```

- [ ] **Step 3: Run it to see it fail**

Run: `cargo test -p vft-core --features ts --test ts_bindings` → Expected: compile errors, `the trait bound 'Judgment: TS' is not satisfied`.

- [ ] **Step 4: Add the derives**

On each of the 18 types, add directly under its `#[derive(...)]` line:

```rust
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
```

Types and files: `Judgment`, `Cause`, `CauseKind`, `Contribution`, `FieldRef`, `Family`, `Stage`, `Verdict` (`judgment.rs`); `FourValued` (`lattice.rs`); `Location` (`request.rs`); `ChainOutcome`, `BanRecord`, `BanCause` (`chain.rs`); `OptionDescriptor`, `OptionKind`, `Expertise`, `Apply`, `Source` (`options.rs`). All of them already derive `Serialize`, so ts-rs's default `serde-compat` feature applies their `rename_all` / `tag` attributes.

- [ ] **Step 5: Bless, then check**

Run: `VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings` → Expected: PASS; 18 files in `ui/src/gen/`.
Run: `cargo test -p vft-core --features ts --test ts_bindings` → Expected: PASS.
Read `ui/src/gen/Judgment.ts` and `ui/src/gen/OptionKind.ts` and confirm: `decided_by: Cause`, `chain: ChainOutcome | null`, `points: number`, `OptionKind` is a union tagged by `"type"`. If any `bigint` appears, the `with_large_int("number")` call was not applied; fix and re-bless.
Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo clippy -p vft-core --all-targets --features ts -- -D warnings` → Expected: green; the default build has no ts-rs (`cargo tree -p vft-core | grep ts-rs` → no output).

- [ ] **Step 6: Commit** (only the generated directory under `ui/`; the prop images stay uncommitted)

```bash
git add crates/vft-core ui/src/gen Cargo.lock
git commit -m "feat(ts): generated wire types for the console behind the ts feature"
```

---

### Task 10: Corpus acceptance counters, results, docs

**Files:**
- Modify: `crates/vft-cli/src/eval.rs` (`ExplainCounts`, `Report`, `run`, CSV `cause` column, test)
- Modify: `crates/vft-cli/src/main.rs` (exit 3 on explain violations)
- Create: `eval/RESULTS-SP2.md`
- Modify: `docs/BENCHMARK.md` (one status line)

**Interfaces:**
- Consumes: `options::lookup`, `CauseKind`, `Judgment.decided_by`.
- Produces: `Report.explain_library` and `Report.explain_serve: Option<ExplainCounts>` with `ExplainCounts { unknown_option_key: u64, detection_without_construct: u64, points_mismatch: u64, examples: Vec<String> }`; CSV header `rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause`.

- [ ] **Step 1: Write the failing test** (`eval.rs` `mod tests`)

```rust
    #[test]
    fn explain_counts_flag_each_acceptance_rule() {
        let mut c = ExplainCounts::default();
        let mut j = vft_core::Judgment::allow();
        c.add("ok", &j);
        assert_eq!((c.unknown_option_key, c.detection_without_construct, c.points_mismatch), (0, 0, 0));
        j.decided_by.option_key = "scoring.nope";
        c.add("key", &j);
        j = vft_core::Judgment::allow();
        j.verdict = Verdict::Block;
        j.score = 95;
        j.decided_by.kind = vft_core::CauseKind::Detection;
        c.add("construct-and-points", &j);
        assert_eq!((c.unknown_option_key, c.detection_without_construct, c.points_mismatch), (1, 1, 1));
        assert_eq!(c.examples.len(), 3, "one per violation: key, construct, points");
    }
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p vft-cli explain_counts` → Expected: compile error, `cannot find type 'ExplainCounts'`.

- [ ] **Step 3: Implement**

```rust
/// SP2 acceptance over every scored judgment.
#[derive(Debug, Default, Serialize)]
pub struct ExplainCounts {
    /// `decided_by.option_key` is not in `options::REGISTRY` (must be 0).
    pub unknown_option_key: u64,
    /// A non-Allow decided by Detection with no construct (must be 0).
    pub detection_without_construct: u64,
    /// |Σ points − score| > 1 (must be 0).
    pub points_mismatch: u64,
    /// First 20 violations, as `rel: rule (msg)`.
    pub examples: Vec<String>,
}

impl ExplainCounts {
    fn add(&mut self, rel: &str, j: &vft_core::Judgment) {
        let hit = |n: &mut u64, rule: &str, ex: &mut Vec<String>| {
            *n += 1;
            if ex.len() < 20 {
                ex.push(format!("{rel}: {rule} ({})", j.decided_by.msg));
            }
        };
        if vft_core::options::lookup(j.decided_by.option_key).is_none() {
            hit(&mut self.unknown_option_key, "unknown option key", &mut self.examples);
        }
        if j.verdict != Verdict::Allow && j.decided_by.kind == vft_core::CauseKind::Detection && j.decided_by.construct.is_none() {
            hit(&mut self.detection_without_construct, "detection without construct", &mut self.examples);
        }
        let sum: f32 = j.contributions.iter().map(|c| c.points).sum();
        if (sum - f32::from(j.score)).abs() > 1.0 {
            hit(&mut self.points_mismatch, "points do not add up", &mut self.examples);
        }
    }

    pub fn violations(&self) -> u64 {
        self.unknown_option_key + self.detection_without_construct + self.points_mismatch
    }
}
```

In `Report` add after `invariant_violations`:

```rust
    pub explain_library: ExplainCounts,
    pub explain_serve: Option<ExplainCounts>,
```

In `run`: create `let mut explain_lib = ExplainCounts::default(); let mut explain_srv = ExplainCounts::default();`; after `let lj = shield.inspect(&req);` call `explain_lib.add(&s.rel, &lj);`; after `let sj = &d.judgment;` call `explain_srv.add(&s.rel, sj);`; set `explain_library: explain_lib, explain_serve: serve.then_some(explain_srv),` in the `Report`. CSV: header `rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause`, and append `,{:?}:{}` with `lj.decided_by.kind, lj.decided_by.option_key` to the row.

In `main.rs`, extend the exit-3 condition:

```rust
            if report.invariant_violations > 0
                || report.serve.as_ref().is_some_and(|s| s.bans_from_allowed > 0)
                || report.explain_library.violations() > 0
                || report.explain_serve.as_ref().is_some_and(|e| e.violations() > 0)
            {
                std::process::exit(3);
            }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --workspace && cargo clippy --all-targets -- -D warnings && cargo test -p vft-core --features ts --test ts_bindings` → Expected: green.

- [ ] **Step 5: Full acceptance run**

Run: `bash eval/decision_gate.sh check "$VFT_BASELINE"` → Expected: `decision gate: identical` (compare_runs ignores the new `cause` column).
Run: `grep -A4 '"explain_' "$VFT_BASELINE"/now-serve-*.json` → Expected: every counter `0` in both files. Any non-zero counter is a finding: report it with its examples to the owner; do not change scoring to hide it.
Run: `cargo run --release -p vft-cli -- eval --corpus "$VFT_CORPUS" --mode library --out "$VFT_BASELINE/now-library.csv" > "$VFT_BASELINE/now-library.json"` and tally the `cause` column: `cut -d, -f8 "$VFT_BASELINE/now-library.csv" | sort | uniq -c | sort -rn`.

- [ ] **Step 6: Write `eval/RESULTS-SP2.md`**

Record, with the numbers measured in Step 5 and nothing estimated: the baseline commit; the gate result for distinct and pooled:100 (identical, with TP/FP/FN copied from the JSON); the three explain counters for library and serve; the `cause` tally (count per `kind:option_key`); and one line stating that SP2 changes no detection, so the published recall / FP numbers stand. Add one line to the status section of `docs/BENCHMARK.md` pointing to `eval/RESULTS-SP2.md`. Ask the owner before editing the Claude Doc; when approved, add the same one-line status there.

- [ ] **Step 7: Commit**

```bash
git add crates/vft-cli eval/RESULTS-SP2.md docs/BENCHMARK.md
git commit -m "feat(eval): SP2 explainability counters and measured results"
```

---

## Acceptance map (spec §6 SP2)

| Acceptance item | Where it is proven |
|---|---|
| Every corpus `decided_by.option_key` exists in the registry | Task 10 `explain_*.unknown_option_key == 0`; unit tests in Task 7 |
| Every non-Allow has a construct or a non-Detection cause | Task 5 (constructs for pattern-less evidence), Task 10 `detection_without_construct == 0` |
| Σ points reproduces the score within ±1 | Task 6 (`tests/points.rs` proptest, unit test), Task 7 (chain contributions), Task 10 `points_mismatch == 0` |
| Registry coverage and default-validation tests pass | Task 3 `every_config_leaf_has_exactly_one_descriptor`, `defaults_pass_the_tree_check`, `defaults_and_shipped_yaml_validate` |
| Each M6 bad input yields a per-key issue | Task 3 `m6_bad_inputs_yield_per_key_issues`; Task 4 `bad_overrides_are_per_key` |
| Corpus verdicts identical to SP1 (main) | Gate after Tasks 2, 5, 6, 7, 8 and in Task 10 |
| `Config.version`, layering, construct registry consumed, `ts` feature | Tasks 1, 4, 2/5/7, 9 |
