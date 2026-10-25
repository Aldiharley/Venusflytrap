# Ban Policy Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pass SP1's failed check "pooled:100 collateral FP ≤ request-level FP" by gating every automatic ban on
the source's hostile share and dropping the single-exfiltration ban.

**Architecture:** `BanPolicy` gains `min_hostile_share` (default 0.5) and `on_exfiltration_block` defaults to
false. `ChainTracker` keeps a bounded 10-bucket request tally per source over `within_secs`; `observe`
computes the ban cause as before, then drops it unless hostile ≥ share × requests. Nothing else changes.

**Tech Stack:** Rust 2021, `#![forbid(unsafe_code)]`, serde/serde_yaml, cargo test, clippy `-D warnings`.

Spec: `docs/superpowers/specs/2026-10-26-ban-policy-redesign-design.md`.

## Global Constraints

- `min_hostile_share` default `0.5`, valid range `0.0..=1.0` (finite); `0` disables the gate.
- `on_exfiltration_block` default `false`; `exploitation_blocks 3`, `within_secs 600`, `ttl_secs 3600`, `ttl_max_secs 86400`, `max_bans 100000` unchanged.
- The gate applies to Honeypot, Exfiltration and RepeatedExploitation causes; never to `ChainTracker::ban`.
- `config/shield.yaml` values must equal `Config::default()`.
- No change to `event_for`, scoring, `Pipeline`, or the eval harness.
- Commits only with the owner's OK; never push.

---

### Task 1: `BanPolicy` defaults, new key, validation

**Files:**
- Modify: `crates/vft-core/src/config.rs` (`BanPolicy`, `Default`, `validate`, tests)
- Modify: `config/shield.yaml` (`chain.ban_policy`)

**Interfaces:**
- Produces: `BanPolicy::min_hostile_share: f64`; `BanPolicy: PartialEq`.

- [ ] **Step 1: Failing tests** in `config.rs` tests:

```rust
#[test]
fn hostile_share_must_be_a_fraction() {
    for bad in ["-0.1", "1.1", ".nan"] {
        let y = format!("chain:\n  ban_policy:\n    min_hostile_share: {bad}\n");
        assert!(issues(&y).iter().any(|i| i.key == "chain.ban_policy.min_hostile_share"), "{bad}");
    }
    assert!(issues("chain:\n  ban_policy:\n    min_hostile_share: 0\n").is_empty());
    assert!(issues("chain:\n  ban_policy:\n    min_hostile_share: 1\n").is_empty());
}
```

and extend `defaults_and_shipped_yaml_validate` with
`assert_eq!(shipped.chain.ban_policy, BanPolicy::default());`.

- [ ] **Step 2:** `cargo test -p vft-core config::` → fails (unknown field / missing PartialEq).
- [ ] **Step 3: Implement.** Add `PartialEq` to `BanPolicy`'s derive; add the field with a doc comment; defaults
  `on_exfiltration_block: false`, `min_hostile_share: 0.5`; in `validate`:

```rust
if !(0.0..=1.0).contains(&b.min_hostile_share) {
    bad("chain.ban_policy.min_hostile_share", format!("must be in 0.0..=1.0, got {}", b.min_hostile_share));
}
```

  (`contains` is false for NaN.) In `shield.yaml`: `on_exfiltration_block: false` and
  `min_hostile_share: 0.5` with short comments.
- [ ] **Step 4:** `cargo test -p vft-core config::` → pass.

### Task 2: hostile-share gate in `ChainTracker::observe`

**Files:**
- Modify: `crates/vft-core/src/chain.rs` (module doc, `SourceState`, `observe`, tests)

**Interfaces:**
- Consumes: `BanPolicy::min_hostile_share`.
- Produces: no new public API; `observe` signature unchanged.

- [ ] **Step 1: Failing tests** in `chain.rs` tests (helper `benign(t, k, n, from_ms)` sends `n` Benign events 1 s apart):

```rust
#[test]
fn blocks_diluted_by_benign_traffic_do_not_ban() {
    let mut t = ChainTracker::new(&ChainConfig::default());
    benign(&mut t, key(8), 100, 0);
    for i in 0..3 {
        assert!(t.observe(key(8), Event::Exploitation, 100_000 + i * 1_000, true).new_ban.is_none());
    }
}

#[test]
fn hostile_share_threshold_is_inclusive() {
    let mut t = ChainTracker::new(&ChainConfig::default());
    benign(&mut t, key(9), 3, 0);
    let bans: Vec<_> = (0..3).map(|i| t.observe(key(9), Event::Exploitation, 10_000 + i, true).new_ban).collect();
    assert!(bans[2].is_some(), "3 hostile of 6 = 0.5 bans");
    benign(&mut t, key(10), 4, 0);
    for i in 0..3 {
        assert!(t.observe(key(10), Event::Exploitation, 10_000 + i, true).new_ban.is_none(), "3 of 7");
    }
}

#[test]
fn honeypot_on_a_busy_source_does_not_ban() {
    let mut t = ChainTracker::new(&ChainConfig::default());
    benign(&mut t, key(11), 10, 0);
    assert!(t.observe(key(11), Event::Honeypot, 20_000, true).new_ban.is_none());
}

#[test]
fn single_exfiltration_bans_only_when_enabled() {
    let mut t = ChainTracker::new(&ChainConfig::default());
    assert!(t.observe(key(12), Event::Exfiltration, 0, true).new_ban.is_none(), "off by default");
    let mut cfg = ChainConfig::default();
    cfg.ban_policy.on_exfiltration_block = true;
    let mut t = ChainTracker::new(&cfg);
    assert_eq!(t.observe(key(12), Event::Exfiltration, 0, true).new_ban.map(|b| b.cause), Some(BanCause::Exfiltration));
    benign(&mut t, key(13), 10, 0);
    assert!(t.observe(key(13), Event::Exfiltration, 20_000, true).new_ban.is_none(), "gated on a busy source");
}

#[test]
fn zero_share_and_exfiltration_trigger_reproduce_sp1() {
    let mut cfg = ChainConfig::default();
    cfg.ban_policy.on_exfiltration_block = true;
    cfg.ban_policy.min_hostile_share = 0.0;
    let mut t = ChainTracker::new(&cfg);
    benign(&mut t, key(14), 100, 0);
    assert!(t.observe(key(14), Event::Exfiltration, 200_000, true).new_ban.is_some());
}

#[test]
fn benign_traffic_older_than_the_ban_window_stops_diluting() {
    let cfg = ChainConfig::default();
    let within = cfg.ban_policy.within_secs * 1000;
    let mut t = ChainTracker::new(&cfg);
    benign(&mut t, key(15), 100, 0);
    let start = within + 100_000;
    let bans: Vec<_> = (0..3).map(|i| t.observe(key(15), Event::Exploitation, start + i * 1_000, true).new_ban).collect();
    assert!(bans[2].is_some());
}
```

- [ ] **Step 2:** `cargo test -p vft-core chain::` → the dilution, honeypot, exfil-default tests fail.
- [ ] **Step 3: Implement.** `const TALLY_BUCKETS: u64 = 10;` and `SourceState.tally: VecDeque<(u64, u32, u32)>`
  (bucket index, requests, hostile). In `observe`, after pushing the event:

```rust
let width = (within_ms / TALLY_BUCKETS).max(1);
let bucket = now_ms / width;
while st.tally.front().is_some_and(|(b, _, _)| b.saturating_add(TALLY_BUCKETS) <= bucket) {
    st.tally.pop_front();
}
if st.tally.back().map(|(b, _, _)| *b) != Some(bucket) {
    st.tally.push_back((bucket, 0, 0));
}
if let Some((_, n, h)) = st.tally.back_mut() {
    *n = n.saturating_add(1);
    *h = h.saturating_add(u32::from(ev != Event::Benign));
}
let (requests, hostile) = st.tally.iter().fold((0u32, 0u32), |(n, h), (_, bn, bh)| (n.saturating_add(*bn), h.saturating_add(*bh)));
```

  then `let hostile_enough = f64::from(hostile) >= bp.min_hostile_share * f64::from(requests);` and
  `let cause = cause.filter(|_| hostile_enough);` before `self.ban`. Update the module doc.
- [ ] **Step 4:** `cargo test -p vft-core` → pass (shield.rs `repeated_exploitation_bans_then_fast_tracks`
  sends 3 XSS blocks from a fresh source: share 3/3, still bans).

### Task 3: pipeline tests

**Files:**
- Modify: `crates/vft-proxy/src/pipeline.rs` (tests only)

- [ ] **Step 1:** Replace `exfiltration_block_bans_and_fast_tracks` with
  `three_exfiltration_blocks_ban_and_fast_track`: the first union-select request is blocked
  (Block or Challenge) and not banned; the third (t = 2,000 ms) bans; a later `/` is Block with
  `banned_source`; a neighbour address is Allow.
- [ ] **Step 2:** Add `busy_shared_source_is_not_banned_for_a_few_blocks`: 50 Chrome `/products?page=2` requests
  from one address (Allow), then three union-select requests (each blocked, none banned), then `/` is Allow.
- [ ] **Step 3:** `cargo test --workspace` → pass, incl. `real_browsers_are_never_banned` unchanged and
  `crates/vft-proxy/tests/hardening.rs` (its union-select request must still be answered "Request blocked.").

### Task 4: verification and measurement

- [ ] `cargo clippy --all-targets -- -D warnings` green.
- [ ] Release build; `venusflytrap eval --mode serve --sources pooled:100|pooled:10|pooled:1000|distinct` and
  `--mode library` on the raw corpus with default config (no `--config`). Gate: pooled:100 collateral ≤ library FP;
  distinct bans_from_allowed 0, invariant_violations 0; library 284 TP / 271 FP.
- [ ] Mutation: re-run the SP1 mutation measurement (`bench_http` on the mutants, as in `eval/RESULTS-SP1.md`);
  gate 19/22 seeds, 548/660 mutants.

### Task 5: results docs

- [ ] `eval/RESULTS-SP1.md`: new section "Ban policy redesign (successor log)" with the measured rows,
  before (SP1 final) / after, every number recorded, regressions stated.
- [ ] `docs/BENCHMARK.md`: §2 pooled row and the "how to read" bullet; §3 table before/after, replace the
  "Failed acceptance check" paragraph with the result; §1 note on the policy if needed.
- [ ] Ask the owner before committing.
