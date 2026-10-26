# Ban policy redesign: hostile-share gate

Follow-up to SP1 (`sp1-serve-hardening`). SP1 publishes this acceptance check as FAILED: under
`venusflytrap eval --mode serve --sources pooled:100` on the raw blazehttp corpus, collateral FP must be no
larger than request-level FP. SP1's numbers: collateral FP 15,577 against 271 request-level FP (serve FP rate
47.71%), and 80 of the 100 shared sources banned.

This spec amends decision 1 of `2026-10-25-operable-service-design.md` §9 ("bans only on a honeypot hit, an
exfiltration block, or 3 exploitation blocks within 10 min").

## 1. Why SP1 fails

In the pooled model each of the 100 sources sends one request about every 10 s (33,877 requests, 100 ms
synthetic step, about 56 minutes). A ban of T seconds therefore blocks about T/10 later requests from that
source, nearly all benign. With a 1-hour TTL, every ban costs about 340 benign requests, so 271 allows for at
most one ban. SP1 has three automatic ban triggers, and the corpus fires two of them on shared sources:

- one blocked exfiltration request (`on_exfiltration_block`) bans at once;
- 3 exploitation blocks within 600 s ban. Each pooled source gets about 5.5 blocked requests in 56 minutes
  (284 TP + 271 FP spread over 100 sources), so three within 10 minutes is common.

Honeypot hits never happen in this corpus (see the honeypot-only row below), so the corpus cannot measure the
honeypot trigger.

## 2. Candidates measured

All rows are `--mode serve` on the raw corpus with the SP1 release build, plus a throwaway (uncommitted)
prototype of the hostile-share gate as a config knob. Library FP is 271 in every run. "Collateral" is
benign requests blocked in serve that the library allowed. "Banned" is benign sources answered with a ban.

| Candidate (config) | pooled:10 collateral | pooled:100 collateral / banned | pooled:1000 collateral | distinct banned |
|---|---|---|---|---|
| SP1 defaults | 31,969 | 15,577 / 80 | 1,723 | 72 |
| first TTL 300 s | – | 5,230 / 80 | – | – |
| first TTL 60 s | – | 1,943 / 80 | – | – |
| no single-exfil ban | 31,678 | 9,366 / 57 | – | – |
| no single-exfil ban, TTL 60 s | – | 898 / 57 | – | – |
| no single-exfil ban, 5 blocks in 600 s | 29,923 | 0 / 1 | 0 | 0 |
| honeypot only | – | 0 / 0 | – | – |
| no bans at all (floor) | – | 0 / 0 | – | – |
| hostile share ≥ 0.25, single-exfil ban kept | – | 327 / 1 | – | – |
| hostile share ≥ 0.5, single-exfil ban kept | – | 327 / 1 | – | – |
| hostile share ≥ 0.05, single-exfil ban kept | – | 7,698 / 46 | – | – |
| hostile share ≥ 0.10, single-exfil ban kept | – | 1,258 / 4 | – | – |
| **hostile share ≥ 0.5, no single-exfil ban** | **0** | **0 / 0** | **8** | **0** |
| hostile share ≥ 0.25, no single-exfil ban | – | 0 / 0 | – | – |

bans_from_allowed and invariant_violations are 0 in every run. "–" = not run.

NAT-aware keys (address plus User-Agent) were checked offline rather than built: 33,398 of the 33,875 readable
files (98.6%) share one User-Agent string and only 191 distinct strings exist, so such a key would split each
pooled source into about one large sub-source and change almost nothing here. Real NATs mostly carry a few
popular browser strings too, and an attacker can rotate the header to dodge any ban. Dropped.

What the table shows:

- **Shorter TTLs alone don't pass.** They scale collateral down roughly in proportion and stay above 271.
- **A count threshold passes only at one pool size.** "5 blocks in 600 s" gives 0 at pooled:100 and :1000 but
  29,923 at pooled:10, because a busier shared source collects 5 blocks easily. That is tuning to the corpus.
- **Honeypot-only passes only because the corpus has no honeypot hits.** It removes every exploitation ban, so
  it says nothing about honeypot bans on shared sources.
- **The hostile-share gate needs the single-exfil ban removed.** With the single-exfil ban kept, a pooled source
  whose first request is an exfiltration block has share 1/1 and is banned (327 collateral at 0.25 and 0.5).
- **Hostile share ≥ 0.5 without the single-exfil ban holds at every pool size**: 0 / 0 / 8 collateral (the 8
  at pooled:1000 come from one source whose 3rd blocked malicious request in 10 minutes banned it for 1 h).

## 3. Design

A source is banned automatically only when its recent traffic is mostly hostile. A busy shared source
(NAT, unconfigured trusted proxy) dilutes its few blocked requests with benign ones and is not banned; its
attacks are still blocked one request at a time. A source that is mostly attacking is banned as before.

### 3.1 `BanPolicy` (`crates/vft-core/src/config.rs`, `config/shield.yaml`)

| Key | SP1 | New | Meaning |
|---|---|---|---|
| `on_honeypot` | true | true | a decoy hit is a ban trigger |
| `on_exfiltration_block` | true | **false** | a single exfiltration block is a ban trigger; exfiltration blocks still count toward `exploitation_blocks` |
| `exploitation_blocks` / `within_secs` | 3 / 600 | 3 / 600 | unchanged |
| `ttl_secs` / `ttl_max_secs` | 3600 / 86400 | 3600 / 86400 | unchanged, doubling on re-offence |
| `max_bans` | 100000 | 100000 | unchanged |
| `min_hostile_share` (new) | – | **0.5** | an automatic ban also needs hostile requests ≥ this share of the source's requests in the last `within_secs`; 0 turns the gate off |

`validate` adds: `min_hostile_share` must be finite and in `0.0..=1.0`.

Setting `on_exfiltration_block: true` and `min_hostile_share: 0` restores SP1 behaviour exactly.

### 3.2 `ChainTracker::observe` (`crates/vft-core/src/chain.rs`)

- `SourceState` gains a bounded request tally: up to 10 buckets of `within_secs / 10` each, every bucket holding
  (requests, hostile requests). Every `observe` call counts one request; it counts as hostile when its event is not
  `Benign`. Buckets older than `within_secs` are dropped. Memory is at most 10 small entries per tracked source,
  so it is independent of request rate (an exact timestamp list would grow with a busy NAT's traffic).
- The ban trigger is computed as today (honeypot, single exfiltration if enabled, `exploitation_blocks` within
  `within_secs`), then passed through the gate `hostile >= min_hostile_share × requests`, which includes the current
  request. `may_ban == false` (allow-list) still wins first.
- The gate covers all three automatic causes, honeypot included: on a busy shared source, one bait-link click
  should not ban everyone behind it (design risk 2 in the operable-service spec). A fresh source whose first
  request hits a decoy has share 1/1 and is banned as before. The corpus cannot measure this case.
- `ChainTracker::ban` (manual and operator bans) is not gated. TTLs and doubling are unchanged.
- Requests answered by the ban fast-track never reach `observe`, so they do not count. The tally window is
  bucketed (effective span between 0.9 and 1.0 × `within_secs`), while the exploitation count keeps exact
  timestamps. This is documented in code.

No change to `event_for`, scoring, the stage bonus, `Pipeline`, or the eval harness.

### 3.3 What gets worse (stated plainly)

- A single exfiltration request from a fresh address no longer bans it. The request itself is still blocked.
  SP1's `exfiltration_block_bans_and_fast_tracks` pipeline test encodes the old rule and changes to three blocks.
- An attacker who sends at least one benign request per hostile one stays under 0.5 and is never banned. Bans
  were already evadable by switching address; the ban is an amplifier for noisy, mostly-hostile sources, not a
  defence against a careful attacker.
- An attacker behind a busy NAT is never banned by the automatic policy.
- Serve-distinct `benign_sources_banned` drops from 72 to 0. Those 72 were single benign requests that were
  false positives and then got banned. The drop is a side effect of removing the single-exfil ban.

## 4. Acceptance

1. pooled:100 collateral FP ≤ request-level FP (measured with the prototype: 0 ≤ 271). Also reported, not gated:
   pooled:10 and pooled:1000.
2. Serve distinct: bans_from_allowed 0, invariant_violations 0.
3. The Chrome, Firefox and Safari fixtures in `crates/vft-proxy/src/pipeline.rs` never ban.
4. Library recall/FP (284 TP / 271 FP) and mutation retention (19/22 seeds, 548/660 mutants) unchanged. The
   library path never touches the chain, so any change here is a bug.
5. `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` green.
6. New numbers added to `eval/RESULTS-SP1.md` (successor section) and `docs/BENCHMARK.md` §3 with before/after;
   §2's pooled row updated.

## 5. Tests

`chain.rs`:
- attack-dominated source (3 exploitation blocks, nothing else) is banned;
- the same 3 blocks spread among 100 benign requests in the window are not banned;
- a fresh honeypot hit bans; a honeypot hit on a source with many recent benign requests does not;
- a single exfiltration block does not ban by default; with `on_exfiltration_block: true` it bans a fresh source;
- `min_hostile_share: 0` and `on_exfiltration_block: true` reproduce SP1 (single exfil bans on a busy source);
- tally buckets expire after `within_secs` (old benign traffic stops diluting).

`config.rs`: `min_hostile_share` of -0.1, 1.1 and NaN each give an issue on that key; the existing
`defaults_and_shipped_yaml_validate` test is extended so the shipped `ban_policy` equals `BanPolicy::default()`.

`pipeline.rs`: the exfiltration fast-track test uses three exfiltration blocks from one address; a new test
sends benign traffic and three blocked attacks from one shared address and checks that no ban occurs; the
real-browser test is unchanged.
