//! FR6 — Cross-request attack-chain inference as a pure state machine.
//!
//! Chain events come from the *decision* (verdict + decision-grade
//! contributions), never from latent evidence, so a request the engine allows
//! cannot advance a source. Stage is the maximum over events inside the window
//! and therefore decays. Bans are a separate policy with TTLs and are never
//! evicted by the source LRU. An automatic ban also needs the source's recent
//! traffic to be mostly hostile (`min_hostile_share`), so a busy shared source
//! is not banned for a few blocks among benign requests. Time is passed in
//! (`now_ms`) — no clock here.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::config::ChainConfig;
use crate::graph::sinks::{self, ConstructInfo};
use crate::judgment::{CauseKind, Family, Judgment, Stage, Verdict};
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
// `sqli.fn-load-file` is only ever latent, so it can never satisfy the
// Dangerous check below; kept as found (renaming must not change behavior).
static EXFIL_CONSTRUCTS: &[&ConstructInfo] = &[
    &sinks::sql::UNION_SELECT,
    &sinks::SIG_UNION_ALL_SELECT,
    &sinks::SIG_SCHEMA_ENUM,
    &sinks::sql::FN_LOAD_FILE,
];
const ATTACK_FAMILIES: &[Family] =
    &[Family::Sqli, Family::Xss, Family::CommandInjection, Family::PathTraversal];

/// Derive the chain event from a decision. Suspicious or latent evidence never
/// stages a source.
pub fn event_for(j: &Judgment) -> Event {
    let dangerous = |f: Family| {
        j.contributions
            .iter()
            .any(|c| !c.shadow && c.value == FourValued::Dangerous && c.family == Some(f))
    };
    if j.decided_by.kind == CauseKind::Honeypot {
        return Event::Honeypot;
    }
    if j.verdict.rank() >= Verdict::Challenge.rank() {
        let exfil = j.contributions.iter().any(|c| {
            !c.shadow
                && c.value == FourValued::Dangerous
                && c.construct.as_deref().is_some_and(|n| EXFIL_CONSTRUCTS.iter().any(|c| c.id == n))
        });
        if exfil {
            return Event::Exfiltration;
        }
        if ATTACK_FAMILIES.iter().any(|f| dangerous(*f)) {
            return Event::Exploitation;
        }
    }
    // An allowed request never stages a source, whatever the config (principle 2).
    if dangerous(Family::Recon) && j.verdict.rank() >= Verdict::Monitor.rank() {
        return Event::Recon;
    }
    let scanner = j
        .contributions
        .iter()
        .any(|c| !c.shadow && c.construct.as_deref() == Some(sinks::INTEL_SCANNER_UA.id) && c.value.is_threat());
    if scanner && j.verdict.rank() >= Verdict::Challenge.rank() {
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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum BanCause {
    Honeypot,
    Exfiltration,
    RepeatedExploitation,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ChainOutcome {
    pub stage_before: Option<Stage>,
    pub stage_after: Option<Stage>,
    /// True only when the stage strictly increased with this event.
    pub advanced: bool,
    pub new_ban: Option<BanRecord>,
    /// When this source's current episode began: its first event, or its first
    /// event after a gap longer than the chain window.
    pub episode_start_ms: Option<u64>,
}

/// Stable group ID for one source's episode, `"{key}@{episode_start_ms}"`.
/// `{key}` is the source key's canonical address ([`SourceKey::ip`]): IPv4 as is,
/// IPv4-mapped IPv6 folded to IPv4, other IPv6 masked to `chain.ipv6_prefix`.
/// Episodes and bans are kept per key, so every request of one episode shares
/// one group ID whichever address in the key sent it.
pub fn group_id(key: SourceKey, o: &ChainOutcome) -> Option<String> {
    o.episode_start_ms.map(|start| format!("{}@{start}", key.ip()))
}

struct SourceState {
    events: VecDeque<(u64, Event)>,
    last_seen: u64,
    /// Start of the current episode; reset when the source idles past the chain window.
    episode_start: u64,
    /// Request tally over the ban window: (bucket index, requests, hostile).
    tally: VecDeque<(u64, u32, u32)>,
}

/// The ban window is tallied in this many buckets of `within_secs / TALLY_BUCKETS`,
/// so memory per source is bounded whatever its request rate. The tally spans
/// between 0.9 and 1.0 x `within_secs`; the exploitation count keeps exact times.
const TALLY_BUCKETS: u64 = 10;

/// Count one request in the tally and return (requests, hostile) in the window.
fn tally(t: &mut VecDeque<(u64, u32, u32)>, now_ms: u64, within_ms: u64, hostile: bool) -> (u32, u32) {
    let bucket = now_ms / (within_ms / TALLY_BUCKETS).max(1);
    while t.front().is_some_and(|(b, _, _)| b.saturating_add(TALLY_BUCKETS) <= bucket) {
        t.pop_front();
    }
    if t.back().map(|(b, _, _)| *b) != Some(bucket) {
        t.push_back((bucket, 0, 0));
    }
    if let Some((_, n, h)) = t.back_mut() {
        *n = n.saturating_add(1);
        *h = h.saturating_add(u32::from(hostile));
    }
    t.iter().fold((0, 0), |(n, h), (_, bn, bh)| (n.saturating_add(*bn), h.saturating_add(*bh)))
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

    /// The config this tracker decides with.
    pub fn config(&self) -> &ChainConfig {
        &self.cfg
    }

    /// Take the `Apply::Live` chain options of `cfg` (window and ban policy)
    /// and keep the restart-only ones (`max_sources`, `events_per_source`,
    /// `ipv6_prefix`, `ban_policy.max_bans`) the tracker was built with. A test
    /// checks this list against `options::REGISTRY`. Tracked sources and bans
    /// stay; the new values apply from the next observation.
    pub fn set_live_config(&mut self, cfg: &ChainConfig) {
        self.cfg.window_secs = cfg.window_secs;
        let (bp, next) = (&mut self.cfg.ban_policy, &cfg.ban_policy);
        bp.on_honeypot = next.on_honeypot;
        bp.on_exfiltration_block = next.on_exfiltration_block;
        bp.exploitation_blocks = next.exploitation_blocks;
        bp.within_secs = next.within_secs;
        bp.ttl_secs = next.ttl_secs;

        bp.ttl_max_secs = next.ttl_max_secs;
        bp.min_hostile_share = next.min_hostile_share;
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
            .or_insert_with(|| SourceState {
            events: VecDeque::new(),
            last_seen: now_ms,
            tally: VecDeque::new(),
            episode_start: now_ms,
        });
        if now_ms.saturating_sub(st.last_seen) > window_ms {
            st.episode_start = now_ms;
        }
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
        let episode_start = st.episode_start;
        let (requests, hostile) = tally(&mut st.tally, now_ms, within_ms, ev != Event::Benign);

        let bp = &self.cfg.ban_policy;
        let hostile_enough = f64::from(hostile) >= bp.min_hostile_share * f64::from(requests);
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
        let new_ban = cause.filter(|_| hostile_enough).map(|c| self.ban(key, c, now_ms));
        self.evict();
        ChainOutcome {
            stage_before,
            stage_after,
            advanced: stage_after > stage_before,
            new_ban,
            episode_start_ms: Some(episode_start),
        }
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

    /// Put back a ban record exactly as stored (no TTL or offence change), e.g.
    /// when loading history at startup. `max_bans` eviction applies as for `ban`.
    pub fn restore_ban(&mut self, key: SourceKey, rec: BanRecord) {
        self.bans.insert(key, rec);
        self.evict();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ChainConfig;
    use crate::judgment::Contribution;
    use std::net::Ipv4Addr;

    fn key(n: u8) -> SourceKey {
        SourceKey::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)), 64)
    }
    const MIN: u64 = 60_000;

    fn judgment(verdict: Verdict, contributions: Vec<Contribution>) -> Judgment {
        let mut j = Judgment::allow();
        j.verdict = verdict;
        j.contributions = contributions;
        j
    }

    fn scanner_ua() -> Contribution {
        Contribution {
            engine: "intel",
            field: None,
            construct: Some("intel.scanner-ua".into()),
            family: Some(Family::Intel),
            value: FourValued::Suspicious,
            weight: 0.8,
            points: 0.0,
            shadow: false,
            exception: None,
        }
    }

    #[test]
    fn scanner_fingerprint_stages_enumeration_only_at_challenge_or_above() {
        let monitor = judgment(Verdict::Monitor, vec![scanner_ua()]);
        assert_eq!(event_for(&monitor), Event::Benign, "a forwarded request never stages a source");
        let challenge = judgment(Verdict::Challenge, vec![scanner_ua()]);
        assert_eq!(event_for(&challenge), Event::Enumeration);
    }

    #[test]
    fn recon_stages_only_when_the_request_is_not_allowed() {
        // Final review F1 (principle 2): an allowed request never stages a source.
        let recon = Contribution {
            engine: "intent",
            field: None,
            construct: Some("sensitive-path".into()),
            family: Some(Family::Recon),
            value: FourValued::Dangerous,
            weight: 0.7,
            points: 0.0,
            shadow: false,
            exception: None,
        };
        assert_eq!(event_for(&judgment(Verdict::Allow, vec![recon.clone()])), Event::Benign);
        assert_eq!(event_for(&judgment(Verdict::Monitor, vec![recon.clone()])), Event::Recon);
        assert_eq!(event_for(&judgment(Verdict::Block, vec![recon])), Event::Recon);
    }

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

    /// `n` benign requests from `k`, one second apart from `from_ms`.
    fn benign(t: &mut ChainTracker, k: SourceKey, n: u64, from_ms: u64) {
        for i in 0..n {
            assert!(t.observe(k, Event::Benign, from_ms + i * 1_000, true).new_ban.is_none());
        }
    }

    #[test]
    fn blocks_diluted_by_benign_traffic_do_not_ban() {
        // A busy shared source (NAT) is not banned for a few blocks among benign traffic.
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
        assert!(bans[2].is_some(), "3 hostile of 6 requests = 0.5 bans");
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
        let o = t.observe(key(12), Event::Exfiltration, 0, true);
        assert_eq!(o.new_ban.map(|b| b.cause), Some(BanCause::Exfiltration));
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
        let bans: Vec<_> =
            (0..3).map(|i| t.observe(key(15), Event::Exploitation, start + i * 1_000, true).new_ban).collect();
        assert!(bans[2].is_some());
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
    fn set_live_config_copies_exactly_the_live_chain_keys_of_the_registry() {
        use crate::options::{Apply, REGISTRY};
        let base = ChainConfig::default();
        let base_tree = serde_json::to_value(&base).unwrap();
        let chain_keys: Vec<_> = REGISTRY.iter().filter(|d| d.key.starts_with("chain.")).collect();
        assert!(chain_keys.len() >= 12, "{}", chain_keys.len());
        for d in chain_keys {
            let ptr = format!("/{}", d.key["chain.".len()..].replace('.', "/"));
            // A value different from the default, still within bounds.
            let mut tree = base_tree.clone();
            let slot = tree.pointer_mut(&ptr).unwrap_or_else(|| panic!("{} not in ChainConfig", d.key));
            *slot = match slot.clone() {
                serde_json::Value::Bool(b) => serde_json::Value::Bool(!b),
                serde_json::Value::Number(n) if n.is_f64() => serde_json::json!(if n.as_f64() == Some(0.25) { 0.75 } else { 0.25 }),
                serde_json::Value::Number(n) => serde_json::json!(n.as_u64().unwrap() + 7),
                other => panic!("{}: unexpected {other}", d.key),
            };
            let next: ChainConfig = serde_json::from_value(tree.clone()).unwrap();
            let mut t = ChainTracker::new(&base);
            t.set_live_config(&next);
            let got = serde_json::to_value(t.config()).unwrap();
            let want = if d.apply == Apply::Live { &tree } else { &base_tree };
            assert_eq!(got.pointer(&ptr), want.pointer(&ptr), "{} ({:?})", d.key, d.apply);
        }
    }

    #[test]
    fn set_live_config_changes_when_a_source_gets_banned() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        assert!(t.observe(key(20), Event::Exploitation, 0, true).new_ban.is_none(), "3 needed by default");
        let mut next = ChainConfig::default();
        next.ban_policy.exploitation_blocks = 1;
        t.set_live_config(&next);
        let o = t.observe(key(21), Event::Exploitation, 1_000, true);
        assert_eq!(o.new_ban.map(|b| b.cause), Some(BanCause::RepeatedExploitation));
    }

    #[test]
    fn restore_ban_keeps_the_record_as_is() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let rec = BanRecord { since_ms: 1_000, until_ms: 9_000, cause: BanCause::Manual, offences: 3 };
        t.restore_ban(key(8), rec);
        assert_eq!(t.active_ban(key(8), 8_999), Some(rec), "the exact record, no TTL recomputation");
        assert_eq!(t.active_ban(key(8), 9_000), None, "inactive from until_ms on");
        assert_eq!(t.ban_count(), 1);
    }

    #[test]
    fn a_ban_after_a_restore_counts_offences_from_the_restored_record() {
        let cfg = ChainConfig::default();
        let mut t = ChainTracker::new(&cfg);
        let rec = BanRecord { since_ms: 0, until_ms: 1_000, cause: BanCause::Honeypot, offences: 2 };
        t.restore_ban(key(8), rec);
        let next = t.ban(key(8), BanCause::Honeypot, 5_000);
        assert_eq!(next.offences, 3);
        assert_eq!(next.until_ms, 5_000 + cfg.ban_policy.ttl_secs * 4 * 1000);
    }

    #[test]
    fn restore_ban_respects_max_bans() {
        let mut cfg = ChainConfig::default();
        cfg.ban_policy.max_bans = 640;
        let mut t = ChainTracker::new(&cfg);
        for n in 0..1_000u32 {
            let k = SourceKey::new(IpAddr::V4(Ipv4Addr::from(0x0C00_0000 | n)), 64);
            t.restore_ban(k, BanRecord { since_ms: 0, until_ms: 10_000 + u64::from(n), cause: BanCause::Manual, offences: 1 });
        }
        assert!(t.ban_count() <= 640);
    }

    #[test]
    fn source_keys_aggregate_ipv6_prefix_and_unmap_ipv4() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert_eq!(SourceKey::new(a, 64), SourceKey::new(b, 64));
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(SourceKey::new(mapped, 64).ip(), "192.0.2.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn shadow_contributions_never_stage_a_source() {
        let sqli = Contribution {
            engine: "graph-taint",
            field: None,
            construct: Some("sqli.union-select".into()),
            family: Some(Family::Sqli),
            value: FourValued::Dangerous,
            weight: 0.95,
            points: 0.0,
            shadow: true,
            exception: None,
        };
        assert_eq!(event_for(&judgment(Verdict::Block, vec![sqli.clone()])), Event::Benign);
        let mut ua = scanner_ua();
        ua.shadow = true;
        assert_eq!(event_for(&judgment(Verdict::Challenge, vec![ua])), Event::Benign);
        let live = Contribution { shadow: false, ..sqli };
        assert_eq!(event_for(&judgment(Verdict::Block, vec![live])), Event::Exfiltration);
    }

    #[test]
    fn events_within_the_window_share_an_episode() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let k = key(9);
        let a = t.observe(k, Event::Benign, 1_000, true);
        let b = t.observe(k, Event::Benign, 1_000 + 3_599_000, true);
        assert_eq!(a.episode_start_ms, Some(1_000));
        assert_eq!(b.episode_start_ms, Some(1_000));
    }

    #[test]
    fn an_idle_window_starts_a_new_episode() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let k = key(9);
        t.observe(k, Event::Benign, 1_000, true);
        let c = t.observe(k, Event::Benign, 1_000 + 3_600_001, true);
        assert_eq!(c.episode_start_ms, Some(1_000 + 3_600_001));
    }

    #[test]
    fn group_id_names_the_source_and_episode() {
        let o = ChainOutcome { episode_start_ms: Some(42), ..Default::default() };
        let k = SourceKey::new("198.51.100.7".parse().unwrap(), 64);
        assert_eq!(group_id(k, &o).as_deref(), Some("198.51.100.7@42"));
        assert_eq!(group_id(k, &ChainOutcome::default()), None);
    }

    /// One episode of one source key has one group ID, whichever of the key's
    /// addresses sent the request.
    fn one_group(a: &str, b: &str, prefix: u8) -> (String, String) {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let ka = SourceKey::new(a.parse().unwrap(), prefix);
        let kb = SourceKey::new(b.parse().unwrap(), prefix);
        let oa = t.observe(ka, Event::Benign, 1_000, true);
        let ob = t.observe(kb, Event::Benign, 2_000, true);
        (group_id(ka, &oa).unwrap(), group_id(kb, &ob).unwrap())
    }

    #[test]
    fn an_ipv6_prefix_shares_one_group_id() {
        let (a, b) = one_group("2001:db8:1:2::1", "2001:db8:1:2:ffff::9", 64);
        assert_eq!(a, b);
        assert_eq!(a, "2001:db8:1:2::@1000");
        // A narrower prefix keeps the two apart.
        let (a, b) = one_group("2001:db8:1:2::1", "2001:db8:1:2:ffff::9", 128);
        assert_ne!(a, b);
    }

    #[test]
    fn ipv4_mapped_ipv6_and_ipv4_share_one_group_id() {
        let (a, b) = one_group("::ffff:192.0.2.7", "192.0.2.7", 64);
        assert_eq!(a, b);
        assert_eq!(a, "192.0.2.7@1000");
    }
}
