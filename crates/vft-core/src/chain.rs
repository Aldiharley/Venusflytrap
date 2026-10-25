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
use crate::graph::sinks::{self, ConstructInfo};
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
            .any(|c| c.value == FourValued::Dangerous && c.family == Some(f))
    };
    if dangerous(Family::Honeypot) {
        return Event::Honeypot;
    }
    if j.verdict.rank() >= Verdict::Challenge.rank() {
        let exfil = j.contributions.iter().any(|c| {
            c.value == FourValued::Dangerous
                && c.construct.as_deref().is_some_and(|n| EXFIL_CONSTRUCTS.iter().any(|c| c.id == n))
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
        Judgment {
            verdict,
            score: 0,
            engines: Vec::new(),
            matched: Vec::new(),
            contributions,
            chain_stage: None,
            normalized_layers: 0,
            banned_source: false,
            reason: String::new(),
        }
    }

    fn scanner_ua() -> Contribution {
        Contribution {
            engine: "intel".into(),
            field: None,
            construct: Some("intel.scanner-ua".into()),
            family: Some(Family::Intel),
            value: FourValued::Suspicious,
            weight: 0.8,
            points: 0.0,
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
