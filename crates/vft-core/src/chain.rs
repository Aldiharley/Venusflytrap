//! FR6 — Cross-request attack-chain inference.
//!
//! Keeps a bounded per-source history and maps the sequence of observed events
//! onto kill-chain stages. Advancing stages raise the score; reaching
//! exploitation/exfiltration (or tripping a honeypot) marks the source for ban.
//! Pure in-memory state owned by the caller (proxy); the library is stateless
//! unless you use `inspect_stateful`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::ChainConfig;
use crate::judgment::Stage;

/// What a single request told us about a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Benign,
    Recon,         // scanning sensitive paths
    Enumeration,   // probing params, errors, schema
    Exploitation,  // a reachable injection/xss/cmd
    Exfiltration,  // data-exfil indicators (union select of columns, load_file)
    Honeypot,      // decoy hit
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
}

struct SourceState {
    events: Vec<(Instant, Event)>,
    peak: Option<Stage>,
    banned: bool,
    last_seen: Instant,
}

pub struct ChainTracker {
    window: Duration,
    max_sources: usize,
    events_per_source: usize,
    sources: HashMap<IpAddr, SourceState>,
}

impl ChainTracker {
    pub fn new(cfg: &ChainConfig) -> Self {
        ChainTracker {
            window: Duration::from_secs(cfg.window_secs),
            max_sources: cfg.max_sources,
            events_per_source: cfg.events_per_source,
            sources: HashMap::new(),
        }
    }

    /// Record an event for a source; returns the current peak stage and whether
    /// the source should be banned.
    pub fn observe(&mut self, ip: IpAddr, event: Event, now: Instant) -> (Option<Stage>, bool) {
        self.evict_if_needed(now);
        let st = self.sources.entry(ip).or_insert_with(|| SourceState {
            events: Vec::new(),
            peak: None,
            banned: false,
            last_seen: now,
        });
        st.last_seen = now;
        // prune old events outside the window
        let window = self.window;
        st.events.retain(|(t, _)| now.duration_since(*t) <= window);
        st.events.push((now, event));
        if st.events.len() > self.events_per_source {
            let overflow = st.events.len() - self.events_per_source;
            st.events.drain(0..overflow);
        }

        if let Some(stage) = event.to_stage() {
            st.peak = Some(match st.peak {
                Some(p) => p.max(stage),
                None => stage,
            });
        }
        // Ban decision: reached exploitation/exfiltration, or honeypot.
        if matches!(event, Event::Honeypot)
            || matches!(st.peak, Some(Stage::Exploitation) | Some(Stage::Exfiltration))
        {
            st.banned = true;
        }
        (st.peak, st.banned)
    }

    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        self.sources.get(ip).map(|s| s.banned).unwrap_or(false)
    }

    fn evict_if_needed(&mut self, _now: Instant) {
        if self.sources.len() <= self.max_sources {
            return;
        }
        // Evict the least-recently-seen sources down to 90% of cap. Banned
        // sources are NOT exempt: exempting them lets an attacker rotating
        // through many IPs (e.g. an IPv6 /64) pin the map above the cap forever,
        // which both leaks memory and forces the O(n log n) sort on every later
        // request (M1). A re-offender simply re-trips detection and is re-banned;
        // the bound on memory and CPU is the more important property.
        let target = (self.max_sources * 9) / 10;
        let mut by_recency: Vec<(IpAddr, Instant)> =
            self.sources.iter().map(|(k, v)| (*k, v.last_seen)).collect();
        by_recency.sort_by_key(|(_, t)| *t);
        let remove = self.sources.len() - target;
        for (ip, _) in by_recency.into_iter().take(remove) {
            self.sources.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn stages_advance_and_ban() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let now = Instant::now();
        let (s1, b1) = t.observe(ip(1), Event::Recon, now);
        assert_eq!(s1, Some(Stage::Recon));
        assert!(!b1);
        let (s2, _) = t.observe(ip(1), Event::Enumeration, now);
        assert_eq!(s2, Some(Stage::Enumeration));
        let (s3, b3) = t.observe(ip(1), Event::Exploitation, now);
        assert_eq!(s3, Some(Stage::Exploitation));
        assert!(b3);
        assert!(t.is_banned(&ip(1)));
    }

    #[test]
    fn honeypot_bans_immediately() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let (_, banned) = t.observe(ip(2), Event::Honeypot, Instant::now());
        assert!(banned);
    }

    #[test]
    fn eviction_is_bounded_even_with_banned_sources() {
        // M1: many banned sources must not pin the map above the cap.
        let cfg = ChainConfig {
            window_secs: 3600,
            max_sources: 100,
            events_per_source: 8,
        };
        let mut t = ChainTracker::new(&cfg);
        let now = Instant::now();
        for n in 0..5000u32 {
            let octets = n.to_be_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
            // every source trips the honeypot => banned
            t.observe(ip, Event::Honeypot, now);
        }
        assert!(
            t.sources.len() <= cfg.max_sources,
            "map grew to {} > cap {}",
            t.sources.len(),
            cfg.max_sources
        );
    }

    #[test]
    fn benign_never_bans() {
        let mut t = ChainTracker::new(&ChainConfig::default());
        let (stage, banned) = t.observe(ip(3), Event::Benign, Instant::now());
        assert_eq!(stage, None);
        assert!(!banned);
    }
}
