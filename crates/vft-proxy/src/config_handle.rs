//! The live config of the data plane: one [`ConfigHandle`] holds the current
//! shield and its revision. Every request loads it once and decides with that
//! snapshot, so a reload never mixes two configs within one decision. A reload
//! goes through [`candidate`] first: restart-only values are kept at the live
//! ones and reported, everything else takes effect on the next request.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::Value;
use vft_core::options::{Apply, REGISTRY};
use vft_core::{Config, Shield};

/// One loaded config: the shield built from it and its revision (1 at start,
/// +1 per swap).
pub struct Loaded {
    pub rev: u64,
    pub shield: Arc<Shield>,
}

pub struct ConfigHandle {
    current: ArcSwap<Loaded>,
}

impl ConfigHandle {
    pub fn new(shield: Arc<Shield>) -> Self {
        ConfigHandle { current: ArcSwap::from_pointee(Loaded { rev: 1, shield }) }
    }

    /// The current config, as one atomic load. The snapshot stays whole for as
    /// long as it is held, whatever is swapped in meanwhile.
    pub fn load(&self) -> Arc<Loaded> {
        self.current.load_full()
    }

    /// Make `shield` current under the next revision and return it. Concurrent
    /// swaps each get their own revision.
    ///
    /// Precondition: `shield` is built from `candidate(live, next).config`
    /// (after `Config::validate` on it), never from `next` directly. Restart-only
    /// values (limits, trusted proxies, chain capacities, ...) are read once at
    /// construction by the proxy and the pipeline, so a shield carrying other
    /// values would report settings the data plane does not use. `swap` does not
    /// check this.
    /// The live `chain.*` options reach the chain store only through
    /// `ChainStore::set_live_config`, which the caller runs after the swap.
    pub fn swap(&self, shield: Shield) -> u64 {
        let shield = Arc::new(shield);
        let prev = self.current.rcu(|cur| Loaded { rev: cur.rev + 1, shield: shield.clone() });
        prev.rev + 1
    }
}

/// What a reload would change.
pub struct Candidate {
    /// The new config with every restart-only value replaced by the live one.
    pub config: Config,
    /// Registry keys whose value differs from live (Live and Restart).
    pub changed: Vec<String>,
    /// The subset with `Apply::Restart` (not applied).
    pub restart_required: Vec<String>,
}

/// Compare `next` with `live` key by key over `options::REGISTRY`; copy every
/// `Apply::Restart` value from `live` into the result. Pure; no I/O.
pub fn candidate(live: &Config, next: Config) -> Candidate {
    let live_tree = serde_json::to_value(live).expect("Config serializes to a JSON tree");
    let mut tree = serde_json::to_value(&next).expect("Config serializes to a JSON tree");
    let (mut changed, mut restart_required) = (Vec::new(), Vec::new());
    for d in REGISTRY {
        let ptr = format!("/{}", d.key.replace('.', "/"));
        let was = live_tree.pointer(&ptr).cloned().unwrap_or(Value::Null);
        let Some(now) = tree.pointer_mut(&ptr) else { continue };
        if *now == was {
            continue;
        }
        changed.push(d.key.to_string());
        if d.apply == Apply::Restart {
            restart_required.push(d.key.to_string());
            *now = was;
        }
    }
    // Both trees came from a `Config` and only whole leaf values moved from one
    // to the other, so the merged tree deserializes.
    let config = serde_json::from_value(tree).expect("a tree merged from two serialized Configs deserializes");
    Candidate { config, changed, restart_required }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::Pipeline;
    use hyper::http;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Barrier;

    fn shield_with(f: impl FnOnce(&mut Config)) -> Shield {
        let mut cfg = Config::default();
        f(&mut cfg);
        Shield::new(cfg)
    }

    #[test]
    fn swap_increments_rev_and_an_earlier_load_keeps_its_shield() {
        let h = ConfigHandle::new(Arc::new(Shield::new(Config::default())));
        let before = h.load();
        assert_eq!(before.rev, 1);
        assert_eq!(h.swap(shield_with(|c| c.scoring.block_at = 95)), 2);
        let after = h.load();
        assert_eq!((after.rev, after.shield.config().scoring.block_at), (2, 95));
        // The load taken before the swap is a whole snapshot: old rev, old shield.
        assert_eq!((before.rev, before.shield.config().scoring.block_at), (1, 90));
        assert_eq!(h.swap(shield_with(|c| c.scoring.block_at = 96)), 3);
        assert_eq!(h.load().rev, 3);
    }

    #[test]
    fn candidate_applies_a_live_change() {
        let live = Config::default();
        let mut next = Config::default();
        next.scoring.block_at = 95;
        let c = candidate(&live, next);
        assert_eq!(c.changed, vec!["scoring.block_at".to_string()]);
        assert!(c.restart_required.is_empty());
        assert_eq!(c.config.scoring.block_at, 95);
    }

    #[test]
    fn candidate_keeps_a_restart_change_at_the_live_value() {
        let live = Config::default();
        let mut next = Config::default();
        next.limits.max_body = live.limits.max_body * 2;
        let c = candidate(&live, next);
        assert_eq!(c.changed, vec!["limits.max_body".to_string()]);
        assert_eq!(c.restart_required, vec!["limits.max_body".to_string()]);
        assert_eq!(c.config.limits.max_body, live.limits.max_body);
    }

    #[test]
    fn candidate_without_changes_is_empty() {
        let c = candidate(&Config::default(), Config::default());
        assert!(c.changed.is_empty(), "{:?}", c.changed);
        assert!(c.restart_required.is_empty());
    }

    /// A shield whose `scoring.monitor_at` encodes `rev`; a benign request's
    /// `decided_by` message names it ("score 0 < scoring.monitor_at N").
    fn rev_shield(rev: u64) -> Shield {
        shield_with(|c| c.scoring.monitor_at = 1 + (rev % 60) as u8)
    }

    /// The threshold `decided_by` names after `scoring.monitor_at `.
    fn monitor_at_in(msg: &str) -> Option<u64> {
        let rest = &msg[msg.find("scoring.monitor_at ")? + "scoring.monitor_at ".len()..];
        rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    }

    #[test]
    fn concurrent_decisions_never_mix_revisions() {
        let handle = Arc::new(ConfigHandle::new(Arc::new(rev_shield(1))));
        let p = Arc::new(Pipeline::with_handle(handle.clone()));
        let head = Arc::new(
            http::Request::builder()
                .uri("/products?page=2")
                .header("host", "shop.example")
                .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
                .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .header("accept-language", "en-US,en;q=0.5")
                .body(())
                .unwrap()
                .into_parts()
                .0,
        );
        let done = Arc::new(AtomicBool::new(false));
        // Swapping starts only once all eight deciders are running.
        let start = Arc::new(Barrier::new(9));
        let deciders: Vec<_> = (0..8u8)
            .map(|n| {
                let (p, head, done, start) = (p.clone(), head.clone(), done.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    let mut seen = 0u64;
                    let mut i = 0u64;
                    while !done.load(Ordering::Acquire) || seen == 0 {
                        let peer = IpAddr::from([10, 7, n, (i % 250) as u8]);
                        let d = p.decide(&head, b"", Some(peer), i);
                        let msg = &d.judgment.decided_by.msg;
                        assert_eq!(monitor_at_in(msg), Some(1 + d.config_rev % 60), "rev {}: {msg}", d.config_rev);
                        seen += 1;
                        i += 1;
                    }
                    seen
                })
            })
            .collect();
        start.wait();
        for rev in 2..=201u64 {
            assert_eq!(handle.swap(rev_shield(rev)), rev);
        }
        done.store(true, Ordering::Release);
        let total: u64 = deciders.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total >= 8);
        assert_eq!(p.current().rev, 201);
    }
}
