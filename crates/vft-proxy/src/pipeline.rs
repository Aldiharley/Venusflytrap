//! The data-plane decision function shared by the proxy handler and the eval:
//! allow-list → ban fast-track → adapt → pure inspect (no lock) → sharded
//! chain observe → finalize. No lock is held during inspection (H3).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use hyper::http::request::Parts;
use hyper::http::HeaderMap;
use vft_core::config::ChainConfig;
use vft_core::{
    event_for, BanCause, BanRecord, ChainOutcome, ChainTracker, Event, Judgment, Request as VftRequest,
    Shield, SourceKey,
};

use crate::adapt;

const SHARDS: usize = 64;

/// A fixed set of independently locked [`ChainTracker`]s, keyed by source.
/// Only a single shard is locked, and only for the duration of one chain call.
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

    /// Record a ban directly (operator action).
    pub fn ban(&self, key: SourceKey, cause: BanCause, now_ms: u64) -> BanRecord {
        self.shard(&key).ban(key, cause, now_ms)
    }

    pub fn lift(&self, key: SourceKey) -> bool {
        self.shard(&key).lift(key)
    }
}

/// The outcome of [`Pipeline::decide`]: the adapted request, its judgment and
/// the chain key it was attributed to (if the client address is known).
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

fn canonical(ip: IpAddr) -> IpAddr {
    SourceKey::new(ip, 128).ip()
}

/// One `X-Forwarded-For` hop: a bare IP, `a.b.c.d:port` or `[v6]:port`.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    hop.parse::<IpAddr>()
        .ok()
        .or_else(|| hop.parse::<std::net::SocketAddr>().ok().map(|s| s.ip()))
}

impl Pipeline {
    pub fn new(shield: Arc<Shield>) -> Self {
        let cfg = shield.config();
        let trusted = cfg
            .proxy
            .trusted_proxies
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(canonical)
            .collect();
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
    /// which case the right-most untrusted `X-Forwarded-For` hop. The walk goes
    /// right to left and discards nothing: a trusted hop continues it, and any
    /// hop that is not UTF-8 or not an IP (bare, `a.b.c.d:port` or `[v6]:port`)
    /// ends it by returning the peer, so a forged hop to its left is never used.
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.trusted.contains(&canonical(peer)) {
            return peer;
        }
        for value in headers.get_all("x-forwarded-for").iter().rev() {
            let Ok(text) = value.to_str() else {
                return peer;
            };
            for hop in text.rsplit(',') {
                let Some(ip) = parse_hop(hop) else {
                    return peer;
                };
                if !self.trusted.contains(&canonical(ip)) {
                    return ip;
                }
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
        // An allow-listed source (checked on its canonical address) is inspected
        // normally and is never banned, so a ban on its address or shared prefix
        // cannot block it.
        let may_ban = !self.shield.intel().is_allowed(&canonical(ip));
        if may_ban {
            if let Some(ban) = self.chain.active_ban(key, now_ms) {
                let judgment = self.shield.banned_judgment(&ban);
                return Decision { request, judgment, src: Some(key) };
            }
        }
        let judgment = self.shield.inspect(&request);
        let outcome = self.chain.observe(key, event_for(&judgment), now_ms, may_ban);
        let judgment = self.shield.finalize(judgment, &outcome);
        Decision { request, judgment, src: Some(key) }
    }
}

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

    /// Every probe goes through `decide`; failures are collected so one run shows them all.
    fn assert_all_blocked(probes: &[(&str, &[(&str, &str)])]) {
        let p = pipeline();
        let mut missed = Vec::new();
        for (n, (uri, headers)) in probes.iter().enumerate() {
            let peer = IpAddr::from([198, 51, 100, 100 + n as u8]);
            let d = p.decide(&parts(uri, headers), b"", Some(peer), 0);
            if !matches!(d.judgment.verdict, Verdict::Block | Verdict::Challenge) {
                missed.push(format!("{uri} {headers:?}: {:?} {} {}", d.judgment.verdict, d.judgment.score, d.judgment.reason));
            }
        }
        assert!(missed.is_empty(), "not blocked:\n{}", missed.join("\n"));
    }

    #[test]
    fn cookie_names_and_unparsed_cookie_segments_are_inspected() {
        // Final review C1: a segment without `=` and a cookie name are attacker bytes.
        assert_all_blocked(&[
            ("/x", &[("cookie", "1 union select password from users")]),
            ("/x", &[("cookie", "<script>alert(1)</script>=1")]),
            ("/x", &[("cookie", "a=1; 1 union select password from users")]),
        ]);
    }

    #[test]
    fn query_keys_and_accept_encoding_are_inspected() {
        // Final review C2: query keys and Accept-Encoding are forwarded, so inspected.
        assert_all_blocked(&[
            ("/x?1%20union%20select%20password%20from%20users", &[]),
            ("/x?1%20union%20select%20password%20from%20users=1", &[]),
            ("/x?%3Cscript%3Ealert(1)%3C/script%3E", &[]),
            ("/x", &[("accept-encoding", "1 union select password from users")]),
        ]);
    }

    #[test]
    fn real_browser_cookies_and_query_keys_stay_allowed() {
        let p = pipeline();
        let peer: IpAddr = "198.51.100.77".parse().unwrap();
        for uri in ["/search?q=shoes&sort=price_asc&utm_source=news", "/p?flag", "/a?x[]=1&x[]=2"] {
            let d = p.decide(&parts(uri, CHROME), b"", Some(peer), 0);
            assert_eq!(d.judgment.verdict, Verdict::Allow, "{uri}: {}", d.judgment.reason);
        }
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

    fn trusting_10_0_0_1() -> Pipeline {
        let mut cfg = Config::default();
        cfg.proxy.trusted_proxies = vec!["10.0.0.1".into()];
        Pipeline::new(Arc::new(Shield::new(cfg)))
    }

    fn xff(v: &'static str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static(v));
        h
    }

    #[test]
    fn client_ip_accepts_ports_and_fails_closed_on_unparseable_hops() {
        let p = trusting_10_0_0_1();
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        // (a) a port on the right-most hop is parsed, not dropped.
        assert_eq!(
            p.client_ip(peer, &xff("198.51.100.1, 203.0.113.5:4711")),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        // (b) an unparseable right-most hop must not expose the forged hop to its left.
        assert_eq!(p.client_ip(peer, &xff("198.51.100.1, unknown")), peer);
        // (c) bracketed IPv6 with a port.
        assert_eq!(
            p.client_ip(peer, &xff("198.51.100.1, [2001:db8::7]:443")),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
        // A trusted hop (with a port) continues the walk past it.
        assert_eq!(
            p.client_ip(peer, &xff("198.51.100.1, 10.0.0.1:80")),
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );
        // An empty hop (trailing comma) is unparseable and fails closed.
        assert_eq!(p.client_ip(peer, &xff("198.51.100.1,")), peer);
    }

    #[test]
    fn client_ip_fails_closed_on_non_utf8_and_walks_header_lines_right_to_left() {
        let p = trusting_10_0_0_1();
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let mut h = http::HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        h.append("x-forwarded-for", HeaderValue::from_bytes(b"\xff\xfe").unwrap());
        assert_eq!(p.client_ip(peer, &h), peer);
        let mut h = http::HeaderMap::new();
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        h.append("x-forwarded-for", HeaderValue::from_static("203.0.113.5, 10.0.0.1"));
        assert_eq!(p.client_ip(peer, &h), "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ban_survives_source_churn_at_minimum_validated_capacity() {
        let mut cfg = Config::default();
        cfg.chain.max_sources = 640;
        cfg.chain.ban_policy.max_bans = 640;
        assert!(cfg.validate().is_ok());
        let p = Pipeline::new(Arc::new(Shield::new(cfg)));
        let attacker: IpAddr = "203.0.113.50".parse().unwrap();
        assert!(p.decide(&parts("/.git/config", CHROME), b"", Some(attacker), 0).judgment.banned_source);
        for i in 0..2_000u32 {
            let ip = IpAddr::from([10, 20, (i >> 8) as u8, i as u8]);
            let d = p.decide(&parts("/index.html", CHROME), b"", Some(ip), 1 + u64::from(i));
            assert_eq!(d.judgment.verdict, Verdict::Allow, "#{i}: {}", d.judgment.reason);
        }
        let d = p.decide(&parts("/index.html", CHROME), b"", Some(attacker), 5_000);
        assert!(d.judgment.banned_source, "ban evicted by benign source churn");
        assert_eq!(d.judgment.verdict, Verdict::Block);
    }

    #[test]
    fn allow_listed_source_is_never_banned_even_via_mapped_ipv6() {
        // Owner decision (Task 2): allow-list uses the canonical IP and wins over bans.
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        let mut shield = Shield::new(Config::default());
        shield.intel_mut().add_allow_ip(v4);
        let p = Pipeline::new(Arc::new(shield));
        let d1 = p.decide(&parts("/.git/config", CHROME), b"", Some(mapped), 0);
        assert!(!d1.judgment.banned_source, "allow-listed honeypot hit must not ban");
        let d2 = p.decide(&parts("/index.html", CHROME), b"", Some(mapped), 1_000);
        assert!(!d2.judgment.banned_source);
        assert_eq!(d2.judgment.verdict, Verdict::Allow, "{}", d2.judgment.reason);
        // Even a ban forced onto the address does not fast-track an allow-listed source.
        p.chain().ban(SourceKey::new(v4, 64), vft_core::BanCause::Manual, 2_000);
        let d3 = p.decide(&parts("/index.html", CHROME), b"", Some(v4), 3_000);
        assert!(!d3.judgment.banned_source);
        assert_eq!(d3.judgment.verdict, Verdict::Allow, "{}", d3.judgment.reason);
        // A non-allow-listed neighbour still bans normally.
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        assert!(p.decide(&parts("/.git/config", CHROME), b"", Some(other), 4_000).judgment.banned_source);
    }

    #[test]
    #[ignore = "throughput measurement; run with --ignored --release"]
    fn decide_throughput_close_to_stateless_inspect() {
        // H3 acceptance: 8-thread decide >= 0.75x 8-thread stateless inspect.
        let p = Arc::new(pipeline());
        let mut q = String::from("/search?");
        for i in 0..4 {
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
        // One discarded round of each mode first, so thread/allocator warm-up
        // is not charged to whichever mode happens to run first.
        let _ = (run(false), run(true));
        let (stateless, stateful) = (run(false), run(true));
        eprintln!("stateless {stateless:.3}s stateful {stateful:.3}s ratio {:.2}", stateless / stateful);
        assert!(stateless / stateful >= 0.75);
    }
}
