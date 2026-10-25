//! FR9 — The orchestrator. Wires normalize → graph/taint → detectors → lattice
//! → score, plus honeypot, intel, and (optionally) the chain tracker.

use crate::chain::{event_for, BanRecord, ChainOutcome, ChainTracker, SourceKey};
use crate::config::Config;
use crate::detect::{
    intent_evidence, AiDetector, AiOracle, ApiSafetyDetector, FieldCtx, FieldDetector,
    GraphTaintDetector, HeuristicOracle, SignatureDetector,
};
use crate::graph;
use crate::honeypot::Honeypot;
use crate::intel::Intel;
use crate::judgment::{Contribution, EngineReport, FieldRef, Judgment, Pattern, Verdict};
use crate::lattice::{Evidence, FourValued};
use crate::normalize::{normalize, Options};
use crate::request::Request;
use crate::score::{arbitrate, Scored};

pub struct Shield {
    cfg: Config,
    norm_opts: Options,
    honeypot: Honeypot,
    intel: Intel,
    oracle: Box<dyn AiOracle>,
}

impl Shield {
    pub fn new(cfg: Config) -> Self {
        Self::with_oracle(cfg, Box::new(HeuristicOracle))
    }

    pub fn with_oracle(cfg: Config, oracle: Box<dyn AiOracle>) -> Self {
        let norm_opts = Options {
            max_payload: cfg.shield.max_payload,
            decode_cap: cfg.shield.decode_cap,
            deep_threshold: cfg.shield.deep_threshold,
        };
        let honeypot = Honeypot::new(&cfg.honeypot);
        let intel = Intel::with_defaults();
        Shield {
            cfg,
            norm_opts,
            honeypot,
            intel,
            oracle,
        }
    }

    pub fn intel_mut(&mut self) -> &mut Intel {
        &mut self.intel
    }
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn intel(&self) -> &Intel {
        &self.intel
    }

    /// Pure, stateless inspection: no chain memory, no clock.
    pub fn inspect(&self, req: &Request) -> Judgment {
        // Intel allow-list short-circuit (still inspect, but never hard-block on
        // intel; allow-list only suppresses the intel deny pin).
        // Lists are keyed by the canonical address (IPv4-mapped IPv6 -> IPv4),
        // the same canonicalization the chain's source keys use.
        let denied = req
            .src_ip
            .map(|ip| {
                let ip = canonical(ip);
                self.intel.is_denied(&ip) && !self.intel.is_allowed(&ip)
            })
            .unwrap_or(false);

        let mut rec = Recorder::default();
        let mut max_layers = 0u8;

        // Per-field detection.
        let field_detectors: Vec<(&dyn FieldDetector, f32)> = vec![
            (&GraphTaintDetector, self.cfg.scoring.weight_graph),
            (&SignatureDetector, self.cfg.scoring.weight_signature),
            (&ApiSafetyDetector, self.cfg.scoring.weight_api),
        ];
        let ai = AiDetector {
            oracle: self.oracle.as_ref(),
        };

        for field in req.fields() {
            let n = normalize(&field.raw, &self.norm_opts);
            max_layers = max_layers.max(n.layers);
            let analysis = graph::analyze(&n.text);
            let ctx = FieldCtx {
                field: &field,
                norm: &n,
                analysis: &analysis,
            };
            let fref = FieldRef::of(&field);
            for (det, w) in &field_detectors {
                let e = det.assess(&ctx);
                rec.record(det.name(), *w, Some(fref.clone()), e);
            }
            // AI detector
            let e = ai.assess(&ctx);
            rec.record(ai.name(), self.cfg.scoring.weight_ai, Some(fref), e);
        }

        // Also inspect the path itself for traversal/recon structure.
        {
            let n = normalize(&req.path, &self.norm_opts);
            max_layers = max_layers.max(n.layers);
            let analysis = graph::analyze(&n.text);
            if !analysis.reachable.is_empty() {
                let e = Evidence::new(
                    FourValued::Dangerous,
                    0.9,
                    analysis.reachable.clone(),
                    "dangerous construct in path",
                );
                rec.record(
                    "graph-taint",
                    self.cfg.scoring.weight_graph,
                    Some(FieldRef::path()),
                    e,
                );
            }
        }

        // Request-level intent (recon of sensitive paths).
        let intent = intent_evidence(req, &self.cfg);
        rec.record("intent", self.cfg.scoring.weight_intent, Some(FieldRef::path()), intent);

        // Intel UA fingerprint.
        let ua_e = self.intel.ua_evidence(req.user_agent());
        rec.record(
            "intel",
            self.cfg.scoring.weight_intent,
            Some(FieldRef::header("user-agent")),
            ua_e,
        );

        // Honeypot.
        let mut hard_block = denied;
        let honeypot_hit = self.honeypot.check(req);
        if let Some(e) = honeypot_hit {
            hard_block = true;
            rec.record("honeypot", 1.0, Some(FieldRef::path()), e);
        }

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
        // An allow-listed source is inspected normally and is never banned,
        // so a ban recorded against its address (or shared /64) cannot block it.
        let may_ban = !self.intel.is_allowed(&canonical(ip));
        if may_ban {
            if let Some(b) = chain.active_ban(key, now_ms) {
                return self.banned_judgment(&b);
            }
        }
        let j = self.inspect(req);
        let o = chain.observe(key, event_for(&j), now_ms, may_ban);
        self.finalize(j, &o)
    }
}

fn canonical(ip: std::net::IpAddr) -> std::net::IpAddr {
    SourceKey::new(ip, 128).ip()
}

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
            score_contribution: 0.0, // filled lazily; kept for format compatibility
            patterns: e.patterns.clone(),
            note: e.note.clone(),
        });
        self.scored.push(Scored { engine: name.to_string(), engine_weight, field, evidence: e });
    }
}

fn build_reason(matched: &[Pattern], conflict: bool, banned: bool, hard: bool) -> String {
    if banned {
        return "source previously advanced the attack chain or tripped a honeypot".into();
    }
    if hard {
        return "hard-block: honeypot or deny-list".into();
    }
    if matched.is_empty() {
        return "no evidence".into();
    }
    let names: Vec<String> = matched
        .iter()
        .map(|p| format!("{:?}:{}", p.family, p.name))
        .collect();
    let base = names.join(", ");
    if conflict {
        format!("{base} (arbitrated: conflicting evidence)")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{BanCause, ChainTracker};
    use crate::judgment::{Family, FieldRef, Stage};
    use crate::lattice::FourValued;
    use crate::request::Location;
    use std::net::{IpAddr, Ipv4Addr};

    fn shield() -> Shield {
        Shield::new(Config::default())
    }

    #[test]
    fn blocks_sqli_in_query() {
        let mut req = Request::get("/items");
        req.query.push(("id".into(), "1 union select password from users".into()));
        let j = shield().inspect(&req);
        assert_eq!(j.verdict, Verdict::Block, "score {} reason {}", j.score, j.reason);
    }

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

    #[test]
    fn allows_benign_request() {
        let mut req = Request::get("/search");
        req.query.push(("q".into(), "best coffee in brisbane".into()));
        let j = shield().inspect(&req);
        assert_eq!(j.verdict, Verdict::Allow, "fp: {} {}", j.score, j.reason);
    }

    #[test]
    fn honeypot_hard_blocks() {
        let j = shield().inspect(&Request::get("/.git/config"));
        assert_eq!(j.verdict, Verdict::Block);
        assert!(j.score >= 90);
    }

    #[test]
    fn recon_probe_flagged() {
        let j = shield().inspect(&Request::get("/.env"));
        assert!(matches!(j.verdict, Verdict::Block | Verdict::Challenge), "v {:?} s {}", j.verdict, j.score);
    }

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
    fn allow_listed_source_is_never_banned_even_via_mapped_ipv6() {
        let mut s = shield();
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        s.intel_mut().add_allow_ip(v4);
        let mut chain = ChainTracker::new(&s.config().chain);
        let mut hp = Request::get("/.git/config");
        hp.src_ip = Some(mapped);
        let j1 = s.inspect_stateful(&hp, &mut chain, 0);
        assert!(!j1.banned_source, "allow-listed honeypot hit must not ban");
        assert_eq!(chain.ban_count(), 0);
        let j2 = s.inspect_stateful(&browser("/index.html", mapped), &mut chain, 1_000);
        assert!(!j2.banned_source);
        assert_eq!(j2.verdict, Verdict::Allow, "{}", j2.reason);
        // Even a ban forced onto the allow-listed address does not fast-track it.
        chain.ban(SourceKey::new(v4, 64), BanCause::Manual, 2_000);
        let j3 = s.inspect_stateful(&browser("/index.html", v4), &mut chain, 3_000);
        assert!(!j3.banned_source);
        assert_eq!(j3.verdict, Verdict::Allow, "{}", j3.reason);
        // A non-allow-listed neighbour is unaffected by the allow-list and bans normally.
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        hp.src_ip = Some(other);
        assert!(s.inspect_stateful(&hp, &mut chain, 4_000).banned_source);
    }

    #[test]
    fn deny_list_matches_mapped_ipv6() {
        let mut s = shield();
        s.intel_mut().add_deny_ip("192.0.2.9".parse().unwrap());
        let mut r = Request::get("/index.html");
        r.src_ip = Some("::ffff:192.0.2.9".parse().unwrap());
        assert_eq!(s.inspect(&r).verdict, Verdict::Block);
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

    #[test]
    fn encoded_attack_still_caught() {
        let mut req = Request::get("/p");
        // double-url-encoded "union select"
        req.query
            .push(("q".into(), "%2555NION%2520%2553ELECT%25201".into()));
        let j = shield().inspect(&req);
        assert!(
            matches!(j.verdict, Verdict::Block | Verdict::Challenge),
            "verdict {:?} score {} reason {}",
            j.verdict,
            j.score,
            j.reason
        );
    }
}
