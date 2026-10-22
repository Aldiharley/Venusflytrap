//! FR9 — The orchestrator. Wires normalize → graph/taint → detectors → lattice
//! → score, plus honeypot, intel, and (optionally) the chain tracker.

use std::time::Instant;

use crate::chain::{ChainTracker, Event};
use crate::config::Config;
use crate::detect::{
    intent_evidence, AiDetector, AiOracle, ApiSafetyDetector, FieldCtx, FieldDetector,
    GraphTaintDetector, HeuristicOracle, SignatureDetector,
};
use crate::graph;
use crate::honeypot::Honeypot;
use crate::intel::Intel;
use crate::judgment::{EngineReport, Family, Judgment, Pattern, Verdict};
use crate::lattice::Evidence;
use crate::normalize::{normalize, Options};
use crate::request::Request;
use crate::score::arbitrate;

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

    /// Stateless inspection: no chain memory.
    pub fn inspect(&self, req: &Request) -> Judgment {
        self.inspect_inner(req, None)
    }

    /// Stateful inspection: feeds the chain tracker and may escalate/ban.
    pub fn inspect_stateful(&self, req: &Request, chain: &mut ChainTracker) -> Judgment {
        self.inspect_inner(req, Some(chain))
    }

    fn inspect_inner(&self, req: &Request, chain: Option<&mut ChainTracker>) -> Judgment {
        // Intel allow-list short-circuit (still inspect, but never hard-block on
        // intel; allow-list only suppresses the intel deny pin).
        let denied = req
            .src_ip
            .map(|ip| self.intel.is_denied(&ip) && !self.intel.is_allowed(&ip))
            .unwrap_or(false);

        let mut engines: Vec<EngineReport> = Vec::new();
        let mut weighted: Vec<(f32, Evidence)> = Vec::new();
        let mut matched: Vec<Pattern> = Vec::new();
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
            for (det, w) in &field_detectors {
                let e = det.assess(&ctx);
                record(&mut engines, &mut weighted, &mut matched, det.name(), *w, e);
            }
            // AI detector
            let e = ai.assess(&ctx);
            record(
                &mut engines,
                &mut weighted,
                &mut matched,
                ai.name(),
                self.cfg.scoring.weight_ai,
                e,
            );
        }

        // Also inspect the path itself for traversal/recon structure.
        {
            let n = normalize(&req.path, &self.norm_opts);
            max_layers = max_layers.max(n.layers);
            let analysis = graph::analyze(&n.text);
            if !analysis.reachable.is_empty() {
                let e = Evidence::new(
                    crate::lattice::FourValued::Dangerous,
                    0.9,
                    analysis.reachable.clone(),
                    "dangerous construct in path",
                );
                record(
                    &mut engines,
                    &mut weighted,
                    &mut matched,
                    "graph-taint",
                    self.cfg.scoring.weight_graph,
                    e,
                );
            }
        }

        // Request-level intent (recon of sensitive paths).
        let intent = intent_evidence(req, &self.cfg);
        record(
            &mut engines,
            &mut weighted,
            &mut matched,
            "intent",
            self.cfg.scoring.weight_intent,
            intent,
        );

        // Intel UA fingerprint.
        let ua_e = self.intel.ua_evidence(req.user_agent());
        record(
            &mut engines,
            &mut weighted,
            &mut matched,
            "intel",
            self.cfg.scoring.weight_intent,
            ua_e,
        );

        // Honeypot.
        let mut hard_block = denied;
        let honeypot_hit = self.honeypot.check(req);
        if let Some(e) = honeypot_hit {
            hard_block = true;
            record(
                &mut engines,
                &mut weighted,
                &mut matched,
                "honeypot",
                1.0,
                e,
            );
        }

        // Chain inference (stateful only).
        let mut chain_stage = None;
        let mut banned_source = false;
        let mut extra = 0u8;
        if let (Some(chain), Some(ip)) = (chain, req.src_ip) {
            let families: Vec<Family> = matched.iter().map(|p| p.family).collect();
            let honeypot = families.contains(&Family::Honeypot);
            let event = classify_event(&matched, honeypot);
            let (stage, ban) = chain.observe(ip, event, Instant::now());
            chain_stage = stage;
            banned_source = ban || chain.is_banned(&ip);
            if banned_source {
                hard_block = true;
            }
            if stage.is_some() {
                extra = self.cfg.scoring.chain_stage_bonus;
            }
        } else if let Some(ip) = req.src_ip {
            // stateless: still reflect prior ban via intel deny only
            let _ = ip;
        }

        let (score, mut verdict, conflict) =
            arbitrate(&weighted, &self.cfg.scoring, hard_block, extra);
        if banned_source {
            verdict = Verdict::Block;
        }

        let reason = build_reason(&matched, conflict, banned_source, hard_block);

        Judgment {
            verdict,
            score,
            engines,
            matched,
            chain_stage,
            normalized_layers: max_layers,
            banned_source,
            reason,
        }
    }
}

fn classify_event(matched: &[Pattern], honeypot: bool) -> Event {
    let families: Vec<Family> = matched.iter().map(|p| p.family).collect();
    // Exfiltration refinement from pattern names.
    let exfil = matched.iter().any(|p| {
        matches!(p.name.as_str(), "union-select" | "union-all-select")
            || p.name == "load_file"
            || p.name == "schema-enum"
    });
    if honeypot {
        Event::Honeypot
    } else if exfil {
        Event::Exfiltration
    } else if families
        .iter()
        .any(|f| matches!(f, Family::Sqli | Family::Xss | Family::CommandInjection | Family::PathTraversal))
    {
        Event::Exploitation
    } else if families.contains(&Family::Recon) {
        Event::Recon
    } else if families.contains(&Family::Intel) {
        Event::Enumeration
    } else {
        Event::Benign
    }
}

fn record(
    engines: &mut Vec<EngineReport>,
    weighted: &mut Vec<(f32, Evidence)>,
    matched: &mut Vec<Pattern>,
    name: &str,
    weight: f32,
    e: Evidence,
) {
    for p in &e.patterns {
        if !matched.contains(p) {
            matched.push(p.clone());
        }
    }
    engines.push(EngineReport {
        engine: name.to_string(),
        value: e.value,
        weight: e.weight,
        score_contribution: 0.0, // filled lazily; kept for format compatibility
        patterns: e.patterns.clone(),
        note: e.note.clone(),
    });
    weighted.push((weight, e));
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

    #[test]
    fn chain_escalates_and_bans() {
        let s = shield();
        let mut chain = ChainTracker::new(&s.config().chain);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

        let mut recon = Request::get("/.env");
        recon.src_ip = Some(ip);
        let j1 = s.inspect_stateful(&recon, &mut chain);
        assert!(j1.chain_stage.is_some());

        let mut exploit = Request::get("/p");
        exploit.src_ip = Some(ip);
        exploit.query.push(("id".into(), "1 union select a,b".into()));
        let j2 = s.inspect_stateful(&exploit, &mut chain);
        assert!(j2.banned_source);
        assert_eq!(j2.verdict, Verdict::Block);
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
