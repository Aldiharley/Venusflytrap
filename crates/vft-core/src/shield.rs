//! FR9 — The orchestrator. Wires normalize → graph/taint → detectors → lattice
//! → score, plus honeypot, intel, and (optionally) the chain tracker.

use crate::chain::{event_for, BanRecord, ChainOutcome, ChainTracker, SourceKey};
use crate::config::Config;
use crate::detect::{
    intent_evidence, AiDetector, AiOracle, ApiSafetyDetector, FieldCtx, FieldDetector,
    GraphTaintDetector, HeuristicOracle, SignatureDetector,
};
use crate::graph::{self, sinks, sinks::Disabled};
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
    disabled: Disabled,
}

impl Shield {
    pub fn new(cfg: Config) -> Self {
        Self::with_oracle(cfg, Box::new(HeuristicOracle))
    }

    pub fn with_oracle(cfg: Config, oracle: Box<dyn AiOracle>) -> Self {
        let disabled = Disabled::resolve(&cfg.shield.disabled);
        let norm_opts = Options {
            max_payload: cfg.shield.max_payload,
            decode_cap: cfg.shield.decode_cap,
            deep_threshold: cfg.shield.deep_threshold,
            disabled: disabled.clone(),
        };
        let honeypot = Honeypot::new(&cfg.honeypot);
        let intel = Intel::with_defaults();
        Shield {
            cfg,
            norm_opts,
            honeypot,
            intel,
            oracle,
            disabled,
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
        let gopts = graph::GraphOpts { disabled: &self.disabled, max_windows: self.cfg.shield.max_graph_windows };

        // Long fields are inspected in overlapping chunks under a per-request
        // byte budget; running out of budget, or a cut during normalization,
        // fails closed with `limit.payload-truncated`.
        let mut budget = self.cfg.shield.max_inspect_bytes;
        let mut payload_truncated = false;
        'fields: for field in req.fields() {
            let ranges = crate::normalize::chunk_ranges(&field.raw, self.cfg.shield.max_payload);
            let last = ranges.len().saturating_sub(1);
            let mut prev_end = 0usize;
            for (i, range) in ranges.into_iter().enumerate() {
                // Each field's text is charged once: a chunk pays only for the
                // bytes it adds beyond the previous chunk's end.
                let added = range.end.saturating_sub(prev_end);
                if added > budget {
                    payload_truncated = true;
                    break 'fields;
                }
                budget -= added;
                prev_end = range.end;
                let chunk = &field.raw[range];
                let n = normalize(chunk, &self.norm_opts);
                max_layers = max_layers.max(n.layers);
                self.inspect_text(&mut rec, &field, &n, &gopts, &field_detectors, &ai);
                if n.truncated {
                    if i == last {
                        // Nothing after the last chunk re-reads what was cut.
                        payload_truncated = true;
                    } else {
                        // Interior cut: the next chunk re-reads this chunk's last
                        // `overlap` raw chars. Everything before them must be
                        // inspected uncut, or the cut loses text.
                        let max = self.cfg.shield.max_payload;
                        let overlap = max - max.saturating_sub(crate::normalize::CHUNK_OVERLAP).max(1);
                        let keep = chunk.chars().count().saturating_sub(overlap);
                        let cut_at = chunk.char_indices().nth(keep).map_or(chunk.len(), |(b, _)| b);
                        let head = normalize(&chunk[..cut_at], &self.norm_opts);
                        if head.truncated {
                            payload_truncated = true;
                        }
                        // The head's bytes are part of the already-charged chunk.
                        max_layers = max_layers.max(head.layers);
                        self.inspect_text(&mut rec, &field, &head, &gopts, &field_detectors, &ai);
                    }
                }
            }
        }
        if let Some(first) = req.non_utf8_headers.first().filter(|_| !self.disabled.is(&sinks::LIMIT_HEADER_NON_UTF8)) {
            rec.record(
                "adapter",
                self.cfg.scoring.weight_api,
                Some(FieldRef::header(first)),
                Evidence::new(
                    FourValued::Suspicious,
                    0.6,
                    vec![sinks::LIMIT_HEADER_NON_UTF8.pattern()],
                    format!("non-UTF-8 bytes in header(s): {}", req.non_utf8_headers.join(", ")),
                ),
            );
        }

        // Also inspect the path itself for traversal/recon structure.
        {
            let n = normalize(&req.path, &self.norm_opts);
            max_layers = max_layers.max(n.layers);
            // A cut path is not fully inspected either.
            payload_truncated |= n.truncated;
            let analysis = graph::analyze_with(&n.text, &gopts);
            if analysis.graph_truncated {
                self.record_graph_truncated(&mut rec, FieldRef::path());
            }
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

        if payload_truncated && !self.disabled.is(&sinks::LIMIT_PAYLOAD_TRUNCATED) {
            rec.record(
                "limit",
                self.cfg.scoring.weight_api,
                None,
                Evidence::new(
                    FourValued::Suspicious,
                    0.6,
                    vec![sinks::LIMIT_PAYLOAD_TRUNCATED.pattern()],
                    "request exceeded shield.max_inspect_bytes or a field was cut; not fully inspected",
                ),
            );
        }

        // Request-level intent (recon of sensitive paths).
        let intent = intent_evidence(req, &self.cfg, &self.disabled);
        rec.record("intent", self.cfg.scoring.weight_intent, Some(FieldRef::path()), intent);

        // Intel UA fingerprint.
        if !self.disabled.is(&sinks::INTEL_SCANNER_UA) {
            let ua_e = self.intel.ua_evidence(req.user_agent());
            rec.record(
                "intel",
                self.cfg.scoring.weight_intent,
                Some(FieldRef::header("user-agent")),
                ua_e,
            );
        }

        // Honeypot.
        let mut hard_block = denied;
        let honeypot_hit = if self.disabled.is(&sinks::HONEYPOT_DECOY_HIT) { None } else { self.honeypot.check(req) };
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

    /// Run the graph analysis, the three field detectors and the AI detector over
    /// one normalized piece of `field`, recording against that field.
    fn inspect_text(
        &self,
        rec: &mut Recorder,
        field: &crate::request::Field,
        n: &crate::normalize::Normalized,
        gopts: &graph::GraphOpts,
        field_detectors: &[(&dyn FieldDetector, f32)],
        ai: &AiDetector,
    ) {
        let fref = FieldRef::of(field);
        let analysis = graph::analyze_with(&n.text, gopts);
        if analysis.graph_truncated {
            self.record_graph_truncated(rec, fref.clone());
        }
        let ctx = FieldCtx {
            field,
            norm: n,
            analysis: &analysis,
            disabled: &self.disabled,
        };
        for (det, w) in field_detectors {
            let e = det.assess(&ctx);
            rec.record(det.name(), *w, Some(fref.clone()), e);
        }
        let e = ai.assess(&ctx);
        rec.record(ai.name(), self.cfg.scoring.weight_ai, Some(fref), e);
    }

    /// A field needed more token windows than `shield.max_graph_windows`: it was
    /// not fully inspected, so fail closed with a Suspicious limit.
    fn record_graph_truncated(&self, rec: &mut Recorder, field: FieldRef) {
        if self.disabled.is(&sinks::LIMIT_GRAPH_TRUNCATED) {
            return;
        }
        rec.record(
            "limit",
            self.cfg.scoring.weight_api,
            Some(field),
            Evidence::new(
                FourValued::Suspicious,
                0.6,
                vec![sinks::LIMIT_GRAPH_TRUNCATED.pattern()],
                "field exceeded shield.max_graph_windows; not fully inspected",
            ),
        );
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
    fn comma_padding_does_not_hide_sqli() {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), format!("{} 1 union select a,b from users", ",".repeat(4100))));
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }

    #[test]
    fn exhausted_windows_emit_a_limit() {
        let mut cfg = Config::default();
        cfg.shield.max_graph_windows = 1;
        let mut req = Request::get("/items");
        req.query.push(("q".into(), ",".repeat(5000)));
        let j = Shield::new(cfg).inspect(&req);
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.graph-truncated")));
    }

    #[test]
    fn base64_xss_with_plus_in_a_header_blocks() {
        let mut req = Request::get("/");
        req.headers.push(("x-data".into(), "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+Pg==".into()));
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }

    #[test]
    fn raw_cookie_header_is_inspected_when_cookies_not_parsed() {
        // A library caller may supply only the raw Cookie header. It must not
        // be skipped: the skip is valid only when parsed cookies cover it.
        let mut req = Request::get("/x");
        req.headers
            .push(("Cookie".into(), "id=1 union select password from users".into()));
        assert!(req.cookies.is_empty());
        let j = shield().inspect(&req);
        assert!(
            matches!(j.verdict, Verdict::Block | Verdict::Challenge),
            "{:?} {}",
            j.verdict,
            j.score
        );
    }

    #[test]
    fn clean_header_does_not_damp_attack() {
        // H4: an unrelated clean field must not pull a Block down to Challenge.
        let mut req = Request::get("/items");
        req.query.push(("id".into(), "1 union select password from users".into()));
        req.headers.push(("Accept-Language".into(), "en".into()));
        let j = shield().inspect(&req);
        assert_eq!(j.verdict, Verdict::Block, "score {} {}", j.score, j.reason);
    }

    #[test]
    fn env_probe_not_damped_below_challenge() {
        let mut req = Request::get("/.env");
        req.headers.push(("Accept-Language".into(), "en".into()));
        let j = shield().inspect(&req);
        assert!(j.verdict.rank() >= Verdict::Challenge.rank(), "{:?} {}", j.verdict, j.score);
    }

    #[test]
    fn many_weak_signals_cannot_reach_block() {
        // M1: 25 values of `red;blue` must not add up to a Block.
        let mut req = Request::get("/form");
        for i in 0..25 {
            req.query.push((format!("c{i}"), "red;blue".into()));
        }
        let j = shield().inspect(&req);
        assert!(j.score < shield().config().scoring.block_at, "score {}", j.score);
        assert_ne!(j.verdict, Verdict::Block);
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
            .find(|c| c.construct.as_deref() == Some("sqli.union-select"))
            .expect("union-select contribution");
        assert_eq!(c.field, Some(FieldRef { loc: Location::Query, name: "id".into() }));
        assert_eq!(c.family, Some(Family::Sqli));
        assert_eq!(c.value, FourValued::Dangerous);
    }

    #[test]
    fn disabling_a_construct_removes_it_from_judgments() {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), "1 union select password from users".into()));
        let on = Shield::new(Config::default()).inspect(&req);
        assert!(on.contributions.iter().any(|c| c.construct.as_deref() == Some("sqli.union-select")));
        let mut cfg = Config::default();
        cfg.shield.disabled = vec!["sqli.union-select".into()];
        let off = Shield::new(cfg).inspect(&req);
        assert!(!off.contributions.iter().any(|c| c.construct.as_deref() == Some("sqli.union-select")));
    }

    #[test]
    fn disabling_the_honeypot_skips_it() {
        let cfg = Config::default();
        let decoy = cfg.honeypot.decoy_paths.first().cloned().expect("default config has a decoy path");
        let req = Request::get(decoy);
        let mut off_cfg = Config::default();
        off_cfg.shield.disabled = vec!["honeypot.decoy-hit".into()];
        let j = Shield::new(off_cfg).inspect(&req);
        assert!(!j.contributions.iter().any(|c| c.construct.as_deref() == Some("honeypot.decoy-hit")));
    }

    #[test]
    fn sqli_survives_an_invalid_utf8_escape_in_the_same_field() {
        let mut req = Request::get("/login");
        req.method = "POST".into();
        req.body = b"user=admin%27%20or%201%3D1--%20&x=%ff".to_vec();
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
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
        // C1 regression: latent cmd.shell-meta from ';' in browser headers must not
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

    #[test]
    fn attack_past_max_payload_blocks() {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), format!("{} 1 union select a,b from users", "a".repeat(70_000))));
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }

    #[test]
    fn exceeding_the_inspection_budget_emits_a_limit() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let mut req = Request::get("/items");
        req.query.push(("q".into(), "a".repeat(200_000)));
        let j = Shield::new(cfg).inspect(&req);
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.payload-truncated")));
    }

    const FDFA: char = '\u{FDFA}'; // NFKC expands this one char into 18

    fn count_limit(j: &Judgment) -> usize {
        j.contributions.iter().filter(|c| c.construct.as_deref() == Some("limit.payload-truncated")).count()
    }

    fn has_limit(j: &Judgment) -> bool {
        count_limit(j) > 0
    }

    fn small_payload_cfg() -> Config {
        let mut cfg = Config::default();
        cfg.shield.max_payload = 1024;
        cfg
    }

    /// A 3,000-char field (several chunks at max_payload 1024) with `k` FDFA
    /// chars at char offset `at`.
    fn field_with_fdfa(at: usize, k: usize) -> String {
        let mut v: Vec<char> = "a".repeat(3000).chars().collect();
        for c in v.iter_mut().skip(at).take(k) {
            *c = FDFA;
        }
        v.into_iter().collect()
    }

    #[test]
    fn interior_cut_within_the_overlap_is_not_a_limit() {
        // 5 FDFA in chunk 0: post-fold overflow is 85 chars (<= 256), and chunk 1
        // re-inspects that tail through the overlap.
        let mut req = Request::get("/items");
        req.query.push(("q".into(), field_with_fdfa(0, 5)));
        assert!(!has_limit(&Shield::new(small_payload_cfg()).inspect(&req)));
    }

    #[test]
    fn interior_cut_beyond_the_overlap_is_a_limit() {
        // 20 FDFA in chunk 0: overflow is 340 chars (> 256).
        let mut req = Request::get("/items");
        req.query.push(("q".into(), field_with_fdfa(0, 20)));
        assert!(has_limit(&Shield::new(small_payload_cfg()).inspect(&req)));
    }

    #[test]
    fn last_chunk_cut_is_a_limit() {
        // 20 FDFA at the end: the last chunk (696 chars) folds past 1024 and no
        // later chunk re-inspects the cut text.
        let mut req = Request::get("/items");
        req.query.push(("q".into(), field_with_fdfa(2950, 20)));
        assert!(has_limit(&Shield::new(small_payload_cfg()).inspect(&req)));
    }

    #[test]
    fn many_cuts_and_an_exhausted_budget_emit_one_limit() {
        let mut cfg = small_payload_cfg();
        cfg.shield.max_inspect_bytes = 1024;
        let mut req = Request::get("/items");
        for i in 0..3 {
            req.query.push((format!("q{i}"), FDFA.to_string().repeat(80))); // 240 bytes, folds to 1,440 chars
        }
        req.query.push(("tail".into(), "a".repeat(500))); // past the budget
        assert_eq!(count_limit(&Shield::new(cfg).inspect(&req)), 1);
    }

    #[test]
    fn limit_can_be_disabled() {
        let mut cfg = small_payload_cfg();
        cfg.shield.disabled = vec!["limit.payload-truncated".into()];
        let mut req = Request::get("/items");
        req.query.push(("q".into(), field_with_fdfa(2950, 20)));
        assert_eq!(count_limit(&Shield::new(cfg).inspect(&req)), 0);
    }

    #[test]
    fn attack_at_the_end_of_a_one_mib_body_blocks() {
        let tail = " 1 union select a,b from users-- ";
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.body = format!("{}{}", "a".repeat(1_048_510 - tail.len()), tail).into_bytes();
        assert_eq!(req.body.len(), 1_048_510);
        assert_eq!(Shield::new(Config::default()).inspect(&req).verdict, Verdict::Block);
    }

    #[test]
    fn lossy_inflated_body_within_the_default_budget_is_not_a_limit() {
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.body = vec![0xFF; 400 * 1024]; // each invalid byte becomes a 3-byte U+FFFD
        assert!(!has_limit(&Shield::new(Config::default()).inspect(&req)));
    }

    /// The review's bypass: folding shrinks and expands text unevenly, so a cut of
    /// <= 256 folded chars can hide far more raw chars that no chunk re-reads.
    fn crafted_bypass_field() -> String {
        let tail = " 1 union select a,b from users-- ";
        format!(
            "{}{}{}{}{}{}",
            FDFA.to_string().repeat(30),
            "a".repeat(613 - tail.len() - 10),
            tail,
            "b".repeat(10),
            "%61".repeat(127),
            "b".repeat(2000)
        )
    }

    #[test]
    fn folded_overflow_cannot_hide_uninspected_raw_text() {
        let field = crafted_bypass_field();
        assert_eq!(field.chars().take(1024).count(), 1024);
        let mut req = Request::get("/items");
        req.query.push(("q".into(), field));
        let j = Shield::new(small_payload_cfg()).inspect(&req);
        // The chunk minus its overlap still folds past the cap, so the loss is
        // reported (fail closed) instead of being silently exempted.
        assert!(has_limit(&j), "verdict {:?} score {} reason {}", j.verdict, j.score, j.reason);
    }

    #[test]
    fn overlap_is_charged_once() {
        let mut cfg = small_payload_cfg();
        cfg.shield.max_inspect_bytes = 3000;
        let mut req = Request::get("/items");
        req.query.push(("q".into(), "a".repeat(3000)));
        assert!(!has_limit(&Shield::new(cfg).inspect(&req)));
    }
}
