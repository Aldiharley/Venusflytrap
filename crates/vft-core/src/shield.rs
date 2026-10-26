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
use crate::normalize::{decode, fold, fold_unless_cut, Decoded, Normalized, Options};
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
        self.inspect_counting(req).0
    }

    /// [`Shield::inspect`], plus the normalization work it spent (folded chars).
    fn inspect_counting(&self, req: &Request) -> (Judgment, usize) {
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
        // byte budget. A chunk is decoded whole; if its fold is cut, the decoded
        // text is re-inspected as overlapping halves (see `inspect_pieces`), so no
        // text is lost unless the budget runs out, splitting bottoms out, or the
        // request's normalization work cap is reached; each hard-blocks via
        // `limit.payload-truncated`. (Lossless covers text, not constructs: one
        // whose span exceeds the 256-char overlap can still straddle a seam.)
        let mut budget = self.cfg.shield.max_inspect_bytes;
        let mut work = NormalizeWork { used: 0, cap: self.cfg.shield.max_normalize_work, exhausted: false };
        let mut payload_truncated = false;
        'fields: for field in req.fields() {
            let ranges = crate::normalize::chunk_ranges(&field.raw, self.cfg.shield.max_payload);
            let mut prev_end = 0usize;
            for range in ranges {
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
                let (lost, layers) = inspect_pieces(chunk, &self.norm_opts, &mut work, &mut |n| {
                    self.inspect_text(&mut rec, &field, n, &gopts, &field_detectors, &ai)
                });
                payload_truncated |= lost;
                max_layers = max_layers.max(layers);
                if work.exhausted {
                    break 'fields;
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

        // Also inspect the path itself for traversal/recon structure, through the
        // same routine (a path longer than max_payload is chunked like a field, but
        // not charged to the byte budget).
        for range in crate::normalize::chunk_ranges(&req.path, self.cfg.shield.max_payload) {
            let (lost, layers) = inspect_pieces(&req.path[range], &self.norm_opts, &mut work, &mut |n| {
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
            });
            payload_truncated |= lost;
            max_layers = max_layers.max(layers);
            if work.exhausted {
                break;
            }
        }

        // Real loss (budget exhausted, or splitting bottomed out on a cut piece)
        // is a hard Block: text we could not inspect is not assumed benign.
        let limit_block = payload_truncated && !self.disabled.is(&sinks::LIMIT_PAYLOAD_TRUNCATED);
        if limit_block {
            rec.record(
                "limit",
                self.cfg.scoring.weight_api,
                None,
                Evidence::new(
                    FourValued::Dangerous,
                    1.0,
                    vec![sinks::LIMIT_PAYLOAD_TRUNCATED.pattern()],
                    "request exceeded shield.max_inspect_bytes or shield.max_normalize_work, or text could not be fully inspected",
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
        let mut honeypot_or_deny = denied;
        let honeypot_hit = if self.disabled.is(&sinks::HONEYPOT_DECOY_HIT) { None } else { self.honeypot.check(req) };
        if let Some(e) = honeypot_hit {
            honeypot_or_deny = true;
            rec.record("honeypot", 1.0, Some(FieldRef::path()), e);
        }
        let hard_block = honeypot_or_deny || limit_block;

        let (score, verdict, conflict) = arbitrate(&rec.scored, &self.cfg.scoring, hard_block);
        let reason = build_reason(&rec.matched, conflict, false, honeypot_or_deny, limit_block);

        let j = Judgment {
            verdict,
            score,
            engines: rec.engines,
            matched: rec.matched,
            contributions: rec.contributions,
            chain_stage: None,
            normalized_layers: max_layers,
            banned_source: false,
            reason,
        };
        (j, work.used)
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

/// A hard block names its causes: a honeypot hit or deny-listed source
/// (`honeypot_or_deny`), and/or `limit.payload-truncated` (`limit`).
fn build_reason(matched: &[Pattern], conflict: bool, banned: bool, honeypot_or_deny: bool, limit: bool) -> String {
    const HARD: &str = "hard-block: honeypot or deny-list";
    const LIMIT: &str = "limit.payload-truncated (request not fully inspected)";
    if banned {
        return "source previously advanced the attack chain or tripped a honeypot".into();
    }
    match (honeypot_or_deny, limit) {
        (true, true) => return format!("{HARD}; {LIMIT}"),
        (true, false) => return HARD.into(),
        (false, true) => return format!("hard-block: {LIMIT}"),
        (false, false) => {}
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

/// Splitting stops after this many halvings. NFKC expands a char at most 18x, so a
/// part of `max_payload / 18` decoded chars cannot be cut; from a 64 KiB chunk that
/// is reached in 5 halvings (with the 256-char overlap).
const MAX_SPLIT_DEPTH: u8 = 6;

/// The request's normalization work: folded chars produced by every fold (field
/// chunks, split parts, path), against `shield.max_normalize_work`.
struct NormalizeWork {
    used: usize,
    cap: usize,
    /// A normalization was refused; nothing more is inspected.
    exhausted: bool,
}

impl NormalizeWork {
    /// Whether a normalization of `chars` input chars may run: its worst-case
    /// work must fit under the cap. A refusal exhausts the request.
    fn admit(&mut self, chars: usize, max_payload: usize) -> bool {
        let bound = crate::normalize::work_bound(chars, max_payload);
        if self.exhausted || self.used.saturating_add(bound) > self.cap {
            self.exhausted = true;
        }
        !self.exhausted
    }

    fn charge(&mut self, folded: usize) {
        self.used = self.used.saturating_add(folded);
    }
}

/// Normalize the raw piece `raw` (a field chunk or path chunk of at most
/// `max_payload` chars) and hand it to `f`. The piece is decoded once, whole, so
/// whole-field encodings such as base64 decode exactly as in [`normalize`]; then
/// its decoded text is folded and canonicalized. If the fold is cut, the DECODED
/// text is re-inspected as two halves overlapping by [`CHUNK_OVERLAP`] chars,
/// recursively, applying only fold and canonicalization to each half (see
/// [`inspect_decoded`]). An uncut piece reaches `f` exactly as [`normalize`]
/// returns it. Returns `(lost, decode layers)`.
///
/// Work: the decode pass is admitted against the piece's worst-case fold, and its
/// charge is the folded chars of the first fold (decoding never adds chars, so that
/// bound covers it); every further fold of a half is admitted and charged the same
/// way. A refused normalization exhausts `work` and reports the piece as lost.
///
/// Splitting is lossless for TEXT: every decoded char reaches some uncut leaf, and
/// any span of up to [`CHUNK_OVERLAP`] chars lies whole in one leaf. A construct
/// whose decoded span is longer than that (e.g. `union` and `select` separated by
/// 400 spaces) can still be split across two leaves and missed; stitching seams in
/// normalized-token space is a Plan B item.
///
/// [`CHUNK_OVERLAP`]: crate::normalize::CHUNK_OVERLAP
/// [`normalize`]: crate::normalize::normalize
fn inspect_pieces(raw: &str, opts: &Options, work: &mut NormalizeWork, f: &mut dyn FnMut(&Normalized)) -> (bool, u8) {
    if !work.admit(raw.chars().count(), opts.max_payload) {
        return (true, 0);
    }
    let d = decode(raw, opts);
    let lost = inspect_decoded(&d, &d.text, 0, opts, work, f);
    (lost, d.layers)
}

/// Fold `text` (all or part of `d.text`) and hand it to `f`; if the fold is cut,
/// recurse over two halves of `text` overlapping by [`CHUNK_OVERLAP`] chars. A
/// part still cut at [`MAX_SPLIT_DEPTH`], or too short to split (at most
/// `2 x CHUNK_OVERLAP` chars), is inspected as cut and reported as lost, as is a
/// part refused by the work cap. Returns whether anything was lost.
///
/// [`CHUNK_OVERLAP`]: crate::normalize::CHUNK_OVERLAP
fn inspect_decoded(
    d: &Decoded,
    text: &str,
    depth: u8,
    opts: &Options,
    work: &mut NormalizeWork,
    f: &mut dyn FnMut(&Normalized),
) -> bool {
    let chars = text.chars().count();
    if !work.admit(chars, opts.max_payload) {
        return true;
    }
    let overlap = crate::normalize::CHUNK_OVERLAP;
    if depth >= MAX_SPLIT_DEPTH || chars <= 2 * overlap || d.truncated {
        // Cannot be split: inspect it, cut or not; a cut here is a real loss.
        let n = fold(d, text, opts);
        work.charge(n.work);
        f(&n);
        return n.truncated;
    }
    match fold_unless_cut(d, text, opts) {
        Ok(n) => {
            work.charge(n.work);
            f(&n);
            return false;
        }
        Err(cut_work) => work.charge(cut_work),
    }
    let at = |k: usize| text.char_indices().nth(k).map_or(text.len(), |(b, _)| b);
    let mid = chars / 2;
    let left = &text[..at(mid + overlap / 2)];
    let right = &text[at(mid - overlap / 2)..];
    let l_lost = inspect_decoded(d, left, depth + 1, opts, work, f);
    let r_lost = inspect_decoded(d, right, depth + 1, opts, work, f);
    l_lost || r_lost
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
    fn exceeding_the_inspection_budget_blocks_with_a_limit() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let mut req = Request::get("/items");
        req.query.push(("q".into(), "a".repeat(200_000)));
        let j = Shield::new(cfg).inspect(&req);
        assert!(has_limit(&j));
        assert_eq!(j.verdict, Verdict::Block);
    }

    const FDFA: char = '\u{FDFA}'; // NFKC expands this one char into 18
    const SQLI: &str = " 1 union select a,b from users-- ";

    fn count_limit(j: &Judgment) -> usize {
        j.contributions.iter().filter(|c| c.construct.as_deref() == Some("limit.payload-truncated")).count()
    }

    fn has_limit(j: &Judgment) -> bool {
        count_limit(j) > 0
    }

    fn has_construct(j: &Judgment, id: &str) -> bool {
        j.contributions.iter().any(|c| c.construct.as_deref() == Some(id))
    }

    fn small_payload_cfg() -> Config {
        let mut cfg = Config::default();
        cfg.shield.max_payload = 1024;
        cfg
    }

    fn query_req(v: String) -> Request {
        let mut req = Request::get("/items");
        req.query.push(("q".into(), v));
        req
    }

    /// `lead` U+FDFA chars, then `a` filler up to char offset `at`, then `attack`,
    /// then `a` filler up to `total` chars.
    fn field_with(lead: usize, at: usize, attack: &str, total: usize) -> String {
        let attack_len = attack.chars().count();
        format!(
            "{}{}{}{}",
            FDFA.to_string().repeat(lead),
            "a".repeat(at - lead),
            attack,
            "a".repeat(total - at - attack_len)
        )
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
        // 5 FDFA in chunk 0 fold it 85 chars past the cap; splitting inspects it all.
        let j = Shield::new(small_payload_cfg()).inspect(&query_req(field_with_fdfa(0, 5)));
        assert!(!has_limit(&j));
    }

    #[test]
    fn interior_cut_is_inspected_losslessly() {
        // 20 FDFA push the attack (raw offset 700) past chunk 0's folded cap of 1024;
        // no other chunk covers it. Splitting finds it.
        let j = Shield::new(small_payload_cfg()).inspect(&query_req(field_with(20, 700, SQLI, 3000)));
        assert!(!has_limit(&j));
        assert!(has_construct(&j, "sqli.union-select"));
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn last_chunk_cut_is_inspected_losslessly() {
        // 20 FDFA fold the last chunk (696 raw chars) to 1,036, so its end is cut.
        let v = format!("{}{}{}{}", "a".repeat(2400), FDFA.to_string().repeat(20), "a".repeat(547), SQLI);
        assert_eq!(v.chars().count(), 3000);
        let j = Shield::new(small_payload_cfg()).inspect(&query_req(v));
        assert!(!has_limit(&j));
        assert!(has_construct(&j, "sqli.union-select"));
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn seam_attacks_after_a_cut_chunk_are_found() {
        // 15 FDFA fold chunk 0 (1,024 raw chars) to 1,279 chars, so it is cut, while
        // the first 768 raw chars fold to 1,023. The attack straddles raw 768, where
        // the next chunk starts.
        for at in [756, 760, 764] {
            let j = Shield::new(small_payload_cfg()).inspect(&query_req(field_with(15, at, SQLI, 3000)));
            assert!(has_construct(&j, "sqli.union-select"), "at {at}");
            assert!(!has_limit(&j), "at {at}");
            assert_eq!(j.verdict, Verdict::Block, "at {at}");
        }
    }

    #[test]
    fn seam_attacks_at_the_default_chunk_size_are_found() {
        // Same construction at the 64 KiB default: the seam is at raw 65,280.
        let j = Shield::new(Config::default()).inspect(&query_req(field_with(15, 65_276, SQLI, 70_000)));
        assert!(has_construct(&j, "sqli.union-select"));
        assert!(!has_limit(&j));
        assert_eq!(j.verdict, Verdict::Block);
        let xss = "<script>alert(document.cookie)</script>";
        let j = Shield::new(Config::default()).inspect(&query_req(field_with(15, 65_276, xss, 70_000)));
        assert!(j.contributions.iter().any(|c| c.construct.as_deref().is_some_and(|id| id.starts_with("xss."))));
        assert!(!has_limit(&j));
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn a_field_of_nfkc_expanding_chars_is_split_not_dropped() {
        // 3,700 FDFA fold to ~66,600 chars, past the default 65,536 cap.
        let v = format!("{}{}", FDFA.to_string().repeat(3700), SQLI);
        let j = Shield::new(Config::default()).inspect(&query_req(v));
        assert!(has_construct(&j, "sqli.union-select"));
        assert!(!has_limit(&j));
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn a_piece_that_cannot_be_split_further_is_a_real_loss() {
        // 400 FDFA is 400 raw chars (<= 2 x overlap, so unsplittable) folding to 7,200.
        let j = Shield::new(small_payload_cfg()).inspect(&query_req(FDFA.to_string().repeat(400)));
        assert!(has_limit(&j));
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn many_cuts_and_an_exhausted_budget_emit_one_limit() {
        let mut cfg = small_payload_cfg();
        cfg.shield.max_inspect_bytes = 1024;
        let mut req = Request::get("/items");
        for i in 0..3 {
            req.query.push((format!("q{i}"), FDFA.to_string().repeat(80)));
        }
        req.query.push(("tail".into(), "a".repeat(2000))); // past the budget
        let j = Shield::new(cfg).inspect(&req);
        assert_eq!(count_limit(&j), 1);
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn limit_can_be_disabled() {
        let mut cfg = small_payload_cfg();
        cfg.shield.max_inspect_bytes = 1024;
        cfg.shield.disabled = vec!["limit.payload-truncated".into()];
        let j = Shield::new(cfg).inspect(&query_req("a".repeat(3000))); // budget exhausted
        assert_eq!(count_limit(&j), 0);
        assert_ne!(j.verdict, Verdict::Block);
    }

    #[test]
    fn attack_at_the_end_of_a_one_mib_body_blocks() {
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.body = format!("{}{}", "a".repeat(1_048_510 - SQLI.len()), SQLI).into_bytes();
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

    #[test]
    fn crafted_fold_shrink_and_expand_field_is_found() {
        // The re-review field: FDFA expands, %61 shrinks, so the chunk's folded
        // overflow says little about which raw text was cut.
        let field = format!(
            "{}{}{}{}{}{}",
            FDFA.to_string().repeat(30),
            "a".repeat(613 - SQLI.len() - 10),
            SQLI,
            "b".repeat(10),
            "%61".repeat(127),
            "b".repeat(2000)
        );
        let j = Shield::new(small_payload_cfg()).inspect(&query_req(field));
        assert!(has_construct(&j, "sqli.union-select"));
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn overlap_is_charged_once() {
        let mut cfg = small_payload_cfg();
        cfg.shield.max_inspect_bytes = 3000;
        assert!(!has_limit(&Shield::new(cfg).inspect(&query_req("a".repeat(3000)))));
    }

    fn path_taint(j: &Judgment) -> bool {
        j.contributions.iter().any(|c| c.engine == "graph-taint" && c.field == Some(FieldRef::path()))
    }

    #[test]
    fn a_long_path_is_split_not_dropped() {
        let mut req = Request::get(format!("/{}", "a".repeat(70_000)));
        req.query.push(("q".into(), "x".into()));
        let j = Shield::new(Config::default()).inspect(&req);
        assert!(!has_limit(&j));
        assert!(!path_taint(&j));
        // An attack past the first 64 KiB of the path is still found.
        let req = Request::get(format!("/{}/../../../../etc/passwd", "a".repeat(70_000)));
        let j = Shield::new(Config::default()).inspect(&req);
        assert!(!has_limit(&j));
        assert!(path_taint(&j), "{}", j.reason);
    }

    fn fdfa_body(bytes: usize) -> Request {
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.body = FDFA.to_string().repeat(bytes / 3).into_bytes();
        req
    }

    #[test]
    fn a_one_mib_fdfa_body_hits_the_normalize_work_cap() {
        // ~349,500 FDFA: lossless inspection needs ~17.7M folded chars (leaves fold
        // to 6.3M, each split node costs max_payload), past the 8 Mi-char default
        // cap, so the request hard-blocks.
        let cfg = Config::default();
        let cap = cfg.shield.max_normalize_work;
        let (j, work) = Shield::new(cfg).inspect_counting(&fdfa_body(1 << 20));
        assert!(has_limit(&j));
        assert_eq!(j.verdict, Verdict::Block);
        assert_eq!(j.reason, LIMIT_REASON);
        assert!(work <= cap, "work {work} > cap {cap}");
        // The first 64 KiB chunk alone is inspected losslessly within the cap.
        assert!(work > 65_536 * 18, "work {work}");
    }

    #[test]
    fn normalize_work_never_passes_the_cap() {
        let cap = Config::default().shield.max_normalize_work;
        let shield = Shield::new(Config::default());
        let mut many = Request::get("/items");
        for i in 0..64 {
            many.query.push((format!("q{i}"), FDFA.to_string().repeat(65_536)));
        }
        // (request, hits the cap). One 64 KiB-char FDFA field needs about 3.4M
        // folded chars and is inspected in full; the rest need more than 8 Mi.
        for (i, (req, capped)) in [
            (fdfa_body(1 << 20), true),
            (fdfa_body(4 << 20), true),
            (query_req(FDFA.to_string().repeat(300_000)), true),
            (query_req(FDFA.to_string().repeat(65_536)), false),
            (many, true),
        ]
        .into_iter()
        .enumerate()
        {
            let (j, work) = shield.inspect_counting(&req);
            eprintln!("case {i}: work {work}, limit {}", has_limit(&j));
            assert!(work <= cap, "case {i}: work {work} > cap {cap}");
            assert_eq!(has_limit(&j), capped, "case {i}");
            assert_eq!(j.verdict == Verdict::Block, capped, "case {i}");
        }
    }

    #[test]
    fn plain_text_within_the_budget_stays_under_the_work_cap() {
        // ASCII never expands: a 4 MiB body (just under the byte budget) folds to
        // about its own length plus chunk overlaps, well under 8 Mi chars.
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.body = "a".repeat((4 << 20) - 1024).into_bytes();
        let (j, work) = shield().inspect_counting(&req);
        assert!(!has_limit(&j));
        assert!(work < (4 << 20) + 64 * 1024, "work {work}");
    }

    #[test]
    fn reaching_the_work_cap_blocks_and_stops_inspection() {
        let mut cfg = Config::default();
        cfg.shield.max_normalize_work = 100_000;
        let mut req = Request::get("/items");
        req.query.push(("a".into(), "a".repeat(65_536)));
        req.query.push(("b".into(), format!("{}{}", "a".repeat(40_000), SQLI)));
        let (j, work) = Shield::new(cfg).inspect_counting(&req);
        assert!(work <= 100_000, "work {work}");
        assert!(has_limit(&j));
        assert!(!has_construct(&j, "sqli.union-select")); // field b was not inspected
        assert_eq!(j.verdict, Verdict::Block);
        assert_eq!(j.reason, LIMIT_REASON);
    }

    /// Whole-field base64 of an attack followed by `n` U+FDFA: the decoded text
    /// folds past `max_payload`, so its fold is cut and split. Two spaces keep the
    /// encoding free of '+' (length = 4 mod 8), as in the final-review probe.
    fn b64_attack_with_fdfa(n: usize) -> String {
        use base64::Engine as _;
        let plain = format!(
            "<script>alert(1)</script> 1 union select password from users  {}",
            FDFA.to_string().repeat(n)
        );
        base64::engine::general_purpose::STANDARD.encode(plain.as_bytes())
    }

    fn has_xss_or_sqli(j: &Judgment) -> bool {
        j.contributions
            .iter()
            .filter_map(|c| c.construct.as_deref())
            .any(|id| id.starts_with("xss.") || id.starts_with("sqli."))
    }

    #[test]
    fn whole_field_base64_survives_a_cut_fold() {
        // C-1 (final review): splitting the raw base64 broke its decoding, so the
        // halves normalized as plain text and the attack vanished (Allow, score 0).
        let mut missed = Vec::new();
        for n in [3_700usize, 4_000, 10_000] {
            let v = b64_attack_with_fdfa(n);
            assert!(!v.contains('+'));
            let mut header = Request::get("/items");
            header.headers.push(("x-data".into(), v.clone()));
            let mut body = Request::get("/items");
            body.method = "POST".into();
            body.body = v.clone().into_bytes();
            for (loc, req) in [("query", query_req(v)), ("header", header), ("body", body)] {
                let j = shield().inspect(&req);
                if !has_xss_or_sqli(&j) || j.verdict != Verdict::Block {
                    missed.push(format!("n {n} {loc}: {:?} {} {}", j.verdict, j.score, j.reason));
                }
            }
        }
        assert!(missed.is_empty(), "{missed:#?}");
    }

    #[test]
    fn an_uncut_piece_reaches_the_detectors_exactly_as_normalize_returns_it() {
        let opts = Options::default();
        let near_cap = b64_attack_with_fdfa(3_000); // decodes to text folding just under the cap
        for raw in [
            "",
            "best coffee in brisbane",
            "%2555NION%2520%2553ELECT%25201",
            "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+Pg==",
            "&lt;script&gt;\\x3c/**/UNION/*!SELECT*/ \u{0430}r 1=1 #x",
            near_cap.as_str(),
        ] {
            let want = crate::normalize::normalize(raw, &opts);
            let mut seen = Vec::new();
            let mut work = NormalizeWork { used: 0, cap: usize::MAX, exhausted: false };
            let (lost, layers) = inspect_pieces(raw, &opts, &mut work, &mut |n| {
                seen.push((n.text.clone(), n.cased.clone(), n.layers, n.flags.clone(), n.truncated, n.work))
            });
            assert!(!lost);
            assert_eq!(layers, want.layers);
            assert_eq!(work.used, want.work);
            assert_eq!(
                seen,
                vec![(want.text, want.cased, want.layers, want.flags, want.truncated, want.work)],
                "{raw:.40}"
            );
        }
    }

    const LIMIT_REASON: &str = "hard-block: limit.payload-truncated (request not fully inspected)";

    #[test]
    fn a_limit_block_names_its_cause() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let j = Shield::new(cfg).inspect(&query_req("a".repeat(200_000)));
        assert_eq!(j.verdict, Verdict::Block);
        assert_eq!(j.reason, LIMIT_REASON);
    }

    #[test]
    fn honeypot_and_deny_list_reasons_are_unchanged() {
        let j = shield().inspect(&Request::get("/.git/config"));
        assert_eq!(j.reason, "hard-block: honeypot or deny-list");
        let mut s = shield();
        s.intel_mut().add_deny_ip("192.0.2.9".parse().unwrap());
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(s.inspect(&r).reason, "hard-block: honeypot or deny-list");
        // Both causes at once: both are named.
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let mut r = Request::get("/.git/config");
        r.query.push(("q".into(), "a".repeat(200_000)));
        let j = Shield::new(cfg).inspect(&r);
        assert_eq!(j.reason, "hard-block: honeypot or deny-list; limit.payload-truncated (request not fully inspected)");
    }
}
