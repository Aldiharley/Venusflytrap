//! FR9 — The orchestrator. Wires normalize → graph/taint → detectors → lattice
//! → score, plus honeypot, intel, and (optionally) the chain tracker.

use crate::chain::{event_for, BanCause, BanRecord, ChainOutcome, ChainTracker, SourceKey};
use crate::config::Config;
use crate::detect::{
    intent_evidence, AiDetector, AiOracle, ApiSafetyDetector, FieldCtx, FieldDetector,
    GraphTaintDetector, HeuristicOracle, SignatureDetector,
};
use crate::graph::{self, sinks, sinks::Disabled};
use crate::honeypot::Honeypot;
use crate::intel::Intel;
use crate::judgment::{Cause, CauseKind, Contribution, FieldRef, Judgment, Verdict};
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
    /// Constructs off when judging: `shield.disabled` plus `shield.shadow`.
    disabled: Disabled,
    /// `shield.disabled` alone, set only when `shield.shadow` is non-empty: the
    /// second pass that finds which shadow constructs fired.
    observe: Option<Disabled>,
    /// `shield.shadow`.
    shadow: Disabled,
}

impl Shield {
    pub fn new(cfg: Config) -> Self {
        Self::with_oracle(cfg, Box::new(HeuristicOracle))
    }

    pub fn with_oracle(cfg: Config, oracle: Box<dyn AiOracle>) -> Self {
        let off: Vec<String> = cfg.shield.disabled.iter().chain(&cfg.shield.shadow).cloned().collect();
        let disabled = Disabled::resolve(&off);
        let shadow = Disabled::resolve(&cfg.shield.shadow);
        let observe = (!cfg.shield.shadow.is_empty()).then(|| Disabled::resolve(&cfg.shield.disabled));
        let norm_opts = Options {
            max_payload: cfg.shield.max_payload,
            decode_cap: cfg.shield.decode_cap,
            deep_threshold: cfg.shield.deep_threshold,
            disabled: disabled.clone(),
        };
        let honeypot = Honeypot::new(&cfg.honeypot);
        let mut intel = Intel::with_defaults();
        for ip in cfg.intel.deny_ips.iter().filter_map(|s| s.parse().ok()) {
            intel.add_deny_ip(canonical(ip));
        }
        for ip in cfg.intel.allow_ips.iter().filter_map(|s| s.parse().ok()) {
            intel.add_allow_ip(canonical(ip));
        }
        Shield {
            cfg,
            norm_opts,
            honeypot,
            intel,
            oracle,
            disabled,
            observe,
            shadow,
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
    ///
    /// With `shield.shadow` set, the request is judged with the shadow ids off
    /// (exactly as if they were in `shield.disabled`), then inspected again with
    /// only `shield.disabled` off; the shadow ids that fired in that pass are
    /// appended as `shadow` contributions with 0 points. They never reach the
    /// score, the verdict, `decided_by` or the chain.
    fn inspect_counting(&self, req: &Request) -> (Judgment, usize) {
        let (mut j, work) = self.inspect_view(req, &self.disabled);
        if let Some(full) = &self.observe {
            let (seen, _) = self.inspect_view(req, full);
            j.contributions.extend(
                seen.contributions
                    .into_iter()
                    .filter(|c| c.construct.as_deref().is_some_and(|id| self.shadow.has(id)))
                    .map(|c| Contribution { points: 0.0, shadow: true, ..c }),
            );
        }
        (j, work)
    }

    /// One inspection with the constructs in `off` switched off.
    fn inspect_view(&self, req: &Request, off: &Disabled) -> (Judgment, usize) {
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
        let gopts = graph::GraphOpts { disabled: off, max_windows: self.cfg.shield.max_graph_windows };

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
        let mut budget_hit = false;
        let (fields, body_facts) = req.fields_with(off);
        'fields: for field in fields {
            let ranges = crate::normalize::chunk_ranges(&field.raw, self.cfg.shield.max_payload);
            let mut prev_end = 0usize;
            for range in ranges {
                // Each field's text is charged once: a chunk pays only for the
                // bytes it adds beyond the previous chunk's end.
                let added = range.end.saturating_sub(prev_end);
                if added > budget {
                    budget_hit = true;
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
        if let Some(first) = req.non_utf8_headers.first().filter(|_| !off.is(&sinks::LIMIT_HEADER_NON_UTF8)) {
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
        let body_ref = || Some(FieldRef { loc: crate::request::Location::Body, name: "<body>".into() });
        if body_facts.non_utf8 && !off.is(&sinks::LIMIT_BODY_NON_UTF8) {
            rec.record(
                "adapter",
                self.cfg.scoring.weight_api,
                body_ref(),
                Evidence::new(FourValued::Suspicious, 0.6, vec![sinks::LIMIT_BODY_NON_UTF8.pattern()], "non-UTF-8 bytes in a text body"),
            );
        }
        if body_facts.unparsed && !off.is(&sinks::LIMIT_BODY_UNPARSED) {
            // Informational: engine weight 0, so 0 points; it says why the body stayed whole.
            rec.record(
                "adapter",
                0.0,
                body_ref(),
                Evidence::new(
                    FourValued::Suspicious,
                    0.0,
                    vec![sinks::LIMIT_BODY_UNPARSED.pattern()],
                    "body declared JSON, ndjson or multipart did not parse; inspected whole",
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
                    self.record_graph_truncated(&mut rec, FieldRef::path(), off);
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
        let limit_block = payload_truncated && !off.is(&sinks::LIMIT_PAYLOAD_TRUNCATED);
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
        let intent = intent_evidence(req, &self.cfg, off);
        rec.record("intent", self.cfg.scoring.weight_intent, Some(FieldRef::path()), intent);

        // Intel UA fingerprint.
        if !off.is(&sinks::INTEL_SCANNER_UA) {
            let ua_e = self.intel.ua_evidence(req.user_agent());
            rec.record(
                "intel",
                self.cfg.scoring.weight_intent,
                Some(FieldRef::header("user-agent")),
                ua_e,
            );
        }

        // Honeypot.
        let deny_pin = denied && !off.is(&sinks::INTEL_DENY_LISTED);
        if deny_pin {
            rec.record(
                "intel",
                1.0,
                None,
                Evidence::new(
                    FourValued::Dangerous,
                    1.0,
                    vec![sinks::INTEL_DENY_LISTED.pattern()],
                    "source is on intel.deny_ips",
                ),
            );
        }
        let mut honeypot_or_deny = deny_pin;
        let honeypot_hit = if off.is(&sinks::HONEYPOT_DECOY_HIT) { None } else { self.honeypot.check(req) };
        let honeypot_seen = honeypot_hit.is_some();
        if let Some(e) = honeypot_hit {
            honeypot_or_deny = true;
            rec.record("honeypot", 1.0, Some(FieldRef::path()), e);
        }
        let hard_block = honeypot_or_deny || limit_block;
        let pins = Pins {
            honeypot: honeypot_seen,
            deny: deny_pin,
            limit: limit_block.then_some(if budget_hit {
                "shield.max_inspect_bytes"
            } else if work.exhausted {
                "shield.max_normalize_work"
            } else {
                "shield.max_payload"
            }),
        };
        let allowlisted = req.src_ip.is_some_and(|ip| self.intel.is_allowed(&canonical(ip)));

        let arb = arbitrate(&rec.scored, &self.cfg.scoring, hard_block);
        let (score, verdict) = (arb.score, arb.verdict);
        for (i, p) in arb.points.iter().enumerate() {
            if let Some(ci) = rec.first_contrib[i] {
                rec.contributions[ci].points += p;
            }
        }
        if hard_block {
            // The deciding pin carries the whole score, in decided_by order.
            let pin = [sinks::HONEYPOT_DECOY_HIT.id, sinks::INTEL_DENY_LISTED.id, sinks::LIMIT_PAYLOAD_TRUNCATED.id]
                .into_iter()
                .find_map(|id| rec.contributions.iter().position(|c| c.construct.as_deref() == Some(id)));
            if let Some(ci) = pin {
                rec.contributions[ci].points = 100.0;
            }
        }
        let decided_by = cause_for(&rec.contributions, verdict, score, &self.cfg.scoring, &pins, allowlisted);

        let j = Judgment {
            verdict,
            score,
            contributions: rec.contributions,
            decided_by,
            chain: None,
            normalized_layers: max_layers,
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
            self.record_graph_truncated(rec, fref.clone(), gopts.disabled);
        }
        let ctx = FieldCtx {
            field,
            norm: n,
            analysis: &analysis,
            disabled: gopts.disabled,
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
    fn record_graph_truncated(&self, rec: &mut Recorder, field: FieldRef, off: &Disabled) {
        if off.is(&sinks::LIMIT_GRAPH_TRUNCATED) {
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
        j.chain = Some(*o);
        let sc = &self.cfg.scoring;
        if o.advanced && o.stage_after.is_some() {
            let bumped = j.score.saturating_add(sc.chain_stage_bonus).min(100);
            let v = crate::score::band(bumped, sc);
            let raised = v.rank() > j.verdict.rank();
            if raised {
                j.verdict = v;
            }
            let before = j.score;
            j.score = j.score.max(bumped);
            if j.score > before {
                j.contributions.push(chain_contribution("chain.stage-advance", f32::from(j.score - before)));
            }
            if let (true, Some((key, threshold))) = (raised, band_key(v, sc)) {
                j.decided_by = Cause {
                    kind: CauseKind::ChainEscalation,
                    option_key: "scoring.chain_stage_bonus",
                    construct: j.decided_by.construct.clone(),
                    field: j.decided_by.field.clone(),
                    msg: format!(
                        "kill-chain stage advance (+{} scoring.chain_stage_bonus) raised the score to {} >= {key} {threshold}; before: {}",
                        sc.chain_stage_bonus, j.score, j.decided_by.msg
                    ),
                };
            }
        }
        if let Some(b) = o.new_ban {
            j.verdict = Verdict::Block;
            let before = j.score;
            j.score = 100;
            if before < 100 {
                j.contributions.push(chain_contribution("chain.ban", f32::from(100 - before)));
            }
            let msg = format!("{}; source banned ({:?}) for {} s", j.decided_by.msg, b.cause, (b.until_ms - b.since_ms) / 1000);
            j.decided_by = ban_cause(&b, msg);
        }
        j
    }

    /// The judgment for a request from an actively banned source (no inspection).
    ///
    /// Its one contribution names the construct `chain.ban`, which is deliberately
    /// NOT in the construct registry (`sinks::constructs()`): it records a chain
    /// decision, not a detection, so no sink emits it and it cannot be disabled.
    /// Consumers of `constructs()` should expect this extra id in judgments.
    pub fn banned_judgment(&self, ban: &BanRecord) -> Judgment {
        Judgment {
            verdict: Verdict::Block,
            score: 100,
            contributions: vec![Contribution {
                engine: "chain",
                field: None,
                construct: Some("chain.ban".into()),
                family: None,
                value: FourValued::Dangerous,
                weight: 1.0,
                points: 100.0,
                shadow: false,
            }],
            decided_by: ban_cause(ban, format!("source banned ({:?}) until t={} ms", ban.cause, ban.until_ms)),
            chain: None,
            normalized_layers: 0,
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

/// Hard pins found during inspection.
struct Pins {
    honeypot: bool,
    deny: bool,
    limit: Option<&'static str>,
}

/// The option key and threshold of the band a verdict sits in (`None` for Allow).
fn band_key(v: Verdict, cfg: &crate::config::ScoringConfig) -> Option<(&'static str, u8)> {
    match v {
        Verdict::Block => Some(("scoring.block_at", cfg.block_at)),
        Verdict::Challenge => Some(("scoring.challenge_at", cfg.challenge_at)),
        Verdict::Monitor => Some(("scoring.monitor_at", cfg.monitor_at)),
        Verdict::Allow => None,
    }
}

/// The contribution that added the most points (the first one on a tie).
fn top_contribution(cs: &[Contribution]) -> Option<&Contribution> {
    let mut best: Option<&Contribution> = None;
    for c in cs.iter().filter(|c| !c.shadow) {
        if best.map_or(c.points > 0.0, |b| c.points > b.points) {
            best = Some(c);
        }
    }
    best
}

/// Spec 5.2: honeypot, intel deny, fail-closed limit, band, no evidence
/// (bans are applied later, by `finalize` and `banned_judgment`).
fn cause_for(
    contributions: &[Contribution],
    verdict: Verdict,
    score: u8,
    cfg: &crate::config::ScoringConfig,
    pins: &Pins,
    allowlisted: bool,
) -> Cause {
    if pins.honeypot {
        let field = contributions
            .iter()
            .find(|c| c.construct.as_deref() == Some(sinks::HONEYPOT_DECOY_HIT.id))
            .and_then(|c| c.field.clone());
        return Cause {
            kind: CauseKind::Honeypot,
            option_key: "honeypot.decoy_paths",
            construct: Some(sinks::HONEYPOT_DECOY_HIT.id.into()),
            field,
            msg: "hard-block: request hit a honeypot decoy path".into(),
        };
    }
    if pins.deny {
        return Cause {
            kind: CauseKind::IntelDeny,
            option_key: "intel.deny_ips",
            construct: Some(sinks::INTEL_DENY_LISTED.id.into()),
            field: None,
            msg: "hard-block: source is on intel.deny_ips".into(),
        };
    }
    if let Some(key) = pins.limit {
        return Cause {
            kind: CauseKind::Limit,
            option_key: key,
            construct: Some(sinks::LIMIT_PAYLOAD_TRUNCATED.id.into()),
            field: None,
            msg: format!("hard-block: limit.payload-truncated (request not fully inspected; {key})"),
        };
    }
    let Some((key, threshold)) = band_key(verdict, cfg) else {
        return if allowlisted {
            Cause {
                kind: CauseKind::Allowlisted,
                option_key: "intel.allow_ips",
                construct: None,
                field: None,
                msg: format!("source is on intel.allow_ips; score {score} < scoring.monitor_at {}", cfg.monitor_at),
            }
        } else {
            Cause {
                kind: CauseKind::NoEvidence,
                option_key: "scoring.monitor_at",
                construct: None,
                field: None,
                msg: format!("score {score} < scoring.monitor_at {}", cfg.monitor_at),
            }
        };
    };
    let top = top_contribution(contributions);
    let construct = top.and_then(|c| c.construct.clone());
    let field = top.and_then(|c| c.field.clone());
    let what = match (&construct, &field) {
        (Some(c), Some(f)) => format!("{c} in {}", f.label()),
        (Some(c), None) => c.clone(),
        (None, _) => "evidence".into(),
    };
    Cause {
        kind: CauseKind::Detection,
        option_key: key,
        construct,
        field,
        msg: format!("score {score} >= {key} {threshold}: {what}"),
    }
}

/// The cause of a ban, keyed by the option that triggered it (D4).
fn ban_cause(b: &BanRecord, msg: String) -> Cause {
    let option_key = match b.cause {
        BanCause::Honeypot => "chain.ban_policy.on_honeypot",
        BanCause::Exfiltration => "chain.ban_policy.on_exfiltration_block",
        BanCause::RepeatedExploitation => "chain.ban_policy.exploitation_blocks",
        BanCause::Manual => "chain.ban_policy.ttl_secs",
    };
    Cause { kind: CauseKind::Ban, option_key, construct: Some("chain.ban".into()), field: None, msg }
}

/// A chain decision recorded as a contribution so the points still add up.
/// `chain.*` ids are deliberately not in the construct registry.
fn chain_contribution(id: &str, points: f32) -> Contribution {
    Contribution {
        engine: "chain",
        field: None,
        construct: Some(id.into()),
        family: None,
        value: FourValued::Dangerous,
        weight: 1.0,
        points,
        shadow: false,
    }
}

#[derive(Default)]
struct Recorder {
    scored: Vec<Scored>,
    /// Index into `contributions` of each `scored` item's first contribution.
    first_contrib: Vec<Option<usize>>,
    contributions: Vec<Contribution>,
}

impl Recorder {
    fn record(&mut self, name: &'static str, engine_weight: f32, field: Option<FieldRef>, e: Evidence) {
        let first = (e.value != FourValued::None).then_some(self.contributions.len());
        if e.value != FourValued::None {
            if e.patterns.is_empty() {
                self.contributions.push(Contribution {
                    engine: name,
                    field: field.clone(),
                    construct: None,
                    family: None,
                    value: e.value,
                    weight: e.weight,
                    points: 0.0,
                    shadow: false,
                });
            }
            for p in &e.patterns {
                self.contributions.push(Contribution {
                    engine: name,
                    field: field.clone(),
                    construct: Some(p.name.clone()),
                    family: Some(p.family),
                    value: e.value,
                    weight: e.weight,
                    points: 0.0,
                    shadow: false,
                });
            }
        }
        self.scored.push(Scored { engine: name.to_string(), engine_weight, field, evidence: e });
        self.first_contrib.push(first);
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
    use crate::chain::{BanCause, ChainOutcome, ChainTracker};
    use crate::judgment::{CauseKind, Family, FieldRef, Stage};
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
        assert_eq!(j.verdict, Verdict::Block, "score {} {}", j.score, j.decided_by.msg);
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
        assert_eq!(j.verdict, Verdict::Block, "score {} reason {}", j.score, j.decided_by.msg);
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
        assert_eq!(j.verdict, Verdict::Allow, "fp: {} {}", j.score, j.decided_by.msg);
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
            assert_eq!(j.verdict, Verdict::Allow, "request {i}: {}", j.decided_by.msg);
            assert!(!j.banned());
            assert_eq!(j.stage(), None);
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
        assert!(!j1.banned());
        let _ = s.inspect_stateful(&xss, &mut chain, 1_000);
        let j3 = s.inspect_stateful(&xss, &mut chain, 2_000);
        assert!(j3.banned(), "third exploitation block within 10 min bans");
        let benign = browser("/index.html", ip);
        let j4 = s.inspect_stateful(&benign, &mut chain, 3_000);
        assert_eq!(j4.verdict, Verdict::Block);
        assert!(j4.banned());
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
        assert!(!j1.banned(), "allow-listed honeypot hit must not ban");
        assert_eq!(chain.ban_count(), 0);
        let j2 = s.inspect_stateful(&browser("/index.html", mapped), &mut chain, 1_000);
        assert!(!j2.banned());
        assert_eq!(j2.verdict, Verdict::Allow, "{}", j2.decided_by.msg);
        // Even a ban forced onto the allow-listed address does not fast-track it.
        chain.ban(SourceKey::new(v4, 64), BanCause::Manual, 2_000);
        let j3 = s.inspect_stateful(&browser("/index.html", v4), &mut chain, 3_000);
        assert!(!j3.banned());
        assert_eq!(j3.verdict, Verdict::Allow, "{}", j3.decided_by.msg);
        // A non-allow-listed neighbour is unaffected by the allow-list and bans normally.
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        hp.src_ip = Some(other);
        assert!(s.inspect_stateful(&hp, &mut chain, 4_000).banned());
    }

    #[test]
    fn deny_and_allow_lists_come_from_config() {
        let mut cfg = Config::default();
        cfg.intel.deny_ips = vec!["192.0.2.9".into(), "192.0.2.10".into()];
        cfg.intel.allow_ips = vec!["192.0.2.10".into()];
        let s = Shield::new(cfg);
        let mut r = Request::get("/index.html");
        r.src_ip = Some("::ffff:192.0.2.9".parse().unwrap());
        let j = s.inspect(&r);
        assert_eq!(j.verdict, Verdict::Block);
        assert!(has_construct(&j, "intel.deny-listed"));
        assert_eq!(crate::chain::event_for(&j), crate::chain::Event::Benign, "a deny pin is not a kill-chain event");
        r.src_ip = Some("192.0.2.10".parse().unwrap());
        assert_eq!(s.inspect(&r).verdict, Verdict::Allow, "the allow-list suppresses the deny pin");
    }

    #[test]
    fn disabling_the_deny_construct_removes_the_pin() {
        let mut cfg = Config::default();
        cfg.intel.deny_ips = vec!["192.0.2.9".into()];
        cfg.shield.disabled = vec!["intel.deny-listed".into()];
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(Shield::new(cfg).inspect(&r).verdict, Verdict::Allow);
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
        assert_eq!(j1.stage(), Some(Stage::Recon));
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
            j.decided_by.msg
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
        // The query key "q" is inspected as its own field (1 byte) before the
        // 3000-byte value; double-charging the overlaps would need ~3,768.
        cfg.shield.max_inspect_bytes = 3000 + "q".len();
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
        assert!(path_taint(&j), "{}", j.decided_by.msg);
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
        assert_eq!(j.decided_by.kind, CauseKind::Limit);
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
        assert_eq!(j.decided_by.kind, CauseKind::Limit);
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
                    missed.push(format!("n {n} {loc}: {:?} {} {}", j.verdict, j.score, j.decided_by.msg));
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

    #[test]
    fn a_limit_block_names_its_cause() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let j = Shield::new(cfg).inspect(&query_req("a".repeat(200_000)));
        assert_eq!(j.verdict, Verdict::Block);
        assert_eq!(j.decided_by.kind, CauseKind::Limit);
    }

    #[test]
    fn honeypot_outranks_deny_and_limit() {
        assert_eq!(shield().inspect(&Request::get("/.git/config")).decided_by.kind, CauseKind::Honeypot);
        let mut s = shield();
        s.intel_mut().add_deny_ip("192.0.2.9".parse().unwrap());
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(s.inspect(&r).decided_by.kind, CauseKind::IntelDeny);
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let mut r = Request::get("/.git/config");
        r.query.push(("q".into(), "a".repeat(200_000)));
        let j = Shield::new(cfg).inspect(&r);
        assert_eq!(j.decided_by.kind, CauseKind::Honeypot);
        assert!(has_limit(&j), "the limit is still recorded as a contribution");
    }

    #[test]
    fn decided_by_follows_the_fixed_order() {
        let s = shield();
        let j = s.inspect(&Request::get("/.git/config"));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Honeypot, "honeypot.decoy_paths"));
        let mut q = Request::get("/items");
        q.query.push(("id".into(), "1 union select password from users".into()));
        let j = s.inspect(&q);
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Detection, "scoring.block_at"));
        assert!(j.decided_by.construct.is_some());
        assert_eq!(j.decided_by.field.as_ref().map(|f| f.name.as_str()), Some("id"));
        assert!(j.decided_by.msg.contains("scoring.block_at"), "{}", j.decided_by.msg);
        let j = s.inspect(&Request::get("/index.html"));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::NoEvidence, "scoring.monitor_at"));
    }

    #[test]
    fn intel_causes_name_their_lists() {
        let mut cfg = Config::default();
        cfg.intel.deny_ips = vec!["192.0.2.9".into()];
        cfg.intel.allow_ips = vec!["192.0.2.10".into()];
        let s = Shield::new(cfg);
        let mut r = Request::get("/index.html");
        r.src_ip = Some("192.0.2.9".parse().unwrap());
        assert_eq!(s.inspect(&r).decided_by.kind, CauseKind::IntelDeny);
        assert_eq!(s.inspect(&r).decided_by.option_key, "intel.deny_ips");
        r.src_ip = Some("192.0.2.10".parse().unwrap());
        let j = s.inspect(&r);
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Allowlisted, "intel.allow_ips"));
    }

    #[test]
    fn limit_cause_names_the_budget_that_stopped_inspection() {
        let mut cfg = Config::default();
        cfg.shield.max_inspect_bytes = 100_000;
        let j = Shield::new(cfg).inspect(&query_req("a".repeat(200_000)));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Limit, "shield.max_inspect_bytes"));
        let (j, _) = Shield::new(Config::default()).inspect_counting(&fdfa_body(1 << 20));
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::Limit, "shield.max_normalize_work"));
    }

    #[test]
    fn chain_causes_name_their_option() {
        let s = shield();
        let mut chain = ChainTracker::new(&s.config().chain);
        let ip: IpAddr = "10.0.0.20".parse().unwrap();
        let mut hp = Request::get("/.git/config");
        hp.src_ip = Some(ip);
        let j1 = s.inspect_stateful(&hp, &mut chain, 0);
        assert_eq!((j1.decided_by.kind, j1.decided_by.option_key), (CauseKind::Ban, "chain.ban_policy.on_honeypot"));
        assert!(j1.chain.and_then(|o| o.new_ban).is_some());
        let sum: f32 = j1.contributions.iter().map(|c| c.points).sum();
        assert!((sum - 100.0).abs() <= 1.0, "Σ {sum}");
        let j2 = s.inspect_stateful(&browser("/index.html", ip), &mut chain, 1_000);
        assert_eq!(j2.decided_by.kind, CauseKind::Ban);
        assert!(j2.chain.is_none(), "a fast-track ban observes nothing");
    }

    #[test]
    fn a_chain_bonus_that_crosses_a_band_is_the_cause() {
        let s = shield();
        let mut j = Judgment::allow();
        j.score = 30;
        let o = ChainOutcome { stage_before: None, stage_after: Some(Stage::Recon), advanced: true, new_ban: None };
        let j = s.finalize(j, &o);
        assert_eq!(j.verdict, Verdict::Monitor);
        assert_eq!((j.decided_by.kind, j.decided_by.option_key), (CauseKind::ChainEscalation, "scoring.chain_stage_bonus"));
        assert!(j
            .contributions
            .iter()
            .any(|c| c.construct.as_deref() == Some("chain.stage-advance") && (c.points - 15.0).abs() < 1e-3));
    }

    #[test]
    fn a_shadowed_construct_is_recorded_but_decides_nothing() {
        let mut sqli = Request::get("/items");
        sqli.query.push(("id".into(), "1 union select password from users".into()));
        let mut scanner = browser("/index.html", "10.0.0.30".parse().unwrap());
        scanner.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("user-agent"));
        scanner.headers.push(("User-Agent".into(), "sqlmap/1.7".into()));
        let mut denied = Request::get("/index.html");
        denied.src_ip = Some("192.0.2.9".parse().unwrap());
        let cases = vec![
            ("sqli.union-select", sqli),
            ("honeypot.decoy-hit", Request::get("/.git/config")),
            ("intel.scanner-ua", scanner),
            ("intel.deny-listed", denied),
        ];
        let scored = |j: &Judgment| -> Vec<(Option<String>, u32)> {
            j.contributions.iter().filter(|c| !c.shadow).map(|c| (c.construct.clone(), c.points.to_bits())).collect()
        };
        for (id, req) in cases {
            let mut live = Config::default();
            live.intel.deny_ips = vec!["192.0.2.9".into()];
            let mut shadow = live.clone();
            shadow.shield.shadow = vec![id.into()];
            let mut off = live.clone();
            off.shield.disabled = vec![id.into()];
            assert!(has_construct(&Shield::new(live).inspect(&req), id), "{id} must fire on its request");
            let s = Shield::new(shadow).inspect(&req);
            let d = Shield::new(off).inspect(&req);
            assert_eq!((s.score, s.verdict), (d.score, d.verdict), "{id}");
            assert_eq!(
                (s.decided_by.kind, s.decided_by.option_key, &s.decided_by.construct, &s.decided_by.field, &s.decided_by.msg),
                (d.decided_by.kind, d.decided_by.option_key, &d.decided_by.construct, &d.decided_by.field, &d.decided_by.msg),
                "{id}"
            );
            assert_eq!(crate::chain::event_for(&s), crate::chain::event_for(&d), "{id}");
            assert_eq!(scored(&s), scored(&d), "{id}: the scored contributions are the disabled run's");
            let hits: Vec<&Contribution> = s.contributions.iter().filter(|c| c.shadow).collect();
            assert!(!hits.is_empty(), "{id} is kept as a shadow contribution");
            assert!(hits.iter().all(|c| c.construct.as_deref() == Some(id) && c.points == 0.0), "{id}: {hits:?}");
            assert!(d.contributions.iter().all(|c| !c.shadow), "{id}");
        }
    }

    #[test]
    fn a_shadowed_honeypot_hit_never_bans() {
        let mut cfg = Config::default();
        cfg.shield.shadow = vec!["honeypot.decoy-hit".into()];
        let s = Shield::new(cfg);
        let mut chain = ChainTracker::new(&s.config().chain);
        let mut hp = Request::get("/.git/config");
        hp.src_ip = Some("10.0.0.40".parse().unwrap());
        let j = s.inspect_stateful(&hp, &mut chain, 0);
        assert!(!j.banned(), "{}", j.decided_by.msg);
        assert_ne!(j.decided_by.kind, CauseKind::Honeypot);
        assert!(j.contributions.iter().any(|c| c.shadow && c.construct.as_deref() == Some("honeypot.decoy-hit")));
        assert_eq!(chain.ban_count(), 0);
    }

    /// The `kind` cases (`accept` / `reject`) of a fixture file, one `kind<TAB>text` per line.
    fn fixture_lines(src: &'static str, kind: &str) -> Vec<&'static str> {
        src.lines().filter_map(|l| l.strip_prefix(kind)?.strip_prefix('\t')).collect()
    }

    fn body_case() -> &'static str {
        fixture_lines(include_str!("../tests/fixtures/body_cases.txt"), "accept")[0]
    }

    fn pct(s: &str) -> String {
        s.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
    }

    fn body_req(ct: &str, body: Vec<u8>) -> Request {
        let mut req = Request::get("/items");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), ct.into()));
        req.body = body;
        req
    }

    fn fields_of(j: &Judgment, id: &str) -> Vec<String> {
        j.contributions.iter().filter(|c| c.construct.as_deref() == Some(id)).filter_map(|c| c.field.as_ref().map(|f| f.name.clone())).collect()
    }

    #[test]
    fn an_attack_in_a_json_leaf_is_found_under_the_leaf_name() {
        let body = serde_json::json!({"a": {"b": body_case()}}).to_string();
        let j = shield().inspect(&body_req("application/json", body.into_bytes()));
        assert_eq!(j.verdict, Verdict::Block, "{} {}", j.score, j.decided_by.msg);
        assert!(j.contributions.iter().any(|c| c.field.as_ref().is_some_and(|f| f.loc == Location::Body && f.name == "json:/a/b")), "{:?}", j.contributions);
    }

    #[test]
    fn an_id_body_field_gets_api_safety_on_its_last_name_segment() {
        let mp = format!("--vftB0undary\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n{}\r\n--vftB0undary--\r\n", body_case());
        let j = shield().inspect(&body_req("multipart/form-data; boundary=vftB0undary", mp.into_bytes()));
        assert_eq!(fields_of(&j, "api.type-violation"), vec!["form:id".to_string()]);
        // Form splitting is deferred: a form body is one `<body>` field, so
        // its `id=` parameter is not an API-safety field name.
        let j = shield().inspect(&body_req("application/x-www-form-urlencoded", format!("id={}", pct(body_case())).into_bytes()));
        assert!(fields_of(&j, "api.type-violation").is_empty());
        let j = shield().inspect(&body_req("application/json", serde_json::json!({"user": {"id": body_case()}}).to_string().into_bytes()));
        assert_eq!(fields_of(&j, "api.type-violation"), vec!["json:/user/id".to_string()]);
    }

    #[test]
    fn disabling_the_parse_ids_restores_the_single_body_field() {
        let mut cfg = Config::default();
        cfg.shield.disabled = ["parse.body-json", "parse.body-multipart"].map(String::from).to_vec();
        let body = serde_json::json!({"a": {"b": body_case()}}).to_string();
        let j = Shield::new(cfg).inspect(&body_req("application/json", body.into_bytes()));
        assert_eq!(j.verdict, Verdict::Block);
        assert!(j.contributions.iter().filter_map(|c| c.field.as_ref()).filter(|f| f.loc == Location::Body).all(|f| f.name == "<body>"));
    }

    #[test]
    fn invalid_utf8_emits_the_limit_only_for_a_declared_text_class() {
        let j = shield().inspect(&body_req("text/plain", b"caf\xe9 au lait".to_vec()));
        assert_eq!(fields_of(&j, "limit.body-non-utf8"), vec!["<body>".to_string()]);
        // A binary or untyped body is inspected (one lossy `<body>` field)
        // but gains no score for its bytes.
        for ct in ["application/x-protobuf", "application/octet-stream", ""] {
            let req = body_req(ct, vec![0x0a, 0x02, 0xff, 0xfe, 0x10, 0x01]);
            assert!(!has_construct(&shield().inspect(&req), "limit.body-non-utf8"), "{ct}");
            assert!(req.fields().iter().any(|f| f.loc == Location::Body && f.name == "<body>"), "{ct}");
        }
        let mut cfg = Config::default();
        cfg.shield.disabled = vec!["limit.body-non-utf8".into()];
        assert!(!has_construct(&Shield::new(cfg).inspect(&body_req("text/plain", b"caf\xe9".to_vec())), "limit.body-non-utf8"));
    }

    #[test]
    fn an_unparsed_json_body_is_informational_only() {
        let j = shield().inspect(&body_req("application/json", b"{\"a\":".to_vec()));
        let c = j.contributions.iter().find(|c| c.construct.as_deref() == Some("limit.body-unparsed")).expect("limit.body-unparsed recorded");
        assert_eq!(c.points, 0.0);
        assert_eq!(j.verdict, Verdict::Allow);
        assert_eq!(j.score, 0);
    }
}
