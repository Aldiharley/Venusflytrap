//! FR3 — Detectors. Each converts some view of the request into weighted
//! four-valued [`Evidence`]. The orchestrator ([`crate::shield`]) runs them and
//! hands the evidence to the lattice/scorer.

use crate::config::Config;
use crate::graph;
use crate::graph::sinks::{self, ConstructInfo, Disabled};
use crate::lattice::{Evidence, FourValued};
use crate::normalize::Normalized;
use crate::request::{Field, Location, Request};

/// Context shared with detectors for one field.
pub struct FieldCtx<'a> {
    pub field: &'a Field,
    pub norm: &'a Normalized,
    pub analysis: &'a graph::Analysis,
    pub disabled: &'a Disabled,
}

/// A detector over a single normalized field.
pub trait FieldDetector {
    fn name(&self) -> &'static str;
    fn assess(&self, ctx: &FieldCtx) -> Evidence;
}

/// Graph/taint detector: the primary engine.
pub struct GraphTaintDetector;
impl FieldDetector for GraphTaintDetector {
    fn name(&self) -> &'static str {
        "graph-taint"
    }
    fn assess(&self, ctx: &FieldCtx) -> Evidence {
        let a = ctx.analysis;
        if !a.reachable.is_empty() {
            Evidence::new(
                FourValued::Dangerous,
                0.95,
                a.reachable.clone(),
                "tainted input reaches a dangerous construct",
            )
        } else if !a.latent.is_empty() {
            Evidence::new(
                FourValued::Suspicious,
                0.5,
                a.latent.clone(),
                "dangerous tokens present but no complete construct",
            )
        } else {
            Evidence::none("no sink reachable")
        }
    }
}

/// A few high-confidence structural signatures as a second opinion.
pub struct SignatureDetector;
impl FieldDetector for SignatureDetector {
    fn name(&self) -> &'static str {
        "signature"
    }
    fn assess(&self, ctx: &FieldCtx) -> Evidence {
        let t = &ctx.norm.text;
        let mut hits = Vec::new();
        for &(needle, c) in SIGNATURES {
            if t.contains(needle) && !ctx.disabled.is(c) {
                hits.push(c.pattern());
            }
        }
        if hits.is_empty() {
            Evidence::none("no signature")
        } else {
            Evidence::new(FourValued::Dangerous, 0.8, hits, "signature match")
        }
    }
}

static SIGNATURES: &[(&str, &ConstructInfo)] = &[
    ("union all select", &sinks::SIG_UNION_ALL_SELECT),
    ("' or '1'='1", &sinks::SIG_CLASSIC_OR),
    ("information_schema", &sinks::SIG_SCHEMA_ENUM),
    ("<script>alert", &sinks::SIG_ALERT_SCRIPT),
    ("onerror=", &sinks::SIG_ONERROR),
    ("/etc/passwd", &sinks::SIG_ETC_PASSWD),
    ("$(cat ", &sinks::SIG_CAT_SUBST),
];

/// A name segment without a trailing `#<digits>` duplicate-key suffix
/// (`id#2` is `id`); any other segment is returned unchanged.
fn strip_dup_suffix(seg: &str) -> &str {
    match seg.rsplit_once('#') {
        Some((head, n)) if !head.is_empty() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => seg,
    }
}

/// API-safety: numeric/identifier fields carrying injection structure, or
/// absurd field sizes.
pub struct ApiSafetyDetector;
impl FieldDetector for ApiSafetyDetector {
    fn name(&self) -> &'static str {
        "api-safety"
    }
    fn assess(&self, ctx: &FieldCtx) -> Evidence {
        let lname = ctx.field.name.to_lowercase();
        // Body leaves carry their parameter in the last name segment
        // (`json:/user/id`), without the `#<n>` suffix of a repeated key
        // (`json:/id#2` is `id`); other locations use the whole name.
        let name = if ctx.field.loc == Location::Body {
            let last = lname.rsplit([':', '/']).next().unwrap_or(&lname);
            strip_dup_suffix(last)
        } else {
            lname.as_str()
        };
        let looks_numeric_field = name == "id" || name.ends_with("_id") || name == "page" || name == "count";
        if looks_numeric_field
            && !ctx.analysis.reachable.is_empty()
            && !ctx.disabled.is(&sinks::API_TYPE_VIOLATION)
        {
            return Evidence::new(
                FourValued::Dangerous,
                0.7,
                vec![sinks::API_TYPE_VIOLATION.pattern()],
                "numeric field carries injection structure",
            );
        }
        // Oversized header value is a mild signal.
        if ctx.field.loc == Location::Header
            && ctx.field.raw.len() > 4096
            && !ctx.disabled.is(&sinks::API_OVERSIZED_HEADER)
        {
            return Evidence::new(
                FourValued::Suspicious,
                0.3,
                vec![sinks::API_OVERSIZED_HEADER.pattern()],
                "oversized header value",
            );
        }
        Evidence::none("api ok")
    }
}

/// Pluggable AI oracle. The default is a deterministic heuristic so results are
/// reproducible and offline; a real model can implement this trait and be
/// injected without touching the lattice (see TECH_SPEC §5).
pub trait AiOracle: Send + Sync {
    /// Return a feature-based threat score in [0,1].
    fn score(&self, norm: &Normalized, analysis: &graph::Analysis) -> f32;
}

#[derive(Default)]
pub struct HeuristicOracle;
impl AiOracle for HeuristicOracle {
    fn score(&self, norm: &Normalized, analysis: &graph::Analysis) -> f32 {
        let mut s = 0.0f32;
        if !analysis.reachable.is_empty() {
            s += 0.5;
        }
        s += 0.1 * analysis.latent.len() as f32;
        if norm.flags.deep_nesting {
            s += 0.2;
        }
        if norm.flags.mixed_script {
            s += 0.2;
        }
        if norm.flags.conditional_comment {
            s += 0.15;
        }
        // entropy-ish: lots of punctuation density
        let punct = norm.text.chars().filter(|c| c.is_ascii_punctuation()).count();
        let len = norm.text.chars().count().max(1);
        if (punct as f32 / len as f32) > 0.3 {
            s += 0.15;
        }
        s.clamp(0.0, 1.0)
    }
}

pub struct AiDetector<'a> {
    pub oracle: &'a dyn AiOracle,
}
impl FieldDetector for AiDetector<'_> {
    fn name(&self) -> &'static str {
        "ai"
    }
    fn assess(&self, ctx: &FieldCtx) -> Evidence {
        let s = self.oracle.score(ctx.norm, ctx.analysis);
        // Absence of evidence is Belnap's None, not Safe: a clean field says
        // nothing about another field's attack (H4).
        let (value, weight) = if s >= 0.6 {
            (FourValued::Dangerous, s)
        } else if s >= 0.35 {
            (FourValued::Suspicious, s)
        } else {
            (FourValued::None, 0.0)
        };
        if value == FourValued::None || ctx.disabled.is(&sinks::AI_ANOMALY_SCORE) {
            return Evidence::none(format!("ai score {s:.2}"));
        }
        Evidence::new(value, weight, vec![sinks::AI_ANOMALY_SCORE.pattern()], format!("ai score {s:.2}"))
    }
}

/// Request-level intent detector (path recon / empty-payload probing). Not a
/// field detector — it looks at the whole request.
pub fn intent_evidence(req: &Request, cfg: &Config, disabled: &Disabled) -> Evidence {
    if disabled.is(&sinks::RECON_SENSITIVE_PATH) {
        return Evidence::none("recon disabled");
    }
    let path = req.canonical_path().to_lowercase();
    // Prefix match only — NOT substring. A substring match flags benign nested
    // paths like `/api/config.json` just because they contain `/config.json`
    // (M5). Recon targets are hit at a path prefix (`/.env`, `/actuator/...`).
    let sensitive = cfg
        .honeypot
        .sensitive_paths
        .iter()
        .any(|p| path.starts_with(&p.to_lowercase()));
    if sensitive {
        // Empty-payload probe of a sensitive path is the article's high-intent
        // recon pattern: no params, just hitting dangerous endpoints. These paths
        // (`.env`, `.git/`, actuator, …) have no legitimate client use, so an
        // empty probe is weighted to reach at least Challenge on its own.
        let (value, weight) = if req.body_is_empty() && req.query.is_empty() {
            (FourValued::Dangerous, 1.0)
        } else {
            (FourValued::Suspicious, 0.6)
        };
        return Evidence::new(
            value,
            weight,
            vec![sinks::RECON_SENSITIVE_PATH.pattern()],
            format!("recon probe of sensitive path {path}"),
        );
    }
    Evidence::none("ordinary path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::{normalize, Options};

    fn ctx_for<'a>(
        field: &'a Field,
        norm: &'a Normalized,
        analysis: &'a graph::Analysis,
        disabled: &'a Disabled,
    ) -> FieldCtx<'a> {
        FieldCtx {
            field,
            norm,
            analysis,
            disabled,
        }
    }

    #[test]
    fn graph_detector_flags_injection() {
        let f = Field {
            loc: Location::Query,
            name: "q".into(),
            raw: "1 union select password from users".into(),
        };
        let n = normalize(&f.raw, &Options::default());
        let a = graph::analyze(&n.text);
        let d = Disabled::default();
        let e = GraphTaintDetector.assess(&ctx_for(&f, &n, &a, &d));
        assert_eq!(e.value, FourValued::Dangerous);
    }

    #[test]
    fn api_detector_flags_numeric_field() {
        let f = Field {
            loc: Location::Query,
            name: "id".into(),
            raw: "5 or 1=1".into(),
        };
        let n = normalize(&f.raw, &Options::default());
        let a = graph::analyze(&n.text);
        let d = Disabled::default();
        let e = ApiSafetyDetector.assess(&ctx_for(&f, &n, &a, &d));
        assert_eq!(e.value, FourValued::Dangerous);
    }

    #[test]
    fn intent_flags_env_probe() {
        let cfg = Config::default();
        let req = Request::get("/.env");
        let e = intent_evidence(&req, &cfg, &Disabled::default());
        assert_eq!(e.value, FourValued::Dangerous);
    }

    #[test]
    fn intent_flags_encoded_env_probe() {
        let cfg = Config::default();
        for p in ["/.%65nv", "/%2eenv", "//.env"] {
            let e = intent_evidence(&Request::get(p), &cfg, &Disabled::default());
            assert_eq!(e.value, FourValued::Dangerous, "missed {p}");
        }
    }

    #[test]
    fn every_threat_evidence_names_a_construct() {
        let shield = crate::Shield::new(crate::Config::default());
        let mut r = crate::Request::get("/p");
        r.query.push(("q".into(), "%27%22%3E%3C!--{{}}$$((;;||&&".into()));
        r.headers.push(("X-Big".into(), "a".repeat(5000)));
        let j = shield.inspect(&r);
        for c in &j.contributions {
            assert!(c.construct.is_some(), "{} on {:?} has no construct", c.engine, c.field);
        }
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("api.oversized-header")));
    }

    #[test]
    fn api_safety_uses_the_last_segment_of_a_body_field_name_only() {
        let a = graph::Analysis { reachable: vec![sinks::sql::UNION_SELECT.pattern()], latent: vec![], graph_truncated: false };
        let d = Disabled::default();
        let n = normalize("x", &Options::default());
        for (loc, name, hit) in [
            (Location::Body, "json:/user/id", true),
            (Location::Body, "json:/user_id", true),
            (Location::Body, "json:/identity", false),
            // The second and later values of a repeated key.
            (Location::Body, "json:/id#2", true),
            (Location::Body, "json:/user/account_id#13", true),
            (Location::Body, "json:/id#x", false),
            (Location::Body, "json:#rest", false),
            (Location::Query, "x:id", false),
            (Location::Query, "id", true),
        ] {
            let f = Field { loc, name: name.into(), raw: "x".into() };
            let e = ApiSafetyDetector.assess(&ctx_for(&f, &n, &a, &d));
            assert_eq!(e.value == FourValued::Dangerous, hit, "{loc:?} {name}");
        }
    }
}
