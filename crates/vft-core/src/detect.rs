//! FR3 — Detectors. Each converts some view of the request into weighted
//! four-valued [`Evidence`]. The orchestrator ([`crate::shield`]) runs them and
//! hands the evidence to the lattice/scorer.

use crate::config::Config;
use crate::graph;
use crate::judgment::{Family, Pattern};
use crate::lattice::{Evidence, FourValued};
use crate::normalize::Normalized;
use crate::request::{Field, Location, Request};

/// Context shared with detectors for one field.
pub struct FieldCtx<'a> {
    pub field: &'a Field,
    pub norm: &'a Normalized,
    pub analysis: &'a graph::Analysis,
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
        for (needle, fam, name) in SIGNATURES {
            if t.contains(needle) {
                hits.push(Pattern::new(*fam, *name));
            }
        }
        if hits.is_empty() {
            Evidence::none("no signature")
        } else {
            Evidence::new(FourValued::Dangerous, 0.8, hits, "signature match")
        }
    }
}

const SIGNATURES: &[(&str, Family, &str)] = &[
    ("union all select", Family::Sqli, "union-all-select"),
    ("' or '1'='1", Family::Sqli, "classic-or"),
    ("information_schema", Family::Sqli, "schema-enum"),
    ("<script>alert", Family::Xss, "alert-script"),
    ("onerror=", Family::Xss, "onerror"),
    ("/etc/passwd", Family::PathTraversal, "etc-passwd"),
    ("$(cat ", Family::CommandInjection, "cat-subst"),
];

/// API-safety: numeric/identifier fields carrying injection structure, or
/// absurd field sizes.
pub struct ApiSafetyDetector;
impl FieldDetector for ApiSafetyDetector {
    fn name(&self) -> &'static str {
        "api-safety"
    }
    fn assess(&self, ctx: &FieldCtx) -> Evidence {
        let name = ctx.field.name.to_lowercase();
        let looks_numeric_field =
            name == "id" || name.ends_with("_id") || name == "page" || name == "count";
        if looks_numeric_field && !ctx.analysis.reachable.is_empty() {
            return Evidence::new(
                FourValued::Dangerous,
                0.7,
                vec![Pattern::new(Family::Sqli, "type-violation")],
                "numeric field carries injection structure",
            );
        }
        // Oversized header value is a mild signal.
        if ctx.field.loc == Location::Header && ctx.field.raw.len() > 4096 {
            return Evidence::new(
                FourValued::Suspicious,
                0.3,
                vec![],
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
        // When the oracle is confident the field is clean (score 0), emit Safe at
        // a weight above the conflict threshold so the lattice's conflict
        // arbitration can actually engage when another engine shouts Dangerous
        // (M4). This only damps a single-engine detection slightly; it never
        // suppresses a block outright, so it cannot weaken a true positive into
        // an allow.
        let (value, weight) = if s >= 0.6 {
            (FourValued::Dangerous, s)
        } else if s >= 0.35 {
            (FourValued::Suspicious, s)
        } else if s > 0.0 {
            (FourValued::None, 0.3)
        } else {
            (FourValued::Safe, 0.7)
        };
        Evidence::new(value, weight, vec![], format!("ai score {s:.2}"))
    }
}

/// Request-level intent detector (path recon / empty-payload probing). Not a
/// field detector — it looks at the whole request.
pub fn intent_evidence(req: &Request, cfg: &Config) -> Evidence {
    let path = req.path.to_lowercase();
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
            vec![Pattern::new(Family::Recon, "sensitive-path-probe")],
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
    ) -> FieldCtx<'a> {
        FieldCtx {
            field,
            norm,
            analysis,
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
        let e = GraphTaintDetector.assess(&ctx_for(&f, &n, &a));
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
        let e = ApiSafetyDetector.assess(&ctx_for(&f, &n, &a));
        assert_eq!(e.value, FourValued::Dangerous);
    }

    #[test]
    fn intent_flags_env_probe() {
        let cfg = Config::default();
        let req = Request::get("/.env");
        let e = intent_evidence(&req, &cfg);
        assert_eq!(e.value, FourValued::Dangerous);
    }
}
