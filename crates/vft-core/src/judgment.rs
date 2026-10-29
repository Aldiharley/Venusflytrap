//! Output model: the verdict, score, and per-engine explanation.

use serde::{Deserialize, Serialize};

/// Attack family a matched pattern belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum Family {
    Sqli,
    Xss,
    CommandInjection,
    PathTraversal,
    Recon,
    Ssrf,
    Honeypot,
    Intel,
    /// The request hit an inspection limit or carried bytes that could not be
    /// decoded as-is.
    Limit,
    /// A heuristic anomaly signal that belongs to no attack family.
    Anomaly,
}

/// A concrete structural pattern the engine recognized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pattern {
    pub family: Family,
    pub name: String,
}

impl Pattern {
    pub fn new(family: Family, name: impl Into<String>) -> Self {
        Pattern {
            family,
            name: name.into(),
        }
    }
}

/// Kill-chain stage inferred for a source across requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum Stage {
    Recon = 0,
    Enumeration = 1,
    Exploitation = 2,
    Exfiltration = 3,
}

/// Final action band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum Verdict {
    Allow,
    Monitor,
    Challenge,
    Block,
}

impl Verdict {
    /// Severity order: Allow < Monitor < Challenge < Block.
    pub fn rank(self) -> u8 {
        match self {
            Verdict::Allow => 0,
            Verdict::Monitor => 1,
            Verdict::Challenge => 2,
            Verdict::Block => 3,
        }
    }
}

/// Which field of the request a piece of evidence is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct FieldRef {
    pub loc: crate::request::Location,
    pub name: String,
}

impl FieldRef {
    /// `query:id`, `header:user-agent`, `path:<path>`.
    pub fn label(&self) -> String {
        let loc = format!("{:?}", self.loc).to_ascii_lowercase();
        format!("{loc}:{}", self.name)
    }
    pub fn of(f: &crate::request::Field) -> Self {
        FieldRef { loc: f.loc, name: f.name.clone() }
    }
    pub fn path() -> Self {
        FieldRef { loc: crate::request::Location::Path, name: "<path>".into() }
    }
    pub fn header(name: &str) -> Self {
        FieldRef { loc: crate::request::Location::Header, name: name.to_ascii_lowercase() }
    }
}

/// One piece of non-`None` evidence about one field, with the construct that
/// produced it. Decision-grade input for the kill chain and the "why" panel.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Contribution {
    pub engine: &'static str,
    pub field: Option<FieldRef>,
    /// Stable dotted construct id (e.g. `sqli.union-select`), the key used by
    /// `shield.disabled` and the construct registry.
    pub construct: Option<String>,
    pub family: Option<Family>,
    pub value: crate::lattice::FourValued,
    pub weight: f32,
    /// Points this contribution added to the score.
    pub points: f32,
    /// A `shield.shadow` construct: it fired, but the request was judged as if
    /// it were disabled. Always 0 points; ignored by the score, the verdict,
    /// `decided_by` and the kill chain.
    pub shadow: bool,
}

/// What kind of thing decided a judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum CauseKind {
    NoEvidence,
    Detection,
    Honeypot,
    IntelDeny,
    Ban,
    ChainEscalation,
    Limit,
    Allowlisted,
}

/// The one setting that decided a judgment, with the construct and field behind it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Cause {
    pub kind: CauseKind,
    /// A key of `options::REGISTRY`, e.g. "scoring.block_at".
    pub option_key: &'static str,
    pub construct: Option<String>,
    pub field: Option<FieldRef>,
    /// One human sentence.
    pub msg: String,
}

/// The engine's decision about a single request.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Judgment {
    pub verdict: Verdict,
    pub score: u8,
    pub contributions: Vec<Contribution>,
    pub decided_by: Cause,
    /// The chain observation applied by `Shield::finalize`.
    pub chain: Option<crate::chain::ChainOutcome>,
    pub normalized_layers: u8,
    /// ATT&CK techniques of the deciding construct (sub-project A).
    pub attack: Vec<crate::attack::AttackTag>,
    /// Measured precision on dev of the deciding construct, 1-100; never affects score or verdict.
    pub confidence: Option<u8>,
}

impl Judgment {
    pub fn allow() -> Self {
        Judgment {
            verdict: Verdict::Allow,
            score: 0,
            contributions: Vec::new(),
            decided_by: Cause {
                kind: CauseKind::NoEvidence,
                option_key: "scoring.monitor_at",
                construct: None,
                field: None,
                msg: "no evidence".into(),
            },
            chain: None,
            normalized_layers: 0,
            attack: Vec::new(),
            confidence: None,
        }
    }

    /// Fill `attack` and `confidence` from `decided_by.construct`.
    ///
    /// Tags describe the detection that decided the request; a ban keeps the
    /// tags of the detection that caused it (see `Shield::finalize`).
    pub fn annotate(self) -> Self {
        let construct = self.decided_by.construct.clone();
        self.annotate_as(construct.as_deref())
    }

    /// Fill `attack` and `confidence` from `construct`, clearing them when it is `None`.
    pub(crate) fn annotate_as(mut self, construct: Option<&str>) -> Self {
        match construct {
            Some(c) => {
                self.attack = crate::attack::tags_for(c);
                self.confidence = crate::confidence::confidence(c);
            }
            None => {
                self.attack.clear();
                self.confidence = None;
            }
        }
        self
    }

    /// The source is banned: by this request (`chain.new_ban`) or already (fast-track).
    pub fn banned(&self) -> bool {
        self.decided_by.kind == CauseKind::Ban
    }

    /// The source's kill-chain stage after this request, when a chain was observed.
    pub fn stage(&self) -> Option<Stage> {
        self.chain.and_then(|o| o.stage_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_read_cause_and_chain() {
        let mut j = Judgment::allow();
        assert!(!j.banned());
        assert_eq!(j.stage(), None);
        j.decided_by.kind = CauseKind::Ban;
        j.chain = Some(crate::chain::ChainOutcome { stage_after: Some(Stage::Recon), ..Default::default() });
        assert!(j.banned());
        assert_eq!(j.stage(), Some(Stage::Recon));
    }

    #[test]
    fn annotate_follows_the_deciding_construct() {
        let mut j = Judgment::allow();
        j.decided_by.construct = Some("honeypot.decoy-hit".into());
        let j = j.annotate();
        assert_eq!(j.attack.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), vec!["T1595.003"]);
        assert_eq!(j.confidence, crate::confidence::confidence("honeypot.decoy-hit"));
        let mut k = j.clone();
        k.decided_by.construct = None;
        let k = k.annotate();
        assert!(k.attack.is_empty() && k.confidence.is_none());
    }
}
