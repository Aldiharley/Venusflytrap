//! Output model: the verdict, score, and per-engine explanation.

use serde::{Deserialize, Serialize};

/// Attack family a matched pattern belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Family {
    Sqli,
    Xss,
    CommandInjection,
    PathTraversal,
    Recon,
    Ssrf,
    Honeypot,
    Intel,
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
pub enum Stage {
    Recon = 0,
    Enumeration = 1,
    Exploitation = 2,
    Exfiltration = 3,
}

/// Final action band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct FieldRef {
    pub loc: crate::request::Location,
    pub name: String,
}

impl FieldRef {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contribution {
    pub engine: String,
    pub field: Option<FieldRef>,
    /// Construct name (today's pattern name; stable dotted ids arrive with the
    /// construct registry).
    pub construct: Option<String>,
    pub family: Option<Family>,
    pub value: crate::lattice::FourValued,
    pub weight: f32,
    /// Points added to the score. Filled in SP2; 0.0 until then.
    pub points: f32,
}

/// One detector's contribution, kept for explainability and the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineReport {
    pub engine: String,
    pub value: crate::lattice::FourValued,
    pub weight: f32,
    pub score_contribution: f32,
    pub patterns: Vec<Pattern>,
    pub note: String,
}

/// The engine's decision about a single request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Judgment {
    pub verdict: Verdict,
    pub score: u8,
    pub engines: Vec<EngineReport>,
    pub matched: Vec<Pattern>,
    pub contributions: Vec<Contribution>,
    pub chain_stage: Option<Stage>,
    pub normalized_layers: u8,
    pub banned_source: bool,
    pub reason: String,
}

impl Judgment {
    pub fn allow() -> Self {
        Judgment {
            verdict: Verdict::Allow,
            score: 0,
            engines: Vec::new(),
            matched: Vec::new(),
            contributions: Vec::new(),
            chain_stage: None,
            normalized_layers: 0,
            banned_source: false,
            reason: "no evidence".into(),
        }
    }
}
