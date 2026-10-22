//! Belnap's four-valued logic used as an evidence lattice.
//!
//! Values: `None` (⊥, no information), `Safe`, `Suspicious`, `Dangerous`.
//! We use the **knowledge/information order** to accumulate evidence
//! monotonically from independent detectors, and surface explicit conflict
//! (strong `Safe` vs strong `Dangerous`) to the arbiter rather than averaging
//! it away. See docs/TECH_SPEC.md §6 and RESEARCH.md C5.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FourValued {
    /// ⊥ — nothing is known from this source.
    None,
    /// Evidence that the input is benign.
    Safe,
    /// Evidence that is concerning but not conclusive.
    Suspicious,
    /// Evidence of an attack.
    Dangerous,
}

impl FourValued {
    /// Rank in the knowledge order (how much this value asserts). `None` is the
    /// bottom; `Dangerous` the strongest assertion of threat.
    fn knowledge_rank(self) -> u8 {
        match self {
            FourValued::None => 0,
            FourValued::Safe => 1,
            FourValued::Suspicious => 2,
            FourValued::Dangerous => 3,
        }
    }

    /// Join in the knowledge order (take the more-informative/assertive value),
    /// with the one twist that `Safe ⊔ Dangerous = Dangerous` is NOT applied
    /// silently here — callers use [`Evidence`] weights and [`conflict`] to
    /// arbitrate. This join is the "accumulate the strongest signal" step.
    pub fn join(self, other: FourValued) -> FourValued {
        if self.knowledge_rank() >= other.knowledge_rank() {
            self
        } else {
            other
        }
    }

    pub fn is_threat(self) -> bool {
        matches!(self, FourValued::Suspicious | FourValued::Dangerous)
    }
}

/// A weighted evidence item produced by a detector.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub value: FourValued,
    /// Confidence/importance weight in [0,1]; the arbiter scales contributions.
    pub weight: f32,
    pub patterns: Vec<crate::judgment::Pattern>,
    pub note: String,
}

impl Evidence {
    pub fn none(note: impl Into<String>) -> Self {
        Evidence {
            value: FourValued::None,
            weight: 0.0,
            patterns: Vec::new(),
            note: note.into(),
        }
    }

    pub fn new(
        value: FourValued,
        weight: f32,
        patterns: Vec<crate::judgment::Pattern>,
        note: impl Into<String>,
    ) -> Self {
        Evidence {
            value,
            weight: weight.clamp(0.0, 1.0),
            patterns,
            note: note.into(),
        }
    }
}

/// Detect a genuine conflict: at least one high-weight `Safe` and one
/// high-weight `Dangerous`. This is the article's "AI says safe but deep
/// semantics say dangerous" case; the arbiter resolves it by configured weights.
pub fn conflict(items: &[Evidence], threshold: f32) -> bool {
    let strong_safe = items
        .iter()
        .any(|e| e.value == FourValued::Safe && e.weight >= threshold);
    let strong_danger = items
        .iter()
        .any(|e| e.value == FourValued::Dangerous && e.weight >= threshold);
    strong_safe && strong_danger
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_takes_stronger() {
        assert_eq!(FourValued::None.join(FourValued::Safe), FourValued::Safe);
        assert_eq!(
            FourValued::Safe.join(FourValued::Dangerous),
            FourValued::Dangerous
        );
        assert_eq!(
            FourValued::Suspicious.join(FourValued::Safe),
            FourValued::Suspicious
        );
    }

    #[test]
    fn conflict_requires_both_strong() {
        let items = vec![
            Evidence::new(FourValued::Safe, 0.9, vec![], "ai"),
            Evidence::new(FourValued::Dangerous, 0.9, vec![], "taint"),
        ];
        assert!(conflict(&items, 0.6));
        let weak = vec![
            Evidence::new(FourValued::Safe, 0.2, vec![], "ai"),
            Evidence::new(FourValued::Dangerous, 0.9, vec![], "taint"),
        ];
        assert!(!conflict(&weak, 0.6));
    }
}
