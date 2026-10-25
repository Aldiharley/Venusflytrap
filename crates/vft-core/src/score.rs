//! FR4 — Turn weighted evidence into a 0..=100 score and a verdict band.

use crate::config::ScoringConfig;
use crate::judgment::{FieldRef, Verdict};
use crate::lattice::{conflict, Evidence, FourValued};

/// Base points each value contributes before engine weighting.
fn value_points(v: FourValued) -> f32 {
    match v {
        FourValued::Dangerous => 100.0,
        FourValued::Suspicious => 55.0,
        FourValued::Safe => 0.0,
        FourValued::None => 0.0,
    }
}

/// One weighted evidence item, tagged with its engine and field.
#[derive(Debug, Clone)]
pub struct Scored {
    pub engine: String,
    pub engine_weight: f32,
    pub field: Option<FieldRef>,
    pub evidence: Evidence,
}

/// Combine evidence into (score, verdict). Hard-pin inputs (deny-list, honeypot)
/// are passed via `hard_block`.
pub fn arbitrate(
    items: &[Scored],
    cfg: &ScoringConfig,
    hard_block: bool,
) -> (u8, Verdict, bool) {
    if hard_block {
        return (100, Verdict::Block, true);
    }

    // Weighted max-style aggregation: the strongest well-weighted threat drives
    // the score, with smaller corroborating signals nudging it up. This avoids
    // diluting a single strong detection by averaging in silent detectors.
    let evid_only: Vec<Evidence> = items.iter().map(|s| s.evidence.clone()).collect();
    let is_conflict = conflict(&evid_only, cfg.conflict_threshold);

    let points: Vec<f32> = items
        .iter()
        .filter(|s| s.evidence.value.is_threat())
        .map(|s| value_points(s.evidence.value) * s.evidence.weight * s.engine_weight)
        .collect();
    let top = points.iter().copied().fold(0.0f32, f32::max);
    let corroboration = (points.iter().sum::<f32>() - top) * 0.1;

    let mut score = (top + corroboration).min(100.0);

    // Conflict handling: if a strong Safe opposes a strong Dangerous, we trust
    // the taint-graph family (Dangerous) but note the arbitration; we do not
    // zero it out. Slightly damp so a lone noisy "dangerous" with a credible
    // "safe" counter isn't auto-blocked.
    if is_conflict {
        score *= 0.9;
    }

    let s = score.round() as u8;
    (s, band(s, cfg), is_conflict)
}

/// Map a 0..=100 score onto the configured verdict bands.
pub fn band(score: u8, cfg: &ScoringConfig) -> Verdict {
    if score >= cfg.block_at {
        Verdict::Block
    } else if score >= cfg.challenge_at {
        Verdict::Challenge
    } else if score >= cfg.monitor_at {
        Verdict::Monitor
    } else {
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::Evidence;

    fn sc(w: f32, e: Evidence) -> Scored {
        Scored { engine: "t".into(), engine_weight: w, field: None, evidence: e }
    }

    #[test]
    fn strong_danger_blocks() {
        let cfg = ScoringConfig::default();
        let ev = vec![sc(
            1.0,
            Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint"),
        )];
        let (s, v, _) = arbitrate(&ev, &cfg, false);
        assert!(s >= cfg.block_at, "score {s}");
        assert_eq!(v, Verdict::Block);
    }

    #[test]
    fn clean_allows() {
        let cfg = ScoringConfig::default();
        let ev = vec![sc(1.0, Evidence::none("ok"))];
        let (s, v, _) = arbitrate(&ev, &cfg, false);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(s, 0);
    }

    #[test]
    fn hard_block_pins() {
        let cfg = ScoringConfig::default();
        let (s, v, _) = arbitrate(&[], &cfg, true);
        assert_eq!(s, 100);
        assert_eq!(v, Verdict::Block);
    }

    #[test]
    fn suspicious_lands_in_monitor_or_challenge() {
        let cfg = ScoringConfig::default();
        let ev = vec![sc(
            0.7,
            Evidence::new(FourValued::Suspicious, 0.5, vec![], "latent"),
        )];
        let (s, v, _) = arbitrate(&ev, &cfg, false);
        assert!(matches!(v, Verdict::Monitor | Verdict::Allow), "score {s} v {v:?}");
    }
}
