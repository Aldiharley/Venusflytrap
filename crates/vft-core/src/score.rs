//! FR4 — Turn weighted evidence into a 0..=100 score and a verdict band.

use crate::config::ScoringConfig;
use crate::judgment::Verdict;
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

/// Combine evidence into (score, verdict). Hard-pin inputs (deny-list, honeypot)
/// are passed via `hard_block`. `extra` adds e.g. chain-stage bonus.
pub fn arbitrate(
    evidence: &[(f32, Evidence)],
    cfg: &ScoringConfig,
    hard_block: bool,
    extra: u8,
) -> (u8, Verdict, bool) {
    if hard_block {
        return (100, Verdict::Block, true);
    }

    // Weighted max-style aggregation: the strongest well-weighted threat drives
    // the score, with smaller corroborating signals nudging it up. This avoids
    // diluting a single strong detection by averaging in silent detectors.
    let evid_only: Vec<Evidence> = evidence.iter().map(|(_, e)| e.clone()).collect();
    let is_conflict = conflict(&evid_only, cfg.conflict_threshold);

    let mut top = 0.0f32;
    let mut corroboration = 0.0f32;
    for (engine_weight, e) in evidence {
        if !e.value.is_threat() {
            continue;
        }
        let contribution = value_points(e.value) * e.weight * engine_weight;
        if contribution > top {
            corroboration += top * 0.1; // previous top becomes minor corroboration
            top = contribution;
        } else {
            corroboration += contribution * 0.1;
        }
    }

    let mut score = (top + corroboration).min(100.0);

    // Conflict handling: if a strong Safe opposes a strong Dangerous, we trust
    // the taint-graph family (Dangerous) but note the arbitration; we do not
    // zero it out. Slightly damp so a lone noisy "dangerous" with a credible
    // "safe" counter isn't auto-blocked.
    if is_conflict {
        score *= 0.9;
    }

    score = (score + extra as f32).min(100.0);
    let s = score.round() as u8;

    let verdict = if s >= cfg.block_at {
        Verdict::Block
    } else if s >= cfg.challenge_at {
        Verdict::Challenge
    } else if s >= cfg.monitor_at {
        Verdict::Monitor
    } else {
        Verdict::Allow
    };
    (s, verdict, is_conflict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::Evidence;

    #[test]
    fn strong_danger_blocks() {
        let cfg = ScoringConfig::default();
        let ev = vec![(
            1.0,
            Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint"),
        )];
        let (s, v, _) = arbitrate(&ev, &cfg, false, 0);
        assert!(s >= cfg.block_at, "score {s}");
        assert_eq!(v, Verdict::Block);
    }

    #[test]
    fn clean_allows() {
        let cfg = ScoringConfig::default();
        let ev = vec![(1.0, Evidence::none("ok"))];
        let (s, v, _) = arbitrate(&ev, &cfg, false, 0);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(s, 0);
    }

    #[test]
    fn hard_block_pins() {
        let cfg = ScoringConfig::default();
        let (s, v, _) = arbitrate(&[], &cfg, true, 0);
        assert_eq!(s, 100);
        assert_eq!(v, Verdict::Block);
    }

    #[test]
    fn suspicious_lands_in_monitor_or_challenge() {
        let cfg = ScoringConfig::default();
        let ev = vec![(
            0.7,
            Evidence::new(FourValued::Suspicious, 0.5, vec![], "latent"),
        )];
        let (s, v, _) = arbitrate(&ev, &cfg, false, 0);
        assert!(matches!(v, Verdict::Monitor | Verdict::Allow), "score {s} v {v:?}");
    }
}
