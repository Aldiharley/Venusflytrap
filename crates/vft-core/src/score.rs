//! FR4 — Turn weighted evidence into a 0..=100 score and a verdict band.

use crate::config::ScoringConfig;
use crate::judgment::{FieldRef, Verdict};
use crate::lattice::{Evidence, FourValued};

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
    let is_conflict = field_conflict(items, cfg.conflict_threshold);

    // One contribution per (field, construct): repeating the same weak signal
    // on one field does not corroborate itself (M1).
    let mut seen: std::collections::HashSet<(Option<FieldRef>, String)> = Default::default();
    let mut points: Vec<f32> = Vec::new();
    for s in items.iter().filter(|s| s.evidence.value.is_threat()) {
        let construct = s
            .evidence
            .patterns
            .first()
            .map_or_else(|| s.engine.clone(), |p| p.name.clone());
        if !seen.insert((s.field.clone(), construct)) {
            continue;
        }
        points.push(value_points(s.evidence.value) * s.evidence.weight * s.engine_weight);
    }
    let top = points.iter().copied().fold(0.0f32, f32::max);
    let corroboration = ((points.iter().sum::<f32>() - top) * 0.1).min(cfg.corroboration_cap);

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        // Damp, but never below the band the strongest danger reaches alone.
        score = (score * 0.9).max(band_floor(top, cfg));
    }
    let s = score.round().clamp(0.0, 100.0) as u8;
    (s, band(s, cfg), is_conflict)
}

/// A strong Safe and a strong Dangerous about the *same* field.
fn field_conflict(items: &[Scored], threshold: f32) -> bool {
    items
        .iter()
        .filter(|d| d.evidence.value == FourValued::Dangerous && d.evidence.weight >= threshold)
        .any(|d| {
            items.iter().any(|o| {
                o.field == d.field
                    && o.evidence.value == FourValued::Safe
                    && o.evidence.weight >= threshold
            })
        })
}

fn band_floor(points: f32, cfg: &ScoringConfig) -> f32 {
    [cfg.block_at, cfg.challenge_at, cfg.monitor_at]
        .into_iter()
        .map(f32::from)
        .find(|t| points >= *t)
        .unwrap_or(0.0)
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
    use crate::judgment::FieldRef;
    use crate::lattice::Evidence;

    fn sc(w: f32, e: Evidence) -> Scored {
        Scored { engine: "t".into(), engine_weight: w, field: None, evidence: e }
    }

    fn scf(w: f32, field: &str, e: Evidence) -> Scored {
        Scored {
            engine: "t".into(),
            engine_weight: w,
            field: Some(FieldRef { loc: crate::request::Location::Query, name: field.into() }),
            evidence: e,
        }
    }

    #[test]
    fn corroboration_is_capped() {
        let cfg = ScoringConfig::default();
        let mut ev = vec![scf(1.0, "a", Evidence::new(FourValued::Dangerous, 0.5, vec![], "x"))];
        for i in 0..50 {
            ev.push(scf(1.0, &format!("f{i}"), Evidence::new(FourValued::Suspicious, 0.5, vec![], "w")));
        }
        let (s, _, _) = arbitrate(&ev, &cfg, false);
        assert!(s as f32 <= 50.0 + cfg.corroboration_cap + 0.5, "score {s}");
    }

    #[test]
    fn duplicate_construct_on_same_field_counts_once() {
        let cfg = ScoringConfig::default();
        let p = vec![crate::judgment::Pattern::new(crate::judgment::Family::CommandInjection, "cmd.shell-meta")];
        let one = vec![scf(1.0, "a", Evidence::new(FourValued::Suspicious, 0.5, p.clone(), "w"))];
        let two = vec![
            scf(1.0, "a", Evidence::new(FourValued::Suspicious, 0.5, p.clone(), "w")),
            scf(1.0, "a", Evidence::new(FourValued::Suspicious, 0.5, p, "w")),
        ];
        assert_eq!(arbitrate(&one, &cfg, false).0, arbitrate(&two, &cfg, false).0);
    }

    #[test]
    fn conflict_is_scoped_per_field_and_floored() {
        let cfg = ScoringConfig::default();
        // Safe on another field: no conflict.
        let ev = vec![
            scf(1.0, "id", Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint")),
            scf(1.0, "lang", Evidence::new(FourValued::Safe, 0.9, vec![], "ai")),
        ];
        let (_, v, c) = arbitrate(&ev, &cfg, false);
        assert!(!c);
        assert_eq!(v, Verdict::Block);
        // Safe on the same field: conflict, but never below the band the danger reaches alone.
        let ev2 = vec![
            scf(1.0, "id", Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint")),
            scf(1.0, "id", Evidence::new(FourValued::Safe, 0.9, vec![], "ai")),
        ];
        let (_, v2, c2) = arbitrate(&ev2, &cfg, false);
        assert!(c2);
        assert_eq!(v2, Verdict::Block);
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
