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

/// The outcome of combining one request's evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct Arbitration {
    pub score: u8,
    pub verdict: Verdict,
    pub conflict: bool,
    /// Points each input item added, aligned with `items`. Their sum is the
    /// score before rounding. All zero for a hard pin; the caller credits it.
    pub points: Vec<f32>,
}

/// Combine evidence into a score and a verdict. Hard-pin inputs (deny-list,
/// honeypot, fail-closed limit) are passed via `hard_block`.
pub fn arbitrate(items: &[Scored], cfg: &ScoringConfig, hard_block: bool) -> Arbitration {
    if hard_block {
        return Arbitration { score: 100, verdict: Verdict::Block, conflict: false, points: vec![0.0; items.len()] };
    }

    // Weighted max-style aggregation: the strongest well-weighted threat drives
    // the score, with smaller corroborating signals nudging it up. This avoids
    // diluting a single strong detection by averaging in silent detectors.
    let is_conflict = field_conflict(items, cfg.conflict_threshold);

    // One contribution per (field, construct): repeating the same weak signal
    // on one field does not corroborate itself (M1).
    let mut seen: std::collections::HashSet<(Option<FieldRef>, String)> = Default::default();
    // (item index, raw points) for each counted threat item.
    let mut counted: Vec<(usize, f32)> = Vec::new();
    for (i, s) in items.iter().enumerate().filter(|(_, s)| s.evidence.value.is_threat()) {
        let construct = s
            .evidence
            .patterns
            .first()
            .map_or_else(|| s.engine.clone(), |p| p.name.clone());
        if !seen.insert((s.field.clone(), construct)) {
            continue;
        }
        counted.push((i, value_points(s.evidence.value) * s.evidence.weight * s.engine_weight));
    }
    let top = counted.iter().map(|c| c.1).fold(0.0f32, f32::max);
    let rest = counted.iter().map(|c| c.1).sum::<f32>() - top;
    let corroboration = (rest * 0.1).min(cfg.corroboration_cap);

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        // Damp, but never below the band the strongest danger reaches alone.
        score = (score * 0.9).max(band_floor(top, cfg));
    }

    // Points: the first maximal item keeps its raw points, the rest share the
    // corroboration in proportion; clamping and damping then scale every item
    // alike, so the points sum to the unrounded score.
    let mut points = vec![0.0f32; items.len()];
    let mut top_n: Option<usize> = None;
    let mut best = 0.0f32;
    for (n, c) in counted.iter().enumerate() {
        if c.1 > best {
            best = c.1;
            top_n = Some(n);
        }
    }
    let share = if rest > 0.0 { corroboration / rest } else { 0.0 };
    for (n, &(i, raw)) in counted.iter().enumerate() {
        points[i] = if Some(n) == top_n { raw } else { raw * share };
    }
    let unscaled = top + corroboration;
    if unscaled > 0.0 {
        let k = score / unscaled;
        for p in &mut points {
            *p *= k;
        }
    }

    let s = score.round().clamp(0.0, 100.0) as u8;
    Arbitration { score: s, verdict: band(s, cfg), conflict: is_conflict, points }
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
        let s = arbitrate(&ev, &cfg, false).score;
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
        assert_eq!(arbitrate(&one, &cfg, false).score, arbitrate(&two, &cfg, false).score);
    }

    #[test]
    fn conflict_is_scoped_per_field_and_floored() {
        let cfg = ScoringConfig::default();
        // Safe on another field: no conflict.
        let ev = vec![
            scf(1.0, "id", Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint")),
            scf(1.0, "lang", Evidence::new(FourValued::Safe, 0.9, vec![], "ai")),
        ];
        let a = arbitrate(&ev, &cfg, false);
        let (v, c) = (a.verdict, a.conflict);
        assert!(!c);
        assert_eq!(v, Verdict::Block);
        // Safe on the same field: conflict, but never below the band the danger reaches alone.
        let ev2 = vec![
            scf(1.0, "id", Evidence::new(FourValued::Dangerous, 0.95, vec![], "taint")),
            scf(1.0, "id", Evidence::new(FourValued::Safe, 0.9, vec![], "ai")),
        ];
        let a2 = arbitrate(&ev2, &cfg, false);
        let (v2, c2) = (a2.verdict, a2.conflict);
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
        let a = arbitrate(&ev, &cfg, false);
        let (s, v) = (a.score, a.verdict);
        assert!(s >= cfg.block_at, "score {s}");
        assert_eq!(v, Verdict::Block);
    }

    #[test]
    fn clean_allows() {
        let cfg = ScoringConfig::default();
        let ev = vec![sc(1.0, Evidence::none("ok"))];
        let a = arbitrate(&ev, &cfg, false);
        let (s, v) = (a.score, a.verdict);
        assert_eq!(v, Verdict::Allow);
        assert_eq!(s, 0);
    }

    #[test]
    fn points_sum_to_the_unrounded_score() {
        let cfg = ScoringConfig::default();
        let mut ev = vec![scf(1.0, "a", Evidence::new(FourValued::Dangerous, 0.95, vec![], "x"))];
        for i in 0..40 {
            ev.push(scf(1.0, &format!("f{i}"), Evidence::new(FourValued::Suspicious, 0.5, vec![], "w")));
        }
        let a = arbitrate(&ev, &cfg, false);
        let sum: f32 = a.points.iter().sum();
        assert!((sum - f32::from(a.score)).abs() <= 0.5, "Σ {sum} vs {}", a.score);
        assert!(a.points[0] > a.points[1], "the top item keeps the most points");
    }

    #[test]
    fn hard_block_pins() {
        let cfg = ScoringConfig::default();
        let a = arbitrate(&[], &cfg, true);
        let (s, v) = (a.score, a.verdict);
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
        let a = arbitrate(&ev, &cfg, false);
        let (s, v) = (a.score, a.verdict);
        assert!(matches!(v, Verdict::Monitor | Verdict::Allow), "score {s} v {v:?}");
    }
}
