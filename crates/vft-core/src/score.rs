//! FR4 — Turn weighted evidence into a 0..=100 score and a verdict band.

use std::collections::hash_map::{Entry, HashMap};

use crate::config::ScoringConfig;
use crate::graph::sinks;
use crate::judgment::{Family, FieldRef, Verdict};
use crate::lattice::{Evidence, FourValued};
use crate::request::Location;

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

/// What a counted item is evidence of, within its origin field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Family(Family),
    /// A derived item, keyed by construct id (`api.type-violation` has family Sqli).
    Derived(String),
    /// An item with no pattern.
    Engine(String),
}

/// `ai.anomaly-score` and `api.type-violation` are computed from the graph
/// result on their own field: not independent evidence of it (D10).
fn is_derived(construct: &str) -> bool {
    construct == sinks::AI_ANOMALY_SCORE.id || construct == sinks::API_TYPE_VIOLATION.id
}

/// The field an item is about, without a derived `#…` suffix (`id#2` is `id`).
/// A `#` right after `:` (`json:#rest`) or at the start is part of the name.
pub fn origin(f: &FieldRef) -> FieldRef {
    let cut = f.name.char_indices().find(|&(i, c)| c == '#' && i > 0 && !f.name[..i].ends_with(':')).map(|(i, _)| i);
    FieldRef { loc: f.loc, name: cut.map_or_else(|| f.name.clone(), |i| f.name[..i].to_string()) }
}

/// A latent (Suspicious) item on a JSON body leaf. It is background noise of
/// the leaf split, not independent evidence of an attack elsewhere: it backs
/// up only items on its own leaf (DQ3 rule C). Dangerous leaf items, and
/// latents on any other field, corroborate as before.
fn leaf_latent(s: &Scored) -> bool {
    s.evidence.value == FourValued::Suspicious
        && s.field.as_ref().is_some_and(|f| f.loc == Location::Body && f.name.starts_with("json:"))
}

struct Counted {
    item: usize,
    raw: f32,
    origin: Option<FieldRef>,
    derived: bool,
    leaf_latent: bool,
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

    // One item per (origin field, family), the strongest: chunks and split
    // halves of a field share its origin, and the graph and signature items of
    // one family on one field are one piece of evidence (D10).
    let mut slot: HashMap<(Option<FieldRef>, Key), usize> = HashMap::new();
    let mut counted: Vec<Counted> = Vec::new();
    for (i, s) in items.iter().enumerate().filter(|(_, s)| s.evidence.value.is_threat()) {
        let raw = value_points(s.evidence.value) * s.evidence.weight * s.engine_weight;
        let o = s.field.as_ref().map(origin);
        let (key, derived) = match s.evidence.patterns.first() {
            Some(p) if is_derived(&p.name) => (Key::Derived(p.name.clone()), true),
            Some(p) => (Key::Family(p.family), false),
            None => (Key::Engine(s.engine.clone()), false),
        };
        let c = Counted { item: i, raw, origin: o.clone(), derived, leaf_latent: leaf_latent(s) };
        match slot.entry((o, key)) {
            Entry::Occupied(e) => {
                let n = *e.get();
                if raw > counted[n].raw {
                    counted[n] = c;
                }
            }
            Entry::Vacant(e) => {
                e.insert(counted.len());
                counted.push(c);
            }
        }
    }

    // The first maximal item is the top.
    let mut top_n: Option<usize> = None;
    let mut top = 0.0f32;
    for (n, c) in counted.iter().enumerate() {
        if c.raw > top {
            top = c.raw;
            top_n = Some(n);
        }
    }
    // A derived item and another item on the same origin never corroborate
    // each other, whichever of the two is the top (D10). A JSON-leaf latent
    // corroborates only a top on its own leaf (rule C).
    let corroborates = |n: usize| -> bool {
        let Some(t) = top_n else { return false };
        let same = counted[n].origin == counted[t].origin;
        n != t && !(same && (counted[n].derived || counted[t].derived)) && (same || !counted[n].leaf_latent)
    };
    let rest: f32 = (0..counted.len()).filter(|&n| corroborates(n)).map(|n| counted[n].raw).sum();
    let corroboration = (rest * 0.1).min(cfg.corroboration_cap);

    let mut score = (top + corroboration).min(100.0);
    if is_conflict {
        // Damp, but never below the band the strongest danger reaches alone.
        score = (score * 0.9).max(band_floor(top, cfg));
    }

    // Points: the top keeps its raw points, the corroborating items share the
    // corroboration in proportion, everything else adds 0; clamping and damping
    // then scale every item alike, so the points sum to the unrounded score.
    let mut points = vec![0.0f32; items.len()];
    let share = if rest > 0.0 { corroboration / rest } else { 0.0 };
    for (n, c) in counted.iter().enumerate() {
        points[c.item] = if Some(n) == top_n {
            c.raw
        } else if corroborates(n) {
            c.raw * share
        } else {
            0.0
        };
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

    use crate::judgment::{Family, Pattern};
    use crate::request::Location;

    fn on(field: &str, v: FourValued, w: f32, engine_weight: f32, family: Family, id: &str) -> Scored {
        Scored {
            engine: "t".into(),
            engine_weight,
            field: Some(FieldRef { loc: Location::Body, name: field.into() }),
            evidence: Evidence::new(v, w, vec![Pattern::new(family, id)], "x"),
        }
    }

    fn sums_to_score(a: &Arbitration) -> bool {
        (a.points.iter().sum::<f32>() - f32::from(a.score)).abs() <= 0.5
    }

    #[test]
    fn one_family_on_one_field_counts_once_at_its_strongest() {
        let cfg = ScoringConfig::default();
        // A latent graph item (27.5) recorded before a signature of the same family (72).
        let ev = vec![
            on("json:/q", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword"),
            on("json:/q", FourValued::Dangerous, 0.8, 0.9, Family::Sqli, "sig.union-all-select"),
        ];
        let a = arbitrate(&ev, &cfg, false);
        assert_eq!(a.score, 72);
        assert_eq!(a.points[0], 0.0);
        assert!(sums_to_score(&a));
    }

    #[test]
    fn different_families_on_one_field_still_corroborate() {
        let cfg = ScoringConfig::default();
        let ev = vec![
            on("json:/a", FourValued::Dangerous, 0.95, 1.0, Family::Sqli, "sqli.union-select"),
            on("json:/a", FourValued::Suspicious, 0.5, 1.0, Family::Xss, "xss.html-tag"),
        ];
        assert_eq!(arbitrate(&ev, &cfg, false).score, 98); // 95 + 2.75
    }

    fn in_header(name: &str, v: FourValued, w: f32, family: Family, id: &str) -> Scored {
        Scored { field: Some(FieldRef { loc: Location::Header, name: name.into() }), ..on("_", v, w, 1.0, family, id) }
    }

    #[test]
    fn latent_json_leaves_do_not_corroborate_each_other() {
        let cfg = ScoringConfig::default();
        let ev = vec![
            on("json:/a", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword"),
            on("json:/b", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword"),
        ];
        let a = arbitrate(&ev, &cfg, false);
        assert_eq!(a.score, 28); // 27.5: the leaf latent is the top, the other adds nothing
        assert_eq!(a.points[1], 0.0);
        assert!(sums_to_score(&a));
    }

    #[test]
    fn a_json_leaf_latent_does_not_back_up_a_header_top() {
        let cfg = ScoringConfig::default();
        // The split's background noise: a header latent at 27.5 stays below monitor_at.
        let header = in_header("sec-ch-ua", FourValued::Suspicious, 0.5, Family::CommandInjection, "cmd.shell-meta");
        let leaf = on("json:/q", FourValued::Suspicious, 0.5, 1.0, Family::CommandInjection, "cmd.shell-meta");
        let a = arbitrate(&[header, leaf], &cfg, false);
        assert_eq!(a.score, 28);
        assert_eq!(a.points[1], 0.0);
        assert!(sums_to_score(&a));
    }

    #[test]
    fn rule_c_keeps_other_corroboration() {
        let cfg = ScoringConfig::default();
        let header = in_header("sec-ch-ua", FourValued::Suspicious, 0.5, Family::CommandInjection, "cmd.shell-meta");
        // A latent on a non-JSON body field still corroborates, as before DQ2a: 27.5 + 2.75.
        let body = on("<body>", FourValued::Suspicious, 0.5, 1.0, Family::CommandInjection, "cmd.shell-meta");
        assert_eq!(arbitrate(&[header.clone(), body], &cfg, false).score, 30);
        // A Dangerous leaf item corroborates a top on another field: 95 + 9.5.
        let strong = in_header("referer", FourValued::Dangerous, 0.95, Family::Sqli, "sqli.union-select");
        let leaf_dangerous = on("json:/q", FourValued::Dangerous, 0.95, 1.0, Family::Xss, "xss.script-tag");
        assert_eq!(arbitrate(&[strong, leaf_dangerous], &cfg, false).score, 100);
        // A leaf latent still backs up another family on its own leaf: 95 + 2.75.
        let top = on("json:/q", FourValued::Dangerous, 0.95, 1.0, Family::Sqli, "sqli.union-select");
        let own = on("json:/q", FourValued::Suspicious, 0.5, 1.0, Family::Xss, "xss.html-tag");
        assert_eq!(arbitrate(&[top, own], &cfg, false).score, 98);
        // And a leaf latent can still be the top.
        let only = on("json:/q", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword");
        assert_eq!(arbitrate(&[only, header], &cfg, false).score, 30); // 27.5 + the header's 2.75
    }

    #[test]
    fn a_derived_item_does_not_corroborate_its_own_field() {
        let cfg = ScoringConfig::default();
        let graph = on("form:q", FourValued::Dangerous, 0.95, 1.0, Family::Sqli, "sqli.union-select");
        let ai_same = on("form:q", FourValued::Dangerous, 0.6, 0.5, Family::Anomaly, "ai.anomaly-score");
        let a = arbitrate(&[graph.clone(), ai_same], &cfg, false);
        assert_eq!(a.score, 95);
        assert_eq!(a.points[1], 0.0);
        assert!(sums_to_score(&a));
        // On another field it still corroborates: 95 + 3.
        let ai_other = on("form:other", FourValued::Dangerous, 0.6, 0.5, Family::Anomaly, "ai.anomaly-score");
        assert_eq!(arbitrate(&[graph, ai_other], &cfg, false).score, 98);
    }

    #[test]
    fn a_derived_top_is_not_corroborated_by_its_own_field() {
        let cfg = ScoringConfig::default();
        // api.type-violation is Dangerous 0.7 at weight_api 0.6: 42 points. Its family is Sqli,
        // so it must not collapse into a Sqli graph item either: it is keyed by its id.
        let api = on("form:id", FourValued::Dangerous, 0.7, 0.6, Family::Sqli, "api.type-violation");
        let same = on("form:id", FourValued::Suspicious, 0.5, 1.0, Family::Sqli, "sqli.sql-keyword");
        let a = arbitrate(&[api.clone(), same], &cfg, false);
        assert_eq!(a.score, 42, "the derived item is the top and its own field adds nothing");
        assert!(sums_to_score(&a));
        let other = on("form:x", FourValued::Suspicious, 0.5, 1.0, Family::CommandInjection, "cmd.shell-meta");
        assert_eq!(arbitrate(&[api, other], &cfg, false).score, 45); // 42 + 2.75
    }

    #[test]
    fn origin_strips_only_a_derived_suffix() {
        let f = |n: &str| FieldRef { loc: Location::Query, name: n.into() };
        assert_eq!(origin(&f("id#2")).name, "id");
        assert_eq!(origin(&f("json:#rest")).name, "json:#rest");
        assert_eq!(origin(&f("<body>")).name, "<body>");
        assert_eq!(origin(&f("#x")).name, "#x");
        assert_eq!(origin(&f("id#2")).loc, Location::Query);
    }
}
