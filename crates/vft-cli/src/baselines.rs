//! Baseline detectors for the benchmark, so Venusflytrap is compared
//! apples-to-apples against (a) a classic regex signature WAF and (b) a
//! structural tokenizer with no graph/taint reasoning.

use regex::RegexSet;
use vft_core::graph;
use vft_core::normalize::{normalize, Options};

/// A handful of classic regex signatures — representative of a first-generation
/// regex WAF. Operates on the RAW value (no normalization), as such WAFs do.
pub struct RegexBaseline {
    set: RegexSet,
}

impl Default for RegexBaseline {
    fn default() -> Self {
        let pats = [
            r"(?i)union\s+select",
            r"(?i)or\s+1\s*=\s*1",
            r"(?i)<script",
            r"(?i)onerror\s*=",
            r"(?i)/etc/passwd",
            r"(?i);\s*(cat|ls|id|whoami)\b",
            r"(?i)information_schema",
            r"\.\./\.\./",
        ];
        RegexBaseline {
            set: RegexSet::new(pats).expect("valid regexes"),
        }
    }
}

impl RegexBaseline {
    pub fn is_attack(&self, raw: &str) -> bool {
        self.set.is_match(raw)
    }
}

/// Tokenizer baseline: normalizes then checks for the mere presence of a
/// dangerous sink token, WITHOUT the graph reachability step. Approximates a
/// naive "semantic" engine that flags keywords but cannot tell structure from
/// coincidence — so it should be noisier (more FPs) than the full engine.
#[derive(Default)]
pub struct TokenizerBaseline {
    opts: Options,
}

impl TokenizerBaseline {
    pub fn is_attack(&self, raw: &str) -> bool {
        let n = normalize(raw, &self.opts);
        let a = graph::analyze(&n.text);
        // Flag if ANY sink is present, reachable or merely latent.
        !a.reachable.is_empty() || !a.latent.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_catches_plain_union() {
        assert!(RegexBaseline::default().is_attack("1 union select x"));
    }

    #[test]
    fn regex_misses_encoded() {
        // double-encoded — a regex baseline on raw input is blind to this.
        assert!(!RegexBaseline::default().is_attack("%2555NION%2520SELECT"));
    }

    #[test]
    fn tokenizer_catches_encoded() {
        assert!(TokenizerBaseline::default().is_attack("%2555NION%2520%2553ELECT%25201"));
    }
}
