//! Construct registry and sink collection.
//!
//! Every pattern the engine can emit, every decoder and every inspection limit
//! has one stable dotted id here (`sqli.union-select`). Sinks emit through
//! [`Hits`], which takes the registry entry itself, so an unregistered id cannot
//! be emitted and a disabled construct is dropped at the source. Ids are never
//! reused; renaming one would need an alias mechanism, which does not exist yet.

pub mod path;
pub mod shell;
pub mod sql;
pub mod xss;

use std::collections::HashSet;

use super::tokenize::{Token, TokenKind};
use crate::judgment::{Family, Pattern};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstructKind {
    /// A formed construct in the token graph (blocks on its own).
    Sink,
    /// A lone dangerous token with no construct (weak signal).
    Latent,
    /// A rule-based detection outside the token graph: signatures, API safety,
    /// recon, honeypot, intel.
    Signature,
    /// A normalizer decoding stage.
    Decoder,
    /// An inspection limit that fails closed.
    Limit,
    /// A rule that narrows when an existing construct fires. It emits no
    /// evidence and has no family; putting its id in `shield.disabled`
    /// restores the construct's earlier behaviour, so an A/B needs one build.
    Gate,
}

#[derive(Debug)]
pub struct ConstructInfo {
    pub id: &'static str,
    /// `None` only for decoders and gates, which emit no evidence and belong
    /// to no attack family.
    pub family: Option<Family>,
    pub kind: ConstructKind,
    pub summary: &'static str,
}

impl ConstructInfo {
    /// The pattern this construct emits. Decoders and gates never emit
    /// patterns; the registry test guarantees every other kind has a family.
    /// registry test guarantees every other kind has a family.
    pub fn pattern(&self) -> Pattern {
        Pattern::new(self.family.unwrap_or(Family::Limit), self.id)
    }
}

// --- Constructs emitted outside the token graph -------------------------------

pub static SIG_UNION_ALL_SELECT: ConstructInfo = ConstructInfo { id: "sig.union-all-select", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "literal `union all select`" };
pub static SIG_CLASSIC_OR: ConstructInfo = ConstructInfo { id: "sig.classic-or", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "literal `' or '1'='1`" };
pub static SIG_SCHEMA_ENUM: ConstructInfo = ConstructInfo { id: "sig.schema-enum", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "literal `information_schema`" };
pub static SIG_ALERT_SCRIPT: ConstructInfo = ConstructInfo { id: "sig.alert-script", family: Some(Family::Xss), kind: ConstructKind::Signature, summary: "literal `<script>alert`" };
pub static SIG_ONERROR: ConstructInfo = ConstructInfo { id: "sig.onerror", family: Some(Family::Xss), kind: ConstructKind::Signature, summary: "literal `onerror=`" };
pub static SIG_ETC_PASSWD: ConstructInfo = ConstructInfo { id: "sig.etc-passwd", family: Some(Family::PathTraversal), kind: ConstructKind::Signature, summary: "literal `/etc/passwd`" };
pub static SIG_CAT_SUBST: ConstructInfo = ConstructInfo { id: "sig.cat-subst", family: Some(Family::CommandInjection), kind: ConstructKind::Signature, summary: "literal `$(cat `" };
pub static API_TYPE_VIOLATION: ConstructInfo = ConstructInfo { id: "api.type-violation", family: Some(Family::Sqli), kind: ConstructKind::Signature, summary: "numeric-looking field (id, *_id, page, count) carries a formed construct" };
pub static API_OVERSIZED_HEADER: ConstructInfo = ConstructInfo { id: "api.oversized-header", family: Some(Family::Anomaly), kind: ConstructKind::Signature, summary: "a header value longer than 4096 bytes" };
pub static AI_ANOMALY_SCORE: ConstructInfo = ConstructInfo { id: "ai.anomaly-score", family: Some(Family::Anomaly), kind: ConstructKind::Signature, summary: "the heuristic anomaly oracle scored the field at or above 0.35" };
pub static RECON_SENSITIVE_PATH: ConstructInfo = ConstructInfo { id: "recon.sensitive-path-probe", family: Some(Family::Recon), kind: ConstructKind::Signature, summary: "canonical path starts with a configured sensitive path" };
pub static HONEYPOT_DECOY_HIT: ConstructInfo = ConstructInfo { id: "honeypot.decoy-hit", family: Some(Family::Honeypot), kind: ConstructKind::Signature, summary: "canonical path hits a configured decoy" };
pub static INTEL_SCANNER_UA: ConstructInfo = ConstructInfo { id: "intel.scanner-ua", family: Some(Family::Intel), kind: ConstructKind::Signature, summary: "User-Agent matches a scanner fingerprint" };
pub static INTEL_DENY_LISTED: ConstructInfo = ConstructInfo { id: "intel.deny-listed", family: Some(Family::Intel), kind: ConstructKind::Signature, summary: "source address is on intel.deny_ips" };
pub static LIMIT_HEADER_NON_UTF8: ConstructInfo = ConstructInfo { id: "limit.header-non-utf8", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "a header carried bytes that are not UTF-8" };

// --- Limits ---------------------------------------------------------------------

pub static LIMIT_PAYLOAD_TRUNCATED: ConstructInfo = ConstructInfo { id: "limit.payload-truncated", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "the request exceeded shield.max_inspect_bytes or shield.max_normalize_work, or a piece was still cut after lossless recursive splitting" };
pub static LIMIT_GRAPH_TRUNCATED: ConstructInfo = ConstructInfo { id: "limit.graph-truncated", family: Some(Family::Limit), kind: ConstructKind::Limit, summary: "a field needed more token windows than shield.max_graph_windows" };

// --- Decoders -------------------------------------------------------------------

pub static DECODE_PERCENT_LOSSY: ConstructInfo = ConstructInfo { id: "decode.percent-lossy", family: None, kind: ConstructKind::Decoder, summary: "URL decoding: '+' to space, %XX byte by byte, lossy UTF-8" };
pub static DECODE_ENTITY: ConstructInfo = ConstructInfo { id: "decode.entity", family: None, kind: ConstructKind::Decoder, summary: "HTML entities: numeric, plus a fixed set of named ones" };
pub static DECODE_ESC_HEX: ConstructInfo = ConstructInfo { id: "decode.esc-hex", family: None, kind: ConstructKind::Decoder, summary: "\\xNN and \\uNNNN escapes" };
pub static DECODE_B64_WHOLE: ConstructInfo = ConstructInfo { id: "decode.b64-whole", family: None, kind: ConstructKind::Decoder, summary: "a field that is base64 as a whole; also tried before '+' becomes a space" };

static REGISTRY: &[&ConstructInfo] = &[
    &sql::UNION_SELECT,
    &sql::BOOLEAN_TAUTOLOGY,
    &sql::QUOTE_BREAKOUT,
    &sql::STACKED_QUERY,
    &sql::SQL_KEYWORD,
    &sql::FN_SLEEP,
    &sql::FN_BENCHMARK,
    &sql::FN_UPDATEXML,
    &sql::FN_EXTRACTVALUE,
    &sql::FN_LOAD_FILE,
    &sql::FN_PG_SLEEP,
    &xss::SCRIPT_TAG,
    &xss::EVENT_HANDLER,
    &xss::DANGEROUS_PROTO,
    &xss::TAG_WITH_HANDLER,
    &xss::HTML_TAG,
    &shell::CMD_SUBSTITUTION,
    &shell::CHAINED_COMMAND,
    &shell::SHELL_META,
    &path::DIRECTORY_TRAVERSAL,
    &path::DOTDOT_SEGMENT,
    &SIG_UNION_ALL_SELECT,
    &SIG_CLASSIC_OR,
    &SIG_SCHEMA_ENUM,
    &SIG_ALERT_SCRIPT,
    &SIG_ONERROR,
    &SIG_ETC_PASSWD,
    &SIG_CAT_SUBST,
    &API_TYPE_VIOLATION,
    &API_OVERSIZED_HEADER,
    &AI_ANOMALY_SCORE,
    &RECON_SENSITIVE_PATH,
    &HONEYPOT_DECOY_HIT,
    &INTEL_SCANNER_UA,
    &INTEL_DENY_LISTED,
    &LIMIT_HEADER_NON_UTF8,
    &LIMIT_GRAPH_TRUNCATED,
    &LIMIT_PAYLOAD_TRUNCATED,
    &DECODE_PERCENT_LOSSY,
    &DECODE_ENTITY,
    &DECODE_ESC_HEX,
    &DECODE_B64_WHOLE,
    &shell::GATE_CMD_POSITION,
];

/// Every registered construct, decoder and limit.
pub fn constructs() -> &'static [&'static ConstructInfo] {
    REGISTRY
}

pub fn lookup(id: &str) -> Option<&'static ConstructInfo> {
    REGISTRY.iter().copied().find(|c| c.id == id)
}

/// The ids in `ids` that name no registered construct (for config validation).
pub fn unknown_ids(ids: &[String]) -> Vec<String> {
    ids.iter().filter(|i| lookup(i).is_none()).cloned().collect()
}

/// The constructs switched off by `shield.disabled`.
#[derive(Debug, Clone, Default)]
pub struct Disabled(HashSet<&'static str>);

impl Disabled {
    /// Resolve configured ids. Unknown ids are skipped here; `Config::validate`
    /// reports them, so a validated config never reaches this with one.
    pub fn resolve(ids: &[String]) -> Disabled {
        Disabled(ids.iter().filter_map(|i| lookup(i)).map(|c| c.id).collect())
    }

    pub fn is(&self, c: &ConstructInfo) -> bool {
        self.0.contains(c.id)
    }

    /// Whether `id` is in the set (for ids carried as strings, such as a
    /// contribution's construct).
    pub fn has(&self, id: &str) -> bool {
        self.0.contains(id)
    }
}

/// Sink output for one field: reachable and latent patterns, de-duplicated,
/// with disabled constructs dropped.
pub struct Hits<'d> {
    disabled: &'d Disabled,
    pub reachable: Vec<Pattern>,
    pub latent: Vec<Pattern>,
}

impl<'d> Hits<'d> {
    pub fn new(disabled: &'d Disabled) -> Self {
        Hits { disabled, reachable: Vec::new(), latent: Vec::new() }
    }

    pub fn reach(&mut self, c: &'static ConstructInfo) {
        push_unique(&mut self.reachable, c, self.disabled);
    }

    pub fn latent(&mut self, c: &'static ConstructInfo) {
        push_unique(&mut self.latent, c, self.disabled);
    }

    /// Whether `c` is in `shield.disabled`. A sink asks this of a gate to
    /// decide whether to apply it.
    pub fn off(&self, c: &ConstructInfo) -> bool {
        self.disabled.is(c)
    }

    /// True if a reachable pattern of `family` has been recorded.
    pub fn reached(&self, family: Family) -> bool {
        self.reachable.iter().any(|p| p.family == family)
    }
}

fn push_unique(v: &mut Vec<Pattern>, c: &'static ConstructInfo, disabled: &Disabled) {
    if disabled.is(c) || v.iter().any(|p| p.name == c.id) {
        return;
    }
    v.push(c.pattern());
}

/// What a sink sees: one window of tokens and the whole normalized field text.
pub struct SinkCtx<'a> {
    pub tokens: &'a [Token],
    pub text: &'a str,
}

pub(crate) fn has_kw(tokens: &[Token], kw: &str) -> bool {
    tokens.iter().any(|t| t.kind == TokenKind::SqlKeyword && t.text == kw)
}

pub(crate) fn has_quote(tokens: &[Token]) -> bool {
    tokens.iter().any(|t| t.kind == TokenKind::Quote)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_dotted() {
        let mut seen = std::collections::HashSet::new();
        for c in constructs() {
            assert!(seen.insert(c.id), "duplicate id {}", c.id);
            assert!(c.id.contains('.') && !c.id.starts_with('.') && !c.id.ends_with('.'), "not dotted: {}", c.id);
            assert!(
                c.id.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '-'),
                "bad characters in {}",
                c.id
            );
            assert!(!c.summary.is_empty(), "{} has no summary", c.id);
        }
    }

    #[test]
    fn only_decoders_lack_a_family() {
        for c in constructs() {
            assert_eq!(c.family.is_none(), matches!(c.kind, ConstructKind::Decoder | ConstructKind::Gate), "{}", c.id);
        }
        assert_eq!(lookup("gate.cmd-position").map(|c| c.kind), Some(ConstructKind::Gate));
    }

    #[test]
    fn lookup_and_unknown_ids() {
        assert_eq!(lookup("honeypot.decoy-hit").map(|c| c.id), Some("honeypot.decoy-hit"));
        assert!(lookup("nope.nope").is_none());
        assert_eq!(unknown_ids(&["honeypot.decoy-hit".into(), "nope.nope".into()]), vec!["nope.nope".to_string()]);
    }

    #[test]
    fn hits_drop_disabled_and_dedupe() {
        let d = Disabled::resolve(&["sig.onerror".into()]);
        let mut h = Hits::new(&d);
        h.reach(&SIG_ONERROR);
        h.reach(&SIG_CLASSIC_OR);
        h.reach(&SIG_CLASSIC_OR);
        h.latent(&SIG_ETC_PASSWD);
        assert_eq!(h.reachable.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["sig.classic-or"]);
        assert_eq!(h.latent.len(), 1);
        assert!(h.reached(Family::Sqli));
        assert!(!h.reached(Family::Xss));
    }

    #[test]
    fn hits_report_whether_a_construct_is_off() {
        let d = Disabled::resolve(&["gate.cmd-position".into()]);
        let h = Hits::new(&d);
        assert!(h.off(&shell::GATE_CMD_POSITION));
        assert!(!h.off(&SIG_ONERROR));
        let none = Disabled::default();
        assert!(!Hits::new(&none).off(&shell::GATE_CMD_POSITION));
    }
}
