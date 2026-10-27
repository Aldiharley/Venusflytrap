//! Command injection sinks.

use super::{ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::{Token, TokenKind};
use crate::judgment::Family;

pub static CMD_SUBSTITUTION: ConstructInfo = ConstructInfo { id: "cmd.cmd-substitution", family: Some(Family::CommandInjection), kind: ConstructKind::Sink, summary: "`$(` or backtick; reachable with a known binary in command position, latent otherwise" };
pub static CHAINED_COMMAND: ConstructInfo = ConstructInfo { id: "cmd.chained-command", family: Some(Family::CommandInjection), kind: ConstructKind::Sink, summary: "shell separator followed by a known binary in command position" };
pub static SHELL_META: ConstructInfo = ConstructInfo { id: "cmd.shell-meta", family: Some(Family::CommandInjection), kind: ConstructKind::Latent, summary: "shell separator with no binary after it" };

pub static GATE_CMD_POSITION: ConstructInfo = ConstructInfo { id: "gate.cmd-position", family: None, kind: ConstructKind::Gate, summary: "cmd.chained-command needs its binary as a whole word not directly followed by =, (, . or :; disabling it restores the token-only rule" };

const BINS: &[&str] = &[
    "cat", "ls", "id", "whoami", "wget", "curl", "nc", "bash", "sh", "ping", "nslookup",
    "uname", "pwd", "chmod", "rm", "python", "perl",
];

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let (tokens, text) = (cx.tokens, cx.text);
    // Command substitution $( ) or backticks. A bare `$(` is usually jQuery
    // (`$(document)`, `$('#id')`) and a lone backtick is often just a 0x60 byte
    // in a binary body, so substitution only forms a construct when a known
    // binary sits in command position right after the opener; otherwise latent.
    if text.contains("$(") || text.contains('`') {
        if substitution_runs_binary(text, BINS) {
            hits.reach(&CMD_SUBSTITUTION);
        } else {
            hits.latent(&CMD_SUBSTITUTION);
        }
    }
    // Chaining: a shell metacharacter followed (in command position) by a known
    // binary — `;`, `|`, `&`, `&&` or `||`, then the binary. Requiring the binary
    // to come *after* the separator avoids flagging benign values that merely
    // contain a short word and a separator elsewhere. The token test is the
    // candidate. `gate.cmd-position` also
    // requires the binary as a whole word on the text that is not directly
    // followed by `=`, `(`, `.` or `:`: `&id=2` is a URL parameter, not a command.
    // A rejected candidate stays visible as the `cmd.shell-meta` latent.
    let has_meta = tokens
        .iter()
        .any(|t| t.kind == TokenKind::ShellMeta && matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||"));
    if binary_after_meta(tokens, BINS) && (hits.off(&GATE_CMD_POSITION) || command_in_position(text, BINS)) {
        hits.reach(&CHAINED_COMMAND);
    } else if has_meta {
        hits.latent(&SHELL_META);
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

/// The `gate.cmd-position` rule: some `;`, `|` or `&` is followed, after
/// optional whitespace, by a known binary as a whole word (`[A-Za-z0-9_]+`,
/// compared in lower case) whose next character is not `=`, `(`, `.` or `:`.
/// A binary name directly followed by one of those is an assignment, a URL
/// parameter, a call or a file name, not a command.
///
/// Works on the text because the lexer drops whitespace, so tokens cannot tell
/// `&id=2` from a separator, a binary and a later `=`.
fn command_in_position(text: &str, bins: &[&str]) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    for (i, &c) in chars.iter().enumerate() {
        if !matches!(c, ';' | '|' | '&') {
            continue;
        }
        let mut j = i + 1;
        while j < n && chars[j].is_whitespace() {
            j += 1;
        }
        let start = j;
        while j < n && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
            j += 1;
        }
        if start == j {
            continue;
        }
        let word = chars[start..j].iter().collect::<String>().to_ascii_lowercase();
        let assignment_like = j < n && matches!(chars[j], '=' | '(' | '.' | ':');
        if bins.contains(&word.as_str()) && !assignment_like {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::sinks::Disabled;
    use crate::graph::tokenize::tokenize;

    /// (reachable names, latent names) of the shell sinks on `text`.
    fn shell_hits(text: &str, disabled: &Disabled) -> (Vec<String>, Vec<String>) {
        let tokens = tokenize(text);
        let mut hits = Hits::new(disabled);
        detect(&SinkCtx { tokens: &tokens, text }, &mut hits);
        (hits.reachable.into_iter().map(|p| p.name).collect(), hits.latent.into_iter().map(|p| p.name).collect())
    }

    const SEPARATORS: &[&str] = &[";", "|", "&", "&&", "||"];

    #[test]
    fn a_query_parameter_named_like_a_binary_is_not_a_chained_command() {
        let on = Disabled::default();
        for s in ["a=1&id=2", "format=json&id=v3", "page=2&id=7&sort=asc", "v=1&id.json", "q=1&id(3)", "q=1&id:2"] {
            let (reach, latent) = shell_hits(s, &on);
            assert!(!reach.iter().any(|n| n == "cmd.chained-command"), "{s:?}: {reach:?}");
            assert!(latent.iter().any(|n| n == "cmd.shell-meta"), "the separator stays visible as a latent on {s:?}: {latent:?}");
        }
    }

    #[test]
    fn disabling_the_gate_restores_the_token_rule() {
        let off = Disabled::resolve(&["gate.cmd-position".into()]);
        for s in ["a=1&id=2", "format=json&id=v3"] {
            let (reach, _) = shell_hits(s, &off);
            assert!(reach.iter().any(|n| n == "cmd.chained-command"), "today's behaviour on {s:?}: {reach:?}");
        }
    }

    #[test]
    fn command_position_needs_a_whole_word_not_followed_by_an_assignment_or_call() {
        let on = Disabled::default();
        for bin in BINS {
            for sep in SEPARATORS {
                for end in ["", " ", " x", ";", "|", "&", "<", ">", ")", "`", " =", " ("] {
                    for word in [bin.to_string(), bin.to_ascii_uppercase()] {
                        let s = format!("x{sep}{word}{end}");
                        assert!(command_in_position(&s, BINS), "{s:?}");
                        let s = format!("x{sep} {word}{end}");
                        assert!(command_in_position(&s, BINS), "{s:?}");
                    }
                }
                for bad in ["=", "(", ".", ":"] {
                    let s = format!("x{sep}{bin}{bad}");
                    assert!(!command_in_position(&s, BINS), "{s:?}");
                    let (reach, latent) = shell_hits(&s, &on);
                    assert!(!reach.iter().any(|n| n == "cmd.chained-command"), "{s:?}: {reach:?}");
                    assert!(latent.iter().any(|n| n == "cmd.shell-meta"), "{s:?}: {latent:?}");
                }
                let longer = format!("x{sep}{bin}x");
                assert!(!command_in_position(&longer, BINS), "not a whole word: {longer:?}");
                let longer = format!("x{sep}x{bin}");
                assert!(!command_in_position(&longer, BINS), "not a whole word: {longer:?}");
            }
        }
        assert!(!command_in_position("", BINS));
        assert!(!command_in_position("no separator here", BINS));
    }

    #[test]
    fn the_gate_only_removes_reaches() {
        let on = Disabled::default();
        let off = Disabled::resolve(&["gate.cmd-position".into()]);
        for bin in BINS {
            for sep in SEPARATORS {
                for end in ["", " x", "=1", "(", ".x", ":1", ";"] {
                    let s = format!("x{sep}{bin}{end}");
                    let (with_gate, _) = shell_hits(&s, &on);
                    let (without, _) = shell_hits(&s, &off);
                    for n in &with_gate {
                        assert!(without.contains(n), "the gate added {n} on {s:?}");
                    }
                }
            }
        }
    }
}
