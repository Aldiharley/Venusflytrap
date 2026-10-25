//! Command injection sinks.

use super::{ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::{Token, TokenKind};
use crate::judgment::Family;

pub static CMD_SUBSTITUTION: ConstructInfo = ConstructInfo { id: "cmd.cmd-substitution", family: Some(Family::CommandInjection), kind: ConstructKind::Sink, summary: "`$(` or backtick; reachable with a known binary in command position, latent otherwise" };
pub static CHAINED_COMMAND: ConstructInfo = ConstructInfo { id: "cmd.chained-command", family: Some(Family::CommandInjection), kind: ConstructKind::Sink, summary: "shell separator followed by a known binary in command position" };
pub static SHELL_META: ConstructInfo = ConstructInfo { id: "cmd.shell-meta", family: Some(Family::CommandInjection), kind: ConstructKind::Latent, summary: "shell separator with no binary after it" };

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
    // binary — `; cat`, `| whoami`, `&& wget`. Requiring the binary to come
    // *after* the separator avoids flagging benign values that merely contain a
    // short word and a separator elsewhere ("cat;dog" is not command injection).
    let has_meta = tokens
        .iter()
        .any(|t| t.kind == TokenKind::ShellMeta && matches!(t.text.as_str(), ";" | "|" | "&" | "&&" | "||"));
    if binary_after_meta(tokens, BINS) {
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
