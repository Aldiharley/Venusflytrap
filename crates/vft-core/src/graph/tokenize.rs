//! A lightweight multi-grammar lexer. It is intentionally permissive: it does
//! not try to be a valid SQL/HTML parser (that is the fail-open trap a strict
//! parser falls into). It just emits typed tokens the graph layer reasons over.
//!
//! The lexer operates over a `Vec<char>` so it is UTF-8 safe: attacker input is
//! arbitrary bytes, and indexing a `str` at a byte offset that lands inside a
//! multi-byte code point would panic. Working in `char` units removes that
//! class of bug entirely (see tests/fuzz_props.rs).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    SqlKeyword,
    Comparator,
    Number,
    Ident,
    String,
    Quote,
    Punct,
    ShellMeta,
    TagOpen,
    EventHandler,
    Other,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: TokenKind,
    /// Lowercased text of the token.
    pub text: String,
}

const SQL_KEYWORDS: &[&str] = &[
    "select", "union", "insert", "update", "delete", "drop", "from", "where", "or", "and", "exec",
    "create", "table", "into", "values", "join", "having", "group", "order", "by", "limit",
    "null", "like", "concat", "sleep", "benchmark", "load_file", "outfile", "information_schema",
];

const COMPARATORS: &[&str] = &["=", "<", ">", "<=", ">=", "<>", "!=", "like"];

pub fn tokenize(s: &str) -> Vec<Token> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;

    let slice = |a: usize, b: usize| -> String { chars[a..b].iter().collect() };

    while i < n {
        let c = chars[i];
        // whitespace
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // quotes
        if c == '\'' || c == '"' || c == '`' {
            out.push(Token {
                kind: TokenKind::Quote,
                text: c.to_string(),
            });
            i += 1;
            continue;
        }
        // tag open "<" possibly starting a tag
        if c == '<' {
            let start = i + 1;
            let mut j = start;
            if j < n && chars[j] == '/' {
                j += 1;
            }
            while j < n && chars[j].is_ascii_alphanumeric() {
                j += 1;
            }
            if j > start {
                out.push(Token {
                    kind: TokenKind::TagOpen,
                    text: format!("<{}", slice(start, j).to_lowercase()),
                });
                i = j;
                continue;
            } else {
                out.push(Token {
                    kind: TokenKind::Comparator,
                    text: "<".into(),
                });
                i += 1;
                continue;
            }
        }
        // shell metacharacters
        if matches!(c, ';' | '|' | '&') {
            let mut text = c.to_string();
            if i + 1 < n && chars[i + 1] == c {
                text.push(c);
                i += 1;
            }
            if c == ';' {
                // ';' plays two roles: SQL stacked-query punctuation and a shell
                // separator. Emit both so each layer can see it.
                out.push(Token {
                    kind: TokenKind::Punct,
                    text: ";".into(),
                });
                out.push(Token {
                    kind: TokenKind::ShellMeta,
                    text: ";".into(),
                });
            } else {
                out.push(Token {
                    kind: TokenKind::ShellMeta,
                    text,
                });
            }
            i += 1;
            continue;
        }
        // comparators (multi-char first)
        if matches!(c, '=' | '<' | '>' | '!') {
            if i + 1 < n {
                let two: String = [c, chars[i + 1]].iter().collect();
                if COMPARATORS.contains(&two.as_str()) {
                    out.push(Token {
                        kind: TokenKind::Comparator,
                        text: two,
                    });
                    i += 2;
                    continue;
                }
            }
            out.push(Token {
                kind: TokenKind::Comparator,
                text: c.to_string(),
            });
            i += 1;
            continue;
        }
        // numbers
        if c.is_ascii_digit() {
            let start = i;
            while i < n && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            out.push(Token {
                kind: TokenKind::Number,
                text: slice(start, i).to_lowercase(),
            });
            continue;
        }
        // identifiers / keywords / event handlers
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < n && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word = slice(start, i).to_lowercase();
            let is_handler = word.starts_with("on") && word.len() > 2 && {
                let mut k = i;
                while k < n && chars[k].is_whitespace() {
                    k += 1;
                }
                k < n && chars[k] == '='
            };
            let kind = if is_handler {
                TokenKind::EventHandler
            } else if COMPARATORS.contains(&word.as_str()) {
                TokenKind::Comparator
            } else if SQL_KEYWORDS.contains(&word.as_str()) {
                TokenKind::SqlKeyword
            } else {
                TokenKind::Ident
            };
            out.push(Token { kind, text: word });
            continue;
        }
        // any other single character is punctuation
        out.push(Token {
            kind: TokenKind::Punct,
            text: c.to_string(),
        });
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_and_comparators() {
        let t = tokenize("UNION SELECT 1=1");
        assert!(t.iter().any(|x| x.kind == TokenKind::SqlKeyword && x.text == "union"));
        assert!(t.iter().any(|x| x.kind == TokenKind::Comparator && x.text == "="));
        assert!(t.iter().filter(|x| x.kind == TokenKind::Number).count() >= 2);
    }

    #[test]
    fn event_handler_recognized() {
        let t = tokenize("onload = alert");
        assert!(t.iter().any(|x| x.kind == TokenKind::EventHandler));
    }

    #[test]
    fn tag_open_recognized() {
        let t = tokenize("<script>");
        assert!(t.iter().any(|x| x.kind == TokenKind::TagOpen && x.text == "<script"));
    }

    #[test]
    fn multibyte_does_not_panic() {
        // comparator followed by a multi-byte code point used to slice mid-char.
        for s in ["<\u{99c60}", "=\u{1f600}", "a\u{4e2d}b", "!\u{0430}", "1=\u{1f4a9}"] {
            let _ = tokenize(s);
        }
    }
}
