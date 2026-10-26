//! SQL injection sinks.

use super::{has_kw, has_quote, ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::{Token, TokenKind};
use crate::judgment::Family;

pub static UNION_SELECT: ConstructInfo = ConstructInfo { id: "sqli.union-select", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "UNION followed by SELECT" };
pub static BOOLEAN_TAUTOLOGY: ConstructInfo = ConstructInfo { id: "sqli.boolean-tautology", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "equal operands compared after OR/AND or with a quote breakout (1=1, 'a'='a')" };
pub static QUOTE_BREAKOUT: ConstructInfo = ConstructInfo { id: "sqli.quote-breakout", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "a quote immediately followed by OR, AND or UNION" };
pub static STACKED_QUERY: ConstructInfo = ConstructInfo { id: "sqli.stacked-query", family: Some(Family::Sqli), kind: ConstructKind::Sink, summary: "';' followed by a DML or DDL keyword" };
pub static SQL_KEYWORD: ConstructInfo = ConstructInfo { id: "sqli.sql-keyword", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "SELECT or UNION with no SQL construct formed" };
pub static FN_SLEEP: ConstructInfo = ConstructInfo { id: "sqli.fn-sleep", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `sleep`" };
pub static FN_BENCHMARK: ConstructInfo = ConstructInfo { id: "sqli.fn-benchmark", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `benchmark`" };
pub static FN_UPDATEXML: ConstructInfo = ConstructInfo { id: "sqli.fn-updatexml", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `updatexml`" };
pub static FN_EXTRACTVALUE: ConstructInfo = ConstructInfo { id: "sqli.fn-extractvalue", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `extractvalue`" };
pub static FN_LOAD_FILE: ConstructInfo = ConstructInfo { id: "sqli.fn-load-file", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `load_file`" };
pub static FN_PG_SLEEP: ConstructInfo = ConstructInfo { id: "sqli.fn-pg-sleep", family: Some(Family::Sqli), kind: ConstructKind::Latent, summary: "text contains `pg_sleep`" };

static LATENT_FNS: &[(&str, &ConstructInfo)] = &[
    ("sleep", &FN_SLEEP),
    ("benchmark", &FN_BENCHMARK),
    ("updatexml", &FN_UPDATEXML),
    ("extractvalue", &FN_EXTRACTVALUE),
    ("load_file", &FN_LOAD_FILE),
    ("pg_sleep", &FN_PG_SLEEP),
];

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let tokens = cx.tokens;
    // UNION ... SELECT (order-respecting, comments already stripped).
    let mut seen_union = false;
    for t in tokens {
        if t.kind == TokenKind::SqlKeyword && t.text == "union" {
            seen_union = true;
        }
        if seen_union && t.kind == TokenKind::SqlKeyword && t.text == "select" {
            hits.reach(&UNION_SELECT);
            break;
        }
    }

    // Tautology / boolean-based: OR/AND <x> <cmp> <x>  e.g. or 1=1, or 'a'='a'.
    if detect_tautology(tokens) {
        hits.reach(&BOOLEAN_TAUTOLOGY);
    }

    // Quote breakout: a string quote immediately followed by a boolean/union SQL
    // keyword (`' OR`, `' AND`, `' UNION`). Requiring adjacency avoids flagging a
    // stray apostrophe from a contraction ("it's") that happens to co-occur with
    // the word "or" elsewhere in the value.
    if quote_then_bool(tokens) {
        hits.reach(&QUOTE_BREAKOUT);
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
            hits.reach(&STACKED_QUERY);
            break;
        }
    }

    // Classic error/based functions as latent signal.
    for &(needle, c) in LATENT_FNS {
        if cx.text.contains(needle) {
            hits.latent(c);
        }
    }

    // Lone SELECT/UNION without structure is latent only.
    if !hits.reached(Family::Sqli) && (has_kw(tokens, "select") || seen_union) {
        hits.latent(&SQL_KEYWORD);
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

/// True if a Quote token is immediately followed by a boolean/union SQL keyword.
fn quote_then_bool(tokens: &[Token]) -> bool {
    tokens.windows(2).any(|w| {
        w[0].kind == TokenKind::Quote
            && w[1].kind == TokenKind::SqlKeyword
            && matches!(w[1].text.as_str(), "or" | "and" | "union")
    })
}
