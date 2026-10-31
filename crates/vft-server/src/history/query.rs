//! The history query language: parse a query string into typed terms and compile
//! them, with a time window, paging and an optional grouping, into one SQL
//! statement over `requests`.
//!
//! SQL safety: [`compile`] builds its statement only by concatenating the
//! `&'static str` pieces listed in [`FRAGMENTS`] and every user-supplied value
//! travels as a bound `?` parameter, so nothing a query contains can reach the SQL text.

use rusqlite::types::Value;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// A query that does not parse or validate. `pos` and `len` are byte offsets
/// into the query string (both 0 for errors that are not about a position in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub pos: usize,
    pub len: usize,
    pub msg: String,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error at {}: {}", self.pos, self.msg)
    }
}

impl std::error::Error for QueryError {}

/// Comparison of a `score` term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
}

/// What a `src` term matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Src {
    /// The canonical text of one source key.
    Addr(String),
    /// Every IPv4 source starting with these 1, 2 or 3 octets (a /8, /16 or /24).
    Cidr(Vec<u8>),
}

/// One condition of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    /// The stored variant name (`Block`).
    Verdict(&'static str),
    /// The stored variant name, or `None` for "no stage".
    Stage(Option<&'static str>),
    Construct {
        id: String,
        prefix: bool,
    },
    Technique(String),
    Src(Src),
    Path(String),
    Method(String),
    /// The stored `CauseKind` variant name.
    Cause(&'static str),
    Exception(String),
    Group(String),
    Sampled(bool),
    Score(Cmp, u8),
}

/// A parsed query: the terms, each flagged negated or not; all are ANDed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub terms: Vec<(bool, Term)>,
}

/// What a grouped query counts rows by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    Src,
    Path,
    Construct,
    Stage,
    Verdict,
}

impl GroupBy {
    /// `src`, `path`, `construct`, `stage` or `verdict`.
    pub fn from_name(s: &str) -> Option<GroupBy> {
        Some(match s {
            "src" => GroupBy::Src,
            "path" => GroupBy::Path,
            "construct" => GroupBy::Construct,
            "stage" => GroupBy::Stage,
            "verdict" => GroupBy::Verdict,
            _ => return None,
        })
    }
}

/// A query over a time window `[from_ms, to_ms)`.
#[derive(Debug, Clone)]
pub struct Request {
    pub q: String,
    pub from_ms: u64,
    pub to_ms: u64,
    pub group_by: Option<GroupBy>,
    pub limit: u32,
    /// `"<ts_ms>:<event_id>"` of the last row of the previous page.
    pub cursor: Option<String>,
}

/// SQL text and its bound parameters.
#[derive(Debug)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Value>,
}

// ---- the SQL fragments -------------------------------------------------------

/// The `requests` columns a row query returns, in this order.
pub const COLUMNS: &str = "event_id, ts_ms, src_key, ip, method, host, path, verdict, score, stage, families, construct, technique, confidence, group_id, cause_kind, decided_option, config_rev, latency_us, upstream_status, sampled, exceptions, extra";

const ROWS_HEAD: &str = "SELECT event_id, ts_ms, src_key, ip, method, host, path, verdict, score, stage, families, construct, technique, confidence, group_id, cause_kind, decided_option, config_rev, latency_us, upstream_status, sampled, exceptions, extra FROM requests WHERE ts_ms >= ? AND ts_ms < ?";
const ROWS_TAIL: &str = " ORDER BY ts_ms DESC, event_id DESC LIMIT ?";
const AND: &str = " AND ";
const NOT_OPEN: &str = "NOT COALESCE(";
const NOT_CLOSE: &str = ", 0)";
const CURSOR: &str = "(ts_ms < ? OR (ts_ms = ? AND event_id < ?))";

const GROUP_HEADS: [&str; 5] = [
    "SELECT COALESCE(src_key, '(none)'), COUNT(*) FROM requests WHERE ts_ms >= ? AND ts_ms < ?",
    "SELECT COALESCE(path, '(none)'), COUNT(*) FROM requests WHERE ts_ms >= ? AND ts_ms < ?",
    "SELECT COALESCE(construct, '(none)'), COUNT(*) FROM requests WHERE ts_ms >= ? AND ts_ms < ?",
    "SELECT COALESCE(stage, '(none)'), COUNT(*) FROM requests WHERE ts_ms >= ? AND ts_ms < ?",
    "SELECT COALESCE(verdict, '(none)'), COUNT(*) FROM requests WHERE ts_ms >= ? AND ts_ms < ?",
];
const GROUP_TAILS: [&str; 5] = [
    " GROUP BY COALESCE(src_key, '(none)') ORDER BY COUNT(*) DESC, COALESCE(src_key, '(none)') ASC LIMIT ?",
    " GROUP BY COALESCE(path, '(none)') ORDER BY COUNT(*) DESC, COALESCE(path, '(none)') ASC LIMIT ?",
    " GROUP BY COALESCE(construct, '(none)') ORDER BY COUNT(*) DESC, COALESCE(construct, '(none)') ASC LIMIT ?",
    " GROUP BY COALESCE(stage, '(none)') ORDER BY COUNT(*) DESC, COALESCE(stage, '(none)') ASC LIMIT ?",
    " GROUP BY COALESCE(verdict, '(none)') ORDER BY COUNT(*) DESC, COALESCE(verdict, '(none)') ASC LIMIT ?",
];

const T_VERDICT: &str = "verdict = ?";
const T_STAGE: &str = "stage = ?";
const T_STAGE_NONE: &str = "stage IS NULL";
const T_CONSTRUCT: &str = "construct = ?";
const T_CONSTRUCT_LIKE: &str = "construct LIKE ? ESCAPE '\\'";
const T_TECHNIQUE: &str = "technique = ?";
const T_SRC: &str = "src_key = ?";
const T_SRC_LIKE: &str = "src_key LIKE ? ESCAPE '\\'";
const T_PATH: &str = "path LIKE ? ESCAPE '\\'";
const T_METHOD: &str = "method = ?";
const T_CAUSE: &str = "cause_kind = ?";
const T_EXCEPTION: &str = "(',' || exceptions || ',') LIKE ? ESCAPE '\\'";
const T_GROUP: &str = "group_id = ?";
const T_SAMPLED: &str = "sampled = ?";
const T_SCORE_EQ: &str = "score = ?";
const T_SCORE_GT: &str = "score > ?";
const T_SCORE_LT: &str = "score < ?";
const T_SCORE_GE: &str = "score >= ?";
const T_SCORE_LE: &str = "score <= ?";

/// Every piece of text [`compile`] can put into a statement. The SQL it returns
/// is always a concatenation of these.
pub const FRAGMENTS: &[&str] = &[
    "?",
    ROWS_HEAD,
    ROWS_TAIL,
    AND,
    NOT_OPEN,
    NOT_CLOSE,
    CURSOR,
    GROUP_HEADS[0],
    GROUP_HEADS[1],
    GROUP_HEADS[2],
    GROUP_HEADS[3],
    GROUP_HEADS[4],
    GROUP_TAILS[0],
    GROUP_TAILS[1],
    GROUP_TAILS[2],
    GROUP_TAILS[3],
    GROUP_TAILS[4],
    T_VERDICT,
    T_STAGE,
    T_STAGE_NONE,
    T_CONSTRUCT,
    T_CONSTRUCT_LIKE,
    T_TECHNIQUE,
    T_SRC,
    T_SRC_LIKE,
    T_PATH,
    T_METHOD,
    T_CAUSE,
    T_EXCEPTION,
    T_GROUP,
    T_SAMPLED,
    T_SCORE_EQ,
    T_SCORE_GT,
    T_SCORE_LT,
    T_SCORE_GE,
    T_SCORE_LE,
];

// ---- parsing -----------------------------------------------------------------

const VERDICTS: [&str; 4] = ["Allow", "Monitor", "Challenge", "Block"];
const STAGES: [&str; 4] = ["Recon", "Enumeration", "Exploitation", "Exfiltration"];
/// The variants of `vft_core::CauseKind`, as stored.
const CAUSES: [&str; 8] = [
    "NoEvidence",
    "Detection",
    "Honeypot",
    "IntelDeny",
    "Ban",
    "ChainEscalation",
    "Limit",
    "Allowlisted",
];

fn err(pos: usize, len: usize, msg: impl Into<String>) -> QueryError {
    QueryError {
        pos,
        len,
        msg: msg.into(),
    }
}

/// Parse a query: whitespace-separated terms, all ANDed. A term is
/// `[-]field:value` or `[-]score<op>N`; a leading `-` negates it.
pub fn parse(q: &str) -> Result<Query, QueryError> {
    let mut terms = Vec::new();
    let mut start: Option<usize> = None;
    // A trailing sentinel closes the last term.
    for (i, c) in q.char_indices().chain(std::iter::once((q.len(), ' '))) {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(i),
            (true, Some(s)) => {
                terms.push(parse_term(q, s, i)?);
                start = None;
            }
            _ => {}
        }
    }
    Ok(Query { terms })
}

/// The term in `q[s..e]` (no whitespace inside).
fn parse_term(q: &str, s: usize, e: usize) -> Result<(bool, Term), QueryError> {
    let negated = q[s..e].starts_with('-');
    let at = if negated { s + 1 } else { s };
    let body = &q[at..e];
    if body.is_empty() {
        return Err(err(s, 1, "a negated term needs a field: -field:value"));
    }
    let name_len = body
        .find(|c: char| !(c.is_ascii_alphabetic() || c == '_'))
        .unwrap_or(body.len());
    let (name, rest) = body.split_at(name_len);
    let name_lc = name.to_ascii_lowercase();

    if name_lc == "score" && (rest.starts_with('<') || rest.starts_with('>')) {
        let (cmp, op_len) = match rest.get(..2) {
            Some(">=") => (Cmp::Ge, 2),
            Some("<=") => (Cmp::Le, 2),
            _ if rest.starts_with('>') => (Cmp::Gt, 1),
            _ => (Cmp::Lt, 1),
        };
        let vpos = at + name_len + op_len;
        let value = &body[name_len + op_len..];
        if value.is_empty() {
            return Err(err(at, body.len(), "empty value for `score`"));
        }
        return Ok((negated, Term::Score(cmp, parse_score(value, vpos)?)));
    }
    let Some(value) = rest.strip_prefix(':') else {
        return Err(err(at, body.len(), "expected field:value or score<op>N"));
    };
    if name.is_empty() {
        return Err(err(at, body.len(), "expected field:value or score<op>N"));
    }
    let vpos = at + name_len + 1;
    if value.is_empty() {
        return Err(err(at, body.len(), format!("empty value for `{name_lc}`")));
    }
    let bad = |msg: &str| err(vpos, value.len(), msg);
    let term = match name_lc.as_str() {
        "verdict" => Term::Verdict(
            pick(&VERDICTS, value).ok_or_else(|| bad("verdict must be one of allow, monitor, challenge, block"))?,
        ),
        "stage" => {
            if value.eq_ignore_ascii_case("none") {
                Term::Stage(None)
            } else {
                Term::Stage(Some(pick(&STAGES, value).ok_or_else(|| {
                    bad("stage must be one of recon, enumeration, exploitation, exfiltration, none")
                })?))
            }
        }
        "construct" => match value.strip_suffix('*') {
            Some(id) => Term::Construct { id: id.into(), prefix: true },
            None => Term::Construct { id: value.into(), prefix: false },
        },
        "technique" => Term::Technique(value.into()),
        "src" => Term::Src(parse_src(value).map_err(bad)?),
        "path" => {
            if !value.starts_with('/') {
                return Err(bad("path must be an absolute path prefix starting with `/`"));
            }
            Term::Path(value.into())
        }
        "method" => {
            if !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(bad("method must be an HTTP method token"));
            }
            Term::Method(value.to_ascii_uppercase())
        }
        "cause" => Term::Cause(
            pick(&CAUSES, value).ok_or_else(|| bad(&format!("cause must be one of {}", CAUSES.join(", "))))?,
        ),
        "exception" => {
            if value.contains(',') {
                return Err(bad("an exception id contains no comma"));
            }
            Term::Exception(value.into())
        }
        "group" => Term::Group(value.into()),
        "sampled" => Term::Sampled(match value.to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(bad("sampled must be true or false")),
        }),
        "score" => Term::Score(Cmp::Eq, parse_score(value, vpos)?),
        _ => {
            return Err(err(
                at,
                name_len.max(1),
                format!(
                    "unknown field `{name}`: use verdict, stage, construct, technique, src, path, method, cause, exception, group, sampled or score"
                ),
            ))
        }
    };
    Ok((negated, term))
}

/// The entry of `names` equal to `value` ignoring case (and `_`/`-`).
fn pick(names: &[&'static str], value: &str) -> Option<&'static str> {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| *c != '_' && *c != '-')
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let want = norm(value);
    names.iter().copied().find(|n| norm(n) == want)
}

fn parse_score(value: &str, vpos: usize) -> Result<u8, QueryError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(vpos, value.len(), "score takes a whole number 0..=100"));
    }
    match value.parse::<u32>() {
        Ok(n) if n <= 100 => Ok(n as u8),
        _ => Err(err(vpos, value.len(), "score must be in 0..=100")),
    }
}

const UNSUPPORTED_PREFIX: &str = "unsupported prefix: use /8, /16 or /24, or an address";
const BAD_SRC: &str = "src takes an IP address or an IPv4 CIDR";

/// An address (canonical source-key text) or an IPv4 /8, /16, /24.
fn parse_src(value: &str) -> Result<Src, &'static str> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let ip: Ipv4Addr = match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => v4,
            Ok(IpAddr::V6(_)) => return Err(UNSUPPORTED_PREFIX),
            Err(_) => return Err(BAD_SRC),
        };
        let octets = match prefix.parse::<u8>() {
            Ok(8) => 1,
            Ok(16) => 2,
            Ok(24) => 3,
            Ok(_) => return Err(UNSUPPORTED_PREFIX),
            Err(_) => return Err(BAD_SRC),
        };
        return Ok(Src::Cidr(ip.octets()[..octets].to_vec()));
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => Ok(Src::Addr(match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        })),
        Ok(ip) => Ok(Src::Addr(ip.to_string())),
        Err(_) => Err(BAD_SRC),
    }
}

/// Escape `%`, `_` and `\` for a `LIKE ... ESCAPE '\'` pattern.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl Term {
    /// The SQL fragment of this term and the value it binds, if any.
    fn sql(&self) -> (&'static str, Option<Value>) {
        let text = |s: &str| Some(Value::Text(s.to_string()));
        match self {
            Term::Verdict(v) => (T_VERDICT, text(v)),
            Term::Stage(Some(s)) => (T_STAGE, text(s)),
            Term::Stage(None) => (T_STAGE_NONE, None),
            Term::Construct { id, prefix: false } => (T_CONSTRUCT, text(id)),
            Term::Construct { id, prefix: true } => {
                (T_CONSTRUCT_LIKE, text(&(like_escape(id) + "%")))
            }
            Term::Technique(t) => (T_TECHNIQUE, text(t)),
            Term::Src(Src::Addr(a)) => (T_SRC, text(a)),
            Term::Src(Src::Cidr(octets)) => {
                let head: Vec<String> = octets.iter().map(u8::to_string).collect();
                (T_SRC_LIKE, text(&format!("{}.%", head.join("."))))
            }
            Term::Path(p) => (T_PATH, text(&(like_escape(p) + "%"))),
            Term::Method(m) => (T_METHOD, text(m)),
            Term::Cause(c) => (T_CAUSE, text(c)),
            Term::Exception(id) => (T_EXCEPTION, text(&format!("%,{},%", like_escape(id)))),
            Term::Group(g) => (T_GROUP, text(g)),
            Term::Sampled(b) => (T_SAMPLED, Some(Value::Integer(i64::from(*b)))),
            Term::Score(cmp, n) => {
                let frag = match cmp {
                    Cmp::Eq => T_SCORE_EQ,
                    Cmp::Gt => T_SCORE_GT,
                    Cmp::Lt => T_SCORE_LT,
                    Cmp::Ge => T_SCORE_GE,
                    Cmp::Le => T_SCORE_LE,
                };
                (frag, Some(Value::Integer(i64::from(*n))))
            }
        }
    }
}

impl GroupBy {
    fn index(self) -> usize {
        match self {
            GroupBy::Src => 0,
            GroupBy::Path => 1,
            GroupBy::Construct => 2,
            GroupBy::Stage => 3,
            GroupBy::Verdict => 4,
        }
    }
}

/// A cursor `"<ts_ms>:<event_id>"` as its parts.
fn parse_cursor(c: &str) -> Result<(i64, &str), QueryError> {
    let bad = || {
        err(
            0,
            0,
            format!("malformed cursor {c:?}: expected <ts_ms>:<event_id>"),
        )
    };
    let (ts, id) = c.split_once(':').ok_or_else(bad)?;
    if id.is_empty() || ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok((ts.parse().map_err(|_| bad())?, id))
}

/// Compile a request into one statement and its parameters. Validates
/// `from_ms < to_ms` and `1 <= limit <= 1000`.
///
/// A row query asks for `limit + 1` rows, so the caller can tell whether a
/// further page exists; a grouped query asks for `limit` groups.
pub fn compile(req: &Request) -> Result<Compiled, QueryError> {
    if req.from_ms >= req.to_ms {
        return Err(err(0, 0, "from must be before to"));
    }
    if !(1..=1000).contains(&req.limit) {
        return Err(err(0, 0, "limit must be between 1 and 1000"));
    }
    let to_i64 = |v: u64, what: &str| {
        i64::try_from(v).map_err(|_| err(0, 0, format!("{what} is out of range")))
    };
    let (from, to) = (to_i64(req.from_ms, "from")?, to_i64(req.to_ms, "to")?);
    let query = parse(&req.q)?;
    let cursor = match (&req.cursor, req.group_by) {
        (Some(_), Some(_)) => return Err(err(0, 0, "a cursor cannot be combined with group_by")),
        (Some(c), None) => Some(parse_cursor(c)?),
        (None, _) => None,
    };

    let mut parts: Vec<&'static str> = Vec::new();
    let mut params: Vec<Value> = vec![Value::Integer(from), Value::Integer(to)];
    parts.push(match req.group_by {
        Some(g) => GROUP_HEADS[g.index()],
        None => ROWS_HEAD,
    });
    for (negated, term) in &query.terms {
        let (frag, value) = term.sql();
        parts.push(AND);
        if *negated {
            // NULL columns count as "not matching", so a negation keeps them.
            parts.extend([NOT_OPEN, frag, NOT_CLOSE]);
        } else {
            parts.push(frag);
        }
        params.extend(value);
    }
    if let Some((ts, id)) = cursor {
        parts.extend([AND, CURSOR]);
        params.extend([
            Value::Integer(ts),
            Value::Integer(ts),
            Value::Text(id.to_string()),
        ]);
    }
    match req.group_by {
        Some(g) => {
            parts.push(GROUP_TAILS[g.index()]);
            params.push(Value::Integer(i64::from(req.limit)));
        }
        None => {
            parts.push(ROWS_TAIL);
            params.push(Value::Integer(i64::from(req.limit) + 1));
        }
    }
    Ok(Compiled {
        sql: parts.concat(),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    fn req(q: &str) -> Request {
        Request {
            q: q.into(),
            from_ms: 1000,
            to_ms: 2000,
            group_by: None,
            limit: 10,
            cursor: None,
        }
    }

    fn text(s: &str) -> Value {
        Value::Text(s.into())
    }

    /// The WHERE fragment and parameters a one-term row query adds to the window.
    fn one(q: &str) -> (String, Vec<Value>) {
        let c = compile(&req(q)).unwrap_or_else(|e| panic!("{q}: {e}"));
        let head = format!("{ROWS_HEAD}{AND}");
        let mid = c
            .sql
            .strip_prefix(&head)
            .unwrap_or_else(|| panic!("{}", c.sql))
            .strip_suffix(ROWS_TAIL)
            .unwrap_or_else(|| panic!("{}", c.sql));
        assert_eq!(c.params[..2], [Value::Integer(1000), Value::Integer(2000)]);
        assert_eq!(c.params.last(), Some(&Value::Integer(11)), "limit + 1");
        (mid.to_string(), c.params[2..c.params.len() - 1].to_vec())
    }

    #[test]
    fn every_field_compiles_to_its_fragment_and_params() {
        let like = "construct LIKE ? ESCAPE '\\'";
        let cases: Vec<(&str, &str, Vec<Value>)> = vec![
            ("verdict:block", "verdict = ?", vec![text("Block")]),
            ("verdict:ALLOW", "verdict = ?", vec![text("Allow")]),
            ("Verdict:Monitor", "verdict = ?", vec![text("Monitor")]),
            ("verdict:challenge", "verdict = ?", vec![text("Challenge")]),
            (
                "stage:exploitation",
                "stage = ?",
                vec![text("Exploitation")],
            ),
            ("stage:RECON", "stage = ?", vec![text("Recon")]),
            ("stage:none", "stage IS NULL", vec![]),
            (
                "construct:sqli.union-select",
                "construct = ?",
                vec![text("sqli.union-select")],
            ),
            ("construct:sqli.*", like, vec![text("sqli.%")]),
            ("construct:a_b%c\\d*", like, vec![text("a\\_b\\%c\\\\d%")]),
            ("construct:*", like, vec![text("%")]),
            ("construct:a%b", "construct = ?", vec![text("a%b")]),
            ("technique:T1190", "technique = ?", vec![text("T1190")]),
            ("src:10.1.2.3", "src_key = ?", vec![text("10.1.2.3")]),
            ("src:::ffff:10.1.2.3", "src_key = ?", vec![text("10.1.2.3")]),
            (
                "src:2001:0DB8:0:0:0:0:0:1",
                "src_key = ?",
                vec![text("2001:db8::1")],
            ),
            ("src:2001:db8::", "src_key = ?", vec![text("2001:db8::")]),
            (
                "src:10.9.9.9/8",
                "src_key LIKE ? ESCAPE '\\'",
                vec![text("10.%")],
            ),
            (
                "src:10.1.9.9/16",
                "src_key LIKE ? ESCAPE '\\'",
                vec![text("10.1.%")],
            ),
            (
                "src:10.1.2.0/24",
                "src_key LIKE ? ESCAPE '\\'",
                vec![text("10.1.2.%")],
            ),
            (
                "path:/admin",
                "path LIKE ? ESCAPE '\\'",
                vec![text("/admin%")],
            ),
            (
                "path:/a_b%c\\",
                "path LIKE ? ESCAPE '\\'",
                vec![text("/a\\_b\\%c\\\\%")],
            ),
            ("method:get", "method = ?", vec![text("GET")]),
            ("cause:ban", "cause_kind = ?", vec![text("Ban")]),
            (
                "cause:ChainEscalation",
                "cause_kind = ?",
                vec![text("ChainEscalation")],
            ),
            (
                "cause:NOEVIDENCE",
                "cause_kind = ?",
                vec![text("NoEvidence")],
            ),
            (
                "exception:referer-sql",
                "(',' || exceptions || ',') LIKE ? ESCAPE '\\'",
                vec![text("%,referer-sql,%")],
            ),
            (
                "exception:a_b",
                "(',' || exceptions || ',') LIKE ? ESCAPE '\\'",
                vec![text("%,a\\_b,%")],
            ),
            ("group:g-1", "group_id = ?", vec![text("g-1")]),
            ("sampled:true", "sampled = ?", vec![Value::Integer(1)]),
            ("sampled:FALSE", "sampled = ?", vec![Value::Integer(0)]),
            ("score>50", "score > ?", vec![Value::Integer(50)]),
            ("score<50", "score < ?", vec![Value::Integer(50)]),
            ("score>=0", "score >= ?", vec![Value::Integer(0)]),
            ("score<=100", "score <= ?", vec![Value::Integer(100)]),
            ("score:7", "score = ?", vec![Value::Integer(7)]),
        ];
        for (q, frag, params) in cases {
            let (got, p) = one(q);
            assert_eq!((got.as_str(), p), (frag, params), "{q}");
        }
    }

    #[test]
    fn parse_gives_typed_terms() {
        let q = parse("  verdict:block  -stage:none\tscore>=5 construct:sqli.* ").unwrap();
        assert_eq!(
            q.terms,
            vec![
                (false, Term::Verdict("Block")),
                (true, Term::Stage(None)),
                (false, Term::Score(Cmp::Ge, 5)),
                (
                    false,
                    Term::Construct {
                        id: "sqli.".into(),
                        prefix: true
                    }
                ),
            ]
        );
        assert!(parse("").unwrap().terms.is_empty());
        assert!(parse("   ").unwrap().terms.is_empty());
        assert_eq!(
            parse("src:10.0.0.0/8").unwrap().terms,
            vec![(false, Term::Src(Src::Cidr(vec![10])))]
        );
    }

    #[test]
    fn negation_wraps_the_fragment_null_safely() {
        let (sql, p) = one("-verdict:allow");
        assert_eq!(sql, "NOT COALESCE(verdict = ?, 0)");
        assert_eq!(p, vec![text("Allow")]);
        let (sql, p) = one("-stage:none");
        assert_eq!(sql, "NOT COALESCE(stage IS NULL, 0)");
        assert!(p.is_empty());
        let (sql, _) = one("-score>5");
        assert_eq!(sql, "NOT COALESCE(score > ?, 0)");
    }

    #[test]
    fn terms_are_anded_in_order_with_their_params() {
        let c = compile(&req("verdict:block -construct:sqli.* score>=10")).unwrap();
        assert_eq!(
            c.sql,
            format!(
                "{ROWS_HEAD} AND verdict = ? AND NOT COALESCE(construct LIKE ? ESCAPE '\\', 0) AND score >= ?{ROWS_TAIL}"
            )
        );
        assert_eq!(
            c.params,
            vec![
                Value::Integer(1000),
                Value::Integer(2000),
                text("Block"),
                text("sqli.%"),
                Value::Integer(10),
                Value::Integer(11)
            ]
        );
        let c = compile(&req("")).unwrap();
        assert_eq!(c.sql, format!("{ROWS_HEAD}{ROWS_TAIL}"));
    }

    #[test]
    fn errors_carry_byte_positions() {
        let cases: &[(&str, usize, usize, &str)] = &[
            ("verdict:maybe", 8, 5, "verdict"),
            ("colour:red", 0, 6, "unknown field"),
            ("-colour:red", 1, 6, "unknown field"),
            ("verdict:block colour:red", 14, 6, "unknown field"),
            ("score>101", 6, 3, "0..=100"),
            ("score:101", 6, 3, "0..=100"),
            ("score>x", 6, 1, "score"),
            ("score>", 0, 6, "empty"),
            ("score<=-1", 7, 2, "score"),
            (
                "src:10.0.0.0/12",
                4,
                11,
                "unsupported prefix: use /8, /16 or /24, or an address",
            ),
            ("src:10.0.0.1/32", 4, 11, "unsupported prefix"),
            ("src:2001:db8::/64", 4, 13, "unsupported prefix"),
            ("src:10.0.0.0/x", 4, 10, "src"),
            ("src:nonsense", 4, 8, "src"),
            ("src:300.1.1.1", 4, 9, "src"),
            ("verdict:", 0, 8, "empty"),
            ("-verdict:", 1, 8, "empty"),
            ("verdict:block verdict:", 14, 8, "empty"),
            ("-", 0, 1, "term"),
            ("verdict", 0, 7, "field:value"),
            (":block", 0, 6, "field:value"),
            ("verdict:block  oops", 15, 4, "field:value"),
            ("stage:middle", 6, 6, "stage"),
            ("cause:bogus", 6, 5, "cause"),
            ("sampled:maybe", 8, 5, "sampled"),
            ("path:admin", 5, 5, "absolute"),
            ("exception:a,b", 10, 3, "exception"),
            ("method:GET;DROP", 7, 8, "method"),
        ];
        for &(q, pos, len, msg) in cases {
            let e = parse(q).unwrap_err();
            assert_eq!((e.pos, e.len), (pos, len), "{q}: {e}");
            assert!(e.msg.contains(msg), "{q}: {e}");
            assert_eq!(
                compile(&req(q)).unwrap_err(),
                e,
                "{q}: compile reports the parse error"
            );
        }
        assert_eq!(
            parse("verdict:maybe")
                .unwrap_err()
                .to_string()
                .split(':')
                .next(),
            Some("error at 8")
        );
    }

    #[test]
    fn window_limit_and_cursor_are_validated() {
        let mut r = req("");
        r.from_ms = 2000;
        assert!(compile(&r).unwrap_err().msg.contains("from"));
        r.from_ms = 1000;
        r.to_ms = 1000;
        assert!(compile(&r).is_err());
        r.to_ms = u64::MAX;
        assert!(compile(&r).is_err(), "beyond SQLite integers");
        r.to_ms = 2000;
        r.limit = 0;
        assert!(compile(&r).unwrap_err().msg.contains("limit"));
        r.limit = 1001;
        assert!(compile(&r).unwrap_err().msg.contains("limit"));
        r.limit = 1000;
        assert!(compile(&r).is_ok());
        r.limit = 1;
        assert!(compile(&r).is_ok());

        for bad in ["", "abc", "12", "12:", ":e1", "x:e1", "-1:e1", " 5:e1"] {
            let mut r = req("");
            r.cursor = Some(bad.into());
            assert!(compile(&r).unwrap_err().msg.contains("cursor"), "{bad:?}");
        }
        let mut r = req("verdict:block");
        r.cursor = Some("1500:evt:9".into());
        let c = compile(&r).unwrap();
        assert_eq!(
            c.sql,
            format!("{ROWS_HEAD} AND verdict = ? AND {CURSOR}{ROWS_TAIL}")
        );
        assert_eq!(
            c.params[2..],
            [
                text("Block"),
                Value::Integer(1500),
                Value::Integer(1500),
                text("evt:9"),
                Value::Integer(11)
            ]
        );
        r.group_by = Some(GroupBy::Src);
        assert!(compile(&r).unwrap_err().msg.contains("cursor"));
    }

    #[test]
    fn group_by_compiles_to_a_counting_statement() {
        let mut r = req("verdict:block");
        r.group_by = Some(GroupBy::Construct);
        let c = compile(&r).unwrap();
        assert_eq!(
            c.sql,
            "SELECT COALESCE(construct, '(none)'), COUNT(*) FROM requests WHERE ts_ms >= ? AND ts_ms < ? AND verdict = ? GROUP BY COALESCE(construct, '(none)') ORDER BY COUNT(*) DESC, COALESCE(construct, '(none)') ASC LIMIT ?"
        );
        assert_eq!(
            c.params,
            vec![
                Value::Integer(1000),
                Value::Integer(2000),
                text("Block"),
                Value::Integer(10)
            ]
        );
        for (name, g) in [
            ("src", GroupBy::Src),
            ("path", GroupBy::Path),
            ("construct", GroupBy::Construct),
            ("stage", GroupBy::Stage),
            ("verdict", GroupBy::Verdict),
        ] {
            assert_eq!(GroupBy::from_name(name), Some(g));
            r.group_by = Some(g);
            let c = compile(&r).unwrap();
            let col = match g {
                GroupBy::Src => "src_key",
                GroupBy::Path => "path",
                GroupBy::Construct => "construct",
                GroupBy::Stage => "stage",
                GroupBy::Verdict => "verdict",
            };
            assert!(
                c.sql.starts_with(&format!(
                    "SELECT COALESCE({col}, '(none)'), COUNT(*) FROM requests"
                )),
                "{name}"
            );
        }
        assert_eq!(GroupBy::from_name("nope"), None);
    }

    #[test]
    fn stored_names_match_the_core_enums() {
        use vft_core::{CauseKind, Stage, Verdict};
        // Exhaustive matches: adding a variant breaks the build here until the lists are updated.
        let cause = |c: CauseKind| match c {
            CauseKind::NoEvidence
            | CauseKind::Detection
            | CauseKind::Honeypot
            | CauseKind::IntelDeny
            | CauseKind::Ban
            | CauseKind::ChainEscalation
            | CauseKind::Limit
            | CauseKind::Allowlisted => format!("{c:?}"),
        };
        let stage = |s: Stage| match s {
            Stage::Recon | Stage::Enumeration | Stage::Exploitation | Stage::Exfiltration => {
                format!("{s:?}")
            }
        };
        let verdict = |v: Verdict| match v {
            Verdict::Allow | Verdict::Monitor | Verdict::Challenge | Verdict::Block => {
                format!("{v:?}")
            }
        };
        for c in [
            CauseKind::NoEvidence,
            CauseKind::Detection,
            CauseKind::Honeypot,
            CauseKind::IntelDeny,
            CauseKind::Ban,
            CauseKind::ChainEscalation,
            CauseKind::Limit,
            CauseKind::Allowlisted,
        ] {
            assert!(CAUSES.contains(&cause(c).as_str()), "{c:?}");
        }
        assert_eq!(CAUSES.len(), 8);
        for s in [
            Stage::Recon,
            Stage::Enumeration,
            Stage::Exploitation,
            Stage::Exfiltration,
        ] {
            assert!(STAGES.contains(&stage(s).as_str()));
        }
        for v in [
            Verdict::Allow,
            Verdict::Monitor,
            Verdict::Challenge,
            Verdict::Block,
        ] {
            assert!(VERDICTS.contains(&verdict(v).as_str()));
        }
    }

    #[test]
    fn fragments_are_distinct_ascii_and_cover_the_columns() {
        for (i, f) in FRAGMENTS.iter().enumerate() {
            assert!(f.is_ascii() && !f.is_empty());
            assert!(!FRAGMENTS[..i].contains(f), "duplicate {f}");
        }
        assert_eq!(COLUMNS.split(", ").count(), 23);
        assert!(ROWS_HEAD.contains(COLUMNS));
    }

    /// Whether `sql` is a concatenation of [`FRAGMENTS`].
    fn is_concatenation(sql: &str) -> bool {
        if !sql.is_ascii() {
            return false;
        }
        let b = sql.as_bytes();
        let mut ok = vec![false; b.len() + 1];
        ok[b.len()] = true;
        for i in (0..b.len()).rev() {
            ok[i] = FRAGMENTS
                .iter()
                .any(|f| b[i..].starts_with(f.as_bytes()) && ok[i + f.len()]);
        }
        ok[0]
    }

    static COMPILED: AtomicUsize = AtomicUsize::new(0);

    /// Whether `q` compiled; when it did, its SQL is fragments and `?` only.
    fn check_safe(q: &str) -> bool {
        let mut r = req(q);
        let Ok(c) = compile(&r) else { return false };
        COMPILED.fetch_add(1, Relaxed);
        assert!(is_concatenation(&c.sql), "{q:?} -> {}", c.sql);
        assert_eq!(c.sql.matches('?').count(), c.params.len(), "{q:?}");
        // Grouped too.
        r.group_by = Some(GroupBy::Path);
        let g = compile(&r).unwrap();
        assert!(is_concatenation(&g.sql), "{q:?} -> {}", g.sql);
        assert_eq!(g.sql.matches('?').count(), g.params.len());
        true
    }

    #[test]
    fn hostile_queries_never_reach_the_sql_text() {
        for q in [
            "verdict:block'; DROP TABLE requests; --",
            "construct:' OR 1=1 --*",
            "path:/x' OR '1'='1",
            "src:10.0.0.1' OR 1=1",
            "group:\"; DELETE FROM requests",
            "exception:x%' ESCAPE '\\' OR 1=1 --",
            "method:get;drop",
            "technique:T1190'--",
            "-group:a'b",
        ] {
            check_safe(q);
        }
        // The values that do compile travel as parameters.
        let c = compile(&req("group:x';DROP;TABLE--")).unwrap();
        assert!(!c.sql.contains("DROP"));
        assert!(c.params.contains(&text("x';DROP;TABLE--")));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn arbitrary_text_compiles_to_fragments_or_errors(q in any::<String>()) {
            check_safe(&q);
        }

        #[test]
        fn term_shaped_text_compiles_to_fragments_or_errors(
            q in "(-?(verdict|stage|construct|technique|src|path|method|cause|exception|group|sampled|score|nope)(:|<|>|>=|<=|=)?[A-Za-z0-9./*%_'\\\\;:\" -]{0,14} ?){0,5}"
        ) {
            check_safe(&q);
        }

        /// Valid terms with arbitrary values always compile, and each value is bound verbatim.
        #[test]
        fn arbitrary_values_of_valid_terms_are_bound_not_inlined(
            group in "[^\\s]{1,16}",
            technique in "[^\\s]{1,16}",
            construct in "[^\\s*]{1,16}",
        ) {
            let q = format!("group:{group} -technique:{technique} construct:{construct}");
            prop_assert!(check_safe(&q), "{q:?}");
            let c = compile(&req(&q)).unwrap();
            prop_assert!(c.params.contains(&Value::Text(group)));
            prop_assert!(c.params.contains(&Value::Text(technique)));
            prop_assert!(c.params.contains(&Value::Text(construct)));
        }
    }

    #[test]
    fn the_safety_check_accepts_real_queries() {
        for q in [
            "verdict:block",
            "-stage:none score>3",
            "src:10.0.0.0/8 path:/a_b",
            "construct:x.*",
        ] {
            assert!(check_safe(q), "{q}");
        }
        assert!(!check_safe("nonsense"));
        assert!(COMPILED.load(Relaxed) >= 4);
    }
}
