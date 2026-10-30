//! Scoped exceptions (sub-project C): a separate file of narrow, owned,
//! expiring exceptions, validated at load and compiled for the shield.
//! Three tiers: `ignore` (constructs do not score in the scope), `log-only`
//! (they do not score but stay visible as 0-point evidence) and
//! `skip-inspection` (matching fields are not inspected at all).

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::graph::sinks::{self, ConstructKind};
use crate::judgment::{Contribution, Family, FieldRef};
use crate::request::Location;

pub const DAY_MS: u64 = 86_400_000;
pub const MAX_LIFETIME_DAYS: u64 = 365;

/// Judged and attributed against exceptions with no `field` only.
pub const REQUEST_LEVEL: [&str; 3] = [
    sinks::RECON_SENSITIVE_PATH.id,
    sinks::HONEYPOT_DECOY_HIT.id,
    sinks::INTEL_SCANNER_UA.id,
];

const FAMILY_WILDCARDS: &[(&str, Family)] = &[
    ("sqli", Family::Sqli),
    ("xss", Family::Xss),
    ("cmd", Family::CommandInjection),
    ("path", Family::PathTraversal),
    ("recon", Family::Recon),
    ("honeypot", Family::Honeypot),
    ("intel", Family::Intel),
    ("anomaly", Family::Anomaly),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum ExceptionAction {
    Ignore,
    LogOnly,
    SkipInspection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum FieldLoc {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

impl FieldLoc {
    pub fn location(self) -> Location {
        match self {
            FieldLoc::Path => Location::Path,
            FieldLoc::Query => Location::Query,
            FieldLoc::Header => Location::Header,
            FieldLoc::Cookie => Location::Cookie,
            FieldLoc::Body => Location::Body,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct FieldMatch {
    pub loc: FieldLoc,
    /// ASCII case-insensitive glob (`*`, `?`) over the engine's field name.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct ExceptionScope {
    /// Empty = any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Matched on segment boundaries against the canonical path; any prefix
    /// but `/` only when the raw path is plain (see `Exceptions::select`).
    pub path_prefix: String,
    /// None = every field, plus the request-level constructs.
    #[serde(default)]
    pub field: Option<FieldMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct ExceptionEntry {
    pub id: String,
    pub action: ExceptionAction,
    /// Construct ids or family wildcards; empty for skip-inspection.
    #[serde(default)]
    pub constructs: Vec<String>,
    pub scope: ExceptionScope,
    pub owner: String,
    pub reason: String,
    pub created: String,
    pub modified: String,
    pub expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct ExceptionsFile {
    pub version: u32,
    #[serde(default)]
    pub exceptions: Vec<ExceptionEntry>,
}

impl ExceptionsFile {
    /// Parse YAML text without validating it (for tools that report per entry).
    pub fn parse(s: &str) -> Result<ExceptionsFile, Vec<Issue>> {
        serde_yaml::from_str(s).map_err(|e| vec![issue(None, "parse", e.to_string())])
    }
}

/// One validation problem; `code` is a stable string shared with the console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub id: Option<String>,
    pub code: &'static str,
    pub msg: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.id {
            Some(id) => write!(f, "{id}: {}", self.msg),
            None => write!(f, "{}", self.msg),
        }
    }
}

fn issue(id: Option<&str>, code: &'static str, msg: impl Into<String>) -> Issue {
    Issue { id: id.map(str::to_string), code, msg: msg.into() }
}

// --- dates (std only; proleptic Gregorian, UTC) ---

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY-MM-DD` (1970..=9999) as ms at 00:00 UTC; None if malformed or not a real date.
pub fn parse_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok()).flatten()
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if y < 1970 || !(1..=12).contains(&m) || d == 0 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1];
    if d > dim {
        return None;
    }
    Some(days_from_civil(y as i64, m, d) as u64 * DAY_MS)
}

/// The UTC date of `ms` as `YYYY-MM-DD`.
pub fn format_date(ms: u64) -> String {
    let (y, m, d) = civil_from_days((ms / DAY_MS) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

// --- matching helpers ---

/// ASCII case-insensitive glob with `*` and `?`.
fn glob(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<u8>, Vec<u8>) = (pat.bytes().map(|b| b.to_ascii_lowercase()).collect(), s.bytes().map(|b| b.to_ascii_lowercase()).collect());
    let (mut pi, mut si, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Segment-boundary prefix match: `/api` matches `/api` and `/api/x`, not `/apix`.
fn prefix_matches(prefix: &str, path: &str) -> bool {
    let p = prefix.trim_end_matches('/');
    if p.is_empty() {
        return true;
    }
    path == p || (path.starts_with(p) && path[p.len()..].starts_with('/'))
}

/// Whether canonicalisation cannot move the raw request path between segments:
/// no encoded `/`, `\`, `.`, `;` or `%` (ASCII case-insensitive), no `\` or
/// `;`, and no `.` or `..` segment. Only a plain path is matched against a
/// prefix other than `/`, so decoding can never carry a request into a scope.
fn plain_path(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    !["%2f", "%5c", "%2e", "%3b", "%25"].iter().any(|t| lower.contains(t))
        && !raw.contains(['\\', ';'])
        && !raw.split('/').any(|seg| seg == "." || seg == "..")
}

fn eligible(c: &sinks::ConstructInfo) -> bool {
    matches!(c.kind, ConstructKind::Sink | ConstructKind::Latent | ConstructKind::Signature) && c.id != sinks::INTEL_DENY_LISTED.id
}

/// Expand ids and family wildcards to eligible registered constructs (sorted, unique).
pub fn expand_constructs(names: &[String]) -> Result<Vec<&'static str>, Vec<Issue>> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut issues = Vec::new();
    for n in names {
        if let Some(fam) = n.strip_suffix(".*") {
            match FAMILY_WILDCARDS.iter().find(|(w, _)| *w == fam) {
                None => issues.push(issue(None, "unknown-construct", format!("unknown family wildcard {n:?}"))),
                Some((_, f)) => {
                    let ids: Vec<&'static str> = sinks::constructs().iter().filter(|c| c.family == Some(*f) && eligible(c)).map(|c| c.id).collect();
                    if ids.is_empty() {
                        issues.push(issue(None, "empty-wildcard", format!("{n:?} names no exceptable construct")));
                    }
                    out.extend(ids);
                }
            }
            continue;
        }
        if n.starts_with("chain.") || n == sinks::INTEL_DENY_LISTED.id {
            issues.push(issue(None, "forbidden-target", format!("{n} can never be excepted")));
            continue;
        }
        match sinks::lookup(n) {
            None => issues.push(issue(None, "unknown-construct", format!("unknown construct id {n:?}"))),
            Some(c) if c.kind == ConstructKind::Limit => issues.push(issue(None, "forbidden-target", format!("{n} is a limit and can never be excepted"))),
            Some(c) if matches!(c.kind, ConstructKind::Decoder | ConstructKind::Gate) => {
                issues.push(issue(None, "not-a-detection", format!("{n} is a {:?}, not a detection", c.kind)))
            }
            Some(c) => out.push(c.id),
        }
    }
    out.sort_unstable();
    out.dedup();
    if issues.is_empty() { Ok(out) } else { Err(issues) }
}

/// Every problem with one entry at `as_of_ms`.
pub fn validate_entry(e: &ExceptionEntry, as_of_ms: u64) -> Vec<Issue> {
    let id = Some(e.id.as_str());
    let mut v = Vec::new();
    if e.id.is_empty() || e.id.len() > 64 || !e.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        v.push(issue(id, "id-format", "id must be 1-64 chars of [a-z0-9-]"));
    }
    if e.owner.trim().is_empty() {
        v.push(issue(id, "required", "owner is required"));
    }
    if e.reason.trim().is_empty() {
        v.push(issue(id, "required", "reason is required"));
    }
    let date = |name: &str, s: &str, v: &mut Vec<Issue>| {
        let d = parse_date(s);
        if d.is_none() {
            v.push(issue(id, "date", format!("{name} {s:?} is not a YYYY-MM-DD date")));
        }
        d
    };
    let (c, m, x) = (date("created", &e.created, &mut v), date("modified", &e.modified, &mut v), date("expires", &e.expires, &mut v));
    if let (Some(c), Some(m)) = (c, m) {
        if m < c {
            v.push(issue(id, "modified-order", "modified is before created"));
        }
    }
    if let (Some(m), Some(x)) = (m, x) {
        if x <= m {
            v.push(issue(id, "expires-order", "expires must be after modified"));
        } else if x - m > MAX_LIFETIME_DAYS * DAY_MS {
            v.push(issue(id, "expires-too-far", format!("expires is more than {MAX_LIFETIME_DAYS} days after modified")));
        }
    }
    if let Some(x) = x {
        if x <= as_of_ms {
            v.push(issue(id, "expired", format!("expired on {} (as of {})", e.expires, format_date(as_of_ms))));
        }
    }
    for meth in &e.scope.methods {
        if meth.is_empty() || !meth.bytes().all(|b| b.is_ascii_alphabetic()) {
            v.push(issue(id, "method", format!("bad method {meth:?}")));
        }
    }
    if !e.scope.path_prefix.starts_with('/') {
        v.push(issue(id, "path-prefix", "path_prefix must start with /"));
    }
    if let Some(f) = &e.scope.field {
        if f.name.is_empty() {
            v.push(issue(id, "field-name", "field.name is empty"));
        }
    }
    match e.action {
        ExceptionAction::SkipInspection => {
            if !e.constructs.is_empty() {
                v.push(issue(id, "constructs-on-skip", "skip-inspection takes no constructs"));
            }
            match &e.scope.field {
                None => v.push(issue(id, "skip-needs-field", "skip-inspection needs scope.field")),
                Some(f) if f.name.contains(['*', '?']) => v.push(issue(id, "skip-wildcard", "skip-inspection needs an exact field name")),
                Some(_) => {}
            }
        }
        ExceptionAction::Ignore | ExceptionAction::LogOnly => {
            if e.constructs.is_empty() {
                v.push(issue(id, "constructs-missing", "constructs is required"));
            } else {
                match expand_constructs(&e.constructs) {
                    Err(is) => v.extend(is.into_iter().map(|i| Issue { id: Some(e.id.clone()), ..i })),
                    // Request-level constructs are reached only by field-less exceptions.
                    Ok(ids) if e.scope.field.is_some() && ids.iter().all(|c| REQUEST_LEVEL.contains(c)) => v.push(issue(
                        id,
                        "field-unreachable",
                        format!("constructs {} are request-level; remove scope.field so the exception can apply", ids.join(", ")),
                    )),
                    Ok(_) => {}
                }
            }
        }
    }
    v
}

/// Every problem with a whole file at `as_of_ms`.
pub fn validate_file(f: &ExceptionsFile, as_of_ms: u64) -> Vec<Issue> {
    let mut v = Vec::new();
    if f.version != 1 {
        v.push(issue(None, "version", format!("unsupported version {}", f.version)));
    }
    let mut seen = HashSet::new();
    for e in &f.exceptions {
        if !seen.insert(e.id.as_str()) {
            v.push(issue(Some(&e.id), "duplicate-id", "duplicate id"));
        }
        v.extend(validate_entry(e, as_of_ms));
    }
    v
}

/// When an exception's expiry is checked: against the `as_of` the file was
/// validated at (eval), or against each request's `now_ms` (serve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClock {
    Fixed,
    PerRequest,
}

#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    pub(crate) id: String,
    pub(crate) action: ExceptionAction,
    constructs: HashSet<&'static str>,
    methods: Vec<String>,
    prefix: String,
    field: Option<(Location, String)>,
    expires_ms: u64,
}

impl Compiled {
    fn field_matches(&self, f: Option<&FieldRef>) -> bool {
        match (&self.field, f) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some((loc, pat)), Some(f)) => f.loc == *loc && glob(pat, &f.name),
        }
    }
}

/// A validated, compiled exceptions file.
#[derive(Debug, Clone, Default)]
pub struct Exceptions {
    compiled: Vec<Compiled>,
    entries: Vec<ExceptionEntry>,
    as_of_ms: u64,
}

impl Exceptions {
    pub fn from_yaml_str(s: &str, as_of_ms: u64) -> Result<Exceptions, Vec<Issue>> {
        Self::compile(ExceptionsFile::parse(s)?, as_of_ms)
    }

    pub fn load(path: &Path, as_of_ms: u64) -> Result<Exceptions, Vec<Issue>> {
        let s = std::fs::read_to_string(path).map_err(|e| vec![issue(None, "io", format!("{}: {e}", path.display()))])?;
        Self::from_yaml_str(&s, as_of_ms)
    }

    pub fn compile(file: ExceptionsFile, as_of_ms: u64) -> Result<Exceptions, Vec<Issue>> {
        let issues = validate_file(&file, as_of_ms);
        if !issues.is_empty() {
            return Err(issues);
        }
        let compiled = file
            .exceptions
            .iter()
            .map(|e| Compiled {
                id: e.id.clone(),
                action: e.action,
                constructs: expand_constructs(&e.constructs).unwrap_or_default().into_iter().collect(),
                methods: e.scope.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                prefix: e.scope.path_prefix.clone(),
                field: e.scope.field.as_ref().map(|f| (f.loc.location(), f.name.clone())),
                expires_ms: parse_date(&e.expires).unwrap_or(0),
            })
            .collect();
        Ok(Exceptions { compiled, entries: file.exceptions, as_of_ms })
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }
    pub fn as_of_ms(&self) -> u64 {
        self.as_of_ms
    }
    pub fn entries(&self) -> &[ExceptionEntry] {
        &self.entries
    }

    /// One line per skip-inspection entry, for serve's startup log.
    pub fn warnings(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| e.action == ExceptionAction::SkipInspection)
            .map(|e| {
                let f = e.scope.field.as_ref().map(|f| format!("{:?}:{}", f.loc, f.name).to_ascii_lowercase()).unwrap_or_default();
                format!("warning: exception {} skips inspection of {f} under {} until {}", e.id, e.scope.path_prefix, e.expires)
            })
            .collect()
    }

    /// The live exceptions whose method and path match this request. A prefix
    /// of `/` matches every path; any other prefix matches the canonical path
    /// only when the raw path is plain (see [`plain_path`]), so a request
    /// whose path relies on decoding or dot segments gets full inspection.
    pub(crate) fn select(&self, method: &str, raw_path: &str, now_ms: u64) -> Selection<'_> {
        let canonical = crate::request::canonical_path(raw_path);
        let plain = plain_path(raw_path);
        let entries = self
            .compiled
            .iter()
            .filter(|c| now_ms < c.expires_ms)
            .filter(|c| c.methods.is_empty() || c.methods.iter().any(|m| m.eq_ignore_ascii_case(method)))
            .filter(|c| c.prefix.trim_end_matches('/').is_empty() || (plain && prefix_matches(&c.prefix, &canonical)))
            .collect();
        Selection { entries }
    }
}

/// The exceptions that apply to one request, in file order.
pub(crate) struct Selection<'a> {
    entries: Vec<&'a Compiled>,
}

impl<'a> Selection<'a> {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first skip-inspection exception matching `f`.
    pub(crate) fn skip_for(&self, f: &FieldRef) -> Option<&'a str> {
        self.entries.iter().copied().find(|c| c.action == ExceptionAction::SkipInspection && c.field_matches(Some(f))).map(|c| c.id.as_str())
    }

    /// Indexes of the ignore/log-only exceptions that apply to `f` (None = the
    /// request-level constructs, which only field-less exceptions reach).
    pub(crate) fn removers_for(&self, f: Option<&FieldRef>) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|&i| self.entries[i].action != ExceptionAction::SkipInspection && self.entries[i].field_matches(f))
            .collect()
    }

    pub(crate) fn removed_ids<'s>(&'s self, idx: &'s [usize]) -> impl Iterator<Item = &'static str> + 's {
        idx.iter().flat_map(move |&i| self.entries[i].constructs.iter().copied())
    }

    /// The exception (id, action) that removed `c` in the first pass, if any.
    pub(crate) fn attribute(&self, c: &Contribution) -> Option<(&'a str, ExceptionAction)> {
        let id = c.construct.as_deref()?;
        let f = if REQUEST_LEVEL.contains(&id) { None } else { c.field.as_ref() };
        self.entries
            .iter()
            .copied()
            .find(|e| e.action != ExceptionAction::SkipInspection && e.field_matches(f) && e.constructs.contains(id))
            .map(|e| (e.id.as_str(), e.action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AS_OF: &str = "2026-10-30";

    fn yaml(body: &str) -> String {
        format!("version: 1\nexceptions:\n{body}")
    }

    const REFERER: &str = "  - id: referer-sql\n    action: ignore\n    constructs: [sqli.*]\n    scope:\n      path_prefix: /api\n      field: { loc: header, name: Refer* }\n    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n";

    fn ex(body: &str) -> Exceptions {
        Exceptions::from_yaml_str(&yaml(body), parse_date(AS_OF).unwrap()).unwrap()
    }

    #[test]
    fn parse_reads_a_file_without_validating_it() {
        let f = ExceptionsFile::parse(&yaml(&REFERER.replace("2026-11-30", "2020-01-01"))).unwrap();
        assert_eq!(f.exceptions.len(), 1);
        assert!(!validate_file(&f, parse_date(AS_OF).unwrap()).is_empty(), "expired and ordered wrongly, still parsed");
        let bad = ExceptionsFile::parse("version: [").unwrap_err();
        assert_eq!(bad[0].code, "parse");
    }

    #[test]
    fn dates_round_trip_and_reject_impossible_days() {
        for s in ["1970-01-01", "2000-02-29", "2026-10-30", "2027-12-31"] {
            assert_eq!(format_date(parse_date(s).unwrap()), s);
        }
        assert_eq!(parse_date("1970-01-02"), Some(DAY_MS));
        for s in ["2026-02-29", "2100-02-29", "2026-13-01", "2026-00-10", "1969-12-31", "2026-1-01", "2026-10-3x"] {
            assert_eq!(parse_date(s), None, "{s}");
        }
    }

    #[test]
    fn glob_and_prefix_rules() {
        assert!(glob("Refer*", "referer") && glob("x-?d", "X-ID") && glob("*", "") && !glob("a?", "a"));
        assert!(glob("json:/user/*", "json:/user/id") && !glob("utm_*", "xutm_a"));
        assert!(prefix_matches("/", "/anything") && prefix_matches("/api", "/api") && prefix_matches("/api/", "/api/x"));
        assert!(!prefix_matches("/api", "/apix"));
    }

    #[test]
    fn sqli_wildcard_expands_by_family() {
        let ids = expand_constructs(&["sqli.*".into()]).unwrap();
        assert!(ids.contains(&"sqli.union-select") && ids.contains(&"sig.classic-or") && ids.contains(&"api.type-violation"));
        assert!(!ids.iter().any(|i| i.starts_with("limit.") || i.starts_with("decode.")));
        assert_eq!(expand_constructs(&["intel.*".into()]).unwrap(), vec!["intel.scanner-ua"]);
    }

    #[test]
    fn a_field_cannot_reach_request_level_constructs() {
        let as_of = parse_date(AS_OF).unwrap();
        let f = ExceptionsFile::parse(&yaml(&REFERER.replace("[sqli.*]", "[recon.*, intel.scanner-ua]"))).unwrap();
        let is = validate_file(&f, as_of);
        assert_eq!(is.iter().map(|i| i.code).collect::<Vec<_>>(), ["field-unreachable"]);
        assert_eq!(is[0].to_string(), "referer-sql: constructs intel.scanner-ua, recon.sensitive-path-probe are request-level; remove scope.field so the exception can apply");
        let mixed = ExceptionsFile::parse(&yaml(&REFERER.replace("[sqli.*]", "[recon.*, sqli.union-select]"))).unwrap();
        assert!(validate_file(&mixed, as_of).is_empty(), "one field construct makes the field reachable");
    }

    #[test]
    fn file_level_errors() {
        let as_of = parse_date(AS_OF).unwrap();
        let dup = yaml(&format!("{REFERER}{REFERER}"));
        let codes = |s: &str| Exceptions::from_yaml_str(s, as_of).unwrap_err().into_iter().map(|i| i.code).collect::<Vec<_>>();
        assert_eq!(codes(&dup), vec!["duplicate-id"]);
        assert_eq!(codes(&yaml(REFERER).replace("version: 1", "version: 2")), vec!["version"]);
        assert_eq!(codes(&yaml(&REFERER.replace("owner: o", "owner: o\n    extra: 1"))), vec!["parse"]);
        assert_eq!(codes(&yaml(&REFERER.replace("    reason: r\n", ""))), vec!["parse"]);
    }

    #[test]
    fn selection_respects_expiry_method_and_prefix() {
        let e = ex(&REFERER.replace("    scope:\n", "    scope:\n      methods: [get]\n"));
        let live = parse_date("2026-11-29").unwrap();
        assert!(!e.select("GET", "/api/search", live).is_empty());
        assert!(e.select("POST", "/api/search", live).is_empty());
        assert!(e.select("GET", "/apix", live).is_empty());
        assert!(e.select("GET", "/api", parse_date("2026-11-30").unwrap()).is_empty(), "as_of == expires is expired");
    }

    #[test]
    fn a_non_root_prefix_needs_a_plain_raw_path() {
        let hooks = ex(&REFERER.replace("path_prefix: /api", "path_prefix: /hooks"));
        let root = ex(&REFERER.replace("path_prefix: /api", "path_prefix: /"));
        let t = parse_date(AS_OF).unwrap();
        assert!(!hooks.select("GET", "/hooks/a", t).is_empty());
        assert!(!hooks.select("GET", "/hooks//a/", t).is_empty(), "empty segments are plain");
        for p in ["/admin/..%2fhooks", "/admin/%252e%252e/hooks", "/hooks;x", "/hooks%3bx/a", "/hooks%3Bx/a", "/hooks/./a", "/hooks%2F", "/hooks%2Fa", "/hooks%5Ca", "/hooks/%2E%2E/hooks", "/hooks\\a", "/a/../hooks"] {
            assert!(hooks.select("GET", p, t).is_empty(), "{p}");
            assert!(!root.select("GET", p, t).is_empty(), "{p}: / keeps matching every path");
        }
    }

    #[test]
    fn removers_and_attribution_follow_the_field() {
        let e = ex(REFERER);
        let sel = e.select("GET", "/api/x", parse_date(AS_OF).unwrap());
        let referer = FieldRef::header("Referer");
        assert_eq!(sel.removers_for(Some(&referer)), vec![0]);
        assert!(sel.removers_for(Some(&FieldRef::header("user-agent"))).is_empty());
        assert!(sel.removers_for(None).is_empty(), "a field-scoped exception never reaches request-level constructs");
        let c = |id: &str, f: FieldRef| Contribution {
            engine: "graph-taint", field: Some(f), construct: Some(id.into()), family: None,
            value: crate::lattice::FourValued::Dangerous, weight: 1.0, points: 0.0, shadow: false, exception: None,
        };
        assert_eq!(sel.attribute(&c("sqli.union-select", referer.clone())), Some(("referer-sql", ExceptionAction::Ignore)));
        assert_eq!(sel.attribute(&c("xss.script-tag", referer)), None);
    }

    #[test]
    fn skip_and_warnings() {
        let body = "  - id: skip-token\n    action: skip-inspection\n    scope:\n      path_prefix: /hook\n      field: { loc: header, name: x-signature }\n    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n";
        let e = ex(body);
        let sel = e.select("POST", "/hook", parse_date(AS_OF).unwrap());
        assert_eq!(sel.skip_for(&FieldRef::header("X-Signature")), Some("skip-token"));
        assert!(sel.removers_for(None).is_empty() && sel.removers_for(Some(&FieldRef::header("X-Signature"))).is_empty(), "a skip removes no constructs");
        assert_eq!(e.warnings().len(), 1);
        assert!(e.warnings()[0].contains("skip-token") && e.warnings()[0].contains("2026-11-30"));
    }
}
