//! Body classification (DQ2 spec section 4.2): split a request body into the
//! fields its consumer parses, so each JSON string leaf and multipart part is
//! inspected under its own name. Binary bodies get no text field. Anything
//! else, a form body included, stays one `<body>` field, as before: form
//! splitting is deferred, because a construct that only forms across two form
//! values is lost when they are split. Every class can be switched off by its
//! `parse.body-*` id, which restores `<body>` for it.

use crate::graph::sinks::{self, Disabled};
use crate::request::{Field, Location};

/// Fields one body may produce; past it the rest is joined into one `#rest` field.
pub const MAX_BODY_FIELDS: usize = 256;
/// JSON nesting deeper than this is not split (the body is inspected whole).
pub const MAX_JSON_DEPTH: usize = 32;
/// Field names are labels, not payload: clipped to this many chars.
const MAX_NAME_CHARS: usize = 64;

/// What classification found, for the limits the shield records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    /// A text-class body (or part) carried bytes that are not valid UTF-8.
    pub non_utf8: bool,
    /// A body declared JSON, ndjson or multipart did not parse, or nested
    /// deeper than [`MAX_JSON_DEPTH`], and was inspected whole.
    pub unparsed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Json,
    Multipart,
    Other,
}

struct Out {
    fields: Vec<Field>,
    facts: BodyFacts,
}

impl Out {
    fn push(&mut self, name: String, raw: String) {
        self.fields.push(Field { loc: Location::Body, name, raw });
    }
}

/// Where a classified byte run sits: the whole body, or one multipart part.
struct Scope {
    /// Name of the single text field when the run is not split.
    text_name: String,
    /// JSON Pointer prefix of the run's leaves.
    pointer: String,
    /// Multipart is parsed one level deep only.
    multipart_ok: bool,
}

impl Scope {
    fn top() -> Self {
        Scope { text_name: "<body>".into(), pointer: String::new(), multipart_ok: true }
    }

    fn part(name: &str) -> Self {
        Scope { text_name: format!("form:{}", clip(name)), pointer: format!("/{}", escape(name)), multipart_ok: false }
    }
}

/// Split `body` into inspectable fields. `content_type` is the request's
/// Content-Type value. A class whose `parse.body-*` id is in `off` falls back
/// to the single `<body>` field.
pub fn body_fields(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts) {
    let mut out = Out { fields: Vec::new(), facts: BodyFacts::default() };
    if body.is_empty() {
        return (out.fields, out.facts);
    }
    let class = classify(content_type.unwrap_or(""), body, off, &Scope::top(), &mut out);
    // Only JSON and multipart bodies produce more than one field.
    let rest = if class == Class::Json { "json:#rest" } else { "form:#rest" };
    cap(&mut out.fields, rest);
    (out.fields, out.facts)
}

fn classify(ct: &str, bytes: &[u8], off: &Disabled, scope: &Scope, out: &mut Out) -> Class {
    let lc = ct.to_ascii_lowercase();
    if is_binary(&lc, bytes) {
        if off.is(&sinks::PARSE_BODY_BINARY) {
            // Today's single lossy field; the bytes are binary, so no non-UTF-8 fact.
            out.push(scope.text_name.clone(), String::from_utf8_lossy(bytes).into_owned());
        }
        return Class::Other;
    }
    if lc.starts_with("multipart/") && scope.multipart_ok && !off.is(&sinks::PARSE_BODY_MULTIPART) {
        match param(ct, "boundary").filter(|b| b.len() <= 70).and_then(|b| parts(bytes, &b)) {
            Some(ps) => {
                for (i, p) in ps.into_iter().enumerate() {
                    part(i, p, off, out);
                }
                return Class::Multipart;
            }
            None => out.facts.unparsed = true,
        }
    }
    // A form body (or part) stays one text field: splitting it is deferred
    // (DQ2a), so it is not sniffed as JSON either.
    let form = lc.contains("x-www-form-urlencoded");
    if !form && !lc.contains("xml") && !off.is(&sinks::PARSE_BODY_JSON) {
        let ndjson = lc.contains("ndjson") || lc.contains("jsonl");
        let declared = ndjson || lc.contains("json");
        let sniffed = matches!(bytes.iter().find(|b| !b.is_ascii_whitespace()), Some(b'{' | b'['));
        if declared || sniffed {
            let mut leaves = Vec::new();
            if json(bytes, ndjson, &scope.pointer, &mut leaves) {
                out.fields.extend(leaves);
                return Class::Json;
            }
            if declared {
                out.facts.unparsed = true;
            }
        }
    }
    let text = text_of(bytes, out);
    out.push(scope.text_name.clone(), text);
    Class::Other
}

/// Binary by magic bytes, or a declared binary type whose bytes look binary.
/// A label alone never hides text (D13); zlib, GIF and PDF magic is printable,
/// so it also needs binary-looking bytes.
fn is_binary(lc: &str, b: &[u8]) -> bool {
    let strong = b.starts_with(&[0x1f, 0x8b])
        || b.starts_with(b"PK\x03\x04")
        || b.starts_with(b"\x89PNG\r\n\x1a\n")
        || b.starts_with(&[0xff, 0xd8, 0xff]);
    let weak = (b.len() >= 2 && b[0] == 0x78 && matches!(b[1], 0x01 | 0x5e | 0x9c | 0xda))
        || b.starts_with(b"GIF87a")
        || b.starts_with(b"GIF89a")
        || b.starts_with(b"%PDF-");
    let declared = lc.contains("protobuf")
        || lc.contains("octet-stream")
        || lc.starts_with("image/")
        || lc.starts_with("audio/")
        || lc.starts_with("video/");
    strong || ((weak || declared) && looks_binary(b))
}

/// A C0 control other than TAB, LF and CR, or bytes that are not valid UTF-8.
fn looks_binary(b: &[u8]) -> bool {
    b.iter().any(|&c| c < 0x20 && !matches!(c, b'\t' | b'\n' | b'\r')) || std::str::from_utf8(b).is_err()
}

/// The text of a text-class run; invalid UTF-8 is decoded lossily and noted.
fn text_of(bytes: &[u8], out: &mut Out) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            out.facts.non_utf8 = true;
            String::from_utf8_lossy(bytes).into_owned()
        }
    }
}

/// Parse one JSON document (or ndjson lines, as `/<line>` members) and collect
/// its leaves under `prefix`. False when it does not parse or nests too deep.
fn json(bytes: &[u8], ndjson: bool, prefix: &str, leaves: &mut Vec<Field>) -> bool {
    use serde_json::Value;
    if ndjson {
        let Ok(text) = std::str::from_utf8(bytes) else { return false };
        for (i, line) in text.lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
            let Ok(v) = serde_json::from_str::<Value>(line) else { return false };
            if !walk(&v, &format!("{prefix}/{i}"), 0, true, leaves) {
                return false;
            }
        }
        return true;
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => walk(&v, prefix, 0, true, leaves),
        Err(_) => false,
    }
}

fn walk(v: &serde_json::Value, ptr: &str, depth: usize, expand: bool, leaves: &mut Vec<Field>) -> bool {
    use serde_json::Value;
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match v {
        Value::String(s) => {
            if expand {
                if let Some(inner) = nested(s) {
                    let mut sub = Vec::new();
                    if walk(&inner, ptr, depth + 1, false, &mut sub) {
                        leaves.extend(sub);
                        return true;
                    }
                }
            }
            leaves.push(leaf(format!("json:{}", clip(ptr)), s.clone()));
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                if !walk(x, &format!("{ptr}/{i}"), depth + 1, expand, leaves) {
                    return false;
                }
            }
        }
        Value::Object(m) => {
            for (k, x) in m {
                let p = format!("{ptr}/{}", escape(k));
                if !k.chars().all(is_ident) {
                    leaves.push(leaf(format!("json-key:{}", clip(&p)), k.clone()));
                }
                if !walk(x, &p, depth + 1, expand, leaves) {
                    return false;
                }
            }
        }
        _ => {}
    }
    true
}

/// A string leaf that is itself a JSON object or array (expanded once, depth <= 2).
fn nested(s: &str) -> Option<serde_json::Value> {
    let t = s.trim_start();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(s).ok().filter(|v| v.is_object() || v.is_array())
}

fn leaf(name: String, raw: String) -> Field {
    Field { loc: Location::Body, name, raw }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '$' | '@')
}

/// RFC 6901 reference token escaping.
fn escape(k: &str) -> String {
    k.replace('~', "~0").replace('/', "~1")
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_NAME_CHARS).collect()
}

/// A `key=value` parameter of a header value such as Content-Type or
/// Content-Disposition (the first `;` item is the type itself).
fn param(value: &str, key: &str) -> Option<String> {
    value
        .split(';')
        .skip(1)
        .find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim().eq_ignore_ascii_case(key).then(|| v.trim().trim_matches('"').to_string())
        })
        .filter(|v| !v.is_empty())
}

fn find(h: &[u8], n: &[u8], from: usize) -> Option<usize> {
    if n.is_empty() || from > h.len() {
        return None;
    }
    h[from..].windows(n.len()).position(|w| w == n).map(|p| p + from)
}

/// The parts of a multipart body (content between delimiter lines), or None
/// when it is malformed: no delimiter, or no closing `--boundary--`.
fn parts<'a>(body: &'a [u8], boundary: &str) -> Option<Vec<&'a [u8]>> {
    let delim = format!("--{boundary}").into_bytes();
    let mut at = find(body, &delim, 0)? + delim.len();
    let mut out = Vec::new();
    loop {
        if body[at..].starts_with(b"--") {
            return Some(out);
        }
        let start = find(body, b"\n", at)? + 1;
        let mut next = start;
        let end = loop {
            let d = find(body, &delim, next)?;
            if d >= 1 && body[d - 1] == b'\n' {
                break d;
            }
            next = d + 1;
        };
        let mut content_end = end - 1;
        if content_end > start && body[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        out.push(&body[start..content_end.max(start)]);
        at = end + delim.len();
    }
}

/// One multipart part: its `filename` is a field of its own; its content is
/// classified by the part's Content-Type (one level: no nested multipart).
fn part(i: usize, p: &[u8], off: &Disabled, out: &mut Out) {
    let (head, content) = match find(p, b"\r\n\r\n", 0) {
        Some(h) => (&p[..h], &p[h + 4..]),
        None => match find(p, b"\n\n", 0) {
            Some(h) => (&p[..h], &p[h + 2..]),
            None => (p, &p[p.len()..]),
        },
    };
    let head = String::from_utf8_lossy(head);
    let (mut name, mut filename, mut ct) = (None, None, String::new());
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("content-disposition") {
            name = param(v, "name");
            filename = param(v, "filename");
        } else if k.trim().eq_ignore_ascii_case("content-type") {
            ct = v.trim().to_string();
        }
    }
    let name = name.unwrap_or_else(|| format!("part{i}"));
    if let Some(f) = filename {
        out.push(format!("form-file:{}", clip(&name)), f);
    }
    classify(&ct, content, off, &Scope::part(&name), out);
}

/// At most [`MAX_BODY_FIELDS`] fields: the overflow is joined (one per line)
/// into the last one and never dropped.
fn cap(fields: &mut Vec<Field>, rest_name: &str) {
    if fields.len() <= MAX_BODY_FIELDS {
        return;
    }
    let rest: Vec<String> = fields.drain(MAX_BODY_FIELDS - 1..).map(|f| f.raw).collect();
    fields.push(Field { loc: Location::Body, name: rest_name.into(), raw: rest.join("\n") });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(ct: &str, body: &[u8]) -> Vec<String> {
        body_fields(Some(ct), body, &Disabled::default()).0.into_iter().map(|f| f.name).collect()
    }

    fn pairs(ct: &str, body: &[u8]) -> Vec<(String, String)> {
        body_fields(Some(ct), body, &Disabled::default()).0.into_iter().map(|f| (f.name, f.raw)).collect()
    }

    #[test]
    fn empty_body_has_no_field() {
        assert!(body_fields(None, b"", &Disabled::default()).0.is_empty());
    }

    #[test]
    fn protobuf_with_control_bytes_has_no_field() {
        let (f, facts) = body_fields(Some("application/x-protobuf"), &[0x0a, 0x03, b'a', b'b', b'c', 0x10, 0x01], &Disabled::default());
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(facts, BodyFacts::default());
    }

    #[test]
    fn printable_protobuf_is_inspected_as_text() {
        assert_eq!(pairs("application/x-protobuf", b"hello world"), vec![("<body>".to_string(), "hello world".to_string())]);
    }

    #[test]
    fn gzip_magic_is_binary_whatever_the_declared_type() {
        let (f, facts) = body_fields(Some("application/json"), &[0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0], &Disabled::default());
        assert!(f.is_empty());
        assert!(!facts.non_utf8 && !facts.unparsed);
    }

    #[test]
    fn printable_magic_alone_does_not_hide_a_form_body() {
        assert_eq!(pairs("application/x-www-form-urlencoded", b"%PDF-a=1&b=2"), vec![("<body>".to_string(), "%PDF-a=1&b=2".to_string())]);
    }

    #[test]
    fn text_plain_json_is_split_into_string_leaves() {
        let mut n = names("text/plain", br#"{"user":{"id":"7","tags":["a","b"]},"n":5}"#);
        n.sort();
        assert_eq!(n, vec!["json:/user/id", "json:/user/tags/0", "json:/user/tags/1"]);
    }

    #[test]
    fn a_json_leaf_that_is_json_is_expanded_once() {
        let body = br#"{"payload":"{\"q\":\"x\",\"deep\":\"{\\\"z\\\":\\\"y\\\"}\"}"}"#;
        let p = pairs("application/json", body);
        assert!(p.contains(&("json:/payload/q".to_string(), "x".to_string())), "{p:?}");
        assert!(p.contains(&("json:/payload/deep".to_string(), r#"{"z":"y"}"#.to_string())), "{p:?}");
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn only_keys_with_non_identifier_characters_are_fields() {
        let n = names("application/json", br#"{"a b":"1","ok_key":"2"}"#);
        assert!(n.contains(&"json-key:/a b".to_string()), "{n:?}");
        assert!(!n.iter().any(|x| x == "json-key:/ok_key"));
    }

    #[test]
    fn json_pointer_tokens_are_escaped() {
        let n = names("application/json", br#"{"a/b":{"c~d":"1"}}"#);
        assert!(n.contains(&"json:/a~1b/c~0d".to_string()), "{n:?}");
    }

    #[test]
    fn ndjson_is_split_line_by_line() {
        let mut n = names("application/x-ndjson", b"{\"a\":\"1\"}\n\n{\"a\":\"2\"}\n");
        n.sort();
        assert_eq!(n, vec!["json:/0/a", "json:/1/a"]);
    }

    #[test]
    fn declared_json_that_does_not_parse_is_whole_and_unparsed() {
        let (f, facts) = body_fields(Some("application/json"), b"{\"a\":", &Disabled::default());
        assert_eq!(f.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["<body>"]);
        assert!(facts.unparsed);
    }

    #[test]
    fn json_nested_deeper_than_the_cap_is_whole() {
        let deep = format!("{}\"x\"{}", "[".repeat(MAX_JSON_DEPTH + 8), "]".repeat(MAX_JSON_DEPTH + 8));
        let (f, facts) = body_fields(Some("application/json"), deep.as_bytes(), &Disabled::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "<body>");
        assert!(facts.unparsed);
        // Sniffed (not declared) JSON falls back without the informational limit.
        let (f, facts) = body_fields(None, deep.as_bytes(), &Disabled::default());
        assert_eq!(f[0].name, "<body>");
        assert!(!facts.unparsed);
    }

    #[test]
    fn a_form_body_is_one_body_field() {
        // Form splitting is deferred (DQ2a): a form body stays whole, as
        // before, and is never sniffed as JSON.
        assert!(sinks::lookup("parse.body-form").is_none());
        for body in [&b"a=1&b=x%26y&&c"[..], br#"{"a":"1"}"#] {
            let raw = std::str::from_utf8(body).unwrap().to_string();
            assert_eq!(pairs("application/x-www-form-urlencoded; charset=utf-8", body), vec![("<body>".to_string(), raw)]);
        }
    }

    #[test]
    fn a_form_part_is_one_part_field() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2\r\n--XyZ--\r\n";
        assert_eq!(pairs("multipart/form-data; boundary=XyZ", body), vec![("form:f".to_string(), "a=1&b=2".to_string())]);
    }

    const MP: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"pic\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x01\r\n--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"id\":\"3\"}\r\n--XyZ--\r\n";

    #[test]
    fn multipart_parts_are_classified_by_their_own_type() {
        let (f, facts) = body_fields(Some("multipart/form-data; boundary=XyZ"), MP, &Disabled::default());
        let p: Vec<(String, String)> = f.into_iter().map(|f| (f.name, f.raw)).collect();
        assert_eq!(
            p,
            vec![
                ("form:note".to_string(), "hello".to_string()),
                ("form-file:pic".to_string(), "a.png".to_string()),
                ("json:/meta/id".to_string(), "3".to_string()),
            ]
        );
        assert_eq!(facts, BodyFacts::default());
    }

    #[test]
    fn multipart_without_a_closing_delimiter_is_whole() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello";
        let (f, facts) = body_fields(Some("multipart/form-data; boundary=XyZ"), body, &Disabled::default());
        assert_eq!(f.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["<body>"]);
        assert!(facts.unparsed);
    }

    #[test]
    fn a_disabled_class_falls_back_to_the_single_body_field() {
        let off = Disabled::resolve(&["parse.body-binary".into()]);
        let (f, facts) = body_fields(Some("application/octet-stream"), &[0x00, 0xff, 0x01], &off);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "<body>");
        assert!(!facts.non_utf8, "a binary body is not a text-class body");
        let off = Disabled::resolve(&["parse.body-json".into()]);
        assert_eq!(names_with(&off, "application/json", br#"{"a":"1"}"#), vec!["<body>"]);
        let off = Disabled::resolve(&["parse.body-multipart".into()]);
        assert_eq!(names_with(&off, "multipart/form-data; boundary=XyZ", MP), vec!["<body>"]);
    }

    fn names_with(off: &Disabled, ct: &str, body: &[u8]) -> Vec<String> {
        body_fields(Some(ct), body, off).0.into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn invalid_utf8_in_a_text_body_is_a_fact() {
        let (f, facts) = body_fields(Some("text/plain"), b"caf\xe9 au lait", &Disabled::default());
        assert_eq!(f[0].name, "<body>");
        assert!(facts.non_utf8);
        let (_, facts) = body_fields(Some("application/x-www-form-urlencoded"), b"a=caf\xe9", &Disabled::default());
        assert!(facts.non_utf8);
    }

    #[test]
    fn the_field_cap_joins_the_rest_and_drops_nothing() {
        let members: Vec<String> = (0..300).map(|i| format!("\"k{i:03}\":\"v{i}\"")).collect();
        let body = format!("{{{}}}", members.join(","));
        let (f, _) = body_fields(Some("application/json"), body.as_bytes(), &Disabled::default());
        assert_eq!(f.len(), MAX_BODY_FIELDS);
        let rest = f.last().unwrap();
        assert_eq!(rest.name, "json:#rest");
        assert_eq!(rest.raw.lines().count(), 300 - (MAX_BODY_FIELDS - 1));
        let mp: String = (0..300).map(|i| format!("--b\r\nContent-Disposition: form-data; name=\"p{i}\"\r\n\r\nv{i}\r\n")).collect::<String>() + "--b--\r\n";
        let (f, _) = body_fields(Some("multipart/form-data; boundary=b"), mp.as_bytes(), &Disabled::default());
        assert_eq!(f.len(), MAX_BODY_FIELDS);
        let rest = f.last().unwrap();
        assert_eq!(rest.name, "form:#rest");
        assert_eq!(rest.raw.lines().count(), 300 - (MAX_BODY_FIELDS - 1));
    }
}
