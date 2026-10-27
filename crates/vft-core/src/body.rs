//! Body classification (DQ2 spec section 4.2): split a request body into the
//! fields its consumer parses, so each JSON string leaf and multipart part is
//! inspected under its own name. Anything else stays one `<body>` field (lossy
//! UTF-8), as before, whatever its type: a form body (form splitting is
//! deferred, because a construct that only forms across two form values is
//! lost when they are split) and a binary-looking one alike. Every class can be
//! switched off by its `parse.body-*` id, which restores `<body>` for it.
//!
//! **Invariant: nothing hides body bytes from inspection.** There is no binary
//! class, and no Content-Type, Content-Encoding, file name or magic prefix
//! switches inspection off. Every byte of a body lies in exactly one inspected
//! non-JSON field's source range (see [`body_sources`]), or else only in the
//! source of JSON leaves: the whole `<body>`; or, for multipart, one
//! `form:<name>` field per part content plus one `form:#frame` field with every
//! other byte (preamble, delimiters, delimiter-line tails, part headers,
//! headerless parts, epilogue). JSON exception: a JSON body, or a multipart
//! part whose content is a JSON document (declared, or untyped or text that
//! parses), is inspected as its string leaves and non-identifier keys (every
//! value of a repeated key: `json:/a`, `json:/a#2`), each with the whole JSON
//! run as its source; its structural characters are not inspected.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::graph::sinks::{self, Disabled};
use crate::request::{Field, Location};

/// Fields one body may produce; past it the rest is joined into one `#rest` field.
pub const MAX_BODY_FIELDS: usize = 256;
/// JSON nesting deeper than this is not split (the body is inspected whole).
pub const MAX_JSON_DEPTH: usize = 32;
/// Field names are labels, not payload: clipped to this many chars.
const MAX_NAME_CHARS: usize = 64;
/// The field that carries a multipart body's framing.
const FRAME: &str = "form:#frame";

/// What classification found, for the limits the shield records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    /// A body (or part) declared as a text class (json, text/*, form, xml)
    /// carried bytes that are not valid UTF-8. Never set for a binary or
    /// untyped body, so binary traffic gains no score.
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

/// An inspected field and the body byte ranges its text comes from. A JSON
/// leaf's text is unescaped, so its source is the whole JSON run it came from.
pub type Sourced = (Field, Vec<Range<usize>>);

#[derive(Default)]
struct Out {
    fields: Vec<Sourced>,
    facts: BodyFacts,
}

impl Out {
    fn push(&mut self, name: String, raw: String, src: Vec<Range<usize>>) {
        self.fields.push((Field { loc: Location::Body, name, raw }, src));
    }
}

/// Split `body` into inspectable fields. `content_type` is the request's
/// Content-Type value. A class whose `parse.body-*` id is in `off` falls back
/// to the single `<body>` field.
pub fn body_fields(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts) {
    let (sourced, facts) = body_sources(content_type, body, off);
    (sourced.into_iter().map(|(f, _)| f).collect(), facts)
}

/// [`body_fields`] with each field's source ranges in `body`, for the
/// invariant in the module doc. A joined `#rest` field lists the ranges of
/// every field it joined.
pub fn body_sources(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Sourced>, BodyFacts) {
    let mut out = Out::default();
    if body.is_empty() {
        return (out.fields, out.facts);
    }
    let class = classify(content_type.unwrap_or(""), body, off, &mut out);
    // Only JSON and multipart bodies produce more than one field.
    let rest = if class == Class::Json { "json:#rest" } else { "form:#rest" };
    cap(&mut out.fields, rest);
    (out.fields, out.facts)
}

fn classify(ct: &str, bytes: &[u8], off: &Disabled, out: &mut Out) -> Class {
    let media = media_type(ct);
    if media.starts_with("multipart/") && !off.is(&sinks::PARSE_BODY_MULTIPART) {
        match param(ct, "boundary").filter(|b| b.len() <= 70).and_then(|b| layout(bytes, &b)) {
            Some(parts) => {
                multipart(bytes, &parts, off, out);
                return Class::Multipart;
            }
            None => out.facts.unparsed = true,
        }
    }
    // One source range: the whole body.
    let whole: Vec<Range<usize>> = std::iter::once(0..bytes.len()).collect();
    if json_run(&media, bytes, &whole, "", off, out) {
        return Class::Json;
    }
    let raw = text_of(bytes, text_class(&media), &mut out.facts);
    out.push("<body>".into(), raw, whole);
    Class::Other
}

/// Split a run (the whole body, or one multipart part's content) into JSON
/// leaves under `prefix` when its declared type or its first byte says JSON
/// and it parses. Each leaf's source is the whole run (the JSON exception of
/// the invariant). A form or xml run is never split: form splitting is
/// deferred (DQ2a). A declared JSON run that does not parse sets `unparsed`.
fn json_run(media: &str, bytes: &[u8], src: &[Range<usize>], prefix: &str, off: &Disabled, out: &mut Out) -> bool {
    let form = media == "application/x-www-form-urlencoded";
    if form || media.contains("xml") || off.is(&sinks::PARSE_BODY_JSON) {
        return false;
    }
    let ndjson = media.contains("ndjson") || media.contains("jsonl");
    let declared = ndjson || media.contains("json");
    let sniffed = matches!(bytes.iter().find(|b| !b.is_ascii_whitespace()), Some(b'{' | b'['));
    if !(declared || sniffed) {
        return false;
    }
    let mut leaves = Vec::new();
    if json(bytes, ndjson, prefix, &mut leaves) {
        out.fields.extend(leaves.into_iter().map(|f| (f, src.to_vec())));
        return true;
    }
    if declared {
        out.facts.unparsed = true;
    }
    false
}

/// The lower-cased media type of a Content-Type value, without parameters.
fn media_type(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// A declared text class: json (ndjson included), text/*, form, xml.
fn text_class(media: &str) -> bool {
    media.contains("json") || media.starts_with("text/") || media == "application/x-www-form-urlencoded" || media.contains("xml")
}

/// Lossy UTF-8 text of a run; invalid bytes are noted only for a declared
/// text class.
fn text_of(bytes: &[u8], text_class: bool, facts: &mut BodyFacts) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => {
            facts.non_utf8 |= text_class;
            String::from_utf8_lossy(bytes).into_owned()
        }
    }
}

/// Parse one JSON document (or ndjson lines, as `/<line>` members) and collect
/// its leaves under `prefix`. False when it does not parse or nests too deep.
fn json(bytes: &[u8], ndjson: bool, prefix: &str, leaves: &mut Vec<Field>) -> bool {
    if ndjson {
        let Ok(text) = std::str::from_utf8(bytes) else { return false };
        let mut all = Vec::new();
        for (i, line) in text.lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
            if !collect(line.as_bytes(), &format!("{prefix}/{i}"), 0, true, &mut all) {
                return false;
            }
        }
        leaves.extend(all);
        return true;
    }
    collect(bytes, prefix, 0, true, leaves)
}

/// Collect the leaves of one whole JSON text into `leaves`; nothing is added
/// when it does not parse, has trailing bytes or nests too deep.
fn collect(bytes: &[u8], ptr: &str, depth: usize, expand: bool, leaves: &mut Vec<Field>) -> bool {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let mut found = Vec::new();
    let ok = Leaves { ptr: ptr.to_string(), depth, expand, out: &mut found }.deserialize(&mut de).and_then(|()| de.end()).is_ok();
    if ok {
        leaves.extend(found);
    }
    ok
}

/// A serde visitor that yields every (pointer, string) entry of a JSON value,
/// repeated keys included (`serde_json::Value` keeps only the last). The
/// second and later values of a key get the pointer suffix `#2`, `#3`, ...
struct Leaves<'a> {
    ptr: String,
    depth: usize,
    /// A string leaf that is itself a JSON object or array is expanded once.
    expand: bool,
    out: &'a mut Vec<Field>,
}

impl Leaves<'_> {
    fn string(self, s: &str) {
        if self.expand {
            let t = s.trim_start();
            if (t.starts_with('{') || t.starts_with('[')) && collect(s.as_bytes(), &self.ptr, self.depth + 1, false, self.out) {
                return;
            }
        }
        self.out.push(leaf(format!("json:{}", clip(&self.ptr)), s.to_string()));
    }
}

impl<'de> DeserializeSeed<'de> for Leaves<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nested deeper than MAX_JSON_DEPTH"));
        }
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Leaves<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<(), E> {
        self.string(s);
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let Leaves { ptr, depth, expand, out } = self;
        let mut i = 0usize;
        while seq.next_element_seed(Leaves { ptr: format!("{ptr}/{i}"), depth: depth + 1, expand, out: &mut *out })?.is_some() {
            i += 1;
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Leaves { ptr, depth, expand, out } = self;
        let mut seen: HashMap<String, usize> = HashMap::new();
        while let Some(k) = map.next_key::<String>()? {
            let n = seen.entry(k.clone()).or_insert(0);
            *n += 1;
            let p = if *n == 1 { format!("{ptr}/{}", escape(&k)) } else { format!("{ptr}/{}#{n}", escape(&k)) };
            if !k.chars().all(is_ident) {
                out.push(leaf(format!("json-key:{}", clip(&p)), k));
            }
            map.next_value_seed(Leaves { ptr: p, depth: depth + 1, expand, out: &mut *out })?;
        }
        Ok(())
    }
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

/// The byte ranges of a multipart body's parts (between delimiter lines), in
/// order, or None when it is malformed: no delimiter, or no closing
/// `--boundary--`.
fn layout(body: &[u8], boundary: &str) -> Option<Vec<Range<usize>>> {
    let delim = format!("--{boundary}").into_bytes();
    let mut at = find(body, &delim, 0)? + delim.len();
    let mut parts = Vec::new();
    loop {
        if body[at..].starts_with(b"--") {
            return Some(parts);
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
        parts.push(start..content_end.max(start));
        at = end + delim.len();
    }
}

/// Each part content is JSON leaves under `/<name>` when it is a JSON
/// document (declared, or an untyped or text part that parses), else one
/// text field `form:<name>`, whatever the part's type, encoding, file name or
/// prefix. Every other byte is the `form:#frame` field, inserted first so the
/// field cap never folds it. Frame runs are joined with a line break so text
/// on both sides of a part is not glued.
fn multipart(body: &[u8], parts: &[Range<usize>], off: &Disabled, out: &mut Out) {
    let first = out.fields.len();
    let mut contents = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        let (at, name, ct) = part_head(i, &body[p.clone()]);
        let content = p.start + at..p.end;
        if !content.is_empty() {
            let media = media_type(&ct);
            let bytes = &body[content.clone()];
            let src = vec![content.clone()];
            if !json_run(&media, bytes, &src, &format!("/{}", escape(&name)), off, out) {
                let raw = text_of(bytes, text_class(&media), &mut out.facts);
                out.push(format!("form:{}", clip(&name)), raw, src);
            }
        }
        contents.push(content);
    }
    let mut runs = Vec::new();
    let mut at = 0;
    for c in &contents {
        if c.start > at {
            runs.push(at..c.start);
        }
        at = at.max(c.end);
    }
    if at < body.len() {
        runs.push(at..body.len());
    }
    if runs.is_empty() {
        return;
    }
    let joined = runs.iter().map(|r| &body[r.clone()]).collect::<Vec<_>>().join(&b'\n');
    // The frame belongs to the multipart body, which is not a text class.
    let raw = String::from_utf8_lossy(&joined).into_owned();
    out.fields.insert(first, (Field { loc: Location::Body, name: FRAME.into(), raw }, runs));
}

/// A part's header block: where its content starts, its `name` (`part<i>`
/// when none) and its declared Content-Type (empty when none). A part that
/// starts with a blank line has no headers; one without a blank line after
/// its headers is all header (its bytes are framing).
fn part_head(i: usize, p: &[u8]) -> (usize, String, String) {
    let (head, at) = if p.starts_with(b"\r\n") {
        (&p[..0], 2)
    } else if p.starts_with(b"\n") {
        (&p[..0], 1)
    } else {
        match find(p, b"\r\n\r\n", 0) {
            Some(h) => (&p[..h], h + 4),
            None => match find(p, b"\n\n", 0) {
                Some(h) => (&p[..h], h + 2),
                None => (p, p.len()),
            },
        }
    };
    let head = String::from_utf8_lossy(head);
    let (mut name, mut ct) = (None, String::new());
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim();
        if k.eq_ignore_ascii_case("content-disposition") {
            name = param(v, "name");
        } else if k.eq_ignore_ascii_case("content-type") {
            ct = v.trim().to_string();
        }
    }
    (at, name.unwrap_or_else(|| format!("part{i}")), ct)
}

/// At most [`MAX_BODY_FIELDS`] fields: the overflow is joined (one per line)
/// into the last one, with all of its source ranges (once each: JSON leaves
/// of one run share it), and never dropped.
fn cap(fields: &mut Vec<Sourced>, rest_name: &str) {
    if fields.len() <= MAX_BODY_FIELDS {
        return;
    }
    let (raws, srcs): (Vec<String>, Vec<Vec<Range<usize>>>) = fields.drain(MAX_BODY_FIELDS - 1..).map(|(f, s)| (f.raw, s)).unzip();
    let mut src: Vec<Range<usize>> = srcs.into_iter().flatten().collect();
    src.sort_by_key(|r| (r.start, r.end));
    src.dedup();
    let field = Field { loc: Location::Body, name: rest_name.into(), raw: raws.join("\n") };
    fields.push((field, src));
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

    fn whole(body: &[u8]) -> Vec<(String, String)> {
        vec![("<body>".to_string(), String::from_utf8_lossy(body).into_owned())]
    }

    #[test]
    fn empty_body_has_no_field() {
        assert!(body_fields(None, b"", &Disabled::default()).0.is_empty());
    }

    const GZ: [u8; 8] = [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0];
    const PROTO: [u8; 7] = [0x0a, 0x03, b'a', b'b', b'c', 0x10, 0x01];

    #[test]
    fn nothing_hides_a_body_whatever_its_type_or_prefix() {
        // Binary magic, control bytes or a binary label never remove the
        // body: it is one lossy `<body>` field, as before classification.
        let mut png_text = b"\x89PNG\r\n\x1a\n".to_vec();
        png_text.extend_from_slice(b"MARKER-TEXT");
        for ct in ["", "application/x-protobuf", "application/octet-stream", "application/gzip", "image/png", "application/json", "text/plain", "application/x-www-form-urlencoded"] {
            for body in [&GZ[..], &PROTO[..], &png_text[..]] {
                assert_eq!(pairs(ct, body), whole(body), "{ct:?}");
            }
        }
        assert_eq!(pairs("application/x-protobuf", b"hello world"), whole(b"hello world"));
    }

    #[test]
    fn invalid_utf8_is_a_fact_only_for_a_declared_text_class() {
        for ct in ["text/plain", "application/json", "application/x-www-form-urlencoded", "application/xml", "text/html; charset=utf-8"] {
            let (f, facts) = body_fields(Some(ct), b"caf\xe9 au lait", &Disabled::default());
            assert_eq!(f[0].name, "<body>", "{ct}");
            assert!(facts.non_utf8, "{ct}");
        }
        for ct in [None, Some(""), Some("application/x-protobuf"), Some("application/octet-stream"), Some("image/png"), Some("application/x-protobuf; x=json")] {
            let (_, facts) = body_fields(ct, &[0x0a, 0x02, 0xff, 0xfe], &Disabled::default());
            assert!(!facts.non_utf8, "{ct:?}");
        }
        // A part's own declared type decides; an untyped part is not a text class.
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\n\xff\xfe\r\n--XyZ\r\nContent-Disposition: form-data; name=\"o\"\r\nContent-Type: application/octet-stream\r\n\r\n\xff\xfe\r\n--XyZ--\r\n";
        assert!(!body_fields(Some("multipart/form-data; boundary=XyZ"), mp, &Disabled::default()).1.non_utf8);
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"t\"\r\nContent-Type: text/plain\r\n\r\n\xff\xfe\r\n--XyZ--\r\n";
        assert!(body_fields(Some("multipart/form-data; boundary=XyZ"), mp, &Disabled::default()).1.non_utf8);
    }

    #[test]
    fn printable_magic_alone_does_not_hide_a_form_body() {
        assert_eq!(pairs("application/x-www-form-urlencoded", b"%PDF-a=1&b=2"), whole(b"%PDF-a=1&b=2"));
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
    fn duplicate_json_keys_keep_every_value() {
        let p = pairs("application/json", br#"{"a":"MARKER-1","b":{"c":"x"},"a":"MARKER-2","a":"MARKER-3"}"#);
        assert!(p.contains(&("json:/a".into(), "MARKER-1".into())), "{p:?}");
        assert!(p.contains(&("json:/a#2".into(), "MARKER-2".into())), "{p:?}");
        assert!(p.contains(&("json:/a#3".into(), "MARKER-3".into())), "{p:?}");
        // The nested expansion goes through the same visitor.
        let p = pairs("application/json", br#"{"s":"{\"k\":\"MARKER-4\",\"k\":\"MARKER-5\"}"}"#);
        assert!(p.contains(&("json:/s/k".into(), "MARKER-4".into())), "{p:?}");
        assert!(p.contains(&("json:/s/k#2".into(), "MARKER-5".into())), "{p:?}");
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
        assert!(sinks::lookup("parse.body-binary").is_none());
        for body in [&b"a=1&b=x%26y&&c"[..], br#"{"a":"1"}"#] {
            assert_eq!(pairs("application/x-www-form-urlencoded; charset=utf-8", body), whole(body));
        }
    }

    fn parts_of(ct: &str, body: &[u8]) -> Vec<(String, String)> {
        pairs(ct, body).into_iter().filter(|(n, _)| n != "form:#frame").collect()
    }

    fn frame_of(ct: &str, body: &[u8]) -> String {
        pairs(ct, body).into_iter().find(|(n, _)| n == "form:#frame").map(|(_, r)| r).expect("a form:#frame field")
    }

    const MP: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"pic\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x01\r\n--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"id\":\"3\"}\r\n--XyZ--\r\n";

    #[test]
    fn a_multipart_part_is_one_text_field_or_json_leaves() {
        let (f, facts) = body_fields(Some("multipart/form-data; boundary=XyZ"), MP, &Disabled::default());
        assert_eq!(f[0].name, "form:#frame", "the frame comes first");
        let p: Vec<(String, String)> = f[1..].iter().map(|f| (f.name.clone(), f.raw.clone())).collect();
        assert_eq!(
            p,
            vec![
                ("form:note".to_string(), "hello".to_string()),
                ("form:pic".to_string(), String::from_utf8_lossy(b"\x89PNG\r\n\x1a\n\x00\x01").into_owned()),
                ("json:/meta/id".to_string(), "3".to_string()),
            ]
        );
        // An untyped or text part that parses as JSON is split too; one that
        // does not parse stays text.
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\n{\"k\":\"MARKER-U\",\"a b\":\"x\"}\r\n--XyZ\r\nContent-Disposition: form-data; name=\"t\"\r\nContent-Type: text/plain\r\n\r\n[\"MARKER-T\"]\r\n--XyZ\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\n{MARKER-NOT-JSON\r\n--XyZ--\r\n";
        let p = parts_of("multipart/form-data; boundary=XyZ", mp);
        for want in [("json:/u/k", "MARKER-U"), ("json-key:/u/a b", "a b"), ("json:/t/0", "MARKER-T"), ("form:n", "{MARKER-NOT-JSON")] {
            assert!(p.contains(&(want.0.to_string(), want.1.to_string())), "{want:?} not in {p:?}");
        }
        // Delimiters and part headers, file names included, are in the frame once.
        assert!(f[0].raw.contains("--XyZ") && f[0].raw.contains("filename=\"a.png\"") && f[0].raw.contains("Content-Type: image/png"), "{:?}", f[0].raw);
        assert_eq!(facts, BodyFacts::default());
        // A form or untyped part with binary magic is text too.
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2\r\n--XyZ\r\nContent-Disposition: form-data; name=\"u\"\r\n\r\n\x1f\x8b\x08\x00MARKER-UNTYPED\r\n--XyZ--\r\n";
        let p = parts_of("multipart/form-data; boundary=XyZ", mp);
        assert_eq!(p[0], ("form:f".to_string(), "a=1&b=2".to_string()));
        assert!(p[1].0 == "form:u" && p[1].1.contains("MARKER-UNTYPED"), "{p:?}");
    }

    #[test]
    fn multipart_framing_is_inspected_as_one_frame_field() {
        let body = b"MARKER-PREAMBLE\r\n--XyZ MARKER-DELIM-TAIL\r\nContent-Disposition: form-data; name=\"MARKER-NAME\"; filename=\"MARKER-FILE\"\r\nX-Extra: MARKER-HEADER\r\n\r\nhello\r\n--XyZ\r\nMARKER-HEADERLESS\r\n--XyZ--\r\nMARKER-EPILOGUE";
        let ct = "multipart/form-data; boundary=XyZ";
        let frame = frame_of(ct, body);
        for m in ["MARKER-PREAMBLE", "--XyZ", "MARKER-DELIM-TAIL", "MARKER-NAME", "MARKER-FILE", "MARKER-HEADER", "MARKER-HEADERLESS", "MARKER-EPILOGUE"] {
            assert!(frame.contains(m), "{m} missing from {frame:?}");
        }
        assert!(!frame.contains("hello"), "inspected content is not repeated: {frame:?}");
        assert_eq!(parts_of(ct, body), vec![("form:MARKER-NAME".to_string(), "hello".to_string())]);
        // An empty header block is not a headerless part.
        assert_eq!(parts_of(ct, b"--XyZ\r\n\r\nhello\r\n--XyZ--\r\n"), vec![("form:part0".to_string(), "hello".to_string())]);
    }

    #[test]
    fn multipart_sources_cover_every_byte_once() {
        // Every byte lies in exactly one non-JSON field, or only in the JSON
        // leaves of its part (whose source is the whole JSON part content).
        let (s, _) = body_sources(Some("multipart/form-data; boundary=XyZ"), MP, &Disabled::default());
        let (mut text, mut json) = (vec![0u32; MP.len()], vec![0u32; MP.len()]);
        for (f, ranges) in &s {
            let hits = if f.name.starts_with("json") { &mut json } else { &mut text };
            for r in ranges {
                for h in &mut hits[r.clone()] {
                    *h += 1;
                }
            }
        }
        assert!((0..MP.len()).all(|i| text[i] == 1 || (text[i] == 0 && json[i] > 0)), "{text:?} {json:?}");
        assert!(json.iter().any(|&h| h > 0), "the JSON part has sources");
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
        let off = Disabled::resolve(&["parse.body-json".into()]);
        assert_eq!(names_with(&off, "application/json", br#"{"a":"1"}"#), vec!["<body>"]);
        let off = Disabled::resolve(&["parse.body-multipart".into()]);
        assert_eq!(names_with(&off, "multipart/form-data; boundary=XyZ", MP), vec!["<body>"]);
    }

    fn names_with(off: &Disabled, ct: &str, body: &[u8]) -> Vec<String> {
        body_fields(Some(ct), body, off).0.into_iter().map(|f| f.name).collect()
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
        // The frame field comes first, so it takes one of the kept slots.
        assert_eq!(f[0].name, "form:#frame");
        let rest = f.last().unwrap();
        assert_eq!(rest.name, "form:#rest");
        assert_eq!(rest.raw.lines().count(), 300 - (MAX_BODY_FIELDS - 2));
        // The joined rest keeps its sources, so every byte still lies in one field.
        let (s, _) = body_sources(Some("multipart/form-data; boundary=b"), mp.as_bytes(), &Disabled::default());
        assert_eq!(s.iter().flat_map(|(_, r)| r.iter().map(|r| r.len())).sum::<usize>(), mp.len());
    }
}
