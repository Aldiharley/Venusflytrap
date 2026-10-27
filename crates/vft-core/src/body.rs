//! Body classification (DQ2 spec section 4.2): a JSON body is split into its
//! string leaves (`json:<JSON-Pointer>`) and non-identifier keys
//! (`json-key:<pointer>`), so each value is inspected under its own name. Any
//! other body stays one `<body>` field (lossy UTF-8), as before, whatever its
//! type: form splitting is deferred (a construct that only forms across two
//! form values is lost when they are split), and multipart splitting is
//! deferred to DQ3 (it needs strict RFC 2046 framing, so that no backend value
//! is split across fields). `parse.body-json` restores `<body>` for JSON.
//!
//! **Invariant: nothing hides body bytes from inspection.** No Content-Type,
//! Content-Encoding or magic prefix switches inspection off. A body that is not
//! split as JSON is exactly one field whose source is the whole body (see
//! [`body_sources`]). JSON exception: a JSON body's bytes are covered by its
//! leaves, each with the whole body as its source; its string values (every
//! value of a repeated key: `json:/a`, `json:/a#2`) and non-identifier keys are
//! inspected, its structural characters, numbers, booleans, null and
//! identifier keys are not. A JSON body with no string leaf or non-identifier
//! key (`{"a":1}`, `[]`) is not split: it stays `<body>`.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::graph::sinks::{self, Disabled};
use crate::request::{Field, Location};

/// Fields one body may produce; past it the rest is joined into one
/// `json:#rest` field.
pub const MAX_BODY_FIELDS: usize = 256;
/// JSON nesting deeper than this is not split (the body is inspected whole).
pub const MAX_JSON_DEPTH: usize = 32;
/// Field names are labels, not payload: clipped to this many chars.
const MAX_NAME_CHARS: usize = 64;

/// What classification found, for the limits the shield records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BodyFacts {
    /// A body declared as a text class (json, text/*, form, xml) carried bytes
    /// that are not valid UTF-8. Never set for a binary or untyped body, so
    /// binary traffic gains no score.
    pub non_utf8: bool,
    /// A body declared JSON or ndjson did not parse, or nested deeper than
    /// [`MAX_JSON_DEPTH`], and was inspected whole.
    pub unparsed: bool,
}

/// An inspected field and the body byte ranges its text comes from. A JSON
/// leaf's text is unescaped, so its source is the whole body.
pub type Sourced = (Field, Vec<Range<usize>>);

/// Split `body` into inspectable fields. `content_type` is the request's
/// Content-Type value. With `parse.body-json` in `off`, a JSON body stays the
/// single `<body>` field.
pub fn body_fields(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts) {
    let (sourced, facts) = body_sources(content_type, body, off);
    (sourced.into_iter().map(|(f, _)| f).collect(), facts)
}

/// [`body_fields`] with each field's source ranges in `body`, for the
/// invariant in the module doc.
pub fn body_sources(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Sourced>, BodyFacts) {
    let mut facts = BodyFacts::default();
    if body.is_empty() {
        return (Vec::new(), facts);
    }
    let media = media_type(content_type.unwrap_or(""));
    let whole: Vec<Range<usize>> = std::iter::once(0..body.len()).collect();
    if let Some(leaves) = json_body(&media, body, off, &mut facts) {
        let mut fields: Vec<Sourced> = leaves.into_iter().map(|f| (f, whole.clone())).collect();
        cap(&mut fields);
        return (fields, facts);
    }
    let raw = text_of(body, text_class(&media), &mut facts);
    (vec![(Field { loc: Location::Body, name: "<body>".into(), raw }, whole)], facts)
}

/// The leaves of a JSON body, when its declared type or its first byte says
/// JSON, it parses and it has at least one leaf. A form or XML body is never
/// split (form splitting is deferred). A declared JSON body that does not
/// parse sets `unparsed`.
fn json_body(media: &str, bytes: &[u8], off: &Disabled, facts: &mut BodyFacts) -> Option<Vec<Field>> {
    if media == "application/x-www-form-urlencoded" || is_xml(media) || off.is(&sinks::PARSE_BODY_JSON) {
        return None;
    }
    let ndjson = media.contains("ndjson") || media.contains("jsonl");
    let declared = ndjson || media.contains("json");
    let sniffed = matches!(bytes.iter().find(|b| !b.is_ascii_whitespace()), Some(b'{' | b'['));
    if !(declared || sniffed) {
        return None;
    }
    let mut leaves = Vec::new();
    if !json(bytes, ndjson, &mut leaves) {
        if declared {
            facts.unparsed = true;
        }
        return None;
    }
    (!leaves.is_empty()).then_some(leaves)
}

/// The lower-cased media type of a Content-Type value, without parameters.
fn media_type(ct: &str) -> String {
    ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// An XML media type: `application/xml`, `text/xml` or a `+xml` suffix (not
/// any type that merely contains `xml`, such as the zip-based Office types).
fn is_xml(media: &str) -> bool {
    media == "application/xml" || media == "text/xml" || media.ends_with("+xml")
}

/// A declared text class: json (ndjson included), text/*, form, xml.
fn text_class(media: &str) -> bool {
    media.contains("json") || media.starts_with("text/") || media == "application/x-www-form-urlencoded" || is_xml(media)
}

/// Lossy UTF-8 text of a body; invalid bytes are noted only for a declared
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
/// its leaves. False when it does not parse or nests too deep.
fn json(bytes: &[u8], ndjson: bool, leaves: &mut Vec<Field>) -> bool {
    if ndjson {
        let Ok(text) = std::str::from_utf8(bytes) else { return false };
        let mut all = Vec::new();
        for (i, line) in text.lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
            if !collect(line.as_bytes(), &format!("/{i}"), 0, true, &mut all) {
                return false;
            }
        }
        leaves.extend(all);
        return true;
    }
    collect(bytes, "", 0, true, leaves)
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

/// At most [`MAX_BODY_FIELDS`] leaves: the overflow is joined (one per line)
/// into a last `json:#rest` field and never dropped.
fn cap(fields: &mut Vec<Sourced>) {
    if fields.len() <= MAX_BODY_FIELDS {
        return;
    }
    let rest: Vec<String> = fields.drain(MAX_BODY_FIELDS - 1..).map(|(f, _)| f.raw).collect();
    let src = fields[0].1.clone();
    fields.push((Field { loc: Location::Body, name: "json:#rest".into(), raw: rest.join("\n") }, src));
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
    fn a_multipart_body_is_one_body_field() {
        // Multipart splitting is deferred to DQ3 (strict RFC 2046 framing).
        assert!(sinks::lookup("parse.body-multipart").is_none());
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nMARKER-PART\r\n--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"id\":\"3\"}\r\n--XyZ--\r\n";
        assert_eq!(pairs("multipart/form-data; boundary=XyZ", mp), whole(mp));
        assert_eq!(pairs("multipart/form-data", mp), whole(mp));
    }

    #[test]
    fn invalid_utf8_is_a_fact_only_for_a_declared_text_class() {
        for ct in ["text/plain", "application/json", "application/x-www-form-urlencoded", "application/xml", "text/xml", "application/atom+xml", "text/html; charset=utf-8"] {
            let (f, facts) = body_fields(Some(ct), b"caf\xe9 au lait", &Disabled::default());
            assert_eq!(f[0].name, "<body>", "{ct}");
            assert!(facts.non_utf8, "{ct}");
        }
        for ct in [
            None,
            Some(""),
            Some("application/x-protobuf"),
            Some("application/octet-stream"),
            Some("image/png"),
            Some("application/x-protobuf; x=json"),
            Some("multipart/form-data; boundary=XyZ"),
        ] {
            let (_, facts) = body_fields(ct, &[0x0a, 0x02, 0xff, 0xfe], &Disabled::default());
            assert!(!facts.non_utf8, "{ct:?}");
        }
    }

    #[test]
    fn office_types_that_contain_xml_are_not_a_text_class() {
        let pk = b"PK\x03\x04\x14\x00\xff\xfe";
        for ct in [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-excel.sheet.macroenabled.12+zip; x=xml",
        ] {
            let (f, facts) = body_fields(Some(ct), pk, &Disabled::default());
            assert_eq!(f.len(), 1, "{ct}");
            assert!(!facts.non_utf8, "{ct}");
        }
        // And only real XML types skip JSON sniffing.
        assert_eq!(names("application/vnd.openxmlformats-officedocument.custom", br#"{"a":"1"}"#), vec!["json:/a"]);
        assert_eq!(names("application/atom+xml", br#"{"a":"1"}"#), vec!["<body>"]);
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
    fn json_without_a_string_leaf_stays_one_body_field() {
        for body in [&br#"{"a":1}"#[..], b"[]", b"{}", br#"[1, true, null, {"k": 2.5}]"#] {
            let (f, facts) = body_fields(Some("application/json"), body, &Disabled::default());
            assert_eq!(f.iter().map(|f| (f.name.clone(), f.raw.clone())).collect::<Vec<_>>(), whole(body));
            assert_eq!(facts, BodyFacts::default(), "it parsed");
        }
        // A non-identifier key is a leaf of its own.
        assert_eq!(names("application/json", br#"{"a b":1}"#), vec!["json-key:/a b"]);
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

    #[test]
    fn disabling_json_falls_back_to_the_single_body_field() {
        let off = Disabled::resolve(&["parse.body-json".into()]);
        assert_eq!(body_fields(Some("application/json"), br#"{"a":"1"}"#, &off).0.into_iter().map(|f| f.name).collect::<Vec<_>>(), vec!["<body>"]);
    }

    #[test]
    fn sources_cover_the_body() {
        // A non-JSON body is one field over the whole body; every JSON leaf's
        // source is the whole body.
        for (ct, body) in [("text/plain", &b"MARKER"[..]), ("application/json", br#"{"a":"x","b":"y"}"#)] {
            let (s, _) = body_sources(Some(ct), body, &Disabled::default());
            assert!(!s.is_empty());
            assert!(s.iter().all(|(_, r)| r.len() == 1 && r[0] == (0..body.len())), "{ct}");
        }
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
    }
}
