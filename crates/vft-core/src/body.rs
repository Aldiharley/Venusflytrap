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

use std::borrow::Cow;
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
        return (leaves.into_iter().map(|f| (f, whole.clone())).collect(), facts);
    }
    let raw = text_of(body, text_class(&media), &mut facts);
    (vec![(Field { loc: Location::Body, name: "<body>".into(), raw }, whole)], facts)
}

/// The leaves of a JSON body, when its declared type or its first byte says
/// JSON, it parses and it has at least one leaf. At most [`MAX_BODY_FIELDS`]:
/// past it the rest is joined into a last `json:#rest` field. A form or XML body is never
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
    let mut out = Out::default();
    if !json(bytes, ndjson, &mut out) {
        if declared {
            facts.unparsed = true;
        }
        return None;
    }
    (!out.is_empty()).then(|| out.finish())
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
/// its leaves into `out`. False when it does not parse or nests too deep; the
/// caller then discards `out`.
fn json(bytes: &[u8], ndjson: bool, out: &mut Out) -> bool {
    if ndjson {
        let Ok(text) = std::str::from_utf8(bytes) else { return false };
        for (i, line) in text.lines().map(str::trim).filter(|l| !l.is_empty()).enumerate() {
            let ptr = if out.spilled { String::new() } else { child("", &i.to_string(), 1).into_owned() };
            if !collect(line.as_bytes(), &ptr, 0, true, out) {
                return false;
            }
        }
        return true;
    }
    collect(bytes, "", 0, true, out)
}

/// Collect the leaves of one whole JSON text into `out`. False when it does
/// not parse, has trailing bytes or nests too deep; `out` may then hold part
/// of it, so a caller that must keep `out` collects into [`Out::under`].
fn collect(bytes: &[u8], ptr: &str, depth: usize, expand: bool, out: &mut Out) -> bool {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    Leaves { ptr: Cow::Borrowed(ptr), depth, expand, out }.deserialize(&mut de).and_then(|()| de.end()).is_ok()
}

/// The leaves of one body under the field cap, in document order. The first
/// [`MAX_BODY_FIELDS`] are fields; once a body has more, the last field and
/// every later value go straight into the `json:#rest` text (one per line).
/// Past the cap no name and no `Field` is built, and no text is dropped.
#[derive(Default)]
struct Out {
    fields: Vec<Field>,
    rest: String,
    /// Values in `rest`.
    rest_n: usize,
    /// Past the cap: every value goes to `rest`.
    spilled: bool,
}

impl Out {
    /// A scratch collector for a nested expansion. It is past the cap when
    /// `self` is, so nothing in it builds a name either.
    fn under(&self) -> Out {
        Out { spilled: self.spilled, ..Out::default() }
    }

    fn room(&self) -> bool {
        !self.spilled && self.fields.len() < MAX_BODY_FIELDS
    }

    /// Add one value; `name` is called only when the value becomes a field.
    fn push(&mut self, name: impl FnOnce() -> String, raw: &str) {
        if self.room() {
            self.fields.push(leaf(name(), raw.to_string()));
        } else {
            self.spill();
            self.append(raw, 1);
        }
    }

    /// Enter the past-the-cap state. A full field list gives up its last
    /// field to `rest`, so that `json:#rest` takes the last slot.
    fn spill(&mut self) {
        if !self.spilled {
            self.spilled = true;
            if self.fields.len() == MAX_BODY_FIELDS {
                if let Some(last) = self.fields.pop() {
                    self.append(&last.raw, 1);
                }
            }
        }
    }

    /// Append `n` values (already joined one per line) to `rest`.
    fn append(&mut self, text: &str, n: usize) {
        if n == 0 {
            return;
        }
        if self.rest_n > 0 {
            self.rest.push('\n');
        }
        self.rest.push_str(text);
        self.rest_n += n;
    }

    /// Add a nested expansion's values after the ones already here.
    fn absorb(&mut self, nested: Out) {
        for f in nested.fields {
            if self.room() {
                self.fields.push(f);
            } else {
                self.spill();
                self.append(&f.raw, 1);
            }
        }
        if nested.rest_n > 0 {
            self.spill();
            self.append(&nested.rest, nested.rest_n);
        }
    }

    fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.rest_n == 0
    }

    fn finish(mut self) -> Vec<Field> {
        if self.rest_n > 0 {
            self.fields.push(leaf("json:#rest".into(), self.rest));
        }
        self.fields
    }
}

/// A serde visitor that yields every (pointer, string) entry of a JSON value,
/// repeated keys included (`serde_json::Value` keeps only the last). The
/// second and later values of a key get the pointer suffix `#2`, `#3`, ...
/// `ptr` is clipped to [`MAX_NAME_CHARS`] as it is built (names are labels),
/// so a long key or a deep path is never copied per value. Past the cap it is
/// empty.
struct Leaves<'a> {
    ptr: Cow<'a, str>,
    depth: usize,
    /// A string leaf that is itself a JSON object or array is expanded once.
    expand: bool,
    out: &'a mut Out,
}

impl Leaves<'_> {
    fn string(self, s: &str) {
        if self.expand {
            let t = s.trim_start();
            if t.starts_with('{') || t.starts_with('[') {
                let mut nested = self.out.under();
                if collect(s.as_bytes(), &self.ptr, self.depth + 1, false, &mut nested) {
                    self.out.absorb(nested);
                    return;
                }
            }
        }
        let ptr = &self.ptr;
        self.out.push(|| format!("json:{}", clip(ptr)), s);
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
        // A pointer already at the name limit is every element's pointer.
        let at_limit = ptr.chars().count() >= MAX_NAME_CHARS;
        let mut i = 0usize;
        loop {
            let p = if out.spilled {
                Cow::Borrowed("")
            } else if at_limit {
                Cow::Borrowed(&*ptr)
            } else {
                child(&ptr, &i.to_string(), 1)
            };
            if seq.next_element_seed(Leaves { ptr: p, depth: depth + 1, expand, out: &mut *out })?.is_none() {
                return Ok(());
            }
            i += 1;
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Leaves { ptr, depth, expand, out } = self;
        let mut seen: HashMap<String, usize> = HashMap::new();
        while let Some(k) = map.next_key::<String>()? {
            let p = if out.spilled {
                Cow::Borrowed("")
            } else {
                let n = seen.entry(k.clone()).or_insert(0);
                *n += 1;
                child(&ptr, &k, *n)
            };
            if !k.chars().all(is_ident) {
                out.push(|| format!("json-key:{}", clip(&p)), &k);
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

/// The child pointer of `ptr` (already clipped): `ptr/token`, with `#dup`
/// for the second and later values of a repeated key, RFC 6901 escaped
/// (`~` is `~0`, `/` is `~1`). It is clipped to [`MAX_NAME_CHARS`] while it
/// is built, so it equals `clip(ptr + "/" + escape(token) + "#dup")` and reads
/// no more of `token` than fits. A `ptr` at the limit is returned as is.
fn child<'p>(ptr: &'p str, token: &str, dup: usize) -> Cow<'p, str> {
    let mut room = MAX_NAME_CHARS.saturating_sub(ptr.chars().count());
    if room == 0 {
        return Cow::Borrowed(ptr);
    }
    let mut s = String::with_capacity(ptr.len() + 1 + token.len().min(4 * MAX_NAME_CHARS) + 4);
    s.push_str(ptr);
    // Push `c` if it fits; true while there is room for more.
    let mut put = |s: &mut String, c: char| {
        if room > 0 {
            s.push(c);
            room -= 1;
        }
        room > 0
    };
    let mut open = put(&mut s, '/');
    for c in token.chars() {
        if !open {
            break;
        }
        open = match c {
            '~' => put(&mut s, '~') && put(&mut s, '0'),
            '/' => put(&mut s, '~') && put(&mut s, '1'),
            c => put(&mut s, c),
        };
    }
    if open && dup > 1 {
        for c in format!("#{dup}").chars() {
            if !put(&mut s, c) {
                break;
            }
        }
    }
    Cow::Owned(s)
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_NAME_CHARS).collect()
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
    fn names_of_a_normal_nested_body_are_unchanged() {
        // The names stored before the linear-splitting fix (final review C1),
        // in document order.
        let body = br#"{"user":{"id":"7","tags":["a","b"],"a/b":{"c~d":"x"}},"id":"1","id":"2","a b":"k","s":"[\"n1\",{\"q\":\"n2\"}]","n":5}"#;
        assert_eq!(
            names("application/json", body),
            vec![
                "json:/user/id",
                "json:/user/tags/0",
                "json:/user/tags/1",
                "json-key:/user/a~1b",
                "json-key:/user/a~1b/c~0d",
                "json:/user/a~1b/c~0d",
                "json:/id",
                "json:/id#2",
                "json-key:/a b",
                "json:/a b",
                "json:/s/0",
                "json:/s/1/q",
            ]
        );
    }

    #[test]
    fn long_pointers_are_clipped_names() {
        // A name is the first MAX_NAME_CHARS chars of the full pointer,
        // whatever the key length, the depth or a duplicate suffix.
        let clipped = |full: String| full.chars().take(MAX_NAME_CHARS).collect::<String>();
        for klen in [1usize, 30, 62, 63, 64, 65, 100, 5000] {
            let k = "k".repeat(klen);
            let body = format!(r#"{{"{k}":"x","{k}":"y","w":{{"{k}":["z",{{"~/":"v"}}]}}}}"#);
            let expect = vec![
                format!("json:{}", clipped(format!("/{k}"))),
                format!("json:{}", clipped(format!("/{k}#2"))),
                format!("json:{}", clipped(format!("/w/{k}/0"))),
                format!("json-key:{}", clipped(format!("/w/{k}/1/~0~1"))),
                format!("json:{}", clipped(format!("/w/{k}/1/~0~1"))),
            ];
            assert_eq!(names("application/json", body.as_bytes()), expect, "key of {klen} chars");
        }
    }

    #[test]
    fn the_cap_keeps_exactly_the_first_values_in_order() {
        let list = |n: usize| format!("[{}]", (0..n).map(|i| format!("\"v{i}\"")).collect::<Vec<_>>().join(","));
        // At the cap: every value is a field, and there is no rest.
        let p = pairs("application/json", list(MAX_BODY_FIELDS).as_bytes());
        assert_eq!(p.len(), MAX_BODY_FIELDS);
        assert_eq!(p.last().unwrap(), &(format!("json:/{}", MAX_BODY_FIELDS - 1), format!("v{}", MAX_BODY_FIELDS - 1)));
        // One past it: the last slot is the rest, which holds the last two.
        let p = pairs("application/json", list(MAX_BODY_FIELDS + 1).as_bytes());
        assert_eq!(p.len(), MAX_BODY_FIELDS);
        assert_eq!(p[MAX_BODY_FIELDS - 2].0, format!("json:/{}", MAX_BODY_FIELDS - 2));
        assert_eq!(p.last().unwrap(), &("json:#rest".to_string(), format!("v{}\nv{}", MAX_BODY_FIELDS - 1, MAX_BODY_FIELDS)));
        // A nested expansion across the cap, and keys past it, keep order.
        let mut parts: Vec<String> = (0..MAX_BODY_FIELDS - 2).map(|i| format!("\"v{i}\"")).collect();
        parts.push(r#""[\"n1\",\"n2\",\"n3\"]""#.into());
        parts.push(r#"{"a b":"w"}"#.into());
        let p = pairs("application/json", format!("[{}]", parts.join(",")).as_bytes());
        assert_eq!(p.len(), MAX_BODY_FIELDS);
        assert_eq!(p[MAX_BODY_FIELDS - 2], (format!("json:/{}/0", MAX_BODY_FIELDS - 2), "n1".to_string()));
        assert_eq!(p.last().unwrap(), &("json:#rest".to_string(), "n2\nn3\na b\nw".to_string()));
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
