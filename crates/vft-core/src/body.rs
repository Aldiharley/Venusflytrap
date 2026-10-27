//! Body classification (DQ2 spec section 4.2): split a request body into the
//! fields its consumer parses, so each JSON string leaf and multipart part is
//! inspected under its own name. Anything else, a form body included, stays
//! one `<body>` field, as before: form splitting is deferred, because a
//! construct that only forms across two form values is lost when they are
//! split. Every class can be switched off by its `parse.body-*` id, which
//! restores `<body>` for it.
//!
//! Classification must never hide text that the backend parses:
//! - a body gets no text field (binary) only when its declared type is
//!   absent, binary or compressed, or a Content-Encoding declares
//!   compression; a declared text class is inspected as text whatever its
//!   prefix;
//! - every multipart byte outside an inspected part's content (preamble,
//!   epilogue, delimiter-line tails, part headers, headerless parts) is
//!   inspected as one `form:#frame` field;
//! - every value of a repeated JSON key is a leaf (`json:/a`, `json:/a#2`).

use std::collections::HashMap;
use std::fmt;

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
/// to the single `<body>` field. Same as [`body_fields_encoded`] with no
/// Content-Encoding.
pub fn body_fields(content_type: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts) {
    body_fields_encoded(content_type, None, body, off)
}

/// [`body_fields`] with the request's Content-Encoding: a compressing coding
/// lets binary-looking bytes make even a declared text class binary.
pub fn body_fields_encoded(content_type: Option<&str>, content_encoding: Option<&str>, body: &[u8], off: &Disabled) -> (Vec<Field>, BodyFacts) {
    let mut out = Out { fields: Vec::new(), facts: BodyFacts::default() };
    if body.is_empty() {
        return (out.fields, out.facts);
    }
    let coded = compressing(content_encoding);
    let class = classify(content_type.unwrap_or(""), coded, body, off, &Scope::top(), &mut out);
    // Only JSON and multipart bodies produce more than one field.
    let rest = if class == Class::Json { "json:#rest" } else { "form:#rest" };
    cap(&mut out.fields, rest);
    (out.fields, out.facts)
}

fn classify(ct: &str, coded: bool, bytes: &[u8], off: &Disabled, scope: &Scope, out: &mut Out) -> Class {
    let lc = ct.to_ascii_lowercase();
    if is_binary(&lc, coded, bytes) {
        if off.is(&sinks::PARSE_BODY_BINARY) {
            // Today's single lossy field; the bytes are binary, so no non-UTF-8 fact.
            out.push(scope.text_name.clone(), String::from_utf8_lossy(bytes).into_owned());
        }
        return Class::Other;
    }
    if lc.starts_with("multipart/") && scope.multipart_ok && !off.is(&sinks::PARSE_BODY_MULTIPART) {
        match param(ct, "boundary").filter(|b| b.len() <= 70).and_then(|b| layout(bytes, &b)) {
            Some(lay) => {
                let first = out.fields.len();
                let mut covered = lay.delims;
                for (i, &(s, e)) in lay.parts.iter().enumerate() {
                    let at = part(i, &bytes[s..e], off, out);
                    covered.push((s + at, e));
                }
                if let Some(frame) = frame(bytes, covered, out) {
                    out.fields.insert(first, frame);
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

/// Whether a Content-Encoding value names a compressing coding.
fn compressing(ce: Option<&str>) -> bool {
    ce.is_some_and(|v| {
        v.split(',')
            .map(|c| c.trim().to_ascii_lowercase())
            .any(|c| matches!(c.as_str(), "gzip" | "x-gzip" | "deflate" | "br" | "compress" | "x-compress" | "zstd"))
    })
}

/// A declared binary media type (`lc` is the lower-cased Content-Type).
fn declared_binary(lc: &str) -> bool {
    lc.contains("protobuf") || lc.contains("octet-stream") || lc.starts_with("image/") || lc.starts_with("audio/") || lc.starts_with("video/")
}

/// A declared compressed or archive media type.
fn declared_compressed(lc: &str) -> bool {
    let media = lc.split(';').next().unwrap_or("").trim();
    let Some(sub) = media.strip_prefix("application/") else { return false };
    matches!(
        sub,
        "gzip" | "x-gzip" | "zip" | "x-zip-compressed" | "zlib" | "x-compress" | "x-compressed" | "x-bzip2" | "x-xz" | "zstd" | "x-7z-compressed" | "x-tar" | "x-rar-compressed" | "brotli" | "x-brotli"
    )
}

/// Binary by magic bytes, or by a declared binary or compressed type (or a
/// compressing Content-Encoding) whose bytes look binary, and only when the
/// declared type is absent, binary or compressed, or the body is coded: a
/// declared text class is always text, whatever its prefix. A label alone
/// never hides text (D13); zlib, GIF and PDF magic is printable, so it also
/// needs binary-looking bytes.
fn is_binary(lc: &str, coded: bool, b: &[u8]) -> bool {
    let declared = declared_binary(lc) || declared_compressed(lc);
    if !(coded || declared || lc.trim().is_empty()) {
        return false;
    }
    let strong = b.starts_with(&[0x1f, 0x8b])
        || b.starts_with(b"PK\x03\x04")
        || b.starts_with(b"\x89PNG\r\n\x1a\n")
        || b.starts_with(&[0xff, 0xd8, 0xff]);
    let weak = (b.len() >= 2 && b[0] == 0x78 && matches!(b[1], 0x01 | 0x5e | 0x9c | 0xda))
        || b.starts_with(b"GIF87a")
        || b.starts_with(b"GIF89a")
        || b.starts_with(b"%PDF-");
    strong || ((weak || declared || coded) && looks_binary(b))
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

/// Byte ranges of a multipart body: each part (between delimiter lines) and
/// each delimiter token (`--boundary`, and the closing `--`).
struct Layout {
    parts: Vec<(usize, usize)>,
    delims: Vec<(usize, usize)>,
}

/// The layout of a multipart body, or None when it is malformed: no
/// delimiter, or no closing `--boundary--`.
fn layout(body: &[u8], boundary: &str) -> Option<Layout> {
    let delim = format!("--{boundary}").into_bytes();
    let first = find(body, &delim, 0)?;
    let mut lay = Layout { parts: Vec::new(), delims: vec![(first, first + delim.len())] };
    let mut at = first + delim.len();
    loop {
        if body[at..].starts_with(b"--") {
            lay.delims.push((at, at + 2));
            return Some(lay);
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
        lay.parts.push((start, content_end.max(start)));
        lay.delims.push((end, end + delim.len()));
        at = end + delim.len();
    }
}

/// One multipart part: its `filename` is a field of its own; its content is
/// classified by the part's Content-Type (one level: no nested multipart).
/// Returns where the content starts in `p`; the header block before it is
/// framing. A part without a blank line after its headers is all header.
fn part(i: usize, p: &[u8], off: &Disabled, out: &mut Out) -> usize {
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
    let (mut name, mut filename, mut ct, mut ce) = (None, None, String::new(), None);
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim();
        if k.eq_ignore_ascii_case("content-disposition") {
            name = param(v, "name");
            filename = param(v, "filename");
        } else if k.eq_ignore_ascii_case("content-type") {
            ct = v.trim().to_string();
        } else if k.eq_ignore_ascii_case("content-encoding") {
            ce = Some(v.trim().to_string());
        }
    }
    let name = name.unwrap_or_else(|| format!("part{i}"));
    if let Some(f) = filename {
        out.push(format!("form-file:{}", clip(&name)), f);
    }
    let content = &p[at..];
    if !content.is_empty() {
        classify(&ct, compressing(ce.as_deref()), content, off, &Scope::part(&name), out);
    }
    at
}

/// The bytes of a multipart body outside `covered` (part contents and
/// delimiter tokens), as one text field; None when they are only whitespace.
/// Runs are joined with a line break so text on both sides of a part is not
/// glued together.
fn frame(body: &[u8], mut covered: Vec<(usize, usize)>, out: &mut Out) -> Option<Field> {
    covered.sort_unstable();
    let mut runs: Vec<&[u8]> = Vec::new();
    let mut at = 0;
    for (s, e) in covered {
        if s > at {
            runs.push(&body[at..s]);
        }
        at = at.max(e);
    }
    if at < body.len() {
        runs.push(&body[at..]);
    }
    if runs.iter().all(|r| r.iter().all(u8::is_ascii_whitespace)) {
        return None;
    }
    let joined = runs.join(&b'\n');
    let raw = text_of(&joined, out);
    Some(Field { loc: Location::Body, name: FRAME.into(), raw })
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

    const GZ: [u8; 8] = [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0];

    #[test]
    fn magic_bytes_hide_a_body_only_without_a_declared_text_type() {
        // No declared type, a binary or compressed one, or a compressing
        // Content-Encoding: the magic makes the body binary.
        for (ct, ce) in [
            (None, None),
            (Some("application/octet-stream"), None),
            (Some("application/gzip"), None),
            (Some("application/json"), Some("gzip")),
            (Some("text/plain"), Some("x-gzip, identity")),
        ] {
            let (f, facts) = body_fields_encoded(ct, ce, &GZ, &Disabled::default());
            assert!(f.is_empty(), "{ct:?} {ce:?} {f:?}");
            assert!(!facts.non_utf8 && !facts.unparsed);
        }
        // A declared text class is always inspected as text, whatever its prefix.
        let mut png_text = b"\x89PNG\r\n\x1a\n".to_vec();
        png_text.extend_from_slice(b"MARKER-TEXT");
        for ct in ["application/json", "text/plain", "application/xml", "application/x-www-form-urlencoded", "application/x-ndjson"] {
            let (f, _) = body_fields(Some(ct), &png_text, &Disabled::default());
            assert_eq!(f.len(), 1, "{ct}");
            assert_eq!(f[0].name, "<body>");
            assert!(f[0].raw.contains("MARKER-TEXT"), "{ct}");
        }
        let (f, facts) = body_fields(Some("application/json"), &GZ, &Disabled::default());
        assert_eq!(f.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["<body>"]);
        assert!(facts.non_utf8);
        // The same holds for a multipart part declared as text.
        let mp = b"--XyZ\r\nContent-Disposition: form-data; name=\"t\"\r\nContent-Type: text/plain\r\n\r\n\x89PNG\r\n\x1a\nMARKER-PART\r\n--XyZ--\r\n";
        let p = pairs("multipart/form-data; boundary=XyZ", mp);
        assert!(p.iter().any(|(n, r)| n == "form:t" && r.contains("MARKER-PART")), "{p:?}");
    }

    #[test]
    fn multipart_framing_is_inspected_as_one_frame_field() {
        let body = b"MARKER-PREAMBLE\r\n--XyZ MARKER-DELIM-TAIL\r\nContent-Disposition: form-data; name=\"MARKER-NAME\"; filename=\"MARKER-FILE\"\r\nX-Extra: MARKER-HEADER\r\n\r\nhello\r\n--XyZ\r\nMARKER-HEADERLESS\r\n--XyZ--\r\nMARKER-EPILOGUE";
        let p = pairs("multipart/form-data; boundary=XyZ", body);
        let frame = p.iter().find(|(n, _)| n == "form:#frame").map(|(_, r)| r.clone()).expect("a form:#frame field");
        for m in ["MARKER-PREAMBLE", "MARKER-DELIM-TAIL", "MARKER-NAME", "MARKER-FILE", "MARKER-HEADER", "MARKER-HEADERLESS", "MARKER-EPILOGUE"] {
            assert!(frame.contains(m), "{m} missing from {frame:?}");
        }
        assert!(!frame.contains("hello"), "inspected content is not repeated: {frame:?}");
        assert!(!frame.contains("--XyZ"), "{frame:?}");
        assert!(p.contains(&("form:MARKER-NAME".to_string(), "hello".to_string())), "{p:?}");
        assert!(p.contains(&("form-file:MARKER-NAME".to_string(), "MARKER-FILE".to_string())), "{p:?}");
        // Framing that is only delimiters and line breaks adds no field; an
        // empty header block is not a headerless part.
        assert_eq!(pairs("multipart/form-data; boundary=XyZ", b"--XyZ\r\n\r\nhello\r\n--XyZ--\r\n"), vec![("form:part0".to_string(), "hello".to_string())]);
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
        let p = pairs("multipart/form-data; boundary=XyZ", body);
        assert_eq!(p.iter().filter(|(n, _)| n != "form:#frame").cloned().collect::<Vec<_>>(), vec![("form:f".to_string(), "a=1&b=2".to_string())]);
    }

    const MP: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"pic\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n\x00\x01\r\n--XyZ\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"id\":\"3\"}\r\n--XyZ--\r\n";

    #[test]
    fn multipart_parts_are_classified_by_their_own_type() {
        let (f, facts) = body_fields(Some("multipart/form-data; boundary=XyZ"), MP, &Disabled::default());
        let p: Vec<(String, String)> = f.iter().filter(|f| f.name != "form:#frame").map(|f| (f.name.clone(), f.raw.clone())).collect();
        assert_eq!(
            p,
            vec![
                ("form:note".to_string(), "hello".to_string()),
                ("form-file:pic".to_string(), "a.png".to_string()),
                ("json:/meta/id".to_string(), "3".to_string()),
            ]
        );
        // The part headers are inspected once, in the frame field.
        let frame = &f.iter().find(|f| f.name == "form:#frame").expect("frame").raw;
        assert!(frame.contains("name=\"meta\"") && frame.contains("Content-Type: image/png"), "{frame:?}");
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
        // The frame field comes first, so it takes one of the kept slots.
        assert_eq!(f[0].name, "form:#frame");
        let rest = f.last().unwrap();
        assert_eq!(rest.name, "form:#rest");
        assert_eq!(rest.raw.lines().count(), 300 - (MAX_BODY_FIELDS - 2));
    }
}
