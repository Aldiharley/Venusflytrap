//! Input model: a normalized view of an inbound HTTP request and the
//! individual fields the engine inspects.

use std::net::IpAddr;

use crate::body::BodyFacts;
use crate::graph::sinks::Disabled;

/// Where a field came from in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum Location {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

/// A single attacker-controllable field extracted from a request.
#[derive(Debug, Clone)]
pub struct Field {
    pub loc: Location,
    pub name: String,
    /// Raw (as-received) value for this field.
    pub raw: String,
}

/// A request handed to the shield. Borrowed where cheap; owned `query`/`headers`
/// so callers (CLI/proxy) can build it from parsed data.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub src_ip: Option<IpAddr>,
    /// Names of headers whose bytes were not valid UTF-8. Their values are
    /// decoded lossily and still inspected; the fact itself is evidence (C4).
    pub non_utf8_headers: Vec<String>,
}

impl Request {
    /// Convenience constructor for a simple GET-like request.
    pub fn get(path: impl Into<String>) -> Self {
        Request {
            method: "GET".into(),
            path: path.into(),
            ..Default::default()
        }
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_is_empty(&self) -> bool {
        self.body.iter().all(|b| b.is_ascii_whitespace())
    }

    /// The path as a backend would resolve it (see [`canonical_path`]). Used by
    /// honeypot and recon checks; the path graph keeps reading `self.path`.
    pub fn canonical_path(&self) -> String {
        canonical_path(&self.path)
    }

    /// The value of the first header named `name` (ASCII case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// All inspectable fields with every body class on (see [`Request::fields_with`]).
    pub fn fields(&self) -> Vec<Field> {
        self.fields_with(&Disabled::default()).0
    }

    /// All inspectable fields: query keys and values, headers, cookie names
    /// and values, and the body classified by [`crate::body::body_fields`]
    /// (JSON leaves, multipart parts, or one `<body>` field, as a form body
    /// stays; none for a binary body). A `parse.body-*` id in `off` restores
    /// `<body>` for its class. The path is inspected separately (it has
    /// path-specific semantics such as traversal and recon). Also returns what
    /// body classification found, for the shield's body limits.
    ///
    /// Not inspected: the `Connection` header (hop-by-hop, stripped before
    /// forwarding) and `Content-Length` (validated by the HTTP front end), and
    /// a raw `Cookie` header whose every segment is a well-formed
    /// `token=value` pair (its names and values are inspected as cookie
    /// fields instead).
    pub fn fields_with(&self, off: &Disabled) -> (Vec<Field>, BodyFacts) {
        let mut out = Vec::new();
        for (k, v) in &self.query {
            // The key is forwarded too, so it is attacker payload like the value.
            if !k.is_empty() {
                out.push(Field {
                    loc: Location::Query,
                    name: format!("key:{k}"),
                    raw: k.clone(),
                });
            }
            out.push(Field {
                loc: Location::Query,
                name: k.clone(),
                raw: v.clone(),
            });
        }
        for (k, v) in &self.headers {
            let lname = k.to_ascii_lowercase();
            if matches!(lname.as_str(), "connection" | "content-length") {
                continue;
            }
            // The raw Cookie header is covered by the parsed cookies below only
            // when every segment parses as `token=value`; anything else (a
            // segment without `=`, a name that is not an RFC 6265 token) is
            // inspected as a header as well.
            if lname == "cookie" && !self.cookies.is_empty() && cookie_header_is_well_formed(v) {
                continue;
            }
            out.push(Field {
                loc: Location::Header,
                name: k.clone(),
                raw: v.clone(),
            });
        }
        for (k, v) in &self.cookies {
            out.push(Field {
                loc: Location::Cookie,
                name: format!("name:{k}"),
                raw: k.clone(),
            });
            out.push(Field {
                loc: Location::Cookie,
                name: k.clone(),
                raw: v.clone(),
            });
        }
        let (body, facts) = crate::body::body_fields(self.header("content-type"), &self.body, off);
        out.extend(body);
        (out, facts)
    }
}

/// RFC 6265 `cookie-name`: a token (visible ASCII, no separators).
fn is_cookie_name_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b))
}

/// Every non-empty `;`-separated segment is `token=value`.
fn cookie_header_is_well_formed(v: &str) -> bool {
    v.split(';').all(|seg| {
        let seg = seg.trim_start();
        seg.trim_end().is_empty() || seg.split_once('=').is_some_and(|(k, _)| is_cookie_name_token(k))
    })
}

/// The path as a backend would resolve it: percent-decoded (up to 3 layers;
/// decoding stops after 3, so deeper nesting is left encoded),
/// backslashes as slashes, matrix parameters (`;x`) dropped per segment, empty
/// and `.` segments removed, `..` resolved (RFC 3986 §5.2.4), trailing slash
/// kept. Used by honeypot and recon checks (H5). The path graph keeps the raw
/// path, because dot segments are the traversal evidence.
pub fn canonical_path(raw: &str) -> String {
    let mut s = raw.to_string();
    for _ in 0..3 {
        let d = crate::normalize::percent_decode_lossy(&s);
        if d == s {
            break;
        }
        s = d;
    }
    let s = s.replace('\\', "/");
    let mut segs: Vec<&str> = Vec::new();
    // RFC 3986 §5.2.4: a final segment of "", "." or ".." leaves a trailing slash.
    let mut trailing = false;
    for seg in s.split('/') {
        match seg.split(';').next().unwrap_or("") {
            "" | "." => trailing = true,
            ".." => {
                segs.pop();
                trailing = true;
            }
            other => {
                segs.push(other);
                trailing = false;
            }
        }
    }
    let mut out = String::with_capacity(s.len() + 1);
    for seg in &segs {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() || trailing {
        out.push('/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_header_well_formedness() {
        for ok in ["a=1", "a=1; b=2", "_ga=GA1.1.1; theme=dark;", "a=", "a=1;  b=x=y"] {
            assert!(cookie_header_is_well_formed(ok), "{ok:?}");
        }
        for bad in ["1 union select", "a=1; junk", "<script>=1", "=1", "a b=1", "a\"=1", "a =1"] {
            assert!(!cookie_header_is_well_formed(bad), "{bad:?}");
        }
    }

    #[test]
    fn query_keys_and_cookie_names_are_fields() {
        let mut req = Request::get("/x");
        req.query.push(("k".into(), "v".into()));
        req.query.push(("".into(), "w".into()));
        req.cookies.push(("c".into(), "d".into()));
        req.headers.push(("Accept-Encoding".into(), "gzip".into()));
        req.headers.push(("Connection".into(), "close".into()));
        let f: Vec<(Location, String, String)> =
            req.fields().into_iter().map(|f| (f.loc, f.name, f.raw)).collect();
        let want = |l, n: &str, r: &str| f.contains(&(l, n.to_string(), r.to_string()));
        assert!(want(Location::Query, "key:k", "k"), "{f:?}");
        assert!(want(Location::Query, "k", "v"));
        assert!(want(Location::Query, "", "w"));
        assert!(!f.iter().any(|(_, n, _)| n == "key:"), "empty key is not a field");
        assert!(want(Location::Cookie, "name:c", "c"));
        assert!(want(Location::Cookie, "c", "d"));
        assert!(want(Location::Header, "Accept-Encoding", "gzip"));
        assert!(!f.iter().any(|(_, n, _)| n == "Connection"));
    }

    #[test]
    fn canonical_path_cases() {
        for (raw, want) in [
            ("/.git/config", "/.git/config"),
            ("/%2egit/config", "/.git/config"),
            ("//.git//config", "/.git/config"),
            ("/.%65nv", "/.env"),
            ("/a/b/../../.git/config", "/.git/config"),
            ("/x/..;/.git/config", "/.git/config"),
            ("/a\\..\\.env", "/.env"),
            ("/%252egit/config", "/.git/config"),
            ("/phpmyadmin/", "/phpmyadmin/"),
            ("/", "/"),
            ("", "/"),
            ("/../../..", "/"),
            ("/phpmyadmin/.", "/phpmyadmin/"),
            ("/.git/x/..", "/.git/"),
            ("/a/..", "/"),
            ("/a/b/.", "/a/b/"),
        ] {
            assert_eq!(canonical_path(raw), want, "raw {raw:?}");
        }
    }

    #[test]
    fn the_body_is_classified_by_its_content_type() {
        let mut req = Request::get("/x");
        req.method = "POST".into();
        req.headers.push(("Content-Type".into(), "application/json".into()));
        req.body = br#"{"a":"1"}"#.to_vec();
        let names: Vec<String> = req.fields().into_iter().filter(|f| f.loc == Location::Body).map(|f| f.name).collect();
        assert_eq!(names, vec!["json:/a"]);
        let off = crate::graph::sinks::Disabled::resolve(&["parse.body-json".into()]);
        let (f, _) = req.fields_with(&off);
        assert!(f.iter().any(|f| f.loc == Location::Body && f.name == "<body>"));
        assert_eq!(req.header("content-type"), Some("application/json"));
    }
}
