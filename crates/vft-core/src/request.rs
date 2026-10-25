//! Input model: a normalized view of an inbound HTTP request and the
//! individual fields the engine inspects.

use std::net::IpAddr;

/// Where a field came from in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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

    /// All inspectable fields: query params, headers, cookies, and the body as a
    /// single field. The path is inspected separately (it has path-specific
    /// semantics such as traversal and recon).
    pub fn fields(&self) -> Vec<Field> {
        let mut out = Vec::new();
        for (k, v) in &self.query {
            out.push(Field {
                loc: Location::Query,
                name: k.clone(),
                raw: v.clone(),
            });
        }
        for (k, v) in &self.headers {
            // Skip hop-by-hop / noisy headers that are not attacker payload vectors
            // in the usual sense; keep the interesting ones.
            if matches!(
                k.to_ascii_lowercase().as_str(),
                "host" | "connection" | "content-length" | "accept-encoding"
            ) {
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
                name: k.clone(),
                raw: v.clone(),
            });
        }
        if !self.body.is_empty() {
            out.push(Field {
                loc: Location::Body,
                name: "<body>".into(),
                raw: String::from_utf8_lossy(&self.body).into_owned(),
            });
        }
        out
    }
}

/// Percent-decode to bytes, then UTF-8 lossily (never skips a layer on bad
/// UTF-8). Private stand-in until the recall-lift decoder
/// (`normalize::percent_decode_lossy`) lands — replace this then.
fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
        let d = percent_decode_lossy(&s);
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
}
