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
