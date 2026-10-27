//! Hyper request parts → `vft_core::Request`. Query keys and values, cookie
//! names and values, the body (up to `shield.max_payload` characters, see the
//! benchmark's known fail-opens) and every forwarded header are inspected,
//! except `Content-Length`, which the HTTP front end has already validated as
//! a length. `Connection` is not inspected either; it is hop-by-hop and never
//! forwarded. A raw `Cookie` header is inspected through its parsed names and
//! values when every segment is `token=value`, and as a header too otherwise.
//! Header bytes that are not valid UTF-8 are decoded lossily and recorded in
//! `non_utf8_headers`, which the engine turns into evidence (C4).

use std::net::IpAddr;

use hyper::http::request::Parts;
use vft_core::Request as VftRequest;

pub fn from_parts(parts: &Parts, body: &[u8], src_ip: Option<IpAddr>) -> VftRequest {
    let mut req = VftRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        body: body.to_vec(),
        src_ip,
        ..Default::default()
    };
    if let Some(q) = parts.uri.query() {
        req.query = form_urlencoded_parse(q);
    }
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        let value = match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                req.non_utf8_headers.push(name.to_string());
                String::from_utf8_lossy(v.as_bytes()).into_owned()
            }
        };
        if name.eq_ignore_ascii_case("cookie") {
            req.cookies.extend(parse_cookies(&value));
        }
        req.headers.push((name.to_string(), value));
    }
    req
}

pub(crate) fn form_urlencoded_parse(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

/// Decode to bytes first, then UTF-8 lossily, so percent-encoded UTF-8 keeps
/// its real code points for the engine's confusable folding.
pub(crate) fn percent_decode(s: &str) -> String {
    let replaced = s.replace('+', " ");
    let b = replaced.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                bytes.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn parse_cookies(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?.trim().to_string();
            let v = it.next().unwrap_or("").trim().to_string();
            (!k.is_empty()).then_some((k, v))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::{self, HeaderValue};
    use vft_core::{Config, Shield, Verdict};

    fn parts_with_cookie(raw: &[u8]) -> http::request::Parts {
        http::Request::builder()
            .uri("/x?a=1")
            .header("cookie", HeaderValue::from_bytes(raw).unwrap())
            .header("host", "example.test")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn non_utf8_cookie_is_still_inspected() {
        // C4: one obs-text byte must not hide the cookie from inspection.
        let parts = parts_with_cookie(b"id=1 union select password from users; z=\xff");
        let req = from_parts(&parts, b"", None);
        assert_eq!(req.non_utf8_headers, vec!["cookie".to_string()]);
        assert!(req.cookies.iter().any(|(k, v)| k == "id" && v.contains("union select")));
        let j = Shield::new(Config::default()).inspect(&req);
        assert_eq!(j.verdict, Verdict::Block, "{} {}", j.score, j.decided_by.msg);
        assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.header-non-utf8")));
    }

    #[test]
    fn host_is_inspected_and_raw_cookie_not_double_counted() {
        // L4
        let parts = parts_with_cookie(b"a=1; b=2");
        let req = from_parts(&parts, b"", None);
        let names: Vec<String> = req.fields().iter().map(|f| f.name.to_ascii_lowercase()).collect();
        assert!(names.contains(&"host".to_string()));
        assert!(!names.contains(&"cookie".to_string()), "raw Cookie header must not be inspected twice");
        assert_eq!(req.cookies.len(), 2);
    }

    #[test]
    fn query_and_percent_decoding() {
        let q = form_urlencoded_parse("x=1%20union&y=2");
        assert_eq!(q[0].1, "1 union");
        assert_eq!(percent_decode("%EF%BC%B3"), "\u{ff33}");
        assert_eq!(percent_decode("100%done"), "100%done");
    }
}
