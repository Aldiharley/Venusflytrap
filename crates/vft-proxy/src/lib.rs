//! FR9/FR10 — Reverse proxy: build a `Request` from each inbound HTTP request,
//! inspect it with a shared [`Shield`], then forward / block / challenge, always
//! attaching decision headers and appending a JSONL audit line.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use vft_core::{ChainTracker, Judgment, Request as VftRequest, Shield, Verdict};

pub mod audit;

/// Shared proxy state.
pub struct ProxyState {
    pub shield: Shield,
    pub chain: Mutex<ChainTracker>,
    pub upstream: String,
    pub audit: audit::AuditLog,
    /// If true, Monitor/Allow forward and only Block/Challenge are stopped.
    pub enforce: bool,
}

impl ProxyState {
    pub fn new(shield: Shield, upstream: String, audit_path: Option<String>, enforce: bool) -> Self {
        let chain = ChainTracker::new(&shield.config().chain);
        ProxyState {
            shield,
            chain: Mutex::new(chain),
            upstream,
            audit: audit::AuditLog::new(audit_path),
            enforce,
        }
    }
}

/// Convert a hyper request (with its collected body) into a vft-core Request.
fn to_vft(
    parts: &hyper::http::request::Parts,
    body: &[u8],
    peer: Option<SocketAddr>,
) -> VftRequest {
    let mut req = VftRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        body: body.to_vec(),
        src_ip: peer.map(|p| p.ip()),
        ..Default::default()
    };
    if let Some(q) = parts.uri.query() {
        for (k, v) in form_urlencoded_parse(q) {
            req.query.push((k, v));
        }
    }
    for (k, v) in parts.headers.iter() {
        if let Ok(s) = v.to_str() {
            if k.as_str().eq_ignore_ascii_case("cookie") {
                for (ck, cv) in parse_cookies(s) {
                    req.cookies.push((ck, cv));
                }
            }
            req.headers.push((k.as_str().to_string(), s.to_string()));
        }
    }
    req
}

fn form_urlencoded_parse(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next().unwrap_or("").to_string();
            let v = it.next().unwrap_or("").to_string();
            (
                percent_decode(&k),
                percent_decode(&v),
            )
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    // Decode to BYTES first, then interpret as UTF-8. Interpreting each decoded
    // byte as a `char` (Latin-1) would turn a percent-encoded UTF-8 sequence like
    // `%EF%BC%B3` (fullwidth S) into mojibake, defeating the engine's confusable
    // folding and letting Unicode-encoded injections slip past (M2). The engine
    // re-normalizes anyway, but it must receive the real code points.
    let replaced = s.replace('+', " ");
    let b = replaced.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    let hexval = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                bytes.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn parse_cookies(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?.trim().to_string();
            let v = it.next().unwrap_or("").trim().to_string();
            if k.is_empty() {
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

/// Judge a request without forwarding — used by the handler and by tests.
pub fn judge(state: &ProxyState, req: &VftRequest) -> Judgment {
    let mut chain = state.chain.lock().expect("chain mutex");
    state.shield.inspect_stateful(req, &mut chain)
}

async fn handle(
    state: Arc<ProxyState>,
    peer: Option<SocketAddr>,
    req: HyperReq<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let collected = body.collect().await?.to_bytes();
    let vreq = to_vft(&parts, &collected, peer);
    let judgment = judge(&state, &vreq);
    state.audit.record(&vreq, &judgment);

    let blocked = state.enforce
        && matches!(judgment.verdict, Verdict::Block | Verdict::Challenge);

    if blocked {
        let body = format!(
            "Request blocked by Venusflytrap (score {}, {:?}).\n",
            judgment.score, judgment.verdict
        );
        let mut resp = Response::new(Full::new(Bytes::from(body)));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        attach_headers(resp.headers_mut(), &judgment);
        return Ok(resp);
    }

    // Forward to upstream.
    match forward(&state.upstream, &parts, &collected).await {
        Ok(mut resp) => {
            attach_headers(resp.headers_mut(), &judgment);
            Ok(resp)
        }
        Err(e) => {
            let mut resp = Response::new(Full::new(Bytes::from(format!(
                "upstream error: {e}\n"
            ))));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            attach_headers(resp.headers_mut(), &judgment);
            Ok(resp)
        }
    }
}

fn attach_headers(headers: &mut hyper::HeaderMap, j: &Judgment) {
    use hyper::header::HeaderValue;
    headers.insert(
        "x-venusflytrap-score",
        HeaderValue::from_str(&j.score.to_string()).unwrap(),
    );
    headers.insert(
        "x-venusflytrap-verdict",
        HeaderValue::from_str(&format!("{:?}", j.verdict)).unwrap(),
    );
    if let Some(stage) = j.chain_stage {
        headers.insert(
            "x-venusflytrap-stage",
            HeaderValue::from_str(&format!("{stage:?}")).unwrap(),
        );
    }
}

async fn forward(
    upstream: &str,
    parts: &hyper::http::request::Parts,
    body: &[u8],
) -> anyhow::Result<Response<Full<Bytes>>> {
    use hyper_util::client::legacy::Client;
    let client: Client<_, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();
    let path_q = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", upstream.trim_end_matches('/'), path_q);
    let mut builder = HyperReq::builder().method(parts.method.clone()).uri(url);
    for (k, v) in parts.headers.iter() {
        if k.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k, v);
    }
    let out = builder.body(Full::new(Bytes::copy_from_slice(body)))?;
    let resp = client.request(out).await?;
    let (rp, rb) = resp.into_parts();
    let bytes = rb.collect().await?.to_bytes();
    let mut rebuilt = Response::new(Full::new(bytes));
    *rebuilt.status_mut() = rp.status;
    *rebuilt.headers_mut() = rp.headers;
    Ok(rebuilt)
}

/// Run the proxy until the process is killed.
pub async fn serve(state: Arc<ProxyState>, bind: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    eprintln!(
        "venusflytrap proxy listening on http://{bind} -> {} (enforce={})",
        state.upstream, state.enforce
    );
    loop {
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let st = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(st.clone(), Some(peer), req));
            if let Err(e) =
                hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await
            {
                eprintln!("connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vft_core::Config;

    fn state() -> ProxyState {
        ProxyState::new(
            Shield::new(Config::default()),
            "http://127.0.0.1:1".into(),
            None,
            true,
        )
    }

    #[test]
    fn judges_sqli_as_block() {
        let st = state();
        let mut req = VftRequest::get("/x");
        req.query.push(("id".into(), "1 union select a,b".into()));
        let j = judge(&st, &req);
        assert_eq!(j.verdict, Verdict::Block);
    }

    #[test]
    fn cookie_and_query_parse() {
        let v = parse_cookies("a=1; b=2; junk");
        assert!(v.contains(&("a".to_string(), "1".to_string())));
        let q = form_urlencoded_parse("x=1%20union&y=2");
        assert_eq!(q[0].1, "1 union");
    }

    #[test]
    fn percent_decode_preserves_utf8() {
        // %EF%BC%B3 is fullwidth 'S' (U+FF33) in UTF-8; must round-trip as that
        // code point, not Latin-1 mojibake (M2).
        assert_eq!(percent_decode("%EF%BC%B3"), "\u{ff33}");
        // and a lone % or bad hex is passed through, no panic
        assert_eq!(percent_decode("100%done"), "100%done");
    }

    #[test]
    fn fullwidth_encoded_sqli_not_evaded() {
        // fullwidth "UNION SELECT 1" percent-encoded; after proper decode +
        // folding the engine should catch it.
        let st = state();
        let fw = "\u{ff35}\u{ff2e}\u{ff29}\u{ff2f}\u{ff2e} \u{ff33}\u{ff25}\u{ff2c}\u{ff25}\u{ff23}\u{ff34} 1";
        let enc: String = fw
            .bytes()
            .map(|b| format!("%{b:02X}"))
            .collect();
        let q = form_urlencoded_parse(&format!("id={enc}"));
        let mut req = VftRequest::get("/x");
        req.query = q;
        let j = judge(&st, &req);
        assert!(
            matches!(j.verdict, Verdict::Block | Verdict::Challenge),
            "fullwidth-encoded sqli evaded: {:?} {}",
            j.verdict,
            j.score
        );
    }
}
