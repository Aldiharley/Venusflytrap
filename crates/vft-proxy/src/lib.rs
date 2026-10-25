//! FR9/FR10 — Hardened reverse proxy. Every request runs through
//! `Pipeline::decide`; Allow/Monitor forward through one pooled client with
//! timeouts, hop-by-hop headers stripped and forwarding headers added;
//! Block/Challenge get a generic 403. Decision headers never reach clients.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use vft_core::config::{DecisionHeaders, LimitsConfig};
use vft_core::{Judgment, Shield, Verdict};

pub mod adapt;
pub mod audit;
pub mod pipeline;
pub use hyper::http;

type Body = BoxBody<Bytes, hyper::Error>;

/// Shared proxy state.
pub struct ProxyState {
    pub pipeline: pipeline::Pipeline,
    pub upstream: String,
    pub audit: audit::AuditLog,
    /// If true, Block/Challenge are stopped; otherwise everything is forwarded.
    pub enforce: bool,
    client: Client<HttpConnector, Full<Bytes>>,
    limits: LimitsConfig,
    decision_headers: DecisionHeaders,
}

impl ProxyState {
    pub fn new(shield: Shield, upstream: String, audit_path: Option<String>, enforce: bool) -> Self {
        let limits = shield.config().limits.clone();
        let decision_headers = shield.config().proxy.decision_headers;
        let mut conn = HttpConnector::new();
        conn.set_connect_timeout(Some(Duration::from_millis(limits.upstream_connect_timeout_ms)));
        let client = Client::builder(TokioExecutor::new()).build(conn);
        ProxyState {
            pipeline: pipeline::Pipeline::new(Arc::new(shield)),
            upstream,
            audit: audit::AuditLog::new(audit_path),
            enforce,
            client,
            limits,
            decision_headers,
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn text(status: StatusCode, msg: &'static str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from_static(msg.as_bytes())).map_err(|n| match n {}).boxed());
    *r.status_mut() = status;
    r
}

/// RFC 9110 section 7.6.1 hop-by-hop headers, plus any header named in `Connection`.
fn strip_hop_by_hop(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        h.remove(n);
    }
}

fn wants_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(hyper::header::UPGRADE)
        || h.get_all(hyper::header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
}

async fn handle(state: Arc<ProxyState>, peer: SocketAddr, req: HyperReq<Incoming>) -> Result<Response<Body>, hyper::Error> {
    let lim = &state.limits;
    if req.headers().len() > lim.max_headers {
        return Ok(text(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "Request header fields too large.\n"));
    }
    if wants_upgrade(req.headers()) {
        return Ok(text(StatusCode::NOT_IMPLEMENTED, "Protocol upgrade is not supported.\n"));
    }
    let declared_len = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared_len.is_some_and(|n| n > lim.max_body) {
        return Ok(text(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large.\n"));
    }

    let (parts, body) = req.into_parts();
    let read = Limited::new(body, lim.max_body).collect();
    let collected = match tokio::time::timeout(Duration::from_millis(lim.body_read_timeout_ms), read).await {
        Err(_) => return Ok(text(StatusCode::REQUEST_TIMEOUT, "Request timeout.\n")),
        Ok(Err(e)) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
            return Ok(text(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large.\n"))
        }
        Ok(Err(_)) => return Ok(text(StatusCode::BAD_REQUEST, "Bad request.\n")),
        Ok(Ok(c)) => c.to_bytes(),
    };

    let decision = state.pipeline.decide(&parts, &collected, Some(peer.ip()), now_ms());
    state.audit.record(&decision.request, &decision.judgment);
    let j = decision.judgment;

    if state.enforce && matches!(j.verdict, Verdict::Block | Verdict::Challenge) {
        return Ok(text(StatusCode::FORBIDDEN, "Request blocked.\n"));
    }
    Ok(forward(&state, &parts, collected, peer, &j).await)
}

async fn forward(state: &ProxyState, parts: &http::request::Parts, body: Bytes, peer: SocketAddr, j: &Judgment) -> Response<Body> {
    let path_q = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", state.upstream.trim_end_matches('/'), path_q);
    let mut headers = parts.headers.clone();
    strip_hop_by_hop(&mut headers);
    headers.remove(hyper::header::HOST);
    let xff = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(prev) => format!("{prev}, {}", peer.ip()),
        None => peer.ip().to_string(),
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    headers.append(hyper::header::VIA, HeaderValue::from_static("1.1 venusflytrap"));
    if state.decision_headers == DecisionHeaders::Upstream {
        headers.insert("x-venusflytrap-score", HeaderValue::from(u16::from(j.score)));
        if let Ok(v) = HeaderValue::from_str(&format!("{:?}", j.verdict)) {
            headers.insert("x-venusflytrap-verdict", v);
        }
        if let Some(stage) = j.chain_stage.and_then(|s| HeaderValue::from_str(&format!("{s:?}")).ok()) {
            headers.insert("x-venusflytrap-stage", stage);
        }
    }
    let mut out = match HyperReq::builder().method(parts.method.clone()).uri(url).body(Full::new(body)) {
        Ok(r) => r,
        Err(_) => return text(StatusCode::BAD_GATEWAY, "Bad gateway.\n"),
    };
    *out.headers_mut() = headers;

    let wait = Duration::from_millis(state.limits.upstream_response_timeout_ms);
    match tokio::time::timeout(wait, state.client.request(out)).await {
        Err(_) => text(StatusCode::GATEWAY_TIMEOUT, "Gateway timeout.\n"),
        Ok(Err(_)) => text(StatusCode::BAD_GATEWAY, "Bad gateway.\n"),
        Ok(Ok(resp)) => {
            let (mut rp, rb) = resp.into_parts();
            strip_hop_by_hop(&mut rp.headers);
            Response::from_parts(rp, rb.boxed())
        }
    }
}

/// Bind and serve until the process is killed.
pub async fn serve(state: Arc<ProxyState>, bind: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    eprintln!(
        "venusflytrap proxy listening on http://{bind} -> {} (enforce={})",
        state.upstream, state.enforce
    );
    serve_listener(state, listener).await
}

/// Serve on an already-bound listener. Accept errors never end the loop (M9).
pub async fn serve_listener(state: Arc<ProxyState>, listener: TcpListener) -> anyhow::Result<()> {
    let slots = Arc::new(Semaphore::new(state.limits.max_connections));
    let mut backoff = Duration::from_millis(10);
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (stream, peer) = match listener.accept().await {
            Ok(x) => {
                backoff = Duration::from_millis(10);
                x
            }
            Err(e) => {
                eprintln!("accept error: {e}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let st = state.clone();
        let header_ms = state.limits.header_read_timeout_ms;
        let max_headers = state.limits.max_headers;
        tokio::spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |req| handle(st.clone(), peer, req));
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(header_ms))
                .max_headers(max_headers);
            let _ = b.serve_connection(TokioIo::new(stream), svc).await;
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
        let parts = hyper::http::Request::builder()
            .uri("/x?id=1%20union%20select%20a,b")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let d = st.pipeline.decide(&parts, b"", None, 0);
        assert_eq!(d.judgment.verdict, Verdict::Block);
    }

    #[test]
    fn fullwidth_encoded_sqli_not_evaded() {
        // fullwidth "UNION SELECT 1" percent-encoded; after proper decode +
        // folding the engine should catch it.
        let st = state();
        let fw = "\u{ff35}\u{ff2e}\u{ff29}\u{ff2f}\u{ff2e} \u{ff33}\u{ff25}\u{ff2c}\u{ff25}\u{ff23}\u{ff34} 1";
        let enc: String = fw.bytes().map(|b| format!("%{b:02X}")).collect();
        let parts = hyper::http::Request::builder()
            .uri(format!("/x?id={enc}"))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let j = st.pipeline.decide(&parts, b"", None, 0).judgment;
        assert!(
            matches!(j.verdict, Verdict::Block | Verdict::Challenge),
            "fullwidth-encoded sqli evaded: {:?} {}",
            j.verdict,
            j.score
        );
    }
}
