//! FR9/FR10 — Reverse proxy: build a `Request` from each inbound HTTP request,
//! inspect it with a shared [`Shield`], then forward / block / challenge, always
//! attaching decision headers and appending a JSONL audit line.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperReq, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use vft_core::{Judgment, Shield, Verdict};

pub mod adapt;
pub mod pipeline;
pub mod audit;
pub use hyper::http;

/// Shared proxy state.
pub struct ProxyState {
    pub pipeline: pipeline::Pipeline,
    pub upstream: String,
    pub audit: audit::AuditLog,
    /// If true, Block/Challenge are stopped; otherwise everything is forwarded.
    pub enforce: bool,
}

impl ProxyState {
    pub fn new(shield: Shield, upstream: String, audit_path: Option<String>, enforce: bool) -> Self {
        ProxyState {
            pipeline: pipeline::Pipeline::new(Arc::new(shield)),
            upstream,
            audit: audit::AuditLog::new(audit_path),
            enforce,
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn handle(
    state: Arc<ProxyState>,
    peer: Option<SocketAddr>,
    req: HyperReq<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let collected = body.collect().await?.to_bytes();
    let decision = state.pipeline.decide(&parts, &collected, peer.map(|p| p.ip()), now_ms());
    state.audit.record(&decision.request, &decision.judgment);
    let judgment = decision.judgment;

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
