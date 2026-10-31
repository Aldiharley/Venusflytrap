//! FR9/FR10 — Hardened reverse proxy. Every request runs through
//! `Pipeline::decide`; Allow/Monitor forward through one pooled client with
//! timeouts, hop-by-hop headers stripped and forwarding headers added;
//! Block/Challenge get a generic 403. Decision headers never reach clients.
#![forbid(unsafe_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use vft_core::config::{DecisionHeaders, LimitsConfig};
use vft_core::{Judgment, Shield, Verdict};

pub mod adapt;
pub mod audit;
pub mod bus;
pub mod config_handle;
pub mod ids;
pub mod ocsf;
pub mod pipeline;
pub use hyper::http;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

/// Upstream response body that fails (aborting the client connection) when no
/// frame arrives within `idle`; the window restarts on every frame.
struct IdleTimeout<B> {
    inner: B,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<B> IdleTimeout<B> {
    fn new(inner: B, idle: Duration) -> Self {
        IdleTimeout { inner, idle, sleep: Box::pin(tokio::time::sleep(idle)) }
    }
}

#[derive(Debug)]
struct ResponseIdle;

impl std::fmt::Display for ResponseIdle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upstream response body idle timeout")
    }
}

impl std::error::Error for ResponseIdle {}

impl<B> hyper::body::Body for IdleTimeout<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                let next = tokio::time::Instant::now() + this.idle;
                this.sleep.as_mut().reset(next);
                Poll::Ready(frame.map(|r| r.map_err(Into::into)))
            }
            Poll::Pending => match this.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err(Box::new(ResponseIdle)))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Shared proxy state.
pub struct ProxyState {
    pub pipeline: pipeline::Pipeline,
    pub upstream: String,
    pub audit: audit::AuditSink,
    /// OCSF 1.9.0 records for the same events (off unless `serve --ocsf`).
    pub ocsf: audit::AuditSink,
    pub ids: ids::EventIds,
    request_seq: std::sync::atomic::AtomicU64,
    /// If true, Block/Challenge are stopped; otherwise everything is forwarded.
    pub enforce: bool,
    /// Where decisions and bans are published; `None` does no event work.
    pub bus: Option<bus::EventBus>,
    client: Client<HttpConnector, Full<Bytes>>,
    limits: LimitsConfig,
    decision_headers: DecisionHeaders,
}

impl ProxyState {
    /// A proxy over a fixed shield (a fresh handle at rev 1).
    pub fn new(shield: Shield, upstream: String, audit: audit::AuditSink, ocsf: audit::AuditSink, enforce: bool) -> Self {
        let handle = Arc::new(config_handle::ConfigHandle::new(Arc::new(shield)));
        Self::with_handle(handle, upstream, audit, ocsf, enforce)
    }

    /// A proxy that follows `handle`. Limits and decision headers are
    /// restart-only, so they are read once from its current config.
    pub fn with_handle(
        handle: Arc<config_handle::ConfigHandle>,
        upstream: String,
        audit: audit::AuditSink,
        ocsf: audit::AuditSink,
        enforce: bool,
    ) -> Self {
        let first = handle.load();
        let limits = first.shield.config().limits.clone();
        let decision_headers = first.shield.config().proxy.decision_headers;
        let mut conn = HttpConnector::new();
        conn.set_connect_timeout(Some(Duration::from_millis(limits.upstream_connect_timeout_ms)));
        let client = Client::builder(TokioExecutor::new()).build(conn);
        ProxyState {
            pipeline: pipeline::Pipeline::with_handle(handle),
            upstream,
            audit,
            ocsf,
            ids: ids::EventIds::new(),
            request_seq: std::sync::atomic::AtomicU64::new(0),
            enforce,
            bus: None,
            client,
            limits,
            decision_headers,
        }
    }

    /// Publish decisions and bans on `bus`.
    pub fn with_bus(mut self, bus: bus::EventBus) -> Self {
        self.bus = Some(bus);
        self
    }
}

/// Publish one request's `Decision`, then a `BanChanged` when it set a ban.
/// Consumes the decision (the judgment moves into the event, no clone); only
/// called with a bus attached.
fn publish_decision(
    bus: &bus::EventBus,
    d: pipeline::Decision,
    event_id: String,
    ts_ms: u64,
    start: std::time::Instant,
    upstream_status: Option<u16>,
) {
    let group_id = d.group_id();
    let src_key = d.src.map(|k| k.ip().to_string());
    let new_ban = d.judgment.chain.as_ref().and_then(|c| c.new_ban);
    let host = d
        .request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let ev = bus::DecisionEvent {
        event_id,
        group_id,
        ts_ms,
        src_key: src_key.clone(),
        ip: d.request.src_ip,
        method: d.request.method,
        host,
        path: d.request.path,
        judgment: d.judgment,
        latency_us: u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        upstream_status,
        config_rev: d.config_rev,
        snippets: Vec::new(),
    };
    bus.publish(bus::BusEvent::Decision(Arc::new(ev)));
    if let (Some(key), Some(ban)) = (src_key, new_ban) {
        bus.publish(bus::BusEvent::BanChanged { key, ban: Some(ban), lifted: false });
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

/// The 403 for a stopped request. Challenge has its own generic body (spec
/// decision 10); the audit line carries the verdict as the cause.
fn refusal(v: Verdict) -> Response<Body> {
    match v {
        Verdict::Challenge => text(StatusCode::FORBIDDEN, "Request requires verification.\n"),
        _ => text(StatusCode::FORBIDDEN, "Request blocked.\n"),
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
    let start = std::time::Instant::now();
    let lim = &state.limits;
    let (parts, body) = req.into_parts();
    if parts.headers.len() > lim.max_headers {
        return Ok(text(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "Request header fields too large.\n"));
    }
    if wants_upgrade(&parts.headers) {
        return Ok(text(StatusCode::NOT_IMPLEMENTED, "Protocol upgrade is not supported.\n"));
    }
    // Spec §5.3 step 3: a banned source is answered from the head, before its
    // body is read (so it cannot hold a body-read slot either).
    if state.enforce {
        if let Some(d) = state.pipeline.fast_track(&parts, Some(peer.ip()), now_ms()) {
            let id = state.request_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let ts = now_ms();
            let eid = state.ids.next(ts);
            let group = d.group_id();
            let m = audit::EventMeta { ts_ms: ts, request_id: id, event_id: &eid, group_id: group.as_deref(), enforced: true };
            state.audit.record(&d.request, &d.judgment, &m);
            state.ocsf.record(&d.request, &d.judgment, &m);
            let resp = refusal(d.judgment.verdict);
            if let Some(bus) = &state.bus {
                publish_decision(bus, d, eid, ts, start, None);
            }
            return Ok(resp);
        }
    }
    let declared_len = parts
        .headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared_len.is_some_and(|n| n > lim.max_body) {
        return Ok(text(StatusCode::PAYLOAD_TOO_LARGE, "Payload too large.\n"));
    }

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
    let id = state.request_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ts = now_ms();
    let eid = state.ids.next(ts);
    // One group ID per source key and episode, computed once for both sinks.
    let group = decision.group_id();
    let m = audit::EventMeta { ts_ms: ts, request_id: id, event_id: &eid, group_id: group.as_deref(), enforced: state.enforce };
    state.audit.record(&decision.request, &decision.judgment, &m);
    state.ocsf.record(&decision.request, &decision.judgment, &m);

    let (resp, upstream_status) = if state.enforce && matches!(decision.judgment.verdict, Verdict::Block | Verdict::Challenge) {
        (refusal(decision.judgment.verdict), None)
    } else {
        forward(&state, &parts, collected, peer, &decision.judgment).await
    };
    if let Some(bus) = &state.bus {
        publish_decision(bus, decision, eid, ts, start, upstream_status);
    }
    Ok(resp)
}

/// Forward to the upstream. The status is the one the upstream sent; the
/// 502/504 the proxy answers with itself carry `None`.
async fn forward(
    state: &ProxyState,
    parts: &http::request::Parts,
    body: Bytes,
    peer: SocketAddr,
    j: &Judgment,
) -> (Response<Body>, Option<u16>) {
    let path_q = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", state.upstream.trim_end_matches('/'), path_q);
    let mut headers = parts.headers.clone();
    strip_hop_by_hop(&mut headers);
    headers.remove(hyper::header::HOST);
    // Decision headers are only ever set by the proxy: drop any the client sent.
    let spoofed: Vec<HeaderName> =
        headers.keys().filter(|k| k.as_str().starts_with("x-venusflytrap-")).cloned().collect();
    for k in spoofed {
        headers.remove(k);
    }
    // Every X-Forwarded-For line in order, then the peer (not just the first line).
    let mut xff: Vec<u8> = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        xff.extend_from_slice(v.as_bytes());
        xff.extend_from_slice(b", ");
    }
    xff.extend_from_slice(peer.ip().to_string().as_bytes());
    // Every piece is already a valid header value, so this does not fail.
    if let Ok(v) = HeaderValue::from_bytes(&xff) {
        headers.insert("x-forwarded-for", v);
    }
    headers.append(hyper::header::VIA, HeaderValue::from_static("1.1 venusflytrap"));
    if state.decision_headers == DecisionHeaders::Upstream {
        headers.insert("x-venusflytrap-score", HeaderValue::from(u16::from(j.score)));
        if let Ok(v) = HeaderValue::from_str(&format!("{:?}", j.verdict)) {
            headers.insert("x-venusflytrap-verdict", v);
        }
        if let Some(stage) = j.stage().and_then(|s| HeaderValue::from_str(&format!("{s:?}")).ok()) {
            headers.insert("x-venusflytrap-stage", stage);
        }
    }
    let mut out = match HyperReq::builder().method(parts.method.clone()).uri(url).body(Full::new(body)) {
        Ok(r) => r,
        Err(_) => return (text(StatusCode::BAD_GATEWAY, "Bad gateway.\n"), None),
    };
    *out.headers_mut() = headers;

    let wait = Duration::from_millis(state.limits.upstream_response_timeout_ms);
    match tokio::time::timeout(wait, state.client.request(out)).await {
        Err(_) => (text(StatusCode::GATEWAY_TIMEOUT, "Gateway timeout.\n"), None),
        Ok(Err(_)) => (text(StatusCode::BAD_GATEWAY, "Bad gateway.\n"), None),
        Ok(Ok(resp)) => {
            let (mut rp, rb) = resp.into_parts();
            strip_hop_by_hop(&mut rp.headers);
            let idle = Duration::from_millis(state.limits.response_idle_timeout_ms);
            let status = rp.status.as_u16();
            (Response::from_parts(rp, IdleTimeout::new(rb, idle).boxed()), Some(status))
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

/// Serve on an already-bound listener until the task is dropped. Accept
/// errors never end the loop (M9).
pub async fn serve_listener(state: Arc<ProxyState>, listener: TcpListener) -> anyhow::Result<()> {
    // The sender lives as long as this future, so the stop never fires.
    let (_never, stop) = watch::channel(false);
    serve_until(state, listener, stop, Duration::ZERO).await.map(|_| ())
}

/// Resolves once `stop` is true or its sender is gone.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|v| *v).await;
}

/// Like `serve_listener`, but stops accepting when `stop` flips to true, then waits for
/// in-flight connections up to `drain` and returns the number still open when it gave up.
///
/// On stop the listener is closed at once; every open connection finishes the
/// request it is serving and then closes (idle keep-alive connections close
/// straight away). Connections still open after `drain` are dropped, which
/// closes their sockets. Dropping the stop sender counts as a stop.
pub async fn serve_until(
    state: Arc<ProxyState>,
    listener: TcpListener,
    mut stop: watch::Receiver<bool>,
    drain: Duration,
) -> anyhow::Result<usize> {
    let slots = Arc::new(Semaphore::new(state.limits.max_connections));
    let mut conns = JoinSet::new();
    let mut backoff = Duration::from_millis(10);
    loop {
        // Reap finished connections so the set stays small.
        while conns.try_join_next().is_some() {}
        let permit = tokio::select! {
            biased;
            _ = stopped(&mut stop) => break,
            p = slots.clone().acquire_owned() => p?,
        };
        let accepted = tokio::select! {
            biased;
            _ = stopped(&mut stop) => break,
            r = listener.accept() => r,
        };
        let (stream, peer) = match accepted {
            Ok(x) => {
                backoff = Duration::from_millis(10);
                x
            }
            Err(e) => {
                eprintln!("accept error: {e}; retrying in {backoff:?}");
                tokio::select! {
                    _ = stopped(&mut stop) => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let st = state.clone();
        let header_ms = state.limits.header_read_timeout_ms;
        let max_headers = state.limits.max_headers;
        let lifetime = Duration::from_millis(state.limits.max_connection_ms);
        let mut conn_stop = stop.clone();
        conns.spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |req| handle(st.clone(), peer, req));
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(header_ms))
                .max_headers(max_headers);
            let conn = b.serve_connection(TokioIo::new(stream), svc);
            tokio::pin!(conn);
            let run = async {
                let mut closing = false;
                loop {
                    tokio::select! {
                        _ = conn.as_mut() => break,
                        _ = stopped(&mut conn_stop), if !closing => {
                            // Finish the request in progress, then close.
                            closing = true;
                            conn.as_mut().graceful_shutdown();
                        }
                    }
                }
            };
            // Dropping the connection future on expiry closes the socket and
            // releases the slot, also when a client stops reading (no write
            // progress means hyper never finishes on its own).
            let _ = tokio::time::timeout(lifetime, run).await;
        });
    }
    drop(listener);
    let _ = tokio::time::timeout(drain, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    let open = conns.len();
    // Abort the rest; their sockets close as the tasks are dropped.
    conns.shutdown().await;
    Ok(open)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vft_core::Config;

    fn state() -> ProxyState {
        ProxyState::new(
            Shield::new(Config::default()),
            "http://127.0.0.1:1".into(),
            audit::AuditSink::off(),
            audit::AuditSink::off(),
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

    mod events {
        use super::*;
        use crate::bus::{BusEvent, DecisionEvent, EventBus};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::broadcast::Receiver;

        /// Upstream stub answering every request `200 ok` (or `status`).
        async fn stub(status: u16) -> SocketAddr {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = l.accept().await else { return };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        let _ = s.read(&mut buf).await;
                        let resp = format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                        let _ = s.write_all(resp.as_bytes()).await;
                    });
                }
            });
            addr
        }

        /// A proxy with a bus attached, over `upstream`.
        async fn proxy(upstream: &str, enforce: bool) -> (SocketAddr, EventBus) {
            let bus = EventBus::new();
            let st = ProxyState::new(
                Shield::new(Config::default()),
                format!("http://{upstream}"),
                audit::AuditSink::off(),
                audit::AuditSink::off(),
                enforce,
            )
            .with_bus(bus.clone());
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(serve_listener(Arc::new(st), l));
            (addr, bus)
        }

        async fn get(addr: SocketAddr, target: &str) -> String {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let raw = format!("GET {target} HTTP/1.1\r\nHost: shop.test\r\nConnection: close\r\n\r\n");
            s.write_all(raw.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
            String::from_utf8_lossy(&out).into_owned()
        }

        async fn next(rx: &mut Receiver<BusEvent>) -> BusEvent {
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("event in time").expect("bus open")
        }

        async fn next_decision(rx: &mut Receiver<BusEvent>) -> Arc<DecisionEvent> {
            match next(rx).await {
                BusEvent::Decision(d) => d,
                other => panic!("expected Decision, got {other:?}"),
            }
        }

        async fn quiet(rx: &mut Receiver<BusEvent>) {
            let r = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
            assert!(r.is_err(), "unexpected extra event: {r:?}");
        }

        #[tokio::test]
        async fn forwarded_allow_publishes_one_decision_with_upstream_status_and_latency() {
            let up = stub(200).await;
            let (addr, bus) = proxy(&up.to_string(), true).await;
            let mut rx = bus.subscribe();
            let resp = get(addr, "/products?page=2").await;
            assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
            let d = next_decision(&mut rx).await;
            assert_eq!(d.judgment.verdict, Verdict::Allow);
            assert_eq!(d.upstream_status, Some(200));
            assert!(d.latency_us > 0);
            assert_eq!((d.method.as_str(), d.host.as_str(), d.path.as_str()), ("GET", "shop.test", "/products"));
            assert_eq!(d.ip, Some("127.0.0.1".parse().unwrap()));
            assert_eq!(d.src_key.as_deref(), Some("127.0.0.1"));
            assert_eq!(d.config_rev, 1);
            assert!(!d.event_id.is_empty());
            assert!(d.ts_ms > 0);
            assert!(d.snippets.is_empty());
            quiet(&mut rx).await;
        }

        #[tokio::test]
        async fn upstream_error_status_is_reported_as_the_upstream_sent_it() {
            let up = stub(502).await;
            let (addr, bus) = proxy(&up.to_string(), true).await;
            let mut rx = bus.subscribe();
            let _ = get(addr, "/").await;
            assert_eq!(next_decision(&mut rx).await.upstream_status, Some(502));
        }

        #[tokio::test]
        async fn a_gateway_error_the_proxy_produced_is_not_an_upstream_status() {
            let (addr, bus) = proxy("127.0.0.1:1", true).await;
            let mut rx = bus.subscribe();
            let resp = get(addr, "/").await;
            assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
            assert_eq!(next_decision(&mut rx).await.upstream_status, None);
        }

        #[tokio::test]
        async fn block_publishes_a_decision_without_an_upstream_status() {
            let up = stub(200).await;
            let (addr, bus) = proxy(&up.to_string(), true).await;
            let mut rx = bus.subscribe();
            let resp = get(addr, "/x?id=1%20union%20select%20a,b").await;
            assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
            let d = next_decision(&mut rx).await;
            assert_eq!(d.judgment.verdict, Verdict::Block);
            assert_eq!(d.upstream_status, None);
            assert_eq!(d.path, "/x");
        }

        #[tokio::test]
        async fn monitor_mode_forwards_a_block_and_reports_the_upstream_status() {
            let up = stub(200).await;
            let (addr, bus) = proxy(&up.to_string(), false).await;
            let mut rx = bus.subscribe();
            let _ = get(addr, "/x?id=1%20union%20select%20a,b").await;
            let d = next_decision(&mut rx).await;
            assert_eq!(d.judgment.verdict, Verdict::Block);
            assert_eq!(d.upstream_status, Some(200));
        }

        #[tokio::test]
        async fn a_ban_publishes_decision_then_ban_changed_and_the_fast_track_only_a_decision() {
            let up = stub(200).await;
            let (addr, bus) = proxy(&up.to_string(), true).await;
            let mut rx = bus.subscribe();
            assert!(get(addr, "/.git/config").await.starts_with("HTTP/1.1 403"));
            let d = next_decision(&mut rx).await;
            assert!(d.judgment.chain.as_ref().is_some_and(|c| c.new_ban.is_some()), "{:?}", d.judgment.chain);
            match next(&mut rx).await {
                BusEvent::BanChanged { key, ban, lifted } => {
                    assert_eq!(key, "127.0.0.1");
                    assert!(!lifted);
                    assert_eq!(ban.map(|b| b.offences), Some(1));
                }
                other => panic!("expected BanChanged, got {other:?}"),
            }
            quiet(&mut rx).await;
            // The next request is answered from the head: a Decision, no new ban.
            assert!(get(addr, "/").await.starts_with("HTTP/1.1 403"));
            let d = next_decision(&mut rx).await;
            assert!(d.judgment.banned());
            assert_eq!(d.upstream_status, None);
            assert_eq!(d.src_key.as_deref(), Some("127.0.0.1"));
            quiet(&mut rx).await;
        }

        #[tokio::test]
        async fn a_bus_with_no_subscriber_never_disturbs_a_request() {
            let up = stub(200).await;
            let (addr, _bus) = proxy(&up.to_string(), true).await;
            assert!(get(addr, "/").await.starts_with("HTTP/1.1 200"));
            assert!(get(addr, "/.git/config").await.starts_with("HTTP/1.1 403"));
        }

        #[tokio::test]
        async fn without_a_bus_requests_behave_as_before() {
            let up = stub(200).await;
            let st = ProxyState::new(
                Shield::new(Config::default()),
                format!("http://{up}"),
                audit::AuditSink::off(),
                audit::AuditSink::off(),
                true,
            );
            assert!(st.bus.is_none());
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(serve_listener(Arc::new(st), l));
            assert!(get(addr, "/").await.starts_with("HTTP/1.1 200"));
        }
    }

    mod drain {
        use super::*;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::watch;

        /// Upstream stub that answers `200 ok` after `delay` (never, if `None`).
        async fn slow_stub(delay: Option<Duration>) -> SocketAddr {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = l.accept().await else { return };
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        let _ = s.read(&mut buf).await;
                        match delay {
                            Some(d) => tokio::time::sleep(d).await,
                            None => std::future::pending::<()>().await,
                        }
                        let _ = s.write_all(b"HTTP/1.1 200 OK
Content-Length: 2
Connection: close

ok").await;
                    });
                }
            });
            addr
        }

        type Served = tokio::task::JoinHandle<anyhow::Result<usize>>;

        async fn proxy(upstream: SocketAddr, drain: Duration) -> (SocketAddr, watch::Sender<bool>, Served) {
            let st = ProxyState::new(
                Shield::new(vft_core::Config::default()),
                format!("http://{upstream}"),
                audit::AuditSink::off(),
                audit::AuditSink::off(),
                true,
            );
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let (tx, rx) = watch::channel(false);
            (addr, tx, tokio::spawn(serve_until(Arc::new(st), l, rx, drain)))
        }

        /// Send one request and read until the server closes (or 5 s).
        async fn send(addr: SocketAddr, keep_alive: bool) -> tokio::net::TcpStream {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let conn = if keep_alive { "keep-alive" } else { "close" };
            let raw = format!("GET / HTTP/1.1
Host: shop.test
Connection: {conn}

");
            s.write_all(raw.as_bytes()).await.unwrap();
            s
        }

        async fn read_all(mut s: tokio::net::TcpStream) -> String {
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
            String::from_utf8_lossy(&out).into_owned()
        }

        #[tokio::test]
        async fn stop_with_nothing_in_flight_returns_zero_and_releases_the_port() {
            let up = slow_stub(Some(Duration::ZERO)).await;
            let (addr, stop, served) = proxy(up, Duration::from_secs(10)).await;
            assert!(read_all(send(addr, false).await).await.starts_with("HTTP/1.1 200"));
            let t = Instant::now();
            stop.send(true).unwrap();
            let open = tokio::time::timeout(Duration::from_secs(5), served).await.unwrap().unwrap().unwrap();
            assert_eq!(open, 0);
            assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
            TcpListener::bind(addr).await.expect("the port is free again");
        }

        #[tokio::test]
        async fn an_in_flight_request_completes_during_the_drain() {
            let up = slow_stub(Some(Duration::from_millis(300))).await;
            let (addr, stop, served) = proxy(up, Duration::from_secs(10)).await;
            let s = send(addr, false).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            stop.send(true).unwrap();
            // No new connections once stopped.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(tokio::net::TcpStream::connect(addr).await.is_err(), "still accepting after stop");
            assert!(read_all(s).await.starts_with("HTTP/1.1 200"));
            let open = tokio::time::timeout(Duration::from_secs(5), served).await.unwrap().unwrap().unwrap();
            assert_eq!(open, 0);
        }

        #[tokio::test]
        async fn an_idle_keep_alive_connection_does_not_hold_up_the_stop() {
            let up = slow_stub(Some(Duration::ZERO)).await;
            let (addr, stop, served) = proxy(up, Duration::from_secs(10)).await;
            let mut s = send(addr, true).await;
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
            let t = Instant::now();
            stop.send(true).unwrap();
            let open = tokio::time::timeout(Duration::from_secs(5), served).await.unwrap().unwrap().unwrap();
            assert_eq!(open, 0);
            assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        }

        #[tokio::test]
        async fn a_request_that_never_finishes_is_cut_off_at_the_drain_limit() {
            let up = slow_stub(None).await;
            let (addr, stop, served) = proxy(up, Duration::from_millis(500)).await;
            let s = send(addr, false).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            let t = Instant::now();
            stop.send(true).unwrap();
            let open = tokio::time::timeout(Duration::from_secs(5), served).await.unwrap().unwrap().unwrap();
            let took = t.elapsed();
            assert_eq!(open, 1);
            assert!(took >= Duration::from_millis(450) && took < Duration::from_secs(2), "{took:?}");
            let resp = read_all(s).await;
            assert!(!resp.contains(" 200 "), "cut off, not answered: {resp}");
        }

        #[tokio::test]
        async fn dropping_the_stop_sender_also_stops() {
            let up = slow_stub(Some(Duration::ZERO)).await;
            let (_addr, stop, served) = proxy(up, Duration::from_secs(10)).await;
            drop(stop);
            let open = tokio::time::timeout(Duration::from_secs(5), served).await.unwrap().unwrap().unwrap();
            assert_eq!(open, 0);
        }
    }
}
