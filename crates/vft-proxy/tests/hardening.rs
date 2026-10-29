//! End-to-end proxy hardening tests over real loopback sockets, with short
//! configured timeouts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vft_core::{Config, Shield};
use vft_proxy::{serve_listener, ProxyState};

struct Stub {
    addr: std::net::SocketAddr,
    conns: Arc<AtomicUsize>,
    last: Arc<Mutex<Vec<u8>>>,
}

/// Upstream stub. `respond = false` accepts and then never answers.
async fn stub(respond: bool) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(Vec::new()));
    let (c, la) = (conns.clone(), last.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let la = la.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = s.read(&mut buf).await.unwrap_or(0);
                *la.lock().unwrap() = buf[..n].to_vec();
                if respond {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                } else {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }
    });
    Stub { addr, conns, last }
}

async fn proxy(cfg: Config, upstream: std::net::SocketAddr) -> std::net::SocketAddr {
    let state = Arc::new(ProxyState::new(Shield::new(cfg), format!("http://{upstream}"), vft_proxy::audit::AuditSink::off(), vft_proxy::audit::AuditSink::off(), true));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve_listener(state, l));
    addr
}

fn short_cfg() -> Config {
    let mut c = Config::default();
    c.limits.max_body = 64 * 1024;
    c.limits.header_read_timeout_ms = 300;
    c.limits.body_read_timeout_ms = 300;
    c.limits.upstream_response_timeout_ms = 300;
    c
}

async fn send(addr: std::net::SocketAddr, raw: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    // The proxy may answer (e.g. 413) and close before the whole body is sent.
    let _ = s.write_all(raw).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn oversized_body_is_413_before_upstream() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let body = vec![b'a'; 200 * 1024];
    let head = format!("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    // Read the answer before sending the body: if body bytes are still unread
    // when the proxy closes, Windows answers with a RST that discards the 413
    // already sitting in the client's receive buffer.
    let mut s = TcpStream::connect(p).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    let (out, _) = read_until_closed(&mut s, Duration::from_secs(5)).await;
    let _ = s.write_all(&body).await;
    let resp = String::from_utf8_lossy(&out);
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_utf8_cookie_attack_is_blocked_and_never_forwarded() {
    // C4 end to end
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let mut raw = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nCookie: id=1 union select password from users; z=".to_vec();
    raw.push(0xff);
    raw.extend_from_slice(b"\r\n\r\n");
    let resp = send(p, &raw).await;
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn hop_by_hop_headers_are_stripped_and_forwarding_headers_added() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let raw = b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close, X-Internal-Auth\r\nX-Internal-Auth: s3cret\r\nKeep-Alive: timeout=5\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nTE: trailers\r\n\r\n";
    let resp = send(p, raw).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let fwd = String::from_utf8_lossy(&up.last.lock().unwrap()).to_ascii_lowercase();
    for h in ["x-internal-auth", "keep-alive:", "proxy-authorization", "\r\nte:"] {
        assert!(!fwd.contains(h), "forwarded {h}: {fwd}");
    }
    assert!(fwd.contains("x-forwarded-for: 127.0.0.1"), "{fwd}");
    assert!(fwd.contains("via: 1.1 venusflytrap"), "{fwd}");
}

#[tokio::test]
async fn upgrade_is_refused() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let resp = send(p, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, close\r\nUpgrade: h2c\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn hung_upstream_is_504() {
    let up = stub(false).await;
    let p = proxy(short_cfg(), up.addr).await;
    let t = Instant::now();
    let resp = send(p, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(resp.starts_with("HTTP/1.1 504"), "{resp}");
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn slowloris_connection_is_closed() {
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let mut s = TcpStream::connect(p).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut buf)).await;
    assert!(r.is_ok(), "connection still open after header-read timeout");
}

#[tokio::test]
async fn no_decision_headers_or_error_text_reach_the_client() {
    // L1, L3: upstream down → generic 502, no score oracle.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    // Windows reports a refused loopback connect only after ~2s of SYN retries,
    // so the response timeout must outlast it for the refusal (502) to win.
    let mut cfg = short_cfg();
    cfg.limits.upstream_response_timeout_ms = 4_000;
    let p = proxy(cfg, dead).await;
    let resp = send(p, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.to_ascii_lowercase();
    assert!(resp.starts_with("http/1.1 502"), "{resp}");
    assert!(!resp.contains("x-venusflytrap"), "{resp}");
    assert!(!resp.contains("error"), "{resp}");
}

/// Upstream stub whose reply is computed from the raw request; with
/// `stall_after` the socket is then held open without sending anything more.
async fn stub_with(reply: fn(&[u8]) -> Vec<u8>, stall_after: bool) -> Stub {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(Vec::new()));
    let (c, la) = (conns.clone(), last.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let la = la.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = s.read(&mut buf).await.unwrap_or(0);
                *la.lock().unwrap() = buf[..n].to_vec();
                let _ = s.write_all(&reply(&buf[..n])).await;
                if stall_after {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }
    });
    Stub { addr, conns, last }
}

/// Read until EOF, a reset, or `limit`; returns what was read and whether the
/// connection ended (EOF or error) before the limit.
async fn read_until_closed(s: &mut TcpStream, limit: Duration) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let ended = tokio::time::timeout(limit, s.read_to_end(&mut out)).await.is_ok();
    (out, ended)
}

#[tokio::test]
async fn too_many_headers_is_431_before_upstream() {
    let up = stub(true).await;
    let mut cfg = short_cfg();
    cfg.limits.max_headers = 16;
    let p = proxy(cfg, up.addr).await;
    let mut raw = String::from("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for i in 0..40 {
        raw.push_str(&format!("X-H{i}: v\r\n"));
    }
    raw.push_str("\r\n");
    let resp = send(p, raw.as_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 431"), "{resp}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stalled_upstream_body_is_cut_after_idle_timeout() {
    // Complete response headers promising 1 MB, a few bytes, then silence.
    fn reply(_: &[u8]) -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\npartial".to_vec()
    }
    let up = stub_with(reply, true).await;
    let mut cfg = short_cfg();
    cfg.limits.response_idle_timeout_ms = 300;
    let p = proxy(cfg, up.addr).await;
    let mut s = TcpStream::connect(p).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    let t = Instant::now();
    let (out, ended) = read_until_closed(&mut s, Duration::from_secs(3)).await;
    let out = String::from_utf8_lossy(&out);
    assert!(ended, "client connection still open after response idle timeout: {out}");
    assert!(t.elapsed() < Duration::from_secs(3));
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}

#[tokio::test]
async fn client_that_never_reads_is_dropped_at_max_connection_ms() {
    const BIG: usize = 8 * 1024 * 1024;
    fn reply(req: &[u8]) -> Vec<u8> {
        if req.starts_with(b"GET /big ") {
            let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {BIG}\r\nConnection: close\r\n\r\n").into_bytes();
            r.resize(r.len() + BIG, b'x');
            r
        } else {
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
        }
    }
    let up = stub_with(reply, false).await;
    let mut cfg = short_cfg();
    cfg.limits.max_connections = 1;
    cfg.limits.max_connection_ms = 500;
    let p = proxy(cfg, up.addr).await;

    // Client A takes the only connection slot and never reads its 8 MB response.
    let t = Instant::now();
    let mut a = TcpStream::connect(p).await.unwrap();
    a.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Client B is only served once A's connection is dropped.
    let mut b = TcpStream::connect(p).await.unwrap();
    let _ = b.write_all(b"GET /small HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    let (out, _) = read_until_closed(&mut b, Duration::from_secs(5)).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    let waited = t.elapsed();
    assert!(waited < Duration::from_secs(3), "second client waited {waited:?}");
    // B could not be served before A's 500 ms lifetime cap expired.
    assert!(waited >= Duration::from_millis(450), "slot was not held by A: {waited:?}");
    drop(a);
}

async fn proxy_with_state(cfg: Config, upstream: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<ProxyState>) {
    let state = Arc::new(ProxyState::new(Shield::new(cfg), format!("http://{upstream}"), vft_proxy::audit::AuditSink::off(), vft_proxy::audit::AuditSink::off(), true));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve_listener(state.clone(), l));
    (addr, state)
}

fn forwarded_lines(up: &Stub, name: &str) -> Vec<String> {
    let fwd = String::from_utf8_lossy(&up.last.lock().unwrap()).into_owned();
    fwd.split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .collect()
}

#[tokio::test]
async fn every_x_forwarded_for_line_is_kept_in_order_with_the_peer_appended() {
    // Final review I3: two XFF lines from an untrusted peer must not collapse to the first.
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let raw = b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Forwarded-For: 198.51.100.1\r\nX-Forwarded-For: 198.51.100.2\r\n\r\n";
    let resp = send(p, raw).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(forwarded_lines(&up, "x-forwarded-for"), vec!["198.51.100.1, 198.51.100.2, 127.0.0.1".to_string()]);
}

const SPOOFED: &[u8] = b"GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Venusflytrap-Stage: Exfiltration\r\nX-Venusflytrap-Score: 77\r\nX-Venusflytrap-Verdict: Block\r\nX-VenusFlytrap-Other: 1\r\n\r\n";

#[tokio::test]
async fn client_decision_headers_never_reach_upstream_when_off() {
    // Final review I4.
    let up = stub(true).await;
    let p = proxy(short_cfg(), up.addr).await;
    let resp = send(p, SPOOFED).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let fwd = String::from_utf8_lossy(&up.last.lock().unwrap()).to_ascii_lowercase();
    assert!(!fwd.contains("x-venusflytrap"), "{fwd}");
}

#[tokio::test]
async fn upstream_mode_forwards_only_proxy_set_decision_headers() {
    let up = stub(true).await;
    let mut cfg = short_cfg();
    cfg.proxy.decision_headers = vft_core::config::DecisionHeaders::Upstream;
    let p = proxy(cfg, up.addr).await;
    let resp = send(p, SPOOFED).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    let score = forwarded_lines(&up, "x-venusflytrap-score");
    let verdict = forwarded_lines(&up, "x-venusflytrap-verdict");
    assert_eq!(score.len(), 1, "{score:?}");
    assert_ne!(score[0], "77", "client score forwarded");
    assert_eq!(verdict.len(), 1, "{verdict:?}");
    assert!(verdict[0] == "Allow" || verdict[0] == "Monitor", "{verdict:?}");
    assert!(forwarded_lines(&up, "x-venusflytrap-stage").is_empty(), "client stage forwarded");
    assert!(forwarded_lines(&up, "x-venusflytrap-other").is_empty());
}

#[tokio::test]
async fn banned_source_gets_403_before_its_body_is_read() {
    // Final review I8 (spec §5.3 step 3): the ban fast-track runs before the body read.
    let up = stub(true).await;
    let mut cfg = short_cfg();
    cfg.limits.body_read_timeout_ms = 10_000;
    let (p, state) = proxy_with_state(cfg, up.addr).await;
    let me = vft_core::SourceKey::new("127.0.0.1".parse().unwrap(), 64);
    state.pipeline.chain().ban(me, vft_core::BanCause::Manual, vft_proxy::now_ms());
    let mut s = TcpStream::connect(p).await.unwrap();
    // A large declared body that is never sent: only the fast-track can answer in time.
    s.write_all(b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 60000\r\nConnection: close\r\n\r\n").await.unwrap();
    let t = Instant::now();
    let (out, _) = read_until_closed(&mut s, Duration::from_secs(3)).await;
    let out = String::from_utf8_lossy(&out);
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.ends_with("Request blocked.\n"), "{out}");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}

const XXE_BODY: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<!DOCTYPE xxe [\r\n<!ELEMENT name ANY >\r\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>\r\n<name>&xxe;</name>";

#[tokio::test]
async fn challenge_and_block_have_distinct_bodies() {
    // Final review I8 / spec decision 10.
    let up = stub(true).await;
    let mut cfg = short_cfg();
    cfg.scoring.chain_stage_bonus = 0; // keep the XXE request in the Challenge band
    let p = proxy(cfg, up.addr).await;
    let raw = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{XXE_BODY}",
        XXE_BODY.len()
    );
    let challenge = send(p, raw.as_bytes()).await;
    assert!(challenge.starts_with("HTTP/1.1 403"), "{challenge}");
    assert!(challenge.ends_with("Request requires verification.\n"), "{challenge}");
    let p2 = proxy(short_cfg(), up.addr).await;
    let block = send(p2, b"GET /x?id=1%20union%20select%20password%20from%20users HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(block.starts_with("HTTP/1.1 403"), "{block}");
    assert!(block.ends_with("Request blocked.\n"), "{block}");
    assert_eq!(up.conns.load(Ordering::SeqCst), 0);
}
