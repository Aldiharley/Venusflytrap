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
    let state = Arc::new(ProxyState::new(Shield::new(cfg), format!("http://{upstream}"), None, true));
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
    let mut raw = format!("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    raw.extend_from_slice(&body);
    let resp = send(p, &raw).await;
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
