//! Loopback-only admin listener: health, status, metrics and config reload.
//!
//! There is no authentication yet, so the listener must only ever bind to a
//! loopback address (see [`check_bind`]).

use crate::metrics::Metrics;
use crate::status::StatusBoard;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

pub trait Reload: Send + Sync + 'static {
    /// Ok(new rev) or Err((issues, live rev)).
    fn reload(&self) -> Result<u64, (Vec<String>, u64)>;
}

pub struct AdminState {
    pub status: Arc<StatusBoard>,
    pub metrics: Arc<Metrics>,
    pub reload: Arc<dyn Reload>,
}

pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/status"),
    ("GET", "/metrics"),
    ("POST", "/api/v1/reload"),
];

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

const MAX_CONNECTIONS: usize = 64;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(15);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors if `bind` is not a loopback address.
pub fn check_bind(bind: SocketAddr) -> anyhow::Result<()> {
    let loopback = match bind.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    };
    if loopback {
        Ok(())
    } else {
        anyhow::bail!(
            "admin listener bind {bind} is not a loopback address: the admin API has no              authentication yet, so it must bind to loopback (127.0.0.0/8 or ::1)"
        )
    }
}

fn respond(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .header("Content-Security-Policy", CSP)
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn json(status: StatusCode, v: &serde_json::Value) -> Response<Full<Bytes>> {
    respond(status, "application/json", v.to_string().into_bytes())
}

async fn handle(state: Arc<AdminState>, method: Method, path: &str) -> Response<Full<Bytes>> {
    let Some(&(allowed, _)) = ROUTES.iter().find(|(_, p)| *p == path) else {
        return json(
            StatusCode::NOT_FOUND,
            &serde_json::json!({"error": "not found"}),
        );
    };
    if method.as_str() != allowed {
        let mut r = json(
            StatusCode::METHOD_NOT_ALLOWED,
            &serde_json::json!({"error": "method not allowed"}),
        );
        r.headers_mut()
            .insert("Allow", hyper::header::HeaderValue::from_static(allowed));
        return r;
    }
    match path {
        "/api/v1/health" => json(StatusCode::OK, &serde_json::json!({"ok": true})),
        "/api/v1/status" => match serde_json::to_vec(&state.status.snapshot()) {
            Ok(body) => respond(StatusCode::OK, "application/json", body),
            Err(_) => json(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({"error": "internal error"}),
            ),
        },
        "/metrics" => {
            let text = state.metrics.render(&state.status.snapshot());
            respond(
                StatusCode::OK,
                "text/plain; version=0.0.4",
                text.into_bytes(),
            )
        }
        _ => {
            // POST /api/v1/reload does file and parse work: keep it off the
            // async worker threads.
            let reload = state.reload.clone();
            match tokio::task::spawn_blocking(move || reload.reload()).await {
                Ok(Ok(rev)) => json(StatusCode::OK, &serde_json::json!({"rev": rev})),
                Ok(Err((issues, rev))) => json(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &serde_json::json!({"rev": rev, "issues": issues}),
                ),
                Err(_) => json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": "reload failed"}),
                ),
            }
        }
    }
}

/// Serve until `stop` flips to true (or its sender is dropped). Stops accepting
/// at once; in-flight requests get a bounded time to finish.
pub async fn serve_admin(
    listener: TcpListener,
    state: Arc<AdminState>,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut conns = JoinSet::new();
    let mut backoff = Duration::from_millis(10);
    loop {
        if *stop.borrow() {
            break;
        }
        let permit = tokio::select! {
            p = slots.clone().acquire_owned() => p?,
            _ = stop.changed() => break,
        };
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((s, _)) => {
                    backoff = Duration::from_millis(10);
                    s
                }
                Err(e) => {
                    tracing::warn!(error = %e, "admin accept error");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                    continue;
                }
            },
            _ = stop.changed() => break,
        };
        let st = state.clone();
        conns.spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let st = st.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        handle(st, req.method().clone(), req.uri().path()).await,
                    )
                }
            });
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .keep_alive(false);
            let _ = tokio::time::timeout(
                CONNECTION_LIFETIME,
                b.serve_connection(TokioIo::new(stream), svc),
            )
            .await;
        });
        // Reap finished connections so the set stays small.
        while conns.try_join_next().is_some() {}
    }
    drop(listener);
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    struct Stub {
        fail: bool,
        calls: AtomicU64,
    }
    impl Reload for Stub {
        fn reload(&self) -> Result<u64, (Vec<String>, u64)> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err((vec!["bad rule".into(), "bad bind".into()], 3))
            } else {
                Ok(4)
            }
        }
    }

    struct Server {
        addr: SocketAddr,
        stop: watch::Sender<bool>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        stub: Arc<Stub>,
    }

    async fn start(fail: bool) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stub = Arc::new(Stub {
            fail,
            calls: AtomicU64::new(0),
        });
        let state = Arc::new(AdminState {
            status: Arc::new(StatusBoard::new()),
            metrics: Arc::new(Metrics::new()),
            reload: stub.clone(),
        });
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(serve_admin(listener, state, rx));
        Server {
            addr,
            stop,
            task,
            stub,
        }
    }

    struct Resp {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }
    impl Resp {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    async fn request(addr: SocketAddr, method: &str, path: &str) -> Resp {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8(buf).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .map(|l| {
                let (k, v) = l.split_once(':').unwrap();
                (k.trim().to_string(), v.trim().to_string())
            })
            .collect();
        Resp {
            status,
            headers,
            body: body.to_string(),
        }
    }

    fn assert_security_headers(r: &Resp) {
        assert_eq!(
            r.header("content-security-policy"),
            Some("default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        );
        assert_eq!(r.header("content-security-policy"), Some(CSP));
        assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
        assert_eq!(r.header("cache-control"), Some("no-store"));
    }

    #[tokio::test]
    async fn health_is_ok_json() {
        let s = start(false).await;
        let r = request(s.addr, "GET", "/api/v1/health").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.body, r#"{"ok":true}"#);
        assert_security_headers(&r);
    }

    #[tokio::test]
    async fn status_returns_the_status_record() {
        let s = start(false).await;
        let r = request(s.addr, "GET", "/api/v1/status").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["health"], "Ok");
        assert_eq!(v["components"].as_array().unwrap().len(), 4);
        assert!(v["config_rev"].is_u64());
        assert_security_headers(&r);
    }

    #[tokio::test]
    async fn metrics_is_prometheus_text() {
        let s = start(false).await;
        let r = request(s.addr, "GET", "/metrics").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("text/plain; version=0.0.4"));
        assert!(r.body.contains("# TYPE"), "{}", r.body);
        assert_security_headers(&r);
    }

    #[tokio::test]
    async fn reload_ok_returns_new_rev() {
        let s = start(false).await;
        let r = request(s.addr, "POST", "/api/v1/reload").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.body, r#"{"rev":4}"#);
        assert_eq!(s.stub.calls.load(Ordering::SeqCst), 1);
        assert_security_headers(&r);
    }

    #[tokio::test]
    async fn reload_failure_is_422_with_issues_and_live_rev() {
        let s = start(true).await;
        let r = request(s.addr, "POST", "/api/v1/reload").await;
        assert_eq!(r.status, 422);
        let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["rev"], 3);
        assert_eq!(v["issues"], serde_json::json!(["bad rule", "bad bind"]));
        assert_security_headers(&r);
    }

    #[tokio::test]
    async fn unknown_path_is_404_with_headers() {
        let s = start(false).await;
        for path in [
            "/",
            "/nope",
            "/api/v1/",
            "/api/v1/unknown",
            "/api/v2/health",
        ] {
            let r = request(s.addr, "GET", path).await;
            assert_eq!(r.status, 404, "{path}");
            assert_eq!(r.body, r#"{"error":"not found"}"#);
            assert_security_headers(&r);
        }
    }

    #[tokio::test]
    async fn wrong_method_is_405_with_allow_and_does_not_run_the_handler() {
        let s = start(false).await;
        let r = request(s.addr, "GET", "/api/v1/reload").await;
        assert_eq!(r.status, 405);
        assert_eq!(r.header("allow"), Some("POST"));
        assert_security_headers(&r);
        let r = request(s.addr, "POST", "/api/v1/health").await;
        assert_eq!(r.status, 405);
        assert_eq!(r.header("allow"), Some("GET"));
        assert_security_headers(&r);
        let r = request(s.addr, "DELETE", "/metrics").await;
        assert_eq!(r.status, 405);
        assert_eq!(r.header("allow"), Some("GET"));
        assert_eq!(s.stub.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_route_in_the_table_is_served_and_nothing_else_under_api() {
        let s = start(false).await;
        for (method, path) in ROUTES {
            let r = request(s.addr, method, path).await;
            assert_ne!(r.status, 404, "{method} {path}");
            assert_ne!(r.status, 405, "{method} {path}");
            assert_security_headers(&r);
        }
        for path in [
            "/api/v1/admin",
            "/api/v1/health/",
            "/api/v1/reload/x",
            "/api/v1/statuses",
        ] {
            for method in ["GET", "POST"] {
                let r = request(s.addr, method, path).await;
                assert_eq!(r.status, 404, "{method} {path}");
            }
        }
    }

    #[test]
    fn check_bind_accepts_only_loopback() {
        for ok in [
            "127.0.0.1:0",
            "127.1.2.3:8899",
            "[::1]:0",
            "[::ffff:127.0.0.1]:0",
        ] {
            check_bind(ok.parse().unwrap()).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "0.0.0.0:8899",
            "192.0.2.1:1",
            "10.0.0.1:80",
            "[::]:80",
            "[2001:db8::1]:80",
            "[::ffff:192.0.2.1]:80",
            "[::ffff:0.0.0.0]:80",
        ] {
            let e = check_bind(bad.parse().unwrap()).unwrap_err().to_string();
            assert!(e.contains("loopback"), "{bad}: {e}");
            assert!(e.contains("authentication"), "{bad}: {e}");
        }
    }

    #[tokio::test]
    async fn stop_ends_the_server_and_refuses_new_connections() {
        let s = start(false).await;
        assert_eq!(request(s.addr, "GET", "/api/v1/health").await.status, 200);
        s.stop.send(true).unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), s.task)
            .await
            .expect("serve_admin returns after stop")
            .unwrap();
        assert!(res.is_ok());
        assert!(TcpStream::connect(s.addr).await.is_err());
    }

    #[tokio::test]
    async fn already_stopped_returns_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = Arc::new(AdminState {
            status: Arc::new(StatusBoard::new()),
            metrics: Arc::new(Metrics::new()),
            reload: Arc::new(Stub {
                fail: false,
                calls: AtomicU64::new(0),
            }),
        });
        let (_tx, rx) = watch::channel(true);
        tokio::time::timeout(Duration::from_secs(5), serve_admin(listener, state, rx))
            .await
            .unwrap()
            .unwrap();
    }
}
