//! `venusflytrap serve` as a process: startup output, the admin bind check
//! and (unix) SIGHUP reload.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_venusflytrap");

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vft-cli-serve-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A running `serve`, killed on drop; stderr lines arrive on `lines`.
struct Serve {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Serve {
    fn start(args: &[&str]) -> Serve {
        let mut child = Command::new(BIN)
            .arg("serve")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let err = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        Serve { child, lines }
    }

    /// The first stderr line containing `needle` (10 s at most).
    fn wait_line(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(l) if l.contains(needle) => return l,
                Ok(l) => seen.push(l),
                Err(_) => break,
            }
        }
        panic!("no stderr line with {needle:?}; got:\n{}", seen.join("\n"));
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The `http://ADDR` in `line`.
fn addr_in(line: &str) -> SocketAddr {
    let rest = &line[line.find("http://").expect("an http:// address") + "http://".len()..];
    rest.split_whitespace().next().unwrap().parse().unwrap()
}

fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // `Host: <ip:port>`: the admin listener serves nothing else.
    write!(s, "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code = out.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    (code, out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default())
}

#[test]
fn a_non_loopback_admin_bind_exits_1_before_binding() {
    // Hold the proxy port: had the proxy bound first, the error would be "in use".
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = held.local_addr().unwrap().to_string();
    let t = Instant::now();
    let out = Command::new(BIN)
        .args(["serve", "--bind", &bind, "--upstream", "http://127.0.0.1:1", "--admin-bind", "0.0.0.0:8899", "--no-history"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("loopback") && err.contains("0.0.0.0:8899"), "{err}");
    assert!(!err.contains("in use") && !err.contains("listening"), "{err}");
    assert!(t.elapsed() < Duration::from_secs(10));
}

#[test]
fn serve_prints_its_addresses_and_answers_on_the_admin_listener() {
    let dir = tmpdir("start");
    let state = dir.join("state");
    let s = Serve::start(&[
        "--bind",
        "127.0.0.1:0",
        "--upstream",
        "http://127.0.0.1:1",
        "--admin-bind",
        "127.0.0.1:0",
        "--state-dir",
        state.to_str().unwrap(),
        "--audit",
        dir.join("audit.jsonl").to_str().unwrap(),
    ]);
    let proxy = addr_in(&s.wait_line("proxy listening on"));
    let admin = addr_in(&s.wait_line("admin listening on"));
    let st = s.wait_line("state dir");
    assert!(st.contains(&state.display().to_string()) && st.contains("history on"), "{st}");
    assert!(state.join("history.db").is_file(), "the history store is in the state dir");
    assert_eq!(get(admin, "/api/v1/health"), (200, r#"{"ok":true}"#.to_string()));
    // The upstream is down: the proxy answers 502 itself.
    assert_eq!(get(proxy, "/").0, 502);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn admin_bind_off_disables_the_admin_listener() {
    let dir = tmpdir("off");
    let s = Serve::start(&[
        "--bind",
        "127.0.0.1:0",
        "--upstream",
        "http://127.0.0.1:1",
        "--admin-bind",
        "off",
        "--no-history",
        "--audit",
        dir.join("audit.jsonl").to_str().unwrap(),
    ]);
    s.wait_line("proxy listening on");
    s.wait_line("admin listener off");
    let st = s.wait_line("state dir");
    assert!(st.contains("history off"), "--no-history: {st}");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn sighup_reloads_the_config() {
    let dir = tmpdir("hup");
    let cfg = dir.join("shield.yaml");
    std::fs::write(&cfg, "version: 1\n").unwrap();
    let s = Serve::start(&[
        "--config",
        cfg.to_str().unwrap(),
        "--bind",
        "127.0.0.1:0",
        "--upstream",
        "http://127.0.0.1:1",
        "--admin-bind",
        "127.0.0.1:0",
        "--no-history",
        "--audit",
        dir.join("audit.jsonl").to_str().unwrap(),
    ]);
    let admin = addr_in(&s.wait_line("admin listening on"));
    let rev = |a| {
        let (_, body) = get(a, "/api/v1/status");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["config_rev"].as_u64().unwrap()
    };
    assert_eq!(rev(admin), 1);
    std::fs::write(&cfg, "version: 1\nscoring:\n  block_at: 95\n").unwrap();
    let ok = Command::new("kill").args(["-HUP", &s.child.id().to_string()]).status().unwrap();
    assert!(ok.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while rev(admin) != 2 {
        assert!(Instant::now() < deadline, "no reload after SIGHUP");
        std::thread::sleep(Duration::from_millis(50));
    }
    // SIGTERM stops it cleanly.
    let mut s = s;
    let _ = Command::new("kill").args(["-TERM", &s.child.id().to_string()]).status();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(st) = s.child.try_wait().unwrap() {
            assert!(st.success(), "{st:?}");
            break;
        }
        assert!(Instant::now() < deadline, "no exit after SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
