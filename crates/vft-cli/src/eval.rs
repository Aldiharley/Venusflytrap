//! Real-corpus evaluation over raw HTTP files. `library` mode scores
//! `Shield::inspect` statelessly; `serve` mode runs the exact function the
//! proxy serves (`Pipeline::decide`) statefully, with the raw Cookie header,
//! and reports ban effects. Both modes share one lenient raw-request parser.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use vft_core::{event_for, Config, Event, Shield, SourceKey, Verdict};
use vft_proxy::http::{self, HeaderName, HeaderValue, Method, Uri};
use vft_proxy::{adapt, pipeline::Pipeline};

pub struct Sample {
    pub rel: String,
    pub label: u8,
    pub raw: Vec<u8>,
    /// The file could not be read (e.g. blocked by host antivirus); counted, never hidden.
    pub unreadable: Option<String>,
}

pub fn load_corpus(dir: &Path) -> anyhow::Result<Vec<Sample>> {
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<Sample>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            walk(root, &p, out)?;
            continue;
        }
        let label = match p.extension().and_then(|e| e.to_str()) {
            Some("white") => 0,
            Some("black") => 1,
            _ => continue,
        };
        let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
        let (raw, unreadable) = match std::fs::read(&p) {
            Ok(raw) => (raw, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        out.push(Sample { rel, label, raw, unreadable });
    }
    Ok(())
}

/// Read `manifest.tsv` from `eval/split.py`: relpath, label, sha256, side.
pub fn load_manifest(path: &Path) -> anyhow::Result<HashMap<String, (u8, String)>> {
    let text = std::fs::read_to_string(path)?;
    let mut m = HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() != 4 {
            anyhow::bail!("{}:{}: expected 4 tab-separated columns", path.display(), n + 1);
        }
        let label: u8 = cols[1].parse()?;
        m.insert(cols[0].to_string(), (label, cols[3].to_string()));
    }
    Ok(m)
}

/// Keep the samples on `side` ("dev" or "heldout"). Every sample must be in the
/// manifest with the same label, so a stale manifest fails loudly.
pub fn select_side(samples: Vec<Sample>, manifest: &HashMap<String, (u8, String)>, side: &str) -> anyhow::Result<Vec<Sample>> {
    if side != "dev" && side != "heldout" {
        anyhow::bail!("--side must be dev or heldout, got {side:?}");
    }
    let mut out = Vec::new();
    for s in samples {
        let Some((label, sd)) = manifest.get(&s.rel) else {
            anyhow::bail!("{} is not in the manifest", s.rel);
        };
        if *label != s.label {
            anyhow::bail!("{}: manifest label {} != corpus label {}", s.rel, label, s.label);
        }
        if sd == side {
            out.push(s);
        }
    }
    Ok(out)
}

pub struct Parsed {
    pub parts: http::request::Parts,
    pub body: Vec<u8>,
    pub skipped_headers: u32,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Percent-encode bytes that a URI target may not carry raw (the corpus holds
/// payloads exactly as an attacker would send them).
fn sanitize_target(t: &[u8]) -> String {
    let mut s = String::with_capacity(t.len());
    for (i, &b) in t.iter().enumerate() {
        let plain = b.is_ascii_alphanumeric() || b"-._~:/?@!$&'()*+,;=".contains(&b);
        let pct = b == b'%' && t.len() > i + 2 && t[i + 1].is_ascii_hexdigit() && t[i + 2].is_ascii_hexdigit();
        if plain || pct {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    // Origin-form needs a leading '/': a few corpus requests omit it
    // (`GET index.action?...`); keep `*` and absolute-form targets as sent.
    if s.is_empty() || !(s.starts_with('/') || s == "*" || s.contains("://")) {
        s.insert(0, '/');
    }
    s
}

/// Lenient raw HTTP/1.x parser (LF or CRLF; obs-text header bytes kept).
pub fn parse_raw(raw: &[u8]) -> Result<Parsed, String> {
    let (head, body) = if let Some(i) = find(raw, b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = find(raw, b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &raw[raw.len()..])
    };
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let reqline = lines.next().ok_or("empty request")?;
    let sp = reqline.iter().position(|&b| b == b' ').ok_or("no method")?;
    let method = Method::from_bytes(&reqline[..sp]).map_err(|e| e.to_string())?;
    let rest = &reqline[sp + 1..];
    let target = match rest.iter().rposition(|&b| b == b' ') {
        Some(i) if rest[i + 1..].starts_with(b"HTTP/") => &rest[..i],
        _ => rest,
    };
    let uri: Uri = sanitize_target(target).parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let mut builder = http::Request::builder().method(method).uri(uri);
    let mut skipped = 0u32;
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            if !line.trim_ascii().is_empty() {
                skipped += 1;
            }
            continue;
        };
        match (
            HeaderName::from_bytes(line[..colon].trim_ascii()),
            HeaderValue::from_bytes(line[colon + 1..].trim_ascii()),
        ) {
            (Ok(n), Ok(v)) => builder = builder.header(n, v),
            _ => skipped += 1,
        }
    }
    let (parts, ()) = builder.body(()).map_err(|e| e.to_string())?.into_parts();
    Ok(Parsed { parts, body: body.to_vec(), skipped_headers: skipped })
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Sources {
    Distinct,
    Pooled(u32),
}

impl FromStr for Sources {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "distinct" {
            return Ok(Sources::Distinct);
        }
        s.strip_prefix("pooled:")
            .and_then(|n| n.parse().ok())
            .filter(|n| *n > 0)
            .map(Sources::Pooled)
            .ok_or_else(|| format!("expected 'distinct' or 'pooled:<N>', got {s:?}"))
    }
}

impl Sources {
    /// A 10.0.0.0/8 source address for sample `i`.
    pub fn ip_for(&self, i: usize, rel: &str) -> IpAddr {
        let n = match self {
            Sources::Distinct => i as u32,
            Sources::Pooled(k) => {
                let mut h: u32 = 0x811c_9dc5;
                for b in rel.bytes() {
                    h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
                }
                h % k
            }
        };
        IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | (n & 0x00FF_FFFF)))
    }
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct Metrics {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
    pub recall: f64,
    pub precision: f64,
    pub f1: f64,
    pub fp_rate: f64,
}

impl Metrics {
    fn add(&mut self, predicted_attack: bool, label: u8) {
        match (predicted_attack, label) {
            (true, 1) => self.tp += 1,
            (true, _) => self.fp += 1,
            (false, 0) => self.tn += 1,
            (false, _) => self.fn_ += 1,
        }
    }
    fn finish(mut self) -> Self {
        let r = self.tp as f64 / (self.tp + self.fn_).max(1) as f64;
        let p = self.tp as f64 / (self.tp + self.fp).max(1) as f64;
        self.recall = r;
        self.precision = p;
        self.f1 = if r + p > 0.0 { 2.0 * r * p / (r + p) } else { 0.0 };
        self.fp_rate = self.fp as f64 / (self.fp + self.tn).max(1) as f64;
        self
    }
}

#[derive(Debug, Serialize)]
pub struct ServeMetrics {
    pub metrics: Metrics,
    pub benign_sources: usize,
    /// Benign sources answered with a ban (from their own FP or a pooled neighbour).
    pub benign_sources_banned: usize,
    /// Benign requests blocked in serve mode that the stateless library allowed.
    pub collateral_fp: u64,
    /// Bans triggered by a request whose library verdict was Allow (the C1 class; must be 0).
    pub bans_from_allowed: u64,
}

/// SP2 acceptance over every scored judgment.
#[derive(Debug, Default, Serialize)]
pub struct ExplainCounts {
    /// `decided_by.option_key` is not in `options::REGISTRY` (must be 0).
    pub unknown_option_key: u64,
    /// A non-Allow decided by Detection with no construct (must be 0).
    pub detection_without_construct: u64,
    /// |Σ points − score| > 1 (must be 0).
    pub points_mismatch: u64,
    /// First 20 violations, as `rel: rule (msg)`.
    pub examples: Vec<String>,
}

impl ExplainCounts {
    fn add(&mut self, rel: &str, j: &vft_core::Judgment) {
        let hit = |n: &mut u64, rule: &str, ex: &mut Vec<String>| {
            *n += 1;
            if ex.len() < 20 {
                ex.push(format!("{rel}: {rule} ({})", j.decided_by.msg));
            }
        };
        if vft_core::options::lookup(j.decided_by.option_key).is_none() {
            hit(&mut self.unknown_option_key, "unknown option key", &mut self.examples);
        }
        if j.verdict != Verdict::Allow && j.decided_by.kind == vft_core::CauseKind::Detection && j.decided_by.construct.is_none() {
            hit(&mut self.detection_without_construct, "detection without construct", &mut self.examples);
        }
        let sum: f32 = j.contributions.iter().map(|c| c.points).sum();
        if (sum - f32::from(j.score)).abs() > 1.0 {
            hit(&mut self.points_mismatch, "points do not add up", &mut self.examples);
        }
    }

    pub fn violations(&self) -> u64 {
        self.unknown_option_key + self.detection_without_construct + self.points_mismatch
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub mode: &'static str,
    pub sources: Sources,
    pub samples: usize,
    pub parse_failures: u64,
    /// Files that could not be read at all (not scored).
    pub read_failures: u64,
    /// First 20 unreadable or unparseable files, as `rel: reason`.
    pub failure_examples: Vec<String>,
    pub skipped_headers: u64,
    pub library: Metrics,
    pub serve: Option<ServeMetrics>,
    /// Library judgments with verdict Allow whose chain event is not Benign (must be 0).
    pub invariant_violations: u64,
    pub explain_library: ExplainCounts,
    pub explain_serve: Option<ExplainCounts>,
    pub latency_us_p50_p95_p99: [u64; 3],
}

fn attack(v: Verdict) -> bool {
    matches!(v, Verdict::Block | Verdict::Challenge)
}

pub fn run(cfg: Config, samples: &[Sample], serve: bool, sources: Sources, step_ms: u64, csv: Option<&Path>) -> anyhow::Result<Report> {
    let shield = Arc::new(Shield::new(cfg));
    let pipeline = Pipeline::new(shield.clone());
    let mut csv_out = match csv {
        Some(p) => {
            let mut f = std::io::BufWriter::new(std::fs::File::create(p)?);
            writeln!(f, "rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause")?;
            Some(f)
        }
        None => None,
    };
    let (mut lib, mut srv) = (Metrics::default(), Metrics::default());
    let (mut parse_failures, mut skipped_headers, mut invariant_violations) = (0u64, 0u64, 0u64);
    let (mut collateral_fp, mut bans_from_allowed) = (0u64, 0u64);
    let mut benign_sources: HashSet<SourceKey> = HashSet::new();
    let mut benign_banned: HashSet<SourceKey> = HashSet::new();
    let (mut explain_lib, mut explain_srv) = (ExplainCounts::default(), ExplainCounts::default());
    let mut read_failures = 0u64;
    let mut failure_examples: Vec<String> = Vec::new();
    let mut lat: Vec<u64> = Vec::with_capacity(samples.len());

    for (i, s) in samples.iter().enumerate() {
        if let Some(e) = &s.unreadable {
            read_failures += 1;
            if failure_examples.len() < 20 {
                failure_examples.push(format!("{}: unreadable: {e}", s.rel));
            }
            continue;
        }
        let p = match parse_raw(&s.raw) {
            Ok(p) => p,
            Err(e) => {
                parse_failures += 1;
                if failure_examples.len() < 20 {
                    failure_examples.push(format!("{}: parse: {e}", s.rel));
                }
                continue;
            }
        };
        skipped_headers += u64::from(p.skipped_headers);
        let ip = sources.ip_for(i, &s.rel);
        let req = adapt::from_parts(&p.parts, &p.body, Some(ip));
        let t = Instant::now();
        let lj = shield.inspect(&req);
        explain_lib.add(&s.rel, &lj);
        if lj.verdict == Verdict::Allow && event_for(&lj) != Event::Benign {
            invariant_violations += 1;
        }
        lib.add(attack(lj.verdict), s.label);

        let mut serve_verdict = String::new();
        let mut banned = false;
        if serve {
            let t2 = Instant::now();
            let d = pipeline.decide(&p.parts, &p.body, Some(ip), i as u64 * step_ms);
            lat.push(t2.elapsed().as_micros() as u64);
            let sj = &d.judgment;
            explain_srv.add(&s.rel, sj);
            srv.add(attack(sj.verdict), s.label);
            banned = sj.banned();
            let fresh_ban = sj.chain.and_then(|o| o.new_ban).is_some();
            if fresh_ban && lj.verdict == Verdict::Allow {
                bans_from_allowed += 1;
            }
            if s.label == 0 {
                let key = SourceKey::new(ip, 64);
                benign_sources.insert(key);
                if sj.banned() {
                    benign_banned.insert(key);
                }
                if attack(sj.verdict) && !attack(lj.verdict) {
                    collateral_fp += 1;
                }
            }
            serve_verdict = format!("{:?}", sj.verdict);
        } else {
            lat.push(t.elapsed().as_micros() as u64);
        }
        if let Some(f) = csv_out.as_mut() {
            let constructs: Vec<&str> = lj.contributions.iter().filter_map(|c| c.construct.as_deref()).collect();
            writeln!(f, "{},{},{:?},{},{},{},{},{:?}:{}", s.rel, s.label, lj.verdict, serve_verdict, lj.score, banned, constructs.join("|"), lj.decided_by.kind, lj.decided_by.option_key)?;
        }
    }
    lat.sort_unstable();
    let pct = |q: f64| lat.get(((lat.len().max(1) - 1) as f64 * q).round() as usize).copied().unwrap_or(0);
    Ok(Report {
        mode: if serve { "serve" } else { "library" },
        sources,
        samples: samples.len(),
        parse_failures,
        read_failures,
        failure_examples,
        skipped_headers,
        library: lib.finish(),
        serve: serve.then(|| ServeMetrics {
            metrics: srv.finish(),
            benign_sources: benign_sources.len(),
            benign_sources_banned: benign_banned.len(),
            collateral_fp,
            bans_from_allowed,
        }),
        invariant_violations,
        explain_library: explain_lib,
        explain_serve: serve.then_some(explain_srv),
        latency_us_p50_p95_p99: [pct(0.5), pct(0.95), pct(0.99)],
    })
}

/// Normalize framing for a socket replay: CRLF line endings, our own
/// `X-Forwarded-For`, `Connection: close`, an exact `Content-Length`. Samples
/// that use Transfer-Encoding or Upgrade are not replayable (`None`).
pub fn rewrite_for_replay(raw: &[u8], xff: IpAddr) -> Option<Vec<u8>> {
    let (head, body) = if let Some(i) = find(raw, b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = find(raw, b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &raw[raw.len()..])
    };
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let mut out = lines.next()?.to_vec();
    out.extend_from_slice(b"\r\n");
    for line in lines {
        let name = line.split(|&b| b == b':').next().unwrap_or(b"").trim_ascii().to_ascii_lowercase();
        match name.as_slice() {
            b"transfer-encoding" | b"upgrade" => return None,
            b"connection" | b"content-length" | b"x-forwarded-for" | b"keep-alive" | b"proxy-connection" => continue,
            _ => {}
        }
        if !line.is_empty() {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(format!("X-Forwarded-For: {xff}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Some(out)
}

#[derive(Debug, Default, Serialize)]
pub struct TcpReport {
    pub replayed: u64,
    pub not_replayable: u64,
    /// Status 403 and the in-process verdict is Block/Challenge.
    pub matched_block: u64,
    /// Status 200 and the in-process verdict is Allow/Monitor.
    pub matched_allow: u64,
    /// The proxy refused the request at the HTTP layer (400/413/431/501) while
    /// the lenient in-process parser accepted it.
    pub proxy_rejected: u64,
    /// Total mismatches; the sum of the five `mismatch_*` buckets below.
    pub mismatched: u64,
    /// In-process Block/Challenge but the proxy answered 200: a request the
    /// engine stops reached the upstream. Must be 0; any other value is critical.
    pub mismatch_block_vs_proxy_allow: u64,
    /// In-process Allow/Monitor but the proxy answered 403.
    pub mismatch_allow_vs_proxy_403: u64,
    /// In-process Allow/Monitor and the proxy answered 502/504: same decision,
    /// then the upstream (the stub) could not be reached or timed out.
    pub mismatch_upstream_5xx: u64,
    /// Connect, write or read failed with no parsable status.
    pub mismatch_io: u64,
    /// Any other status/decision pair.
    pub mismatch_other: u64,
    /// Up to 20 examples per mismatch bucket, as `<bucket> <rel> ...`.
    pub mismatch_examples: Vec<String>,
    /// First 20 proxy-rejected files, as `rel status=<code>`.
    pub proxy_rejected_examples: Vec<String>,
}

/// How one replayed sample compares with the in-process decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    MatchedBlock,
    MatchedAllow,
    ProxyRejected,
    BlockVsProxyAllow,
    AllowVsProxy403,
    Upstream5xx,
    Io,
    Other,
}

impl ReplayOutcome {
    /// `blocked`: the in-process verdict is Block/Challenge.
    pub fn classify(status: &Result<u16, String>, blocked: bool) -> Self {
        match (status, blocked) {
            (Err(_), _) => ReplayOutcome::Io,
            (Ok(403), true) => ReplayOutcome::MatchedBlock,
            (Ok(200), false) => ReplayOutcome::MatchedAllow,
            (Ok(400 | 413 | 431 | 501), _) => ReplayOutcome::ProxyRejected,
            (Ok(200), true) => ReplayOutcome::BlockVsProxyAllow,
            (Ok(403), false) => ReplayOutcome::AllowVsProxy403,
            (Ok(502 | 504), false) => ReplayOutcome::Upstream5xx,
            (Ok(_), _) => ReplayOutcome::Other,
        }
    }

    fn bucket(self) -> &'static str {
        match self {
            ReplayOutcome::MatchedBlock => "matched_block",
            ReplayOutcome::MatchedAllow => "matched_allow",
            ReplayOutcome::ProxyRejected => "proxy_rejected",
            ReplayOutcome::BlockVsProxyAllow => "mismatch_block_vs_proxy_allow",
            ReplayOutcome::AllowVsProxy403 => "mismatch_allow_vs_proxy_403",
            ReplayOutcome::Upstream5xx => "mismatch_upstream_5xx",
            ReplayOutcome::Io => "mismatch_io",
            ReplayOutcome::Other => "mismatch_other",
        }
    }
}

impl TcpReport {
    fn add(&mut self, outcome: ReplayOutcome, example: impl FnOnce() -> String) {
        let n = match outcome {
            ReplayOutcome::MatchedBlock => &mut self.matched_block,
            ReplayOutcome::MatchedAllow => &mut self.matched_allow,
            ReplayOutcome::ProxyRejected => {
                if self.proxy_rejected_examples.len() < 20 {
                    self.proxy_rejected_examples.push(example());
                }
                self.proxy_rejected += 1;
                return;
            }
            ReplayOutcome::BlockVsProxyAllow => &mut self.mismatch_block_vs_proxy_allow,
            ReplayOutcome::AllowVsProxy403 => &mut self.mismatch_allow_vs_proxy_403,
            ReplayOutcome::Upstream5xx => &mut self.mismatch_upstream_5xx,
            ReplayOutcome::Io => &mut self.mismatch_io,
            ReplayOutcome::Other => &mut self.mismatch_other,
        };
        *n += 1;
        let in_bucket = *n;
        if matches!(outcome, ReplayOutcome::MatchedBlock | ReplayOutcome::MatchedAllow) {
            return;
        }
        self.mismatched += 1;
        if in_bucket <= 20 {
            self.mismatch_examples.push(format!("{} {}", outcome.bucket(), example()));
        }
    }
}

const REPLAY_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Send `raw` to `addr` and return the HTTP status of the reply. Connect, write and read are each bounded by
/// `limit`. A write failure or timeout (the proxy may answer 413/431 and close
/// before reading the whole request) still gets a bounded read of whatever the
/// proxy sent; when no status arrived the result is an error (the write failure if there was one).
async fn send_and_read(addr: std::net::SocketAddr, raw: &[u8], limit: std::time::Duration) -> Result<u16, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = match tokio::time::timeout(limit, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connect: {e}")),
        Err(_) => return Err("connect timeout".into()),
    };
    let write_err = match tokio::time::timeout(limit, sock.write_all(raw)).await {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(format!("write: {e}")),
        Err(_) => Some("write timeout".to_string()),
    };
    let mut resp = Vec::new();
    let _ = tokio::time::timeout(limit, sock.read_to_end(&mut resp)).await;
    let status: u16 = std::str::from_utf8(&resp)
        .ok()
        .and_then(|t| t.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    match (status, write_err) {
        (0, Some(e)) => Err(e),
        (0, None) => Err("no parsable status line in reply".to_string()),
        (code, _) => Ok(code),
    }
}

pub fn run_tcp(cfg: Config, samples: &[Sample], limit: usize) -> anyhow::Result<TcpReport> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut cfg = cfg;
    cfg.proxy.trusted_proxies = vec!["127.0.0.1".into()];
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let up_addr = up.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut s, _)) = up.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1 << 20];
                    let _ = s.read(&mut buf).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                });
            }
        });
        let state = Arc::new(vft_proxy::ProxyState::new(
            Shield::new(cfg.clone()),
            format!("http://{up_addr}"),
            vft_proxy::audit::AuditSink::off(),
            true,
        ));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_addr = l.local_addr()?;
        tokio::spawn(vft_proxy::serve_listener(state, l));
        let local = Pipeline::new(Arc::new(Shield::new(cfg)));
        let loopback: IpAddr = "127.0.0.1".parse()?;

        let mut r = TcpReport::default();
        for (i, s) in samples.iter().take(limit).enumerate() {
            if s.unreadable.is_some() {
                r.not_replayable += 1;
                continue;
            }
            let ip = Sources::Distinct.ip_for(i, &s.rel);
            let Some(raw) = rewrite_for_replay(&s.raw, ip) else {
                r.not_replayable += 1;
                continue;
            };
            let Ok(p) = parse_raw(&raw) else {
                r.not_replayable += 1;
                continue;
            };
            let d = local.decide(&p.parts, &p.body, Some(loopback), vft_proxy::now_ms());
            let status = send_and_read(proxy_addr, &raw, REPLAY_IO_TIMEOUT).await;
            r.replayed += 1;
            let blocked = attack(d.judgment.verdict);
            let outcome = ReplayOutcome::classify(&status, blocked);
            r.add(outcome, || match &status {
                Ok(code) => format!("{} status={code} in_process={:?} score={}", s.rel, d.judgment.verdict, d.judgment.score),
                Err(e) => format!("{} io_failure={e} in_process={:?}", s.rel, d.judgment.verdict),
            });
        }
        Ok(r)
    })
}

#[derive(Debug, Serialize)]
pub struct AblationRow {
    pub id: &'static str,
    pub kind: String,
    pub tp: u64,
    pub fp: u64,
    /// True positives this construct contributes: baseline TP minus TP with it disabled.
    pub d_tp: i64,
    /// False positives this construct contributes.
    pub d_fp: i64,
}

/// Leave-one-out over `ids` in library mode: one baseline run, then one run per
/// id with only that id added to `shield.disabled`.
pub fn ablate(cfg: &Config, samples: &[Sample], ids: &[&'static str]) -> anyhow::Result<Vec<AblationRow>> {
    let lib = |c: Config| -> anyhow::Result<Metrics> {
        let sources: Sources = "distinct".parse().map_err(anyhow::Error::msg)?;
        Ok(run(c, samples, false, sources, 100, None)?.library)
    };
    let base = lib(cfg.clone())?;
    let mut rows = Vec::new();
    for &id in ids {
        let info = vft_core::graph::sinks::lookup(id).ok_or_else(|| anyhow::anyhow!("unknown construct id {id:?}"))?;
        let mut c = cfg.clone();
        if !c.shield.disabled.iter().any(|d| d == id) {
            c.shield.disabled.push(id.to_string());
        }
        let m = lib(c)?;
        rows.push(AblationRow {
            id: info.id,
            kind: format!("{:?}", info.kind),
            tp: m.tp,
            fp: m.fp,
            d_tp: base.tp as i64 - m.tp as i64,
            d_fp: base.fp as i64 - m.fp as i64,
        });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_counts_flag_each_acceptance_rule() {
        let mut c = ExplainCounts::default();
        let mut j = vft_core::Judgment::allow();
        c.add("ok", &j);
        assert_eq!((c.unknown_option_key, c.detection_without_construct, c.points_mismatch), (0, 0, 0));
        j.decided_by.option_key = "scoring.nope";
        c.add("key", &j);
        j = vft_core::Judgment::allow();
        j.verdict = Verdict::Block;
        j.score = 95;
        j.decided_by.kind = vft_core::CauseKind::Detection;
        c.add("construct-and-points", &j);
        assert_eq!((c.unknown_option_key, c.detection_without_construct, c.points_mismatch), (1, 1, 1));
        assert_eq!(c.examples.len(), 3, "one per violation: key, construct, points");
    }

    #[test]
    fn ablate_reports_what_a_construct_contributes() {
        let attack = Sample { rel: "a.black".into(), label: 1, raw: b"GET /?q=1%20union%20select%20a,b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let benign = Sample { rel: "b.white".into(), label: 0, raw: b"GET /?q=hello HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), unreadable: None };
        let rows = ablate(&Config::default(), &[attack, benign], &["sqli.union-select"]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "sqli.union-select");
        assert_eq!((rows[0].d_tp, rows[0].d_fp), (1, 0));
    }

    #[test]
    fn replay_io_failures_are_errors_and_early_replies_are_read() {
        use tokio::io::AsyncWriteExt;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let limit = std::time::Duration::from_millis(300);
            // Nothing is listening: a connect failure is an Err, not a panic.
            let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dead_addr = dead.local_addr().unwrap();
            drop(dead);
            let e = send_and_read(dead_addr, b"GET / HTTP/1.1

", limit).await.unwrap_err();
            assert!(e.starts_with("connect"), "{e}");
            let big = vec![b'a'; 64 << 20];
            // Replies 413 at once and never reads: the write stalls, the reply is still classified.
            let early = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let early_addr = early.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut s, _) = early.accept().await.unwrap();
                let _ = s.write_all(b"HTTP/1.1 413 Payload Too Large
Content-Length: 0
Connection: close

").await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            });
            assert_eq!(send_and_read(early_addr, &big, limit).await, Ok(413));
            // Accepts, never reads, never replies: no reply is an Err (stalled write or empty read).
            let mute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mute_addr = mute.local_addr().unwrap();
            tokio::spawn(async move {
                let (_s, _) = mute.accept().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            });
            assert!(send_and_read(mute_addr, &big, limit).await.is_err());
        });
    }

    #[test]
    fn tcp_report_separates_block_and_allow_matches() {
        let mk = |rel: &str, label, raw: &[u8]| Sample { rel: rel.into(), label, raw: raw.to_vec(), unreadable: None };
        let samples = vec![
            mk("a.white", 0, b"GET /index.html?page=2 HTTP/1.1
Host: x

"),
            mk("b.black", 1, b"GET /?id=1%20UNION%20SELECT%20password%20FROM%20users-- HTTP/1.1
Host: x

"),
        ];
        let r = run_tcp(Config::default(), &samples, 10).unwrap();
        assert_eq!((r.matched_allow, r.matched_block, r.mismatched, r.proxy_rejected), (1, 1, 0, 0), "{r:?}");
    }

    #[test]
    fn replay_mismatches_are_bucketed_by_direction() {
        use ReplayOutcome::*;
        let ok = |c: u16| Ok::<u16, String>(c);
        let cases = [
            (ok(403), true, MatchedBlock),
            (ok(200), false, MatchedAllow),
            (ok(413), true, ProxyRejected),
            (ok(400), false, ProxyRejected),
            (ok(200), true, BlockVsProxyAllow),
            (ok(403), false, AllowVsProxy403),
            (ok(502), false, Upstream5xx),
            (ok(504), false, Upstream5xx),
            (ok(502), true, Other),
            (ok(500), false, Other),
            (Err("connect: refused".into()), true, Io),
            (Err("write timeout".into()), false, Io),
        ];
        let mut r = TcpReport::default();
        for (status, blocked, want) in cases {
            let got = ReplayOutcome::classify(&status, blocked);
            assert_eq!(got, want, "{status:?} blocked={blocked}");
            r.add(got, || "x".into());
        }
        assert_eq!((r.matched_block, r.matched_allow, r.proxy_rejected), (1, 1, 2));
        assert_eq!(
            (r.mismatch_block_vs_proxy_allow, r.mismatch_allow_vs_proxy_403, r.mismatch_upstream_5xx, r.mismatch_io, r.mismatch_other),
            (1, 1, 2, 2, 2)
        );
        assert_eq!(r.mismatched, 8);
        assert_eq!(r.mismatch_examples.len(), 8);
        assert!(r.mismatch_examples.iter().any(|e| e.starts_with("mismatch_block_vs_proxy_allow ")));
        // Examples are capped per bucket, so a flood of one kind cannot hide another.
        for _ in 0..50 {
            r.add(Upstream5xx, || "y".into());
        }
        r.add(BlockVsProxyAllow, || "z".into());
        assert!(r.mismatch_examples.contains(&"mismatch_block_vs_proxy_allow z".to_string()));
        assert_eq!(r.mismatch_examples.iter().filter(|e| e.starts_with("mismatch_upstream_5xx")).count(), 20);
    }

    #[test]
    fn replay_rewrite_sets_framing_and_xff() {
        let raw = b"POST /a HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nContent-Length: 999\r\nX-Forwarded-For: 1.2.3.4\r\n\r\nab";
        let out = rewrite_for_replay(raw, "10.0.0.5".parse().unwrap()).unwrap();
        let s = String::from_utf8_lossy(&out).to_ascii_lowercase();
        assert!(s.contains("x-forwarded-for: 10.0.0.5\r\n"));
        assert!(!s.contains("1.2.3.4"));
        assert!(s.contains("connection: close\r\n"));
        assert!(s.contains("content-length: 2\r\n"));
        assert!(s.ends_with("\r\n\r\nab"));
        let chunked = b"POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(rewrite_for_replay(chunked, "10.0.0.5".parse().unwrap()).is_none());
    }

    #[test]
    fn parses_lf_only_and_raw_payload_targets() {
        let raw = b"GET /p?q=<script>alert(1)</script> HTTP/1.1\nHost: x\nCookie: a=1\n\n";
        let p = parse_raw(raw).expect("parses");
        assert_eq!(p.parts.uri.path(), "/p");
        assert!(p.parts.uri.query().unwrap().contains("%3Cscript%3E"));
        assert_eq!(p.parts.headers.get("cookie").unwrap(), "a=1");
    }

    #[test]
    fn target_without_leading_slash_is_rooted() {
        let p = parse_raw(b"GET index.action?redirect:${#a=1} HTTP/1.1
Host: x

").expect("parses");
        assert_eq!(p.parts.uri.path(), "/index.action");
        assert!(p.parts.uri.query().unwrap().starts_with("redirect:$%7B%23a=1"));
    }

    #[test]
    fn keeps_obs_text_header_bytes_and_body() {
        let mut raw = b"POST /f HTTP/1.1\r\nHost: x\r\nX-T: a".to_vec();
        raw.push(0xe9);
        raw.extend_from_slice(b"\r\n\r\nname=1");
        let p = parse_raw(&raw).expect("parses");
        assert_eq!(p.parts.headers.get("x-t").unwrap().as_bytes(), b"a\xe9");
        assert_eq!(p.body, b"name=1");
    }

    #[test]
    fn sources_parse_and_are_deterministic() {
        assert!(matches!("distinct".parse::<Sources>(), Ok(Sources::Distinct)));
        assert!(matches!("pooled:100".parse::<Sources>(), Ok(Sources::Pooled(100))));
        assert!("pooled:x".parse::<Sources>().is_err());
        let s = Sources::Pooled(10);
        assert_eq!(s.ip_for(0, "a/b.white"), s.ip_for(99, "a/b.white"));
    }

    fn sample(rel: &str, label: u8) -> Sample {
        Sample { rel: rel.into(), label, raw: b"GET / HTTP/1.1\r\n\r\n".to_vec(), unreadable: None }
    }

    fn manifest_file(text: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vft-manifest-{}-{}.tsv", std::process::id(), text.len()));
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn select_side_keeps_only_that_side() {
        let p = manifest_file("a.white\t0\tff\tdev\nb.black\t1\tee\theldout\n");
        let m = load_manifest(&p).unwrap();
        let picked = select_side(vec![sample("a.white", 0), sample("b.black", 1)], &m, "dev").unwrap();
        assert_eq!(picked.iter().map(|s| s.rel.as_str()).collect::<Vec<_>>(), vec!["a.white"]);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn select_side_rejects_unknown_files_and_label_mismatch() {
        let p = manifest_file("a.white\t0\tff\tdev\n");
        let m = load_manifest(&p).unwrap();
        assert!(select_side(vec![sample("zzz.white", 0)], &m, "dev").is_err());
        assert!(select_side(vec![sample("a.white", 1)], &m, "dev").is_err());
        assert!(select_side(vec![sample("a.white", 0)], &m, "test").is_err());
        let _ = std::fs::remove_file(p);
    }
}
