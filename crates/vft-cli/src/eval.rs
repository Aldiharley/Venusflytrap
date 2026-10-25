//! Real-corpus evaluation over raw HTTP files. `library` mode scores
//! `Shield::inspect` statelessly; `serve` mode runs the exact function the
//! proxy serves (`Pipeline::decide`) statefully, with the raw Cookie header,
//! and reports ban effects. Both modes share one lenient raw-request parser.

use std::collections::HashSet;
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
            writeln!(f, "rel,label,lib_verdict,serve_verdict,score,banned,constructs")?;
            Some(f)
        }
        None => None,
    };
    let (mut lib, mut srv) = (Metrics::default(), Metrics::default());
    let (mut parse_failures, mut skipped_headers, mut invariant_violations) = (0u64, 0u64, 0u64);
    let (mut collateral_fp, mut bans_from_allowed) = (0u64, 0u64);
    let mut benign_sources: HashSet<SourceKey> = HashSet::new();
    let mut benign_banned: HashSet<SourceKey> = HashSet::new();
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
            srv.add(attack(sj.verdict), s.label);
            banned = sj.banned_source;
            let fresh_ban = sj.banned_source && !sj.contributions.iter().any(|c| c.construct.as_deref() == Some("chain.ban"));
            if fresh_ban && lj.verdict == Verdict::Allow {
                bans_from_allowed += 1;
            }
            if s.label == 0 {
                let key = SourceKey::new(ip, 64);
                benign_sources.insert(key);
                if sj.banned_source {
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
            writeln!(f, "{},{},{:?},{},{},{},{}", s.rel, s.label, lj.verdict, serve_verdict, lj.score, banned, constructs.join("|"))?;
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
        latency_us_p50_p95_p99: [pct(0.5), pct(0.95), pct(0.99)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
