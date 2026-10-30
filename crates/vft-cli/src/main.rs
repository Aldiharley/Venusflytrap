//! Venusflytrap CLI: `scan`, `bench`, `serve`.
#![forbid(unsafe_code)]

mod baselines;
mod bench;
mod corpus;
mod eval;

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use vft_core::exceptions::{format_date, parse_date, ExceptionsFile, DAY_MS};
use vft_core::{Config, ExceptionClock, Exceptions, Request, Shield};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum EvalMode {
    Library,
    Serve,
    Tcp,
}

#[derive(Parser)]
#[command(name = "venusflytrap", version, about = "Semantic taint-graph WAF + honeypot engine")]
struct Cli {
    /// Optional path to a shield.yaml config (defaults are used if omitted).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a single request and print the judgment as JSON.
    Scan {
        /// Request path.
        #[arg(long, default_value = "/")]
        path: String,
        /// Query value to inspect (as ?q=VALUE).
        #[arg(long)]
        query: Option<String>,
        /// Read the body/value from stdin instead.
        #[arg(long)]
        stdin: bool,
    },
    /// Run the synthetic smoke benchmark (not a result; real-corpus numbers are in docs/BENCHMARK.md).
    Bench {
        #[arg(long, default_value_t = 1337)]
        seed: u64,
        /// Samples per class (benign/attack/obfuscated).
        #[arg(long, default_value_t = 2000)]
        n: usize,
        /// Output path for the markdown report.
        #[arg(long, default_value = "target/bench/BENCHMARK-synthetic.md")]
        out: PathBuf,
    },
    /// Start the reverse proxy.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        #[arg(long)]
        upstream: String,
        /// Append JSONL audit to this file (stdout if omitted).
        #[arg(long)]
        audit: Option<String>,
        /// Rotate the audit file to <name>.1 once it reaches this many MiB.
        #[arg(long, default_value_t = 100)]
        audit_max_mb: u64,
        /// Also write OCSF 1.9.0 JSONL to this file (rotated at --audit-max-mb).
        #[arg(long)]
        ocsf: Option<String>,
        /// Only log, don't actually block (observation mode) when set.
        #[arg(long)]
        monitor_only: bool,
        /// Scoped exceptions file (see `exceptions check`); expiry is checked per request.
        #[arg(long)]
        exceptions: Option<PathBuf>,
    },
    /// Evaluate on a raw labeled corpus (*.white benign, *.black malicious).
    Eval {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long, value_enum, default_value_t = EvalMode::Serve)]
        mode: EvalMode,
        /// distinct | pooled:<N>
        #[arg(long, default_value = "distinct")]
        sources: String,
        /// Synthetic clock step between requests.
        #[arg(long, default_value_t = 100)]
        step_ms: u64,
        /// Optional per-sample CSV.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Maximum samples to replay in `--mode tcp`.
        #[arg(long, default_value_t = 1000)]
        limit: usize,
        /// Split manifest from eval/split.py (use with --side).
        #[arg(long, requires = "side")]
        manifest: Option<PathBuf>,
        /// Which half of the split to score: dev or heldout.
        #[arg(long, requires = "manifest")]
        side: Option<String>,
        /// Disable a construct or decoder by id (repeatable).
        #[arg(long)]
        disable: Vec<String>,
        /// Run a construct in shadow (repeatable): detected and recorded as a
        /// shadow contribution, never scored.
        #[arg(long)]
        shadow: Vec<String>,
        /// Report, per shadow construct, the rows it would gain (would_tp),
        /// cost (would_fp) or not change (already) if promoted.
        #[arg(long)]
        promotion: bool,
        /// Write every scored request, as the engine receives it, to this JSONL
        /// file in eval/parse_corpus.py's schema (plus `rel`), for eval/baselines.py.
        #[arg(long)]
        dump_requests: Option<PathBuf>,
        /// Scoped exceptions file applied to every shield of the run.
        #[arg(long)]
        exceptions: Option<PathBuf>,
        /// The date (YYYY-MM-DD) the exceptions file is validated and judged at; default today (UTC).
        #[arg(long, requires = "exceptions")]
        as_of: Option<String>,
    },
    /// Leave-one-out ablation in library mode; writes a TSV.
    Ablate {
        #[arg(long)]
        corpus: PathBuf,
        #[arg(long, requires = "side")]
        manifest: Option<PathBuf>,
        #[arg(long, requires = "manifest")]
        side: Option<String>,
        /// Construct ids to ablate (repeatable); default: every registered construct.
        #[arg(long = "id")]
        ids: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Configuration tools.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Scoped-exception file tools.
    Exceptions {
        #[command(subcommand)]
        action: ExceptionsCmd,
    },
}

#[derive(Subcommand)]
enum ExceptionsCmd {
    /// Parse an exceptions file, list each entry as live or expired and print every issue;
    /// exit 1 if there is any.
    Check {
        file: PathBuf,
        /// The date (YYYY-MM-DD) to check at; default today (UTC).
        #[arg(long)]
        as_of: Option<String>,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Parse and validate a config file, optionally with an overrides file on top;
    /// exit 1 and list every issue if invalid.
    Validate {
        file: PathBuf,
        /// Sparse `key: value` overrides applied on top of FILE (lists replace).
        #[arg(long)]
        overrides: Option<PathBuf>,
    },
}

/// `--ocsf` must not name the `--audit` file (compared as given): two
/// writers appending to one file would interleave their formats.
fn check_ocsf_path(audit: Option<&str>, ocsf: Option<&str>) -> anyhow::Result<()> {
    match (audit, ocsf) {
        (Some(a), Some(o)) if a == o => {
            anyhow::bail!("--ocsf and --audit name the same file ({o}); give the OCSF output its own path")
        }
        _ => Ok(()),
    }
}

fn load_config(path: Option<&PathBuf>) -> anyhow::Result<Config> {
    Config::load_or_default(path.map(|p| p.as_path())).context("loading config")
}

/// The current time in ms since the epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Midnight UTC of today, in ms.
fn today_ms() -> u64 {
    let ms = now_ms();
    ms - ms % DAY_MS
}

/// `--as-of`, or today; a malformed date is an error.
fn as_of_ms(as_of: Option<&str>) -> anyhow::Result<u64> {
    match as_of {
        None => Ok(today_ms()),
        Some(s) => parse_date(s).ok_or_else(|| anyhow::anyhow!("--as-of {s:?} is not a YYYY-MM-DD date")),
    }
}

/// Load an exceptions file at `as_of_ms`; every issue is printed to stderr and ends the process with `code`.
fn load_exceptions(path: &Path, as_of_ms: u64, code: i32) -> Exceptions {
    match Exceptions::load(path, as_of_ms) {
        Ok(ex) => ex,
        Err(issues) => {
            for i in &issues {
                eprintln!("{}: {i}", path.display());
            }
            std::process::exit(code);
        }
    }
}

/// The body of `exceptions check`: one line per entry
/// (id, action, `live` or `expired`, expanded constructs or `-`), then every issue.
/// Returns whether the file is clean (no issues); the caller exits 1 if not.
fn exceptions_check(path: &Path, as_of_ms: u64, out: &mut impl Write) -> anyhow::Result<bool> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file = match ExceptionsFile::parse(&text) {
        Ok(f) => f,
        Err(issues) => {
            for i in &issues {
                writeln!(out, "{i}")?;
            }
            return Ok(false);
        }
    };
    for e in &file.exceptions {
        let action = serde_json::to_value(e.action)?;
        let state = if parse_date(&e.expires).is_some_and(|x| x <= as_of_ms) { "expired" } else { "live" };
        let constructs = match vft_core::exceptions::expand_constructs(&e.constructs) {
            Ok(ids) if !ids.is_empty() => ids.join(","),
            _ => "-".to_string(),
        };
        writeln!(out, "{}\t{}\t{state}\t{constructs}", e.id, action.as_str().unwrap_or("?"))?;
    }
    let issues = vft_core::exceptions::validate_file(&file, as_of_ms);
    for i in &issues {
        writeln!(out, "{i}")?;
    }
    Ok(issues.is_empty())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Scan { path, query, stdin } => {
            let cfg = load_config(cli.config.as_ref())?;
            let shield = Shield::new(cfg);
            let mut req = Request::get(&path);
            if stdin {
                use std::io::Read;
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                req.body = buf.into_bytes();
            }
            if let Some(q) = query {
                req.query.push(("q".into(), q));
            }
            let j = shield.inspect(&req);
            println!("{}", serde_json::to_string_pretty(&j)?);
            // Non-zero exit if blocked, handy for scripting.
            if matches!(j.verdict, vft_core::Verdict::Block) {
                std::process::exit(2);
            }
        }
        Command::Bench { seed, n, out } => {
            eprintln!("running benchmark: seed={seed}, {n} samples/class ...");
            let report = bench::run(seed, n);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&out, &report.markdown)
                .with_context(|| format!("writing {}", out.display()))?;
            eprintln!(
                "wrote {} | full-engine obfuscated recall {:.1}%, FP rate {:.3}%, p95 {} µs",
                out.display(),
                report.full_recall_obfuscated * 100.0,
                report.full_fp_rate * 100.0,
                report.full_p95_us
            );
        }
        Command::Serve {
            bind,
            upstream,
            audit,
            audit_max_mb,
            ocsf,
            monitor_only,
            exceptions,
        } => {
            check_ocsf_path(audit.as_deref(), ocsf.as_deref())?;
            let cfg = load_config(cli.config.as_ref())?;
            let mut shield = Shield::new(cfg);
            if let Some(path) = &exceptions {
                let ex = load_exceptions(path, now_ms(), 1);
                for w in ex.warnings() {
                    eprintln!("{w}");
                }
                shield = shield.with_exceptions(ex, ExceptionClock::PerRequest);
            }
            let max_bytes = audit_max_mb.saturating_mul(1024 * 1024);
            let sink = vft_proxy::audit::AuditSink::new(audit.map(std::path::PathBuf::from), max_bytes);
            let ocsf_sink = match ocsf {
                Some(p) => vft_proxy::audit::AuditSink::with_format(
                    Some(std::path::PathBuf::from(p)),
                    max_bytes,
                    vft_proxy::audit::Format::Ocsf,
                ),
                None => vft_proxy::audit::AuditSink::off(),
            };
            let state = Arc::new(vft_proxy::ProxyState::new(
                shield,
                upstream,
                sink,
                ocsf_sink,
                !monitor_only,
            ));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(vft_proxy::serve(state, bind))?;
        }
        Command::Eval { corpus, mode, sources, step_ms, out, limit, manifest, side, disable, shadow, promotion, dump_requests, exceptions, as_of } => {
            let mut cfg = load_config(cli.config.as_ref())?;
            cfg.shield.disabled.extend(disable);
            cfg.shield.shadow.extend(shadow);
            cfg.validate().map_err(|e| anyhow::anyhow!(e.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("; ")))?;
            if promotion && cfg.shield.shadow.is_empty() {
                anyhow::bail!("--promotion needs construct ids in shield.shadow (config file or --shadow)");
            }
            let ex = match &exceptions {
                Some(path) => {
                    let at = as_of_ms(as_of.as_deref())?;
                    let ex = load_exceptions(path, at, 2);
                    eprintln!("exceptions: {} as of {} ({} entries)", path.display(), format_date(at), ex.entries().len());
                    ex
                }
                None => Exceptions::default(),
            };
            let sources: eval::Sources = sources.parse().map_err(anyhow::Error::msg)?;
            let mut samples = eval::load_corpus(&corpus)?;
            if let (Some(m), Some(s)) = (manifest.as_ref(), side.as_deref()) {
                samples = eval::select_side(samples, &eval::load_manifest(m)?, s)?;
            }
            if mode == EvalMode::Tcp {
                if promotion || dump_requests.is_some() {
                    anyhow::bail!("--promotion and --dump-requests need --mode library or serve");
                }
                let r = eval::run_tcp(cfg, &ex, &samples, limit)?;
                println!("{}", serde_json::to_string_pretty(&r)?);
                if r.mismatched > 0 {
                    std::process::exit(3);
                }
                return Ok(());
            }
            let report = eval::run(cfg, &ex, &samples, mode == EvalMode::Serve, sources, step_ms, eval::Outputs { csv: out.as_deref(), promotion, dump: dump_requests.as_deref() })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if let Some(rows) = &report.promotion {
                eprintln!("construct\twould_tp\twould_fp\talready\tpromote");
                for r in rows {
                    eprintln!("{}\t{}\t{}\t{}\t{}", r.construct, r.would_tp, r.would_fp, r.already, r.promote);
                }
            }
            if report.invariant_violations > 0
                || report.serve.as_ref().is_some_and(|s| s.bans_from_allowed > 0)
                || report.explain_library.violations() > 0
                || report.explain_serve.as_ref().is_some_and(|e| e.violations() > 0)
            {
                std::process::exit(3);
            }
        }
        Command::Ablate { corpus, manifest, side, ids, out } => {
            let cfg = load_config(cli.config.as_ref())?;
            let mut samples = eval::load_corpus(&corpus)?;
            if let (Some(m), Some(s)) = (manifest.as_ref(), side.as_deref()) {
                samples = eval::select_side(samples, &eval::load_manifest(m)?, s)?;
            }
            let all: Vec<&'static str> = vft_core::graph::sinks::constructs().iter().map(|c| c.id).collect();
            let chosen: Vec<&'static str> = if ids.is_empty() {
                all
            } else {
                let mut v = Vec::new();
                for id in &ids {
                    let c = vft_core::graph::sinks::lookup(id).ok_or_else(|| anyhow::anyhow!("unknown construct id {id:?}"))?;
                    v.push(c.id);
                }
                v
            };
            let rows = eval::ablate(&cfg, &samples, &chosen)?;
            let mut f = std::io::BufWriter::new(std::fs::File::create(&out)?);
            writeln!(f, "id\tkind\ttp\tfp\td_tp\td_fp\tnet")?;
            for r in &rows {
                writeln!(f, "{}\t{}\t{}\t{}\t{}\t{}\t{}", r.id, r.kind, r.tp, r.fp, r.d_tp, r.d_fp, r.d_tp - r.d_fp)?;
            }
        }
        Command::Exceptions { action: ExceptionsCmd::Check { file, as_of } } => {
            let at = as_of_ms(as_of.as_deref())?;
            let mut out = std::io::stdout().lock();
            let clean = exceptions_check(&file, at, &mut out)?;
            out.flush()?;
            if !clean {
                std::process::exit(1);
            }
        }
        Command::Config { action: ConfigCmd::Validate { file, overrides } } => {
            let base = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let ov = match overrides.as_ref() {
                Some(p) => Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?),
                None => None,
            };
            match vft_core::options::layer(Some(&base), ov.as_deref()) {
                Ok(l) => {
                    println!("{}: ok", file.display());
                    for (key, src) in &l.sources {
                        if *src == vft_core::options::Source::Override {
                            println!("  {key}: override");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}: {e}", file.display());
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_ocsf_path, exceptions_check};
    use vft_core::exceptions::parse_date;

    #[test]
    fn ocsf_path_must_differ_from_audit_path() {
        let err = check_ocsf_path(Some("a.jsonl"), Some("a.jsonl")).unwrap_err().to_string();
        assert!(err.contains("--ocsf") && err.contains("--audit") && err.contains("a.jsonl"), "{err}");
        assert!(check_ocsf_path(Some("a.jsonl"), Some("o.jsonl")).is_ok());
        assert!(check_ocsf_path(None, Some("o.jsonl")).is_ok());
        assert!(check_ocsf_path(Some("a.jsonl"), None).is_ok());
        assert!(check_ocsf_path(None, None).is_ok());
    }

    const VALID: &str = "  - id: referer-sql\n    action: ignore\n    constructs: [\"sqli.*\"]\n    scope:\n      path_prefix: /\n      field: { loc: header, name: referer }\n    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n";
    const EXPIRED: &str = "  - id: old-skip\n    action: skip-inspection\n    scope:\n      path_prefix: /\n      field: { loc: header, name: x-sig }\n    owner: o\n    reason: r\n    created: 2026-01-01\n    modified: 2026-01-01\n    expires: 2026-02-01\n";

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vft-cli-exc-{}-{name}.yaml", std::process::id()));
        std::fs::write(&p, format!("version: 1\nexceptions:\n{body}")).unwrap();
        p
    }

    fn run_check(name: &str, body: &str) -> (bool, String) {
        let p = tmp(name, body);
        let mut out = Vec::new();
        let ok = exceptions_check(&p, parse_date("2026-10-30").unwrap(), &mut out).unwrap();
        let _ = std::fs::remove_file(&p);
        (ok, String::from_utf8(out).unwrap())
    }

    #[test]
    fn exceptions_check_lists_live_and_expired_and_fails_on_issues() {
        let (ok, text) = run_check("mixed", &format!("{VALID}{EXPIRED}"));
        assert!(!ok, "{text}");
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("referer-sql\tignore\tlive\t"), "{text}");
        assert!(lines[0].contains("sqli.union-select"), "wildcard is expanded: {text}");
        assert_eq!(lines[1], "old-skip\tskip-inspection\texpired\t-", "{text}");
        assert!(lines[2..].iter().any(|l| l.starts_with("old-skip: expired on 2026-02-01")), "{text}");
    }

    #[test]
    fn exceptions_check_passes_a_valid_file() {
        let (ok, text) = run_check("valid", VALID);
        assert!(ok, "{text}");
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("\tlive\t"), "{text}");
    }

    #[test]
    fn exceptions_check_reports_unparseable_files_and_errors_on_missing_ones() {
        let p = std::env::temp_dir().join(format!("vft-cli-exc-{}-bad.yaml", std::process::id()));
        std::fs::write(&p, "version: [").unwrap();
        let mut out = Vec::new();
        assert!(!exceptions_check(&p, 0, &mut out).unwrap());
        assert!(!out.is_empty());
        let _ = std::fs::remove_file(&p);
        assert!(exceptions_check(&p, 0, &mut Vec::new()).is_err());
    }
}
