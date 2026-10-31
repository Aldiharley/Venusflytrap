//! Venusflytrap CLI: `scan`, `bench`, `serve`.
#![forbid(unsafe_code)]

mod baselines;
mod bench;
mod corpus;
mod eval;

use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use vft_core::exceptions::{format_date, parse_date, ExceptionsFile, DAY_MS};
use vft_core::{Config, Exceptions, Request, Shield};

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
        /// Admin listener (loopback `host:port`), or `off`. Default: `admin.bind` from the config.
        #[arg(long)]
        admin_bind: Option<String>,
        /// Directory for the history database.
        #[arg(long, default_value = "./state")]
        state_dir: PathBuf,
        /// Run without the history database.
        #[arg(long)]
        no_history: bool,
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
    /// Query the history database.
    History {
        #[command(subcommand)]
        action: HistoryCmd,
    },
}

#[derive(Subcommand)]
enum HistoryCmd {
    /// Run a query over the recorded requests and print the page as JSON; exit 2 on a bad query.
    Query {
        /// Query terms, ANDed: verdict:block -stage:none construct:sqli.* src:10.0.0.0/8 score>=50 ...
        #[arg(long, default_value = "", allow_hyphen_values = true)]
        q: String,
        /// Start of the window (inclusive): YYYY-MM-DDTHH:MM:SSZ, or ms since the epoch.
        #[arg(long)]
        from: String,
        /// End of the window (exclusive): YYYY-MM-DDTHH:MM:SSZ, or ms since the epoch.
        #[arg(long)]
        to: String,
        /// Count rows by this instead of listing them.
        #[arg(long, value_parser = ["src", "path", "construct", "stage", "verdict"])]
        group_by: Option<String>,
        /// Rows (or groups) per page, 1..=1000.
        #[arg(long, default_value_t = 100)]
        limit: u32,
        /// The `next` value of the previous page.
        #[arg(long)]
        cursor: Option<String>,
        /// Directory holding history.db.
        #[arg(long, default_value = "./state")]
        state_dir: PathBuf,
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

/// The admin listener address: `--admin-bind` (`off` disables it), else the
/// config's `admin.bind`. Anything but a loopback address is an error.
fn admin_bind(arg: Option<&str>, cfg: &Config) -> anyhow::Result<Option<SocketAddr>> {
    let (text, from) = match arg {
        Some(a) if a.eq_ignore_ascii_case("off") => return Ok(None),
        Some(a) => (a, "--admin-bind"),
        None => (cfg.admin.bind.as_str(), "admin.bind"),
    };
    let addr: SocketAddr =
        text.parse().map_err(|_| anyhow::anyhow!("{from} {text:?} is not an ip:port address or `off`"))?;
    vft_server::admin::check_bind(addr)?;
    Ok(Some(addr))
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

/// A time bound: milliseconds since the epoch, or `YYYY-MM-DDTHH:MM:SSZ` (UTC).
fn parse_time(s: &str) -> anyhow::Result<u64> {
    let bad = || anyhow::anyhow!("{s:?} is not a time: use YYYY-MM-DDTHH:MM:SSZ or milliseconds since the epoch");
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().map_err(|_| bad());
    }
    let b = s.as_bytes();
    if !s.is_ascii() || b.len() != 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return Err(bad());
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let t = &s[r];
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok()).flatten()
    };
    let date = parse_date(&s[..10]).ok_or_else(bad)?;
    let (h, m, sec) = (num(11..13).ok_or_else(bad)?, num(14..16).ok_or_else(bad)?, num(17..19).ok_or_else(bad)?);
    if h > 23 || m > 59 || sec > 59 {
        return Err(bad());
    }
    Ok(date + ((h * 60 + m) * 60 + sec) * 1000)
}

/// Run a history query on the database in `dir` and print the page as JSON to `out`.
/// The outer error is a failure to run it (no database, I/O); the inner one a bad query.
fn history_query(
    out: &mut impl Write,
    dir: &Path,
    req: &vft_server::history::query::Request,
) -> anyhow::Result<Result<(), vft_server::history::query::QueryError>> {
    let conn = vft_server::history::read::open_read_only(dir)?;
    match vft_server::history::read::run(&conn, req) {
        Ok(page) => {
            writeln!(out, "{}", serde_json::to_string_pretty(&page)?)?;
            Ok(Ok(()))
        }
        Err(e) => Ok(Err(e)),
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
            admin_bind: admin_arg,
            state_dir,
            no_history,
        } => {
            check_ocsf_path(audit.as_deref(), ocsf.as_deref())?;
            let cfg = load_config(cli.config.as_ref())?;
            // Before anything binds.
            let admin = admin_bind(admin_arg.as_deref(), &cfg)?;
            if let Some(path) = &exceptions {
                // Issues end the process here, before anything binds; the
                // runtime loads the file itself and logs its warnings.
                load_exceptions(path, now_ms(), 1);
            }
            vft_server::logging::init();
            let enforce = !monitor_only;
            let opts = vft_server::runtime::RuntimeOptions {
                bind,
                upstream: upstream.clone(),
                config_path: cli.config.clone(),
                exceptions_path: exceptions,
                audit: audit.map(PathBuf::from),
                audit_max_bytes: audit_max_mb.saturating_mul(1024 * 1024),
                ocsf: ocsf.map(PathBuf::from),
                enforce,
                admin_bind: admin,
                state_dir: state_dir.clone(),
                history: !no_history,
            };
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(async move {
                let runtime = vft_server::runtime::Runtime::start(opts).await?;
                eprintln!(
                    "venusflytrap proxy listening on http://{} -> {upstream} (enforce={enforce})",
                    runtime.proxy_addr()
                );
                match runtime.admin_addr() {
                    Some(a) => eprintln!("admin listening on http://{a}"),
                    None => eprintln!("admin listener off"),
                }
                eprintln!(
                    "state dir {}, history {}",
                    state_dir.display(),
                    if runtime.history() { "on" } else { "off" }
                );
                runtime.run_until_signal().await
            })?;
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
        Command::History { action: HistoryCmd::Query { q, from, to, group_by, limit, cursor, state_dir } } => {
            use vft_server::history::query::{GroupBy, Request as HistoryRequest};
            let req = HistoryRequest {
                q,
                from_ms: parse_time(&from).context("--from")?,
                to_ms: parse_time(&to).context("--to")?,
                group_by: group_by.as_deref().and_then(GroupBy::from_name),
                limit,
                cursor,
            };
            let mut out = std::io::stdout().lock();
            let result = history_query(&mut out, &state_dir, &req)?;
            out.flush()?;
            if let Err(e) = result {
                eprintln!("{e}");
                std::process::exit(2);
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
    use super::{admin_bind, check_ocsf_path, exceptions_check, history_query, parse_time};
    use vft_core::exceptions::parse_date;
    use vft_core::Config;

    #[test]
    fn admin_bind_takes_the_flag_then_the_config_and_only_loopback() {
        let mut cfg = Config::default();
        assert_eq!(admin_bind(None, &cfg).unwrap(), Some("127.0.0.1:8899".parse().unwrap()));
        assert_eq!(admin_bind(Some("[::1]:9000"), &cfg).unwrap(), Some("[::1]:9000".parse().unwrap()));
        assert_eq!(admin_bind(Some("off"), &cfg).unwrap(), None);
        assert_eq!(admin_bind(Some("OFF"), &cfg).unwrap(), None);
        let e = admin_bind(Some("0.0.0.0:8899"), &cfg).unwrap_err().to_string();
        assert!(e.contains("loopback"), "{e}");
        let e = admin_bind(Some("localhost:8899"), &cfg).unwrap_err().to_string();
        assert!(e.contains("--admin-bind") && e.contains("off"), "{e}");
        cfg.admin.bind = "10.0.0.1:8899".into();
        assert!(admin_bind(None, &cfg).unwrap_err().to_string().contains("loopback"));
    }

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
    fn parse_time_takes_rfc3339_utc_or_milliseconds() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_time("1970-01-02T00:00:01Z").unwrap(), 86_401_000);
        assert_eq!(parse_time("2026-10-30T13:45:59Z").unwrap(), parse_date("2026-10-30").unwrap() + (13 * 3600 + 45 * 60 + 59) * 1000);
        assert_eq!(parse_time("1761832800000").unwrap(), 1_761_832_800_000);
        assert_eq!(parse_time("0").unwrap(), 0);
        for bad in [
            "", "now", "2026-10-30", "2026-10-30T13:45:59", "2026-10-30T13:45:59+00:00", "2026-10-30 13:45:59Z",
            "2026-10-30T24:00:00Z", "2026-10-30T13:60:00Z", "2026-10-30T13:45:60Z", "2026-02-30T00:00:00Z",
            "2026-10-30T1x:45:59Z", "2026-10-30T13:45:59.5Z", "-5", "99999999999999999999999", "2026-10-30T13:45:5é",
        ] {
            let e = parse_time(bad).unwrap_err().to_string();
            assert!(e.contains("YYYY-MM-DDTHH:MM:SSZ"), "{bad:?}: {e}");
        }
    }

    fn history_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vft-cli-hist-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn request(q: &str) -> vft_server::history::query::Request {
        vft_server::history::query::Request { q: q.into(), from_ms: 0, to_ms: 1000, group_by: None, limit: 10, cursor: None }
    }

    #[test]
    fn history_query_prints_a_page_and_reports_bad_queries_and_missing_databases() {
        let dir = history_dir("query");
        let missing = history_query(&mut Vec::new(), &dir, &request("")).unwrap_err().to_string();
        assert!(missing.contains("no history database") && missing.contains("history.db"), "{missing}");

        let handle = vft_server::history::HistoryHandle::open(
            &dir,
            vft_core::config::HistoryConfig::default(),
            std::sync::Arc::new(vft_server::metrics::Metrics::new()),
        )
        .unwrap();
        handle.close(std::time::Duration::from_secs(5));

        let mut out = Vec::new();
        history_query(&mut out, &dir, &request("verdict:block -stage:none")).unwrap().unwrap();
        let page: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(page, serde_json::json!({"rows": [], "groups": null, "next": null}));
        assert!(String::from_utf8(out).unwrap().contains('\n'), "pretty printed");

        let mut out = Vec::new();
        let mut grouped = request("");
        grouped.group_by = Some(vft_server::history::query::GroupBy::Verdict);
        history_query(&mut out, &dir, &grouped).unwrap().unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&out).unwrap()["groups"], serde_json::json!([]));

        let mut out = Vec::new();
        let e = history_query(&mut out, &dir, &request("verdict:maybe")).unwrap().unwrap_err();
        assert_eq!((e.pos, e.len), (8, 5));
        assert_eq!(e.to_string().split(':').next(), Some("error at 8"));
        assert!(out.is_empty(), "nothing is printed for a bad query");
        let _ = std::fs::remove_dir_all(&dir);
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
