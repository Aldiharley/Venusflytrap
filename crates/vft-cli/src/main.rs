//! Venusflytrap CLI: `scan`, `bench`, `serve`.
#![forbid(unsafe_code)]

mod baselines;
mod bench;
mod corpus;
mod eval;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use vft_core::{Config, Request, Shield};

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
        /// Only log, don't actually block (observation mode) when set.
        #[arg(long)]
        monitor_only: bool,
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
    },
    /// Configuration tools.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Parse and validate a config file; exit 1 and list every issue if invalid.
    Validate { file: PathBuf },
}

fn load_config(path: Option<&PathBuf>) -> anyhow::Result<Config> {
    Config::load_or_default(path.map(|p| p.as_path())).context("loading config")
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
            monitor_only,
        } => {
            let cfg = load_config(cli.config.as_ref())?;
            let shield = Shield::new(cfg);
            let sink = vft_proxy::audit::AuditSink::new(
                audit.map(std::path::PathBuf::from),
                audit_max_mb.saturating_mul(1024 * 1024),
            );
            let state = Arc::new(vft_proxy::ProxyState::new(
                shield,
                upstream,
                sink,
                !monitor_only,
            ));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(vft_proxy::serve(state, bind))?;
        }
        Command::Eval { corpus, mode, sources, step_ms, out, limit, manifest, side } => {
            let cfg = load_config(cli.config.as_ref())?;
            let sources: eval::Sources = sources.parse().map_err(anyhow::Error::msg)?;
            let mut samples = eval::load_corpus(&corpus)?;
            if let (Some(m), Some(s)) = (manifest.as_ref(), side.as_deref()) {
                samples = eval::select_side(samples, &eval::load_manifest(m)?, s)?;
            }
            if mode == EvalMode::Tcp {
                let r = eval::run_tcp(cfg, &samples, limit)?;
                println!("{}", serde_json::to_string_pretty(&r)?);
                if r.mismatched > 0 {
                    std::process::exit(3);
                }
                return Ok(());
            }
            let report = eval::run(cfg, &samples, mode == EvalMode::Serve, sources, step_ms, out.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.invariant_violations > 0 || report.serve.as_ref().is_some_and(|s| s.bans_from_allowed > 0) {
                std::process::exit(3);
            }
        }
        Command::Config { action: ConfigCmd::Validate { file } } => match Config::load(&file) {
            Ok(_) => println!("{}: ok", file.display()),
            Err(e) => {
                eprintln!("{}: {e}", file.display());
                std::process::exit(1);
            }
        },
    }
    Ok(())
}
