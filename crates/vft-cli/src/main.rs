//! Venusflytrap CLI: `scan`, `bench`, `serve`.
#![forbid(unsafe_code)]

mod baselines;
mod bench;
mod corpus;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use vft_core::{Config, Request, Shield};

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
    /// Run the benchmark and write docs/BENCHMARK.md.
    Bench {
        #[arg(long, default_value_t = 1337)]
        seed: u64,
        /// Samples per class (benign/attack/obfuscated).
        #[arg(long, default_value_t = 2000)]
        n: usize,
        /// Output path for the markdown report.
        #[arg(long, default_value = "docs/BENCHMARK.md")]
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
        /// Only log, don't actually block (observation mode) when set.
        #[arg(long)]
        monitor_only: bool,
    },
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
            monitor_only,
        } => {
            let cfg = load_config(cli.config.as_ref())?;
            let shield = Shield::new(cfg);
            let state = Arc::new(vft_proxy::ProxyState::new(
                shield,
                upstream,
                audit,
                !monitor_only,
            ));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(vft_proxy::serve(state, bind))?;
        }
    }
    Ok(())
}
