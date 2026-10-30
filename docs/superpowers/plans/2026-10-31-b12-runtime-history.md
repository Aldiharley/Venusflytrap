# B1+B2 — Service runtime and history store: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `serve` becomes an operable service — hot reload, event bus, supervisor, status, `/metrics`, graceful shutdown, a loopback admin listener — that records its decisions, rollups, chain events, bans and config revisions in SQLite with retention, ban restore at boot and a safe query language.

**Architecture:** `vft-proxy` (data plane) gains a `ConfigHandle` (`ArcSwap<Loaded>`, one load per request) and a non-blocking `EventBus`. A new `vft-server` crate owns the `Runtime` (ordered start with rollback, reverse stop), reload, status, metrics, the admin listener and the history store (one SQLite writer thread fed by a bounded channel from the bus, a read pool, retention, query compiler). `vft-cli serve` runs on the `Runtime`; `eval` keeps linking only `vft-proxy`.

**Tech Stack:** Rust 1.96 (edition 2021), tokio, hyper 1, `arc-swap 1.9.2`, `tracing 0.1.44`, `tracing-subscriber 0.3.23`, `rusqlite 0.40.2` (`bundled`), serde/serde_yaml/serde_json, ts-rs (feature `ts`).

**Spec:** `docs/superpowers/specs/2026-10-31-runtime-history-design.md`.

## Global Constraints

- No detection change, and `eval` is not modified: the dev A/B and the full-corpus serve diff against main (`d6eec01`) show 0 changed cells and 0 changed decisions.
- `serve --no-history` behaves as today apart from the admin listener.
- Proxy p99 with history on stays within 5 % of `--no-history` on a TCP corpus replay.
- Publishing to the bus and enqueueing history writes never block the proxy; a full queue or a lagging consumer drops and counts.
- New dependencies are exactly: `arc-swap = "=1.9.2"`, `tracing = "=0.1.44"`, `tracing-subscriber = { version = "=0.3.23", features = ["env-filter", "fmt"] }`, `rusqlite = { version = "=0.40.2", features = ["bundled"] }`, and tokio's `signal` feature. No other new crate (SHA-256 is implemented in-house).
- `#![forbid(unsafe_code)]` in every crate of ours, including `vft-server`; `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` green.
- The admin listener refuses any non-loopback bind in B1+B2; `--admin-bind off` disables it.
- Every admin response carries `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- Raw field values are never stored unless `history.store_snippets` is on, and then at most 128 characters per field and never `Authorization`, `Cookie` or `Set-Cookie`.
- The query language never accepts raw SQL; generated SQL text contains only whitelisted fragments and `?` placeholders.
- No outside product names in code, UI or docs.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Environment (all tasks)

- Checkout `M:\Projects\venusflytrap`, branch `b12-runtime-history` (no worktree). Use the Bash tool for POSIX commands.
- Corpus: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\ext\blazehttp\testcases`
- Split manifest: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\split\manifest.tsv`
- Runs directory: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\b12\runs`
- Python: `py -I -X utf8`. `ui/node_modules` is installed (never run `npm install`/`npm ci`).

## File map

| File | Responsibility |
|---|---|
| `crates/vft-core/src/config.rs`, `options.rs`, `config/shield.yaml` | `history.*` and `admin.bind` options |
| `crates/vft-core/src/chain.rs` | `ChainTracker::restore_ban` |
| `crates/vft-proxy/src/config_handle.rs` (new) | `Loaded`, `ConfigHandle`, candidate building with restart-only values kept |
| `crates/vft-proxy/src/bus.rs` (new) | `BusEvent`, `DecisionEvent`, `EventBus` |
| `crates/vft-proxy/src/pipeline.rs`, `lib.rs` | pipeline on the handle; publish events; drain-aware serve loop |
| `crates/vft-server/src/lib.rs` (new crate) | module wiring |
| `crates/vft-server/src/{status,supervise,metrics,sha256,logging}.rs` | runtime building blocks |
| `crates/vft-server/src/admin.rs` | loopback admin listener |
| `crates/vft-server/src/runtime.rs` | `Runtime::start/stop`, reload, signals |
| `crates/vft-server/src/history/{mod,schema,writer,retention,query,read}.rs` | history store |
| `crates/vft-server/examples/{replay,history_bench}.rs` | measurement tools |
| `crates/vft-cli/src/main.rs` | `serve` on the runtime; `history query` |
| `eval/RESULTS-B12-runtime-history.md` | measured results |

---

### Task 1: Options for history and admin; ban restore in the core

**Files:**
- Modify: `crates/vft-core/src/config.rs` (new `HistoryConfig`, `AdminConfig`, fields `history`, `admin` on `Config`, validation)
- Modify: `crates/vft-core/src/options.rs` (new `OptionKind::Addr`; four descriptors)
- Modify: `config/shield.yaml` (two new sections, values equal to defaults)
- Modify: `crates/vft-core/src/chain.rs` (`ChainTracker::restore_ban`)
- Regenerate: `ui/src/gen/OptionKind.ts` (bless: `VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings`)

**Interfaces — produces:**

```rust
// config.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    /// Share of untouched Allow judgments stored (every non-Allow and every Allow an exception touched is stored).
    pub allow_sample_rate: f64,   // default 0.01, range 0.0..=1.0
    /// Days of requests and chain events kept; rollups keep 90 days.
    pub retention_days: u32,      // default 14, range 1..=3650
    /// Keep up to 128 characters of each field value (never Authorization, Cookie, Set-Cookie).
    pub store_snippets: bool,     // default false
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Local admin listener (`host:port`); must be a loopback address until auth exists.
    pub bind: String,             // default "127.0.0.1:8899"
}
// Config gains: pub history: HistoryConfig, pub admin: AdminConfig
```

- `options.rs`: `OptionKind::Addr` ("a `host:port` socket address"); descriptors, in the existing `opt(...)` style:
  - `history.allow_sample_rate` — `Float { min: 0.0, max: 1.0 }`, section `history`, Advanced, `Live`
  - `history.retention_days` — `Int { min: 1, max: 3650 }`, `history`, Basic, `Live`
  - `history.store_snippets` — `Bool`, `history`, Advanced, `Live`
  - `admin.bind` — `Addr`, section `admin`, Advanced, `Restart`
  - `check_value` for `Addr`: must parse as `std::net::SocketAddr` (issue text: "must be host:port, e.g. 127.0.0.1:8899"). The loopback rule is enforced by the server at startup (Task 5), not here.
- `chain.rs`: `pub fn restore_ban(&mut self, key: SourceKey, rec: BanRecord)` — inserts the record as is (no TTL recomputation, no offence change), respecting `max_bans` eviction like `ban`. `vft-proxy` `ChainStore::restore_ban(&self, key, rec)` forwards to the shard (add in this task; it lives in `pipeline.rs`).

- [ ] **Step 1: Failing tests**
  - `config.rs`: defaults (`0.01`, `14`, `false`, `"127.0.0.1:8899"`); `history.allow_sample_rate: 1.5` → issue on that key; `admin.bind: "nope"` → issue on `admin.bind`; the shipped `config/shield.yaml` equals defaults (existing test covers it once the sections are added).
  - `options.rs`: the existing registry-coverage test must list the four new keys (it fails until they are registered).
  - `chain.rs`: `restore_ban` makes `active_ban` return the exact record before `until_ms` and `None` from `until_ms` on; a later `ban` for the same key counts offences from the restored record.
- [ ] **Step 2: Run** — `cargo test -p vft-core` — expect failures.
- [ ] **Step 3: Implement**, add both sections to `config/shield.yaml` with a one-line comment per key, bless the TS bindings.
- [ ] **Step 4: Verify** — `cargo test --workspace`, clippy, `cargo test -p vft-core --features ts --test ts_bindings`, and in `ui/`: `npm run check`.
- [ ] **Step 5: Commit** — `feat(core): history and admin options; restore a ban record`.

---

### Task 2: Config handle and reload candidates in the data plane

**Files:**
- Create: `crates/vft-proxy/src/config_handle.rs`
- Modify: `crates/vft-proxy/Cargo.toml` (`arc-swap = "=1.9.2"`), `crates/vft-proxy/src/lib.rs` (`pub mod config_handle;`, `ProxyState` built from a handle), `crates/vft-proxy/src/pipeline.rs`

**Interfaces — produces:**

```rust
pub struct Loaded {
    pub rev: u64,
    pub shield: vft_core::Shield,
}

pub struct ConfigHandle { /* ArcSwap<Loaded> */ }
impl ConfigHandle {
    pub fn new(shield: Shield) -> Self;              // rev 1
    pub fn load(&self) -> Arc<Loaded>;               // one atomic load
    pub fn swap(&self, shield: Shield) -> u64;       // stores rev+1, returns it
}

/// What a reload would change.
pub struct Candidate {
    pub config: vft_core::Config,          // restart-only values replaced by the live ones
    pub changed: Vec<String>,              // registry keys whose value differs from live (Live and Restart)
    pub restart_required: Vec<String>,     // the subset with Apply::Restart (not applied)
}
/// Compare `next` with `live` key by key over `options::REGISTRY`; copy every `Apply::Restart`
/// value from `live` into the result. Pure; no I/O.
pub fn candidate(live: &Config, next: Config) -> Candidate;
```

- `candidate` works on `serde_yaml::Value` trees of both configs: for each registry key (dotted path), compare the two values; if different push the key to `changed`; if the descriptor is `Restart`, also push to `restart_required` and write the live value into the next tree. Deserialize the merged tree back into `Config` (it was valid on both sides, so this cannot fail; use `expect` with a message naming the invariant).
- `Pipeline`:
  - `Pipeline::new(handle: Arc<ConfigHandle>) -> Self` replaces the old constructor, and `Pipeline::from_shield(shield: Shield) -> Self` wraps a plain shield in a fresh handle (rev 1) for callers that have one. Eval (`crates/vft-cli/src/eval.rs` ~425-426 and ~828-837) currently shares one `Arc<Shield>` between library mode and the pipeline: build a second `Shield` from the same `cfg.clone()` and `ex.clone()` for `Pipeline::from_shield` and keep the existing one for library mode. The eval output must not change.
  - Per request, `decide` and `fast_track` call `self.handle.load()` once and use that `Loaded` for every shield access in that call. `trusted` stays fixed (restart-only). `source()` reads `ipv6_prefix` from the chain store's own config captured at construction (restart-only), not from the loaded shield.
  - Replace `pub fn shield(&self) -> &Shield` with `pub fn current(&self) -> Arc<Loaded>`; update the single test caller (`pipeline.rs` ~531).
  - `Decision` gains `pub config_rev: u64`.
- `ProxyState::new(handle: Arc<ConfigHandle>, upstream, audit, ocsf, enforce)`; limits and decision headers are read from the handle's first load (restart-only). Add `ProxyState::from_shield(shield, …)` with the old argument list for existing call sites (CLI eval tcp mode, tests).

- [ ] **Step 1: Failing tests** (`config_handle.rs` tests):
  - `swap` increments `rev` and `load` returns the new shield; an `Arc<Loaded>` taken before a swap still sees the old rev (no mixing).
  - `candidate`: changing `scoring.block_at` → `changed == ["scoring.block_at"]`, `restart_required` empty, value applied; changing `limits.max_body` → in both lists, value kept at live; no change → both empty.
  - Concurrency: 8 threads deciding in a loop while another thread swaps 200 times; every `Decision.config_rev` observed equals the rev of the shield used (assert via a shield whose `scoring.block_at` encodes the rev, e.g. 50 + rev % 40, and check `decided_by` thresholds match `config_rev`).
- [ ] **Step 2: Run** — `cargo test -p vft-proxy config_handle` — expect compile failure.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify** — `cargo test --workspace`, clippy. Then the no-change check for this task: `cargo build --release -p vft-cli`; run `eval --corpus <corpus> --mode serve --sources distinct --out <runs>/t2-serve-b.csv` with `./target/release/venusflytrap.exe` and the same command with `--out <runs>/t2-serve-a.csv` using the main baseline `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\b12\bin\main-d6eec01.exe` (the controller builds it before Task 2); compare with `py -I -X utf8 eval/compare_runs.py <a.csv> <b.csv>`. Expected: 0 changed decisions. Record in the report.
- [ ] **Step 5: Commit** — `feat(proxy): config handle with per-request load and reload candidates`.

---

### Task 3: Event bus in the data plane

**Files:**
- Create: `crates/vft-proxy/src/bus.rs`
- Modify: `crates/vft-proxy/src/lib.rs` (`pub mod bus;`, `ProxyState.bus: Option<bus::EventBus>`, publishing in `handle`)

**Interfaces — produces:**

```rust
#[derive(Debug, Clone)]
pub struct DecisionEvent {
    pub event_id: String,
    pub group_id: Option<String>,
    pub ts_ms: u64,
    pub src_key: Option<String>,     // SourceKey::ip() as text, e.g. "2001:db8:1:2::" or "192.0.2.7"
    pub ip: Option<std::net::IpAddr>,
    pub method: String,
    pub host: String,                // Host header, or "" when absent
    pub path: String,                // request path without the query string
    pub judgment: vft_core::Judgment,
    pub latency_us: u64,             // handler start to response headers
    pub upstream_status: Option<u16>,// None when not forwarded
    pub config_rev: u64,
    pub snippets: Vec<(vft_core::FieldRef, String)>, // filled only when history.store_snippets is on (Task 7 rules)
}
#[derive(Debug, Clone)]
pub enum BusEvent {
    Decision(Arc<DecisionEvent>),
    ConfigApplied { rev: u64, changed: Vec<String>, restart_required: Vec<String> },
    ConfigRejected { issues: Vec<String> },
    BanChanged { key: String, ban: Option<vft_core::BanRecord>, lifted: bool },
}
#[derive(Clone)]
pub struct EventBus { /* broadcast::Sender<BusEvent> */ }
impl EventBus {
    pub const CAPACITY: usize = 8192;
    pub fn new() -> Self;
    /// Never blocks; with no subscribers the event is discarded.
    pub fn publish(&self, ev: BusEvent);
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<BusEvent>;
}
```

- In `handle`: measure `latency_us` from the start of `handle` to the moment the response (refusal or forwarded headers) is ready; publish one `Decision` per request that reached a decision (fast-tracked bans included), after the audit sinks. When `judgment.chain` has `new_ban: Some(b)` and the decision has a source key, also publish `BanChanged { key, ban: Some(b), lifted: false }`. Snippets stay empty in this task.
- `forward` must report the upstream status: change it to return the response and let `handle` read `status().as_u16()` (504/502 produced by the proxy itself count as `None`, since nothing came from upstream).
- With `bus: None` (eval, `--no-history`-style uses, tests) nothing is published and no work is done for events (no clones, no allocation for `DecisionEvent`).

- [ ] **Step 1: Failing tests** (`lib.rs` tests over real sockets, as the existing proxy tests do): a forwarded Allow publishes one `Decision` with `upstream_status == Some(200)` and `latency_us > 0`; a Block publishes `upstream_status == None`; a request that triggers a ban publishes `Decision` then `BanChanged`; a bus with no subscriber never errors; `publish` on a full channel (a subscriber that never reads, 9,000 events) neither blocks nor panics and the subscriber gets `Lagged`.
- [ ] **Step 2: Run** — expect failures. **Step 3: Implement.** **Step 4: Verify** — workspace tests, clippy.
- [ ] **Step 5: Commit** — `feat(proxy): non-blocking event bus with decision and ban events`.

---

### Task 4: `vft-server` crate — status, supervisor, metrics, SHA-256, logging

**Files:**
- Create: `crates/vft-server/Cargo.toml`, `crates/vft-server/src/{lib,status,supervise,metrics,sha256,logging}.rs`
- Modify: root `Cargo.toml` workspace members (add `crates/vft-server`)

**Cargo.toml** dependencies: `vft-core`, `vft-proxy` (path), `serde`, `serde_json`, `serde_yaml` (workspace), `anyhow`, `thiserror`, `tokio` (`rt-multi-thread, net, macros, sync, io-util, time, signal`), `hyper`, `hyper-util`, `http-body-util`, `bytes` (same versions as `vft-proxy`), `tracing = "=0.1.44"`, `tracing-subscriber = { version = "=0.3.23", features = ["env-filter", "fmt"] }`, `rusqlite = { version = "=0.40.2", features = ["bundled"] }`. `lib.rs` starts with `#![forbid(unsafe_code)]`.

**Interfaces — produces:**

```rust
// status.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Health { Ok, Warn, Degraded, Critical }
#[derive(Debug, Clone, Serialize)]
pub struct ComponentStatus { pub name: &'static str, pub health: Health, pub reason: String }
#[derive(Debug, Clone, Serialize)]
pub struct StatusRecord {
    pub health: Health,                    // worst of components
    pub components: Vec<ComponentStatus>,  // proxy, config, bus, history — in that order
    pub config_rev: u64,
    pub restart_required: Vec<String>,
    pub drops: std::collections::BTreeMap<String, u64>, // per consumer
    pub version: &'static str,             // env!("CARGO_PKG_VERSION")
    pub uptime_s: u64,
}
pub struct StatusBoard { /* Mutex<state>, start Instant */ }
impl StatusBoard {
    pub fn new() -> Self;                  // all components Ok
    pub fn set(&self, name: &'static str, health: Health, reason: impl Into<String>);
    pub fn set_config(&self, rev: u64, restart_required: Vec<String>);
    pub fn add_drops(&self, consumer: &str, n: u64);
    pub fn snapshot(&self) -> StatusRecord;
}
// supervise.rs
/// Run `make()` in a loop: on Err or panic, log, wait (1 s doubling to 60 s; reset after 60 s healthy), restart.
/// Stops when `stop` is notified (watch channel set to true). Returns when stopped.
pub async fn supervise<F, Fut>(name: &'static str, stop: tokio::sync::watch::Receiver<bool>, make: F)
where F: FnMut() -> Fut, Fut: Future<Output = anyhow::Result<()>> + Send + 'static;
// metrics.rs
pub struct Metrics { /* AtomicU64 counters */ }
impl Metrics {
    pub fn new() -> Self;
    pub fn observe_decision(&self, verdict: vft_core::Verdict, latency_us: u64);
    pub fn reload(&self, applied: bool);
    pub fn history_written(&self, rows: u64);
    pub fn history_dropped(&self, rows: u64);
    pub fn set_history_queue(&self, depth: u64);
    pub fn render(&self, status: &StatusRecord) -> String; // Prometheus text format 0.0.4
}
// sha256.rs
pub fn sha256_hex(data: &[u8]) -> String;
// logging.rs
pub fn init();  // tracing-subscriber fmt to stderr, EnvFilter from RUST_LOG, default "info"; idempotent
```

- Metric names: `vft_requests_total{verdict="allow|monitor|challenge|block"}`, `vft_request_latency_seconds_bucket{le="0.0005|0.001|0.0025|0.005|0.01|0.025|0.05|0.1|0.25|+Inf"}` with `_sum` and `_count`, `vft_bus_dropped_total{consumer="…"}`, `vft_reloads_total{result="applied|rejected"}`, `vft_history_rows_written_total`, `vft_history_rows_dropped_total`, `vft_history_queue_depth`, `vft_config_rev`, `vft_up` (1). Each family has `# HELP` and `# TYPE` lines.
- `supervise` catches panics by running each attempt in `tokio::spawn` and treating a `JoinError` as a failure.

- [ ] **Step 1: Failing tests**: health rollup is the worst component; `snapshot` ordering; `supervise` restarts a task that panics twice then succeeds (use paused tokio time: `#[tokio::test(start_paused = true)]` and assert backoff 1 s then 2 s), and stops promptly when `stop` flips; `render` output parses with a small in-test line parser (every non-comment line is `name{labels} value`, every family has HELP and TYPE, histogram buckets are cumulative and end with `+Inf` equal to `_count`); `sha256_hex` matches the FIPS 180-2 vectors for `""`, `"abc"` and the 448-bit message `"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"`, plus a 1,000,000 × `"a"` vector.
- [ ] **Step 2–4:** run (fail), implement, verify (`cargo test -p vft-server`, workspace tests, clippy).
- [ ] **Step 5: Commit** — `feat(server): status board, supervisor, metrics, sha-256, logging`.

---

### Task 5: Loopback admin listener

**Files:**
- Create: `crates/vft-server/src/admin.rs`

**Interfaces — consumes:** Task 4 `StatusBoard`, `Metrics`. **Produces:**

```rust
pub trait Reload: Send + Sync + 'static {
    /// Ok(new rev) or Err((issues, live rev)).
    fn reload(&self) -> Result<u64, (Vec<String>, u64)>;
}
pub struct AdminState { pub status: Arc<StatusBoard>, pub metrics: Arc<Metrics>, pub reload: Arc<dyn Reload> }
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/health"),
    ("GET", "/api/v1/status"),
    ("GET", "/metrics"),
    ("POST", "/api/v1/reload"),
];
/// Errors if `bind` is not a loopback address.
pub fn check_bind(bind: std::net::SocketAddr) -> anyhow::Result<()>;
/// Serve until `stop` flips to true.
pub async fn serve_admin(listener: tokio::net::TcpListener, state: Arc<AdminState>, stop: watch::Receiver<bool>) -> anyhow::Result<()>;
```

- Responses: health → `200 {"ok":true}`; status → `200` JSON `StatusRecord`; metrics → `200 text/plain; version=0.0.4`; reload → `200 {"rev":N}` or `422 {"rev":N,"issues":[…]}`. Unknown path → `404 {"error":"not found"}`; known path with the wrong method → `405` with `Allow`. Every response carries the three security headers from Global Constraints and `Cache-Control: no-store`.
- `check_bind` rejects every non-loopback IP (IPv4 `127.0.0.0/8` and `::1` are loopback; IPv4-mapped loopback counts too).

- [ ] **Step 1: Failing tests** (real loopback sockets with `hyper_util` client or raw TCP): each route's status and content type; 404 and 405; headers present on every response including errors; `check_bind("0.0.0.0:8899")` and `("192.0.2.1:1")` fail, `("127.0.0.1:0")`, `("[::1]:0")` pass; a route-table test that requests every `ROUTES` entry and gets non-404, and that a request to any other path under `/api/v1/` gets 404; a `Reload` stub returning `Err` gives 422 with the issues.
- [ ] **Step 2–4:** run (fail), implement, verify.
- [ ] **Step 5: Commit** — `feat(server): loopback admin listener for health, status, metrics and reload`.

---

### Task 6: Runtime, reload, signals, graceful shutdown; `serve` on the runtime

**Files:**
- Create: `crates/vft-server/src/runtime.rs`
- Modify: `crates/vft-proxy/src/lib.rs` (`serve_until`), `crates/vft-cli/Cargo.toml` (`vft-server` path dependency), `crates/vft-cli/src/main.rs` (`serve`)

**Interfaces — consumes:** Tasks 2–5. **Produces:**

```rust
// vft-proxy lib.rs
/// Like `serve_listener`, but stops accepting when `stop` flips to true, then waits for
/// in-flight connections up to `drain` and returns the number still open when it gave up.
pub async fn serve_until(state: Arc<ProxyState>, listener: TcpListener, stop: watch::Receiver<bool>, drain: Duration) -> anyhow::Result<usize>;

// vft-server runtime.rs
pub struct RuntimeOptions {
    pub bind: SocketAddr,
    pub upstream: String,
    pub config_path: Option<PathBuf>,
    pub exceptions_path: Option<PathBuf>,
    pub audit: Option<PathBuf>, pub audit_max_bytes: u64, pub ocsf: Option<PathBuf>,
    pub enforce: bool,
    pub admin_bind: Option<SocketAddr>,   // None = off
    pub state_dir: PathBuf,
    pub history: bool,
}
pub struct Runtime { /* handles */ }
impl Runtime {
    /// Ordered start with rollback: load config (+exceptions, PerRequest clock) → [history: open db,
    /// migrate, record config revision "startup", restore active bans] → start bus consumers →
    /// admin listener → proxy listener. On any error, stop what started, in reverse, and return it.
    pub async fn start(opts: RuntimeOptions) -> anyhow::Result<Runtime>;
    pub fn reload(&self) -> Result<u64, (Vec<String>, u64)>;
    pub fn status(&self) -> StatusRecord;
    /// Stop accepting, drain ≤ 10 s, stop admin, flush history, stop supervised tasks.
    pub async fn stop(self) -> anyhow::Result<()>;
    /// Wait for Ctrl+C (all platforms) or SIGTERM (unix); SIGHUP (unix) calls reload and keeps waiting.
    pub async fn run_until_signal(self) -> anyhow::Result<()>;
}
```

- Reload: read `config_path` (defaults if `None`), `Config::validate()`, read `exceptions_path` and load it at the current time (`Exceptions::load`), `candidate(live, next)`, build `Shield::new(candidate.config).with_exceptions(ex, ExceptionClock::PerRequest)`, `handle.swap`. Success: status `config` Ok, `set_config(rev, restart_required)`, publish `ConfigApplied`, metrics `reload(true)`, and (when history is on) enqueue a config-revision row (Task 7 provides `HistoryHandle::config_revision`). Failure: nothing swapped, status `config` Warn with the issues joined, publish `ConfigRejected`, metrics `reload(false)`. A later success clears the Warn.
- In B1 without history, `Runtime` still runs the metrics consumer: one supervised task subscribes to the bus and calls `observe_decision` and counts `Lagged(n)` as drops for consumer `metrics`.
- `serve` (CLI): adds `--admin-bind <addr|off>` (default from config `admin.bind`), `--state-dir <dir>` (default `./state`), `--no-history`; keeps `--audit`, `--audit-max-mb`, `--ocsf`, `--monitor-only`, `--exceptions`, `--config`; builds `RuntimeOptions`, `Runtime::start`, then `run_until_signal`. A non-loopback admin bind fails before anything binds (exit 1 with a clear message). Startup prints the proxy address, admin address, state dir and whether history is on.
- Until Task 7 lands, `history: true` must be accepted but behave as off with a `tracing::warn!` ("history not available in this build") — Task 7 replaces this.

- [ ] **Step 1: Failing tests** (`runtime.rs`, real sockets, a stub upstream from the existing proxy tests' pattern):
  - start → proxy forwards; `/api/v1/health` 200; stop returns Ok and both ports are released (re-binding them succeeds).
  - reload with a changed `scoring.block_at` file → rev 2, status config Ok, `ConfigApplied` seen on the bus; reload with an invalid file → rev stays, status Warn, 422 through the admin route; reload changing `limits.max_body` → `restart_required` contains it and the live value is unchanged.
  - reload during load: 4 client tasks sending 2,000 requests total while the test reloads 20 times → 0 failed requests (every response 200 from the stub or 403 for the attack request mixed in).
  - drain: an in-flight request to a stub that answers after 300 ms completes successfully when `stop` is called mid-request; a stub that never answers is cut off after the drain limit (use a 500 ms drain in the test via a test-only constructor parameter).
  - SIGHUP: the signal path calls one internal function `on_hup(&self)`; a platform-independent test calls `on_hup` and asserts a reload happened. A `#[cfg(unix)]` smoke test starts the built CLI binary with `serve`, sends `kill -HUP <pid>` via `std::process::Command::new("kill")`, and asserts the admin status shows rev 2.
  - CLI: `serve --admin-bind 0.0.0.0:8899` exits 1 with the loopback message before binding.
- [ ] **Step 2–4:** run (fail), implement, verify (workspace tests, clippy).
- [ ] **Step 5: Commit** — `feat(server): runtime with reload, signals and graceful shutdown; serve runs on it`.

---

### Task 7: History store — schema, writer, sampling, rollups, chain events, bans, config revisions

**Files:**
- Create: `crates/vft-server/src/history/{mod,schema,writer}.rs`
- Modify: `crates/vft-server/src/runtime.rs` (open, consumer, revisions), `crates/vft-proxy/src/lib.rs` (fill `snippets` when enabled)

**Schema** (`schema.rs`, migration 1 sets `PRAGMA user_version = 1`; `PRAGMA journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`):

```sql
CREATE TABLE requests (
  event_id TEXT PRIMARY KEY, ts_ms INTEGER NOT NULL, src_key TEXT, ip TEXT,
  method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL,
  verdict TEXT NOT NULL, score INTEGER NOT NULL, stage TEXT, families INTEGER NOT NULL,
  construct TEXT, technique TEXT, confidence INTEGER, group_id TEXT,
  cause_kind TEXT NOT NULL, decided_option TEXT NOT NULL, config_rev INTEGER NOT NULL,
  latency_us INTEGER NOT NULL, upstream_status INTEGER, sampled INTEGER NOT NULL,
  exceptions TEXT NOT NULL, extra TEXT NOT NULL
);
CREATE INDEX requests_ts ON requests(ts_ms);
CREATE INDEX requests_verdict_ts ON requests(verdict, ts_ms);
CREATE INDEX requests_src_ts ON requests(src_key, ts_ms);
CREATE INDEX requests_construct_ts ON requests(construct, ts_ms);
CREATE INDEX requests_group ON requests(group_id);
CREATE TABLE rollup_minute (
  minute_ms INTEGER NOT NULL, verdict TEXT NOT NULL, families INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (minute_ms, verdict, families)
);
CREATE TABLE chain_events (ts_ms INTEGER NOT NULL, src_key TEXT NOT NULL, kind TEXT NOT NULL, stage TEXT, detail TEXT NOT NULL);
CREATE INDEX chain_events_src_ts ON chain_events(src_key, ts_ms);
CREATE INDEX chain_events_ts ON chain_events(ts_ms);
CREATE TABLE bans (
  key TEXT NOT NULL, cause TEXT NOT NULL, since_ms INTEGER NOT NULL, until_ms INTEGER NOT NULL,
  offences INTEGER NOT NULL, lifted_ms INTEGER, PRIMARY KEY (key, since_ms)
);
CREATE TABLE config_revisions (
  rev INTEGER NOT NULL, ts_ms INTEGER NOT NULL, source TEXT NOT NULL,
  config_sha256 TEXT NOT NULL, exceptions_sha256 TEXT NOT NULL, changed_keys TEXT NOT NULL
);
```

- Column rules: `verdict`/`stage`/`cause_kind` are the Rust variant names (`Block`, `Exploitation`, `Detection`); `families` is a bitmask over `Family` in declaration order (bit 0 Sqli … bit 9 Anomaly) of every non-shadow contribution's family; `construct` = `decided_by.construct`; `technique` = `judgment.attack[0].id`; `exceptions` = ids joined with `,` (empty string when none); `extra` = JSON `{"contributions":[{"construct","field","points","shadow","exception"}…], "skipped":["loc:name"…], "snippets":[["loc:name","…"]…]}`; `exceptions_sha256` is the empty string when no file is given.
- Rollups: every `Decision` (sampled or not) adds 1 to `(minute_ms = ts_ms - ts_ms % 60000, verdict, families)` via `INSERT … ON CONFLICT DO UPDATE SET count = count + 1`.
- Chain events: from a `Decision` whose `judgment.chain` has `advanced` → `kind "stage"`, `stage = stage_after`; whose `new_ban` is `Some` → `kind "ban"`, `detail` = JSON of the ban. `BanChanged` writes/updates `bans` (`lifted: true` sets `lifted_ms`).
- Sampling: store when verdict ≠ Allow, or `exceptions`/`skipped` non-empty, or `sample(event_id) < allow_sample_rate`, where `sample` = the first 8 hex digits of `sha256_hex(event_id)` as u32 / 2^32 (deterministic). `sampled = 1` only for rows stored by the last rule.
- Snippets: when `history.store_snippets` is on, `ProxyState` fills `DecisionEvent.snippets` for every field with a contribution, at most 128 chars (char boundary), never for header names `authorization`, `cookie`, `set-cookie` (case-insensitive) or cookie fields.

**Interfaces — produces:**

```rust
pub enum WriteMsg {
    Decision(Arc<DecisionEvent>),
    Ban { key: String, ban: Option<BanRecord>, lifted: bool, ts_ms: u64 },
    ConfigRevision { rev: u64, ts_ms: u64, source: &'static str, config_sha256: String, exceptions_sha256: String, changed_keys: Vec<String> },
    Flush(std::sync::mpsc::SyncSender<()>),
}
pub struct HistoryHandle { /* SyncSender<WriteMsg>, counters, join handle */ }
impl HistoryHandle {
    pub const QUEUE: usize = 4096;
    /// Opens/creates `<dir>/history.db`, runs migrations, starts the writer thread.
    pub fn open(dir: &Path, cfg: HistoryConfig, metrics: Arc<Metrics>) -> anyhow::Result<HistoryHandle>;
    /// try_send; returns false (and counts a drop) when the queue is full.
    pub fn enqueue(&self, msg: WriteMsg) -> bool;
    pub fn config_revision(&self, rev: u64, source: &'static str, config: &[u8], exceptions: &[u8], changed: Vec<String>);
    pub fn flush(&self, timeout: Duration) -> bool;      // waits for the writer to commit everything queued so far
    pub fn close(self, timeout: Duration);                // flush, stop the thread
    pub fn dropped(&self) -> u64;
    pub fn written(&self) -> u64;
}
```

- Writer thread: owns the only write connection; batches into one transaction per 500 messages or 250 ms; updates metrics (`history_written`, `set_history_queue`); a SQLite error marks status `history` Degraded with the error text and keeps going (the failing batch is counted as dropped).
- Runtime wiring: a supervised task subscribes to the bus and maps `Decision` and `BanChanged` to `WriteMsg` with `enqueue`; `Lagged(n)` adds `n` drops for consumer `history`. Config revisions are enqueued on start (`source "startup"`) and on every applied reload (`"reload"`). `stop` calls `close(Duration::from_secs(5))` after the proxy drained. Replace Task 6's "history not available" warning.

- [ ] **Step 1: Failing tests** (`history` tests with a temp dir under `std::env::temp_dir()`):
  - open twice: migrations idempotent, `user_version == 1`, WAL on.
  - one Block, one touched Allow, 1,000 untouched Allows with rate 0.01 → the Block and touched Allow stored with `sampled = 0`; the stored untouched Allows number within 0..=30 and all have `sampled = 1`; rollups sum to 1,002.
  - a stage advance and a ban produce `chain_events` rows; `BanChanged` lifted sets `lifted_ms`.
  - config revision row written with the SHA-256 of the given bytes.
  - queue full: a writer blocked on a test barrier, 4,096 + 10 enqueues → 10 return false, `dropped() == 10`.
  - snippets: off → `extra.snippets` empty; on → truncated to 128 chars, none for `Authorization`/`Cookie`/`Set-Cookie`.
  - runtime: start with history in a temp `--state-dir`, send 3 requests through the proxy, `flush`, read the DB with a read-only connection: 3 rollup counts, the non-Allow rows present, one `startup` revision.
- [ ] **Step 2–4:** run (fail), implement, verify.
- [ ] **Step 5: Commit** — `feat(server): sqlite history writer with sampling, rollups, chain events, bans and revisions`.

---

### Task 8: Retention and ban restore at boot

**Files:**
- Create: `crates/vft-server/src/history/retention.rs`
- Modify: `crates/vft-server/src/history/mod.rs`, `crates/vft-server/src/runtime.rs`

**Interfaces — produces:**

```rust
/// Delete requests and chain_events older than now - retention_days, rollups older than now - 90 days,
/// in batches of at most 5,000 rows per transaction. Returns rows deleted per table.
pub fn sweep(conn: &rusqlite::Connection, now_ms: u64, retention_days: u32) -> rusqlite::Result<(u64, u64, u64)>;
/// Active bans: until_ms > now and lifted_ms IS NULL, newest row per key.
pub fn active_bans(conn: &rusqlite::Connection, now_ms: u64) -> rusqlite::Result<Vec<(String, BanRecord)>>;
```

- Add the variant `WriteMsg::Sweep { now_ms: u64, retention_days: u32 }` (Task 7's enum). The sweep runs as that message, handled by the writer thread (so it shares the single write connection), sent by a supervised hourly timer in the runtime (first run 1 minute after start).
- `Runtime::start`, with history on: after migrations and before the admin and proxy listeners, read `active_bans` with a read connection and call `ChainStore::restore_ban(SourceKey::new(key.parse()?, ipv6_prefix), rec)` for each; log the count. A key that does not parse is logged and skipped.

- [ ] **Step 1: Failing tests**: sweep deletes exactly rows with `ts_ms < cutoff` across a boundary (rows at cutoff−1, cutoff, cutoff+1); rollups use the 90-day cutoff; batches (insert 12,000 old rows, sweep deletes all in ≥ 3 transactions — count via a test hook); `active_bans` excludes expired and lifted, picks the newest per key; runtime: run a source into a ban, stop, start again with the same state dir → the first request from that source is answered 403 by the fast-track before inspection (assert the judgment's `decided_by.kind == Ban`), and the proxy port only accepts connections after restore (start returns only after both).
- [ ] **Step 2–4:** run (fail), implement, verify.
- [ ] **Step 5: Commit** — `feat(server): history retention sweep and ban restore before the proxy opens`.

---

### Task 9: Query language and `history query`

**Files:**
- Create: `crates/vft-server/src/history/{query,read}.rs`
- Modify: `crates/vft-cli/src/main.rs` (`History { Query {…} }` subcommand)

**Grammar** (terms separated by whitespace, all ANDed; a term is `[-]field:value` or `score<op>N`):

| Field | Value | SQL fragment |
|---|---|---|
| `verdict` | `allow|monitor|challenge|block` (case-insensitive) | `verdict = ?` |
| `stage` | `recon|enumeration|exploitation|exfiltration|none` | `stage = ?` / `stage IS NULL` |
| `construct` | id, optional trailing `*` | `construct = ?` / `construct LIKE ? ESCAPE '\'` (escape `%`, `_`, `\`) |
| `technique` | e.g. `T1190` | `technique = ?` |
| `src` | an IP address, or an IPv4 CIDR with prefix /8, /16 or /24 | an address: `src_key = ?` with the address's canonical text (`IpAddr` parse then `to_string`; IPv4-mapped IPv6 folded to IPv4) — for IPv6 the user gives the source key as shown in results (the /64-masked form); an IPv4 CIDR: `src_key LIKE ? ESCAPE '\'` with the first 1, 2 or 3 octets and `.%`. Any other prefix, or an IPv6 CIDR, → error `unsupported prefix: use /8, /16 or /24, or an address` |
| `path` | absolute path prefix | `path LIKE ? ESCAPE '\'` (escaped, `%` appended) |
| `method` | token | `method = ?` (uppercased) |
| `cause` | `CauseKind` name, case-insensitive | `cause_kind = ?` |
| `exception` | exception id | `(',' || exceptions || ',') LIKE ? ESCAPE '\'` with `%,id,%` |
| `group` | group id | `group_id = ?` |
| `sampled` | `true|false` | `sampled = ?` |
| `score` | `score>N`, `score<N`, `score>=N`, `score<=N`, `score:N` (0..=100) | `score <op> ?` |

- `-` before a term negates it (`NOT (…)`). An unknown field, an empty value, a bad value, or anything else → `QueryError { pos, len, msg }` (byte offsets into `q`).
- **Interfaces — produces:**

```rust
pub enum Term { /* one variant per field above, holding typed values */ }
pub struct Query { pub terms: Vec<(bool /*negated*/, Term)> }
pub fn parse(q: &str) -> Result<Query, QueryError>;
pub struct Compiled { pub sql: String, pub params: Vec<rusqlite::types::Value> }
pub struct Request { pub q: String, pub from_ms: u64, pub to_ms: u64, pub group_by: Option<GroupBy>, pub limit: u32, pub cursor: Option<String> }
pub enum GroupBy { Src, Path, Construct, Stage, Verdict }
/// Validates from < to, 1 <= limit <= 1000; builds SELECT … FROM requests WHERE ts_ms >= ? AND ts_ms < ? AND <terms>
/// ORDER BY ts_ms DESC, event_id DESC LIMIT ? (keyset cursor "ts_ms:event_id"), or the GROUP BY variant.
pub fn compile(req: &Request) -> Result<Compiled, QueryError>;
pub struct Page { pub rows: Vec<serde_json::Value>, pub groups: Option<Vec<(String, u64)>>, pub next: Option<String> }
pub fn run(conn: &rusqlite::Connection, req: &Request) -> Result<Page, QueryError>; // read.rs
```

- `compile` builds SQL only from `&'static str` fragments and `?`; every user value goes into `params`.
- CLI: `venusflytrap history query --q <q> --from <RFC3339|ms> --to <RFC3339|ms> [--group-by …] [--limit N] [--cursor C] [--state-dir DIR]` opens `<dir>/history.db` read-only and prints the `Page` as JSON; a `QueryError` prints `error at <pos>: <msg>` and exits 2. RFC 3339 parsing: accept `YYYY-MM-DDTHH:MM:SSZ` only (std-only parser; reuse `vft_core::exceptions::parse_date` for the date part).

- [ ] **Step 1: Failing tests**: each field parses and compiles to the expected fragment and params; negation; errors with positions (`verdict:maybe`, `colour:red`, `score>101`, `src:10.0.0.0/12`, empty value); SQL-safety property test (proptest, 2,000 cases): for arbitrary strings `q`, `compile` either errors or returns SQL whose text, after removing every whitelisted fragment and `?`, is empty of any character from `q` that is not whitespace — implement as: assert `sql` is a concatenation of fragments from a `FRAGMENTS` list exported by `query.rs`; integration: insert 50 rows and check `run` results for `verdict:block`, `construct:sqli.*`, `-verdict:allow`, `exception:referer-sql`, group-by `construct`, and cursor paging (two pages, no overlap, no gap).
- [ ] **Step 2–4:** run (fail), implement, verify.
- [ ] **Step 5: Commit** — `feat(server): history query language and venusflytrap history query`.

---

### Task 10: Measurement tools, measurements and results note

**Files:**
- Create: `crates/vft-server/examples/replay.rs`, `crates/vft-server/examples/history_bench.rs`
- Create: `eval/RESULTS-B12-runtime-history.md`
- Modify: `docs/BENCHMARK.md` (one status line), `README.md` (a short "Running as a service" section: flags, admin endpoints, `history query`)

**Tools:**
- `replay`: starts a `Runtime` (history on or off by flag) against an in-process stub upstream (200, empty body), then replays the corpus's request files over TCP from N client tasks at a target rate for a fixed duration, cycling the files; options `--corpus`, `--rate`, `--seconds`, `--clients`, `--history on|off`, `--reload-every-ms`, `--state-dir`. It prints JSON: sent, ok (status 200 or 403), failed, p50/p95/p99 latency (client-side), reloads applied, history written/dropped.
- `history_bench`: (a) writes N synthetic `DecisionEvent`s through `HistoryHandle` as fast as possible and reports events/s and drops; (b) fills a database to 1,000,000 rows over a 7-day span with a realistic mix (5 % non-Allow), then runs 200 queries of the 24-hour forms (`verdict:block`, `construct:sqli.*`, `src:<ip>`, `-verdict:allow`, group-by `construct`) over random 24-hour windows and reports p50/p95 per form.

**Measurements** (all on this laptop; record CPU, RAM, OS, rustc, commit):
1. No change: dev A/B (`eval/ab_dev.sh b12-nochange "" "" <main-d6eec01 binary> ./target/release/venusflytrap`) → 0 changed cells; full-corpus serve diff, `distinct` and `pooled:100` → 0 changed decisions. The main binary is `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\b12\bin\main-d6eec01.exe`.
2. Latency: `replay --history off` and `--history on` at 1,000 rps for 60 s, 3 runs each; p99 with history within 5 % of without (report all runs; if it fails, stop and report — do not tune silently).
3. Reload under load: `replay --rate 2000 --seconds 60 --reload-every-ms 3000` → failed = 0; reloads applied = 20.
4. History throughput: `history_bench` write mode → ≥ 5,000 events/s sustained over 60 s with 0 drops.
5. Query p95: `history_bench` query mode → every form p95 < 100 ms over 1 M rows.
6. Stalled consumer: covered by the Task 3/7 tests; cite them.

- [ ] Steps: build tools → run measurements (long runs in the background) → write the note with every number from a run (commands included) → status line in `docs/BENCHMARK.md` → README section → commit `docs(eval): B1+B2 runtime and history measurements`.
- If a target is missed, the note says so plainly with the numbers; do not change the target.
