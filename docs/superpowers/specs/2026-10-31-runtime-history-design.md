# B1+B2 — Service runtime and history store (design)

*First part of sub-project B of the EDR-lessons follow-up (A → C → B), which
builds the service layer of `2026-10-25-operable-service-design.md`. B is four
parts, each with its own spec: **B1 runtime (SP3)** and **B2 history store
(SP4)** in this spec; B3 admin API, auth and live channel (SP5); B4 the console
on the real API. Approved by the owner on 2026-10-31.*

## 1. Goal

Turn `serve` into a service that can be operated and remembers what it decided:

- a `vft-server` crate with a `Runtime` that starts and stops the parts in order,
- hot reload of `shield.yaml` and the `--exceptions` file without dropping a
  request,
- an event bus, a supervisor for background tasks, a status board, `/metrics`,
  and graceful shutdown,
- a loopback-only admin listener for health, status, metrics and reload,
- a SQLite history of decisions, rollups, chain events, bans and config
  revisions, with retention, ban restore at boot and a safe query language.

## 2. Non-goals

- Admin auth, keys, sessions, CSRF rules, the HTTP history/request/source
  endpoints, the SSE live channel, manual ban/unban and `admin_audit` (B3).
- The console on the real API (B4).
- `PATCH /api/v1/config` and the API-managed overrides file (B3), TLS, intel
  feeds (SP7).
- Recording the exception id per skipped field: the judgment shape stays as C
  left it; B3/B4 decide it together with the API.
- Any detection change. `eval` is not touched.
- No outside product names in code, UI or docs.

## 3. Crates and dependencies

- New crate `crates/vft-server` (control plane), `#![forbid(unsafe_code)]`.
  New dependencies, approved by the owner: `arc-swap`, `tracing`,
  `tracing-subscriber`, `rusqlite` with the `bundled` feature (SQLite's C code
  is compiled in; no `unsafe` in our crates). tokio gains the `signal` feature.
  Every new version is pinned and at least two weeks old.
- `vft-proxy` stays the data plane: it gains the config handle (`arc-swap`) and
  a non-blocking event sender, and never links SQLite or admin routes.
- `vft-cli`: `serve` runs on `vft_server::Runtime`; new `history query`
  subcommand. `eval`, `scan`, `bench`, `ablate` are unchanged and link only
  `vft-proxy`/`vft-core`.

## 4. B1 — Runtime

### 4.1 Config handle and reload

- `ConfigHandle` (in `vft-proxy`): an `ArcSwap<Loaded>`, where
  `Loaded { rev: u64, shield: Shield, files: FileStamps }`. The pipeline loads
  it once per request, so a request never mixes revisions. The chain store and
  bans live outside `Loaded` and survive every reload.
- Reload: read `shield.yaml` (when `--config` was given) and the `--exceptions`
  file (when given) → `Config::validate()` and exceptions validation at the
  current time → build the new `Shield` off the request path → compare with the
  live config → swap with `rev + 1` → publish `ConfigApplied`.
- An invalid candidate is rejected as a whole: the live revision stays, status
  turns Warn listing the failing keys or exception issues, `ConfigRejected` is
  published. The next good reload clears the Warn.
- Options whose registry descriptor says `Apply::Restart` (e.g.
  `chain.max_sources`, `chain.ipv6_prefix`, `limits.max_body`,
  `proxy.trusted_proxies`, `proxy.decision_headers`) are not applied by a
  reload: the new `Shield` keeps their live values, and status lists them as
  "restart required" until the next start.
- Triggers: SIGHUP (Unix) and `POST /api/v1/reload` on the admin listener (all
  platforms). There is no file watcher.

### 4.2 Admin listener (local)

- Binds `admin.bind` (default `127.0.0.1:8899`; `--admin-bind` overrides). A
  non-loopback address is a startup error in B1+B2 (B3 adds auth and TLS).
  `--admin-bind off` disables it.
- Routes: `GET /api/v1/health` (liveness), `GET /api/v1/status`
  (`StatusRecord`), `GET /metrics` (Prometheus text), `POST /api/v1/reload`
  (200 with the new rev, or 422 with the issues and the unchanged rev). Any
  other path → 404. A static route table is the single source; a test asserts
  the router serves exactly it.
- Every response carries the design's headers: the CSP of §5.8 of the service
  design, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

### 4.3 Event bus

- `tokio::sync::broadcast` with capacity 8192 of `BusEvent`:
  `Decision { event_id, group_id, ts_ms, src_key, ip, method, host, path,
  judgment summary, latency_us, upstream_status, config_rev }`,
  `ConfigApplied { rev, changed, restart_required }`,
  `ConfigRejected { issues }`, `BanChanged { key, ban, lifted }`.
- Publishing never blocks the proxy. Each consumer has its own lag counter; a
  lagging consumer skips events and counts them.
- The existing JSONL and OCSF audit sinks stay as they are (not moved onto the
  bus). History (B2) is the first bus consumer.

### 4.4 Supervisor, status, metrics, logs

- `supervise(name, task)`: restarts a failed or panicked background task with
  backoff 1 s → 60 s, reset after 60 s healthy; one cancellation token stops
  them all.
- `StatusBoard`: per component (proxy, config, bus, history) a state
  `Ok | Warn | Degraded | Critical` with a reason; the rollup is the worst one.
  `StatusRecord` = rollup, components, counters, drops per consumer,
  `config_rev`, restart-required keys, version, uptime.
- `/metrics`: hand-written Prometheus text from atomics: requests by verdict,
  a latency histogram, bus drops per consumer, reloads applied/rejected,
  history queue depth, rows written, rows dropped.
- Logs: `tracing` with `tracing-subscriber` (plain text to stderr; level from
  `RUST_LOG`, default `info`).

### 4.5 Lifecycle

- `Runtime::start` is one ordered function with rollback on failure:
  load config → open history and run migrations → restore active bans into the
  chain store → start the history writer → start the admin listener → open the
  proxy listener. `Runtime::stop` runs it in reverse.
- Shutdown on SIGTERM (Unix) or Ctrl+C (all platforms): stop accepting, drain
  in-flight requests for up to 10 s, flush the history queue, exit 0.
- `serve` flags added: `--admin-bind <addr|off>`, `--state-dir <dir>` (default
  `./state`; holds `history.db`), `--no-history`. Existing flags unchanged.

## 5. B2 — History store

### 5.1 Writer and readers

- SQLite in WAL mode at `<state-dir>/history.db`; migrations by
  `PRAGMA user_version`.
- One OS thread owns the write connection, fed from the bus through
  `std::sync::mpsc::sync_channel(4096)` with `try_send`. A full queue drops the
  event, counts it (status + `/metrics`) and never blocks a request.
- Transactions of 500 rows or 250 ms, whichever comes first.
- Reads use a pool of 4 read-only connections.

### 5.2 Tables

- `requests`: every non-Allow judgment, every Allow with a non-empty
  `exceptions` or `skipped`, and other Allows sampled at
  `history.allow_sample_rate` (default 0.01) with `sampled = 1`. Columns:
  `event_id` (primary key), `ts_ms`, `src_key`, `ip`, `method`, `host`,
  `path` (no query string), `verdict`, `score`, `stage`, `families` (bitmask),
  `construct`, `technique`, `confidence`, `group_id`, `cause_kind`,
  `decided_option`, `config_rev`, `latency_us`, `upstream_status`, `sampled`,
  `exceptions` (comma-separated ids), `extra` (JSON: contributions summary and
  skipped fields). Indexes: `ts_ms`, `(verdict, ts_ms)`, `(src_key, ts_ms)`,
  `(construct, ts_ms)`, `group_id`.
- `rollup_minute`: one row per minute × verdict × family with a count; counts
  100 % of requests (sampling does not affect it).
- `chain_events`: stage changes and bans per source (`ts_ms`, `src_key`,
  `kind`, `stage`, `detail`).
- `bans`: `key`, `cause`, `since_ms`, `until_ms`, `offences`, `lifted_ms`.
- `config_revisions`: `rev`, `ts_ms`, `source` (`startup` | `reload`),
  `config_sha256`, `exceptions_sha256`, `changed_keys`.
- `api_keys` and `admin_audit` are created by a B3 migration, not here.
- Raw field values are never stored by default. `history.store_snippets`
  (default off) keeps at most 128 characters per field and never
  `Authorization`, `Cookie` or `Set-Cookie`.
- New options (`history.allow_sample_rate`, `history.retention_days`,
  `history.store_snippets`) are registered with descriptors, validation and
  `Apply` modes like every other option.

### 5.3 Retention

An hourly sweep (supervised) deletes `requests` and `chain_events` older than
`history.retention_days` (default 14) and `rollup_minute` older than 90 days,
in batches that never hold the write connection for more than 250 ms.

### 5.4 Bans across restarts

Every ban and lift is written. At boot, active bans (`until_ms > now`, not
lifted) are restored into the chain store before the proxy listener opens.
Chain windows are not persisted.

### 5.5 Query language

- `q` is a list of `field:value` terms, optionally negated with `-`, ANDed;
  fields come from a whitelist: `verdict`, `stage`, `construct` (`*` suffix
  wildcard), `technique`, `src` (address or CIDR), `path` (prefix), `method`,
  `cause`, `exception`, `group`, `sampled`, `score` (`>`, `<`, `>=`, `<=`).
- It parses to a typed AST, which compiles to SQL from fixed fragments with
  bound parameters. Raw SQL is never accepted; an unknown field or operator is
  a typed error. A time range (`from`, `to`) is required; `limit` ≤ 1000;
  keyset cursor paging; optional `group_by` (`src`, `path`, `construct`,
  `stage`, `verdict`).
- B2 exposes it through `venusflytrap history query --q … --from … --to …
  [--group-by …] [--limit …] [--state-dir …]` (read-only connection, JSON
  output). The HTTP endpoint is B3, behind auth.

## 6. Testing and acceptance

- **No change:** `eval` untouched; the dev A/B and the full-corpus serve diff
  against main show 0 changed cells and 0 changed decisions. `serve
  --no-history` behaves as today apart from the admin listener.
- **Latency:** proxy p99 with history on stays within 5 % of `--no-history` on
  a TCP corpus replay.
- **Reload:** during a 2,000 rps replay, 0 failed requests and no request sees
  two revisions; an invalid reload keeps the old rev and shows Warn with the
  issues; a changed restart-only option is reported, not applied.
- **Bus and supervisor:** a stalled consumer raises its drop counter while
  proxy p99 moves < 5 %; a panicking task restarts with backoff.
- **Admin listener:** non-loopback bind fails at startup; routes equal the
  table; headers present; `/metrics` parses as Prometheus text.
- **Shutdown:** Ctrl+C (all platforms) and SIGTERM (`cfg(unix)`) drain and
  exit 0; SIGHUP reload tested under `cfg(unix)`.
- **History:** ≥ 5,000 events/s sustained with no drops on the development
  laptop; indexed 24 h queries p95 < 100 ms over 1 M rows; bans survive a
  restart and the listener opens only after the restore; retention deletes
  exactly the expired rows; sampling within tolerance over 100 k requests.
- **Query language:** unit and property tests: every input yields an AST or a
  typed error; generated SQL text contains only whitelisted fragments and
  placeholders, never input text.
- Results with machine, row counts and commands in
  `eval/RESULTS-B12-runtime-history.md`.
- `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D
  warnings` green; `#![forbid(unsafe_code)]` in every crate of ours.
