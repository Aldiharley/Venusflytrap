# Venusflytrap as an operable service — program design

*Date: 2026-10-25 · Status: draft for review · Scope: program-level design for seven sub-projects (SP1–SP7). SP1 gets its own implementation plan; SP2–SP7 get plans when they start.*

## 1. Goal

Turn Venusflytrap from a measured detection library with a demo proxy into a service an operator can run, understand and control:

- a reverse proxy that is safe to put in front of real traffic;
- verdicts that explain themselves ("blocked by `scoring.block_at = 90` because `sqli.union-select` fired in `query:id`");
- a queryable history of decisions and bans;
- a local admin API and an embedded web console, including a live view of attack chains (per-source kill-chain stages, honeypot hits, bans).

The GUI is the last and thinnest layer. It renders backend metadata (option descriptors, causes, history rows) and adds little logic of its own.

## 2. Non-goals

- TLS termination on the data plane (run behind a terminator listed in `proxy.trusted_proxies`).
- HTTP/2, WebSocket or `Upgrade` passthrough (refused with 501 in v1).
- A real Challenge flow (Challenge stays a 403 with a distinct cause until asked for).
- Per-route policy layers, notifications/webhooks, a desktop tray shell.
- Detection-quality work. Recall lift (body structuring, decoders, sink registry, new constructs) is owned by the separate recall-lift design; this program only consumes its interfaces (§7).

## 3. Starting point (measured, 2026-10-25)

- Library path on the real blazehttp corpus (33,877 requests), command-position `$(` fix applied: 42.9% recall, 51.3% precision, 0.81% FP rate. Mutation robustness: 96% of detection retained (libinjection 57%, regex 54%).
- These numbers describe `Shield::inspect` only. The proxy path has not been measured, and a code review on 2026-10-25 confirmed it is broken:
  - **C1** every real browser is banned on its first request in proxy mode (latent `shell-meta` from the `;` in User-Agent feeds the kill chain; one Exploitation event bans forever);
  - **C4** headers with non-UTF-8 bytes skip inspection but are still forwarded;
  - **H2** no body limit or timeouts; **H3** one global mutex around all inspection; **H4** clean fields damp attacks in other fields; **H5** honeypot and recon read the raw path (`/%2egit/config` passes); **H6** hop-by-hop and proxy headers forwarded;
  - plus medium/low findings M1–M3, M6, M8–M10, L1–L4, L6.
- C2, C3, H1, L5 (truncation fail-opens and decoder bugs) and the body-as-one-field gap are owned by the recall-lift design.

## 4. Design principles

1. **The core stays pure.** `vft-core` is a deterministic function from `Request` to `Judgment`: no I/O, no clock, no locks. Time is passed in.
2. **Decision, not evidence, drives state.** The kill chain and bans consume the verdict and its cause, never raw or latent patterns. A request the engine allows cannot advance a source's chain.
3. **Every forwarded byte is inspected or declared uninspected**, and the declaration is itself evidence.
4. **Nothing on the hot path blocks.** No global lock, no disk write, no slow client can stall a request. Every bounded queue drops and counts; drops are shown to the operator.
5. **Fail closed, and say so.** A limit that stops inspection produces evidence with a cause naming its option key.
6. **One key names one setting everywhere**: in config, in `decided_by`, in the API, in the settings screen and in deep links.
7. **Secure by default for the admin surface.** Separate loopback listener, most-restrictive default permission, no debug endpoints, strict CSP.
8. **Honest measurement.** The eval runs the same function the proxy runs. Library and serve numbers are published side by side; no target is asserted for a number before it is measured.

Provenance: the API, history, option-registry and console patterns below were re-derived from prose research into existing open-source firewall products. No third-party code, assets or names are used.

## 5. Target architecture

### 5.1 Crates

```
crates/
  vft-core/     pure engine. New: options.rs (descriptor registry), Cause/Contribution in
                judgment.rs, chain.rs as a pure state machine, canonical path in request.rs
  vft-proxy/    data plane library: limits, adapter, Pipeline::decide, forwarder,
                ConfigHandle, ChainStore, BanStore, event bus sender. No SQLite, no web framework.
  vft-server/   control plane (new, SP3+): Runtime, history (SQLite), admin API + auth,
                live hub (SSE), embedded console assets, status/metrics
  vft-cli/      venusflytrap scan | bench | eval | serve | config validate | admin create-key | debug-bundle
ui/             console source (TypeScript); ui/src/gen/ holds generated wire types
```

One new crate, not four: history, admin API and live hub share one lifecycle and one database handle. The eval harness links only `vft-proxy`, so the data plane stays free of database and web dependencies. No `Module` trait: `Runtime::start` is one hand-ordered function with rollback, `stop` runs it in reverse.

### 5.2 Key types

**Judgment carries its cause** (`vft-core::judgment`, pure):

```rust
pub struct FieldRef { pub loc: Location, pub name: String }         // "query:id", "json:/a/0"
pub struct Contribution {
    pub engine: &'static str, pub field: Option<FieldRef>,
    pub construct: Option<String>,        // stable construct id, e.g. "sqli.union-select"
    pub value: FourValued, pub weight: f32, pub points: f32,
}
pub enum CauseKind { NoEvidence, Detection, Honeypot, IntelDeny, Ban, ChainEscalation, Limit, Allowlisted }
pub struct Cause {
    pub kind: CauseKind,
    pub option_key: &'static str,         // must exist in options::REGISTRY
    pub construct: Option<String>, pub field: Option<FieldRef>, pub msg: String,
}
pub struct Judgment {
    pub verdict: Verdict, pub score: u8,
    pub contributions: Vec<Contribution>, // replaces engines + flat matched
    pub decided_by: Cause,
    pub chain: Option<ChainOutcome>,      // filled by finalize()
    pub normalized_layers: u8,
}
```

`decided_by` is chosen in a fixed order: ban → honeypot → intel deny → fail-closed limit → the band threshold crossed (`scoring.block_at` / `challenge_at` / `monitor_at`) with the top contribution's construct and field → `NoEvidence`. Request id, timestamp and config revision are runtime facts and live in the event envelope, not in `Judgment`.

**Option registry** (`vft-core::options`): a hand-written `REGISTRY: &[OptionDescriptor]` with key, kind and bounds, section, markdown help, expertise level, `Apply::{Live, Restart}` and `sensitive`. `Config::validate()` checks per-key bounds and cross-field rules (`monitor_at < challenge_at < block_at <= 100`, finite weights in `[0, 2]`, `max_payload >= 1024`, `decode_cap in 1..=32`, `shield.disabled ⊆ constructs()`). Config gains `version: 1` and `deny_unknown_fields`. Tests: every leaf of `Config::default()` has exactly one descriptor; `Config::default().validate()` is `Ok`.

**Chain** (`vft-core::chain`, pure, `now: u64` ms passed in):

```rust
pub fn event_for(j: &Judgment) -> Event;   // decision-grade evidence only (§5.4)
pub fn observe(st: &mut SourceState, ev: Event, now: u64, p: &ChainPolicy) -> ChainOutcome;
impl Shield { pub fn finalize(&self, j: Judgment, o: ChainOutcome) -> Judgment }  // never lowers a verdict
```

Stage is the maximum over events inside the window, so it decays. Bans are a separate policy with TTLs (§9, decision 1).

**Data-plane state** (`vft-proxy`): `ConfigHandle(ArcSwap<Loaded{rev, cfg, shield}>)`; `ChainStore` as 64 shards of `Mutex<LruMap<SourceKey, SourceState>>`; `BanStore` in separate shards, never evicted by chain LRU, capped with soonest-expiry-first eviction. `SourceKey` is an IPv4 /32 or an IPv6 /64 (`chain.ipv6_prefix`); IPv4-mapped IPv6 canonicalizes to IPv4. Poisoned locks recover via `into_inner`; `expect`/`unwrap` are denied in non-test code.

**Event envelope**:

```rust
pub struct JudgmentEvent {
    pub id: RequestId, pub ts_ms: i64, pub config_rev: u64,
    pub src: SourceKey, pub ip: IpAddr, pub method: String, pub host: String, pub path: String,
    pub judgment: Judgment, pub latency_us: u32, pub upstream_status: Option<u16>,
}
pub enum BusEvent { Judgment(Arc<JudgmentEvent>), Ban(BanChange), ConfigApplied { rev: u64, keys: Vec<String> }, State(StateRecord) }
```

### 5.3 Request flow

Hot path:

1. **Accept** under a connection semaphore (`limits.max_connections`, 1024). Accept errors back off 10 ms → 1 s and never exit the loop.
2. **Read the head**: HTTP/1.1, `header_read_timeout` 10 s, caps on header count and header bytes.
3. **Fast-track**: load `Arc<Loaded>` once; derive `src_ip` (peer, or `X-Forwarded-For` only from `proxy.trusted_proxies`); check `BanStore`, then intel deny. A hit returns 403 with its cause and skips inspection.
4. **Body** through a length limit (`limits.max_body`, 1 MiB) → 413 before any upstream connection; body timeout.
5. **Adapt**: `adapt::from_parts(&parts, &body, src) -> Request`. Non-UTF-8 header bytes are decoded lossily and add a Suspicious `limit.header-non-utf8` contribution. `Host` is inspected; the raw `Cookie` header is not double-counted alongside parsed cookies. `canonical_path` is computed once (percent-decode, remove dot segments, collapse slashes).
6. **Inspect**: `shield.inspect(&req)`, no lock.
7. **Chain**: `observe` under one shard lock for microseconds, then `finalize`.
8. **Act**: Allow/Monitor forward through one pooled client with connect and response timeouts, hop-by-hop headers stripped (including those named in `Connection`), `Upgrade` refused, `X-Forwarded-For` and `Via` appended, response streamed. Block/Challenge return 403 with a generic body; upstream failure returns a generic 502/504 that does not echo the error. Decision headers go upstream only when `proxy.decision_headers: upstream`, never to the client.

Off-path: after the response completes, `bus.send(BusEvent::Judgment(..))` on a `tokio::sync::broadcast` (capacity 8192). Consumers — history writer, live hub, optional JSONL sink — each count their own `Lagged(n)` as drops (`vft_events_dropped_total{consumer}`).

`Pipeline::decide(&parts, &body, src, now)` is steps 3–7. The handler and the eval both call it.

### 5.4 Chain events come from the decision

- `Honeypot` if `decided_by.kind == Honeypot`;
- `Exfiltration` if verdict ≥ Challenge and a Dangerous contribution has an exfil construct (`sqli.union-select`, `sqli.schema-enum`, `sqli.load-file`);
- `Exploitation` if verdict ≥ Challenge and the top contribution is Dangerous in SQLi, XSS, command injection or path traversal;
- `Recon` if intent is Dangerous; `Enumeration` if a scanner fingerprint matched and verdict ≥ Challenge (a forwarded request never stages a source);
- otherwise `Benign`.

Suspicious or latent evidence never stages a source. Invariant test: for every Allow in the corpus, `event_for == Benign`.

Staging: SP1 implements these rules over the verdict plus a minimal `contributions: Vec<Contribution>` (`engine`, `field: Option<FieldRef>`, `construct` = today's pattern name, `value`, `weight`; `points` left at 0), with the honeypot case read from the honeypot contribution. SP2 adds `Cause`/`decided_by` and real `points`, and `event_for` switches to reading `decided_by` with no change in behaviour (pinned by the corpus invariant test).

### 5.5 Concurrency

| Shared state | Primitive | Held for |
|---|---|---|
| Config + Shield | `ArcSwap<Loaded>`, one load per request | one atomic op |
| Chain | 64-shard `Mutex<LruMap>` | `observe` only |
| Bans | 64-shard `Mutex<HashMap>` | lookup / insert |
| Events | `broadcast` (8192) | never blocks; laggards drop and count |
| History writes | one OS thread owning the DB connection, `sync_channel(4096)` + `try_send` | 500 rows or 250 ms per transaction |
| Live clients | per-client `mpsc(256)` | overflow → `Resync` + fresh snapshot |
| Background tasks | `supervise(name, fut)`: restart on error/panic, 1 s → 60 s backoff, reset after 60 s healthy; one cancellation token | — |

### 5.6 Config and hot reload

Two layers: the operator's `shield.yaml` (never rewritten by Venusflytrap) and an API-managed `state/overrides.yaml` (sparse `key: value`; scalars override, lists replace). `/api/v1/options` reports each option's source (default, base, override).

Triggers: SIGHUP (Unix), `PATCH /api/v1/config`, and `venusflytrap config validate` as a dry run. No file watcher.

Apply: parse → `validate()` → build a new `Shield` off-path → write overrides atomically (temp + rename) → `store(Arc<Loaded{rev+1}>)` → publish `ConfigApplied` → re-evaluate live state (lift bans for newly allow-listed sources, re-check TTL caps). An invalid candidate is rejected as a whole; the last good config stays live and a Warn state lists the failing keys. `Apply::Restart` options are saved and flagged "restart required".

### 5.7 Persistence

SQLite (`rusqlite`, bundled), WAL, one writer thread, a reader pool of 4, migrations via `PRAGMA user_version`. Tables: `requests` (id, ts, src_key, ip, method, host, path, verdict, score, stage, families bitmask, construct, decided_option, config_rev, latency_us, upstream_status, extra JSON), `rollup_minute`, `chain_events`, `bans`, `config_revisions`, `api_keys`, `admin_audit`.

- Every non-Allow judgment is stored; Allows are sampled at `history.allow_sample_rate` (0.01) and labelled as sampled; `rollup_minute` counts 100% of requests.
- Raw field values are not stored by default. `history.store_snippets` (off) keeps 128 characters and never stores `Authorization`, `Cookie` or `Set-Cookie`.
- Retention: hourly sweep, `history.retention_days` (14) for rows, 90 days for rollups.
- At boot, active bans are restored before the proxy listener opens. Chain windows are not persisted.
- Query: `POST /api/v1/history/query {q, from, to, group_by?, limit<=1000, cursor?}`. `q` is a `field:value` language (`verdict:block stage:exploitation construct:sqli.* src:203.0.113.0/24 -verdict:allow`) parsed server-side into a typed AST against a column/operator whitelist with bound parameters. A time range is required. Raw SQL is never accepted.

### 5.8 Admin API and auth

- Separate listener, default `admin.bind: 127.0.0.1:8899`. A non-loopback bind without `admin.tls` is a startup error. Optional Unix socket (0600) on Linux maps the service UID or root to Admin via peer credentials. Health is never served on the proxied port.
- Permissions `Public < Viewer < Operator < Admin`. A static `ENDPOINTS` table drives routing and `GET /api/v1/endpoints`; an endpoint with no declared permission is Admin. A test asserts the router's routes equal the table.
- Keys `vft_<id>_<secret>` (256-bit), stored as SHA-256 of the secret, scoped to a permission, mandatory expiry ≤ 90 days. Bootstrap: `venusflytrap admin create-key --perm admin --ttl 1d` writes to the DB and prints the key once.
- Browser sessions: `POST /api/v1/session` exchanges a key for an `HttpOnly; SameSite=Strict` (+`Secure` with TLS) cookie; keys never go to `localStorage`. Cookie-authenticated mutations require `Origin` equal to the server's origin and `Sec-Fetch-Site: same-origin`. No exemptions, no development-mode bypass.
- Every response: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- No profiling, stack or debug endpoints. Support data comes from the local `venusflytrap debug-bundle`, which redacts IPs, query strings and every `sensitive` option.

| Method and path | Perm | Purpose |
|---|---|---|
| `GET /api/v1/health` | Public | liveness |
| `GET /api/v1/status` | Viewer | worst-state rollup, component states, counters, drops, `config_rev`, version |
| `GET /metrics` | Viewer | Prometheus text |
| `GET /api/v1/endpoints` | Viewer | self-description |
| `GET /api/v1/options` | Viewer | descriptors + effective value, default, source (sensitive redacted) |
| `POST /api/v1/config/validate` | Operator | dry run, per-key issues |
| `PATCH /api/v1/config` | Admin | `{base_rev, set, unset}`; 409 stale rev, 422 per-key errors |
| `GET /api/v1/config/revisions` | Viewer | change history |
| `GET /api/v1/constructs` | Viewer | construct registry with enabled state |
| `POST /api/v1/history/query` | Viewer | monitor |
| `GET /api/v1/dashboard?from&to` | Viewer | one batched aggregate |
| `GET /api/v1/requests/{id}` | Viewer | full judgment, `decided_by`, source timeline |
| `GET /api/v1/sources/{key}` | Viewer | chain state, chain events, ban |
| `GET`/`POST /api/v1/bans`, `DELETE /api/v1/bans/{key}` | Viewer / Operator | list, manual ban, lift |
| `GET /api/v1/live?streams=board,blocks,status` | Viewer | SSE live channel |
| `POST`/`DELETE /api/v1/session` | Public / any | login / logout |
| `GET`/`POST /api/v1/keys`, `DELETE /api/v1/keys/{id}` | Admin | key management |
| `GET /*` | Public | embedded console assets |

### 5.9 Live channel

Server-sent events (one direction, automatic reconnect with `Last-Event-ID`, same-origin cookie). The live hub keeps a `BoardState` projection of active sources (stage ≥ Recon or banned, capped at 500, ordered by stage then recency):

```rust
pub struct SourceView { key: String, ip: IpAddr, stage: Option<Stage>, stage_path: Vec<(i64, Stage)>,
  first_seen: i64, last_seen: i64, requests: u32, blocked: u32, honeypot_hits: u32,
  top_constructs: Vec<(String, u32)>, ban: Option<BanView>, last_request_id: String }
pub enum LiveFrame {
  Snapshot { seq: u64, sources: Vec<SourceView>, dropped_total: u64 },
  Delta    { seq: u64, upserts: Vec<SourceView>, removes: Vec<String>, blocks: Vec<BlockLite> },
  Counters { rps_by_verdict: [u32; 4], dropped_total: u64 },
  Status(StatusRecord),
  Resync,
}
```

New subscribers get `Snapshot`, then `Delta` frames coalesced per source on a 250 ms tick, `Counters` every second, a heartbeat every 15 s. At most 16 clients. Every 30 s the hub reconciles against `ChainStore` and `BanStore`, so dropped events cannot leave the board wrong for long. `dropped_total` is shown in the UI.

### 5.10 Console

- **Stack**: Svelte 5 + Vite (SPA build) + TypeScript, Bits UI headless primitives. Charts: uPlot for time series, `d3-scale`/`d3-time` for the per-source timeline SVG. No force-directed graph library.
- **Types**: wire types derive `ts_rs::TS` behind a `ts` cargo feature and export to `ui/src/gen/`; CI fails on drift.
- **Packaging**: `vft-server/build.rs` embeds `ui/dist` with `include_bytes!` into a static asset table (no unsafe, no macro dependency). If `ui/dist` is absent, a stub page says "console not built", so `cargo test --workspace` needs no Node. Hashed filenames, `Cache-Control: immutable`, same-origin, no CDN. Built assets are not committed.
- **Budgets**: initial JavaScript ≤ 150 KB gzipped; no route chunk over 80 KB.
- **Accessibility**: axe-core in CI with zero serious/critical violations; light and dark via `prefers-color-scheme`; verdicts and stages carry text and shape, never color alone; full keyboard paths; every chart has a "show as table" toggle; motion disabled under `prefers-reduced-motion`.

Screens:

1. **Dashboard** — worst-state banner, requests over time by verdict, sources by stage, top constructs, top targeted paths, honeypot hits, active bans, dropped-event counters. One `/dashboard` call.
2. **Monitor** — query bar with counted suggestions, time range, group-by chips (`src`, `path`, `construct`, `stage`, `verdict`), click-to-filter, state in the URL, cursor paging, auto-refresh 10 s / 1 min / off.
3. **Request details** — verdict chip, score gauge drawn against the bands of the deciding `config_rev`, the `decided_by` sentence, "Decided by `scoring.block_at = 90` (override)" linking to `/settings?highlight=scoring.block_at`, contributions table (engine, field, construct, value, weight, points). Actions: disable this construct (Admin, confirm dialog), ban source, open source.
4. **Attack chains (live)** — an HTML grid (`role="grid"`): rows are sources, columns are Recon / Enumeration / Exploitation / Exfiltration; each cell shows first-reached time and count; bans show as a labelled badge with a TTL countdown. Rows reorder with keyed animation. Click through to the source page.
5. **Source** — kill-chain timeline, the source's requests (monitor pre-filtered), ban/lift controls.
6. **Honeypot & bans** — decoy paths, hits over time, bans table with lift / extend / manual ban.
7. **Settings** — rendered from `/api/v1/options`, grouped by section, expertise filter, "changed from default" and "source: override" markers, inline per-key 422 errors, diff preview before save, "restart required" badge, deep-link highlight, revision history.
8. **Keys** — create a scoped expiring key (shown once), list, revoke.

### 5.11 Intel (SP7)

`IntelSnapshot` holds a CIDR prefix trie (IPv4, IPv6, IPv4-mapped), categories, and per-source metadata including license. Loading is wired into the runtime. Updates build a fresh snapshot, sanity-check counts and the invalid-line ratio (> 10% rejects), and swap atomically via `ArcSwap`; on failure the last good snapshot keeps serving and a Warn state is raised. The feed index must be signed (unsigned is a hard error); downloads are size-capped and verified before decompression; the last N snapshots are kept for rollback. Matches record both active and inactive lists, giving a shadow-mode signal for feeds not yet enabled.

## 6. Sub-projects

Order: **SP1 → SP2 → SP3 → (SP4 ∥ SP7) → SP5 → SP6.** The SP6 shell, routing and design tokens may start against SP2's generated types with mocked fixtures.

### SP1 — correctness, proxy hardening, honest serve-path eval

Scope:
- Proxy hardening (§5.3 steps 1–8): C4, H2, H6, M9, L1, L3, L4, `trusted_proxies`; L2 as an async JSONL sink with rotation and a write-error counter.
- Judgment: the minimal `Contribution` / `FieldRef` described in §5.4 replaces the flat `matched` list as the chain's input (the flat list stays for the audit line until SP2).
- Chain: C1, M2, M3 via `inspect` / `observe` / `finalize`, decision-derived events (§5.4), ban policy with TTLs, sharded `ChainStore` and `BanStore`, time passed in (H3).
- Scoring: H4 (the AI detector emits `None` for no signal; conflict scoped per field; damping cannot drop a verdict below the band the strongest Dangerous contribution reaches alone). M1 (corroboration capped at +15, deduplicated per field and construct).
- H5: `canonical_path`, read by honeypot and intent. The path graph keeps reading the raw path, because dot segments are the traversal evidence it looks for.
- M6: `deny_unknown_fields`, error on a missing explicit `--config`, `Config::validate()` with the cross-field rules, `venusflytrap config validate`. (The full descriptor table is SP2.)
- L6: README and `docs/BENCHMARK.md` headline real-corpus numbers; `bench` writes under `target/` unless `--out` is given.
- Eval: `venusflytrap eval --corpus <dir> --mode library|serve --sources distinct|pooled:<N>` reads raw `.white`/`.black` files in Rust, parses them into `http` parts and calls `Pipeline::decide`; it keeps the raw `Cookie` header and runs stateful. The Python parser stays for the libinjection baseline only, with the input-fairness gap stated.

Acceptance:
- Chrome, Firefox and Safari default header sets give Allow, `event_for == Benign` and no ban in stateful mode.
- For every Allow in the corpus, `event_for == Benign`.
- `eval --mode serve --sources distinct`: sources banned by a request whose library verdict is Allow = 0 (the C1 class). Benign sources banned because of a false-positive block are reported, not targeted.
- `--sources pooled:100` reports request-level FP, benign-source ban rate and collateral FP (benign requests blocked only by a ban); collateral FP ≤ request-level FP.
- `docs/BENCHMARK.md` and the Claude Doc publish library and serve numbers side by side, with no target asserted for the serve FP figure.
- Each C1, C4, H4, H5, M1 repro is a regression test with its expected verdict (e.g. `1 union select` + `Accept-Language` stays Block; `/%2egit/config`, `//.git/config`, `/.%65nv` hit honeypot or intent; 25 × `red;blue` stays below `block_at`).
- End to end: `Cookie` with `union select` plus `; z=\xff` → 403, and the upstream stub receives nothing.
- H2 (defaults: 1 MiB body, 10 s header read, 30 s upstream response; tests use shortened configured timeouts over real sockets): an oversized body → 413 with zero upstream connections; a slowloris connection is closed once the header-read timeout passes; a hung upstream → 504 once the response timeout passes.
- H3: 8-thread `Pipeline::decide` throughput ≥ 0.75× stateless `inspect` throughput.
- A TCP replay of 1,000 corpus samples through a live `serve` matches in-process `Pipeline::decide` verdicts 1:1.
- Mutation-robustness eval re-run; any change is reported.
- `cargo test --workspace` and `clippy --all-targets -D warnings` green; proptest suite unchanged and green.

### SP2 — explainable judgments and option registry

`Cause` / `decided_by`, `Contribution` with real points, `options::REGISTRY`, `Config.version`, base + override layering, consumption of the construct registry, the `ts` feature. Acceptance: every corpus `decided_by.option_key` exists in the registry; every non-Allow has a construct or a non-Detection cause; Σ points reproduces the score within ±1 before banding; registry coverage and default-validation tests pass; each M6 bad input yields a per-key issue; corpus verdicts identical to SP1.

### SP3 — service runtime

`vft-server` skeleton: `ConfigHandle` with SIGHUP and internal reload, `BusEvent` broadcast with per-consumer drop counters, `supervise`, `StatusBoard` with worst-state rollup, `tracing`, `/metrics`, graceful shutdown (drain ≤ 10 s); `serve` runs on `Runtime`. Acceptance: reload during a 2,000 rps replay → 0 failed requests and no request mixes config revisions; a stalled consumer raises drop counters while proxy p99 moves < 5%; bus + chain ≤ 20 µs p99 over inspect; SIGTERM drains and exits 0.

### SP4 — history store

Schema and migrations, writer thread, sampling and rollups, retention, ban persistence and restore, config revisions, the `q` parser and DSL. Acceptance: ≥ 5,000 events/s sustained with no drops on the development laptop; indexed 24 h queries p95 < 100 ms over 1M rows; bans survive restart and the listener opens only after restore; a fuzzed `q` parser yields a typed AST or an error, never SQL text from input; unknown columns/operators → 400.

### SP5 — admin API, auth, live channel

Admin listener (TCP, optional Unix socket, TLS required off-loopback), `ENDPOINTS`, permissions, keys and sessions, Origin/CSRF rules, CSP, every endpoint in §5.8, the SSE hub. Acceptance: route set equals `ENDPOINTS` and undeclared perm is Admin; every non-Public route → 401 without credentials and 403 with too low a perm; expired/revoked keys rejected; non-loopback bind without TLS fails at startup; cross-origin `PATCH` with a valid cookie → 403; with 16 SSE clients and one stalled, the stalled one gets `Resync` + `Snapshot` and the others' delta latency and proxy p99 move < 5%; the board reconciles to `ChainStore` within 30 s after injected drops.

### SP6 — console

The Svelte SPA and the screens in §5.10, generated types, embedding, Playwright end-to-end tests against a real server replaying the corpus. Acceptance: initial JS ≤ 150 KB gzipped; axe-core zero serious/critical violations on every screen in light and dark; a keyboard-only path completes (find a blocked request → open "why" → jump to the setting → change it → see "saved" or the inline 422 → confirm the new `config_rev` on the next judgment); no CSP violations; the live board updates within 1 s of a replayed honeypot hit.

### SP7 — intel snapshots

§5.11. Acceptance: a bad feed (> 10% invalid lines or a bad signature) leaves the old snapshot serving and raises a Warn state; CIDR deny works for IPv4, IPv6 and IPv4-mapped addresses; rollback restores the previous snapshot in < 1 s.

## 7. Interfaces with the recall-lift design

Owned by recall-lift and consumed here:

1. **Construct registry**: `graph::sinks::constructs() -> &'static [ConstructInfo { id, family, summary }]` with stable dotted ids (`sqli.union-select`, `xss.event-handler`, `cmd.chained-command`, `path.directory-traversal`); `Pattern.name == id`; renames add an alias, ids are never reused. These ids are the `decided_by.construct` keys, the `shield.disabled` vocabulary and the `construct:` query field.
2. **Fail-closed limit evidence** with fixed constructs `limit.payload-truncated`, `limit.graph-truncated`, `limit.body-unparsed`, each naming its option key.
3. **Body field names** from `body.rs`: `form:<name>`, `json:<JSON-Pointer>`, `multipart:<part>`, `xml:<path>`.
4. **Lossy percent decoder** `normalize::percent_decode_lossy`, reused by `canonical_path`. Until it lands, SP1 uses a private minimal decoder in `request.rs`, marked for deletion.
5. **`shield.disabled: Vec<String>`**: whichever side lands second adds its descriptor; the coverage test enforces it.

Shared files: `shield.rs`, `judgment.rs`, `config.rs`. SP1's detection-neutral split (API split, `FieldRef`) lands first with byte-identical corpus verdicts; the H4/M1 scoring fixes land as a separate, measured change; recall-lift rebases onto both. SP1's re-measured library numbers become recall-lift's M0 baseline.

## 8. Risks

1. **The serve-path FP rate will likely be worse than 0.81%**, because the serve path inspects raw headers and cookies the library eval skipped. SP1 publishes it; SP1 does not tune toward it.
2. **Bans amplify denial of service**: spoofed `X-Forwarded-For`, shared NAT and honeypot bait links can ban innocent users. Mitigations: `trusted_proxies`, TTL bans, allow-list exemption, the collateral-FP metric.
3. **The admin API adds attack surface.** Mitigations: separate loopback listener, default-Admin permissions, no debug endpoints, TLS required off-host.
4. **Merge conflicts with recall-lift** in the shared files. Mitigation: land-first split (§7).
5. **History write load under attack floods.** Mitigations: sampling, batching, drop-and-count with drops shown in the UI.
6. **H4/M1 scoring fixes change library numbers.** They are measured and reported as their own change, never folded silently into a refactor.

## 9. Decisions adopted (from the architecture review's recommendations)

1. Bans only on a honeypot hit, an exfiltration block, or 3 exploitation blocks within 10 min; TTL 1 h, doubling on re-offence up to 24 h; permanent bans only by hand.
2. Persist bans, not chain windows.
3. Payload snippets in history off by default (opt-in 128 characters, never credential headers).
4. Sample 1% of Allows; per-minute rollups count 100%.
5. Frontend: Svelte 5 + Vite + Bits UI.
6. Built UI assets are not committed; embedded if present, stub otherwise.
7. Admin default `127.0.0.1:8899` over TCP; optional Unix socket on Linux; TLS required off-host.
8. API config edits go to `state/overrides.yaml`; the operator's YAML is never rewritten.
9. SSE, not WebSocket, for the live channel.
10. Challenge stays a 403 with a distinct body and cause until a real challenge is requested.
11. `Upgrade`/WebSocket passthrough refused with 501 in v1.
12. `rusqlite` (bundled C) accepted: `forbid(unsafe_code)` binds our crates; `cargo deny` advisory and license checks added to CI.
13. SP1's detection-neutral split lands before recall-lift's changes to the shared files.
14. TLS termination stays a non-goal for the data plane.

## 10. Process gates (every sub-project)

- `cargo test --workspace` and `cargo clippy --all-targets -- -D warnings` green; `#![forbid(unsafe_code)]` in every crate.
- The real-corpus eval re-run after each change; the Claude Doc's results tables updated with measured numbers; regressions reported plainly.
- The synthetic corpus result is never quoted as a result.
- No commit or push without the owner's approval.
