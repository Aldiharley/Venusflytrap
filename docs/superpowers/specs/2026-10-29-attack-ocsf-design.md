# A — ATT&CK tags, measured confidence, event and group IDs, native OCSF (design)

*Sub-project A of three (A → C → B) taken from ranks 1–2 of
`reports/Endpoint EDR lessons for Venusflytrap.md` (git-ignored). Approved by the
owner on 2026-10-29.*

## 1. Goal

Make every decision legible to a SIEM and to ATT&CK-based reporting, without
changing a single detection:

- each judgment carries MITRE ATT&CK tactic and technique tags,
- a 1–100 **confidence**, kept apart from the score: measured precision on dev,
- a stable **event ID** per request and a **group ID** per attack episode,
- the proxy can write native **OCSF 1.9.0** records next to the JSONL audit,
- the console shows all of it, in its existing style.

## 2. Non-goals

- No detection change. The score, verdict and every eval number stay identical.
  The dev A/B must show ΔTP = ΔFP = 0 and no changed verdict.
- No syslog or CEF framing, no streaming, no history store or admin API (that is B),
  no exceptions (that is C).
- No outside product names in code, UI or docs beyond the plain names of public
  standards (MITRE ATT&CK, OCSF).

## 3. Components

### 3.1 ATT&CK tags (vft-core)

- `ConstructInfo` gains `attack: &'static [Technique]`, where
  `Technique { tactic: &'static str, tactic_id: &'static str, id: &'static str, name: &'static str }`.
- Mapping (static, reviewed in code):

  | Constructs | Tactic | Technique |
  |---|---|---|
  | SQL, XSS, command and path sinks and their signatures, `api.type-violation` | Initial Access (TA0001) | T1190 Exploit Public-Facing Application |
  | command sinks, also | Execution (TA0002) | T1059 Command and Scripting Interpreter |
  | path sinks and `sig.etc-passwd`, also | Discovery (TA0007) | T1083 File and Directory Discovery |
  | `recon.sensitive-path-probe`, `intel.scanner-ua` | Reconnaissance (TA0043) | T1595.002 Vulnerability Scanning |
  | `honeypot.decoy-hit` | Reconnaissance (TA0043) | T1595.003 Wordlist Scanning |
  | latents | the same tags as their family's sinks | |
  | limits, decoders, gates, `ai.anomaly-score`, `api.oversized-header`, `intel.deny-listed` | none (`&[]`) | |

- `Judgment` gains `attack: Vec<Technique>` (serialized): the tags of the construct
  in `decided_by`, or empty when nothing decided by a construct.
- A registry test asserts every non-decoder, non-gate construct appears in an
  explicit mapping match (an empty list is an explicit answer), so a new construct
  cannot ship untagged by accident.

### 3.2 Measured confidence (vft-core + eval)

- `eval/confidence.py <dev library CSV>` counts, per deciding construct (the CSV
  `top` column on Challenge/Block rows), TP and FP on dev. It writes
  `crates/vft-core/src/confidence.rs`: a sorted static table
  `(construct id, confidence)` with a header naming the source run, split manifest
  hash and date. Confidence = ⌊100 × Wilson 95 % lower bound of TP / (TP + FP)⌋.
  Constructs that decide fewer than 5 dev rows get no entry.
- `Judgment` gains `confidence: Option<u8>`: the table value for the deciding
  construct, `None` otherwise. It never affects score or verdict.
- Tests: the script on a committed small CSV fixture produces a known table
  (Python unit test); a Rust test checks the table is sorted, unique, in 1–100 and
  names registered constructs only.

### 3.3 Group ID (vft-core chain)

- Per source the chain tracker records `episode_start_ms`: the time of the first
  event after the source has been idle for a full chain window (3,600 s) or was
  never seen.
- `ChainOutcome` gains `episode_start_ms: u64`. The group ID is
  `"{src_ip}@{episode_start_ms}"`; requests with no source IP have none.
- Tests: two events within the window share an episode; an event after a gap of
  one full window starts a new one; the existing chain and ban tests stay green.

### 3.4 Event ID (vft-proxy)

- A UUIDv7-format string built from `ts_ms`, a per-process random value drawn at
  start, and a monotonic counter. `request_id` is kept as it is.

### 3.5 JSONL audit additions (vft-proxy)

- Each line gains `event_id`, `group_id`, `confidence` and `attack`
  (`[{tactic_id, id}]`). Existing fields are unchanged.

### 3.6 OCSF encoder (vft-proxy)

- New module `ocsf.rs`; enabled by `audit.ocsf_path` (absent = off). A second
  instance of the existing sink type writes OCSF JSONL there, with the same
  non-blocking send, rotation and drop and error counters.
- Per request, one **HTTP Activity** record: `class_uid 4002`, `category_uid 4`,
  `activity_id` from the method (Get 3, Post 6, …, other 99),
  `type_uid = 400200 + activity_id`, `time`, `severity_id` (Allow 1, Monitor 2,
  Challenge 3, Block 4), `metadata {version "1.9.0", product {name "Venusflytrap",
  vendor_name "Venusflytrap", version}, uid = event_id, profiles
  ["security_control"]}`, `http_request {http_method, url {path}}`,
  `src_endpoint {ip}`, and the Security Control fields `action_id`
  (Allowed for Allow and Monitor, Denied for Challenge and Block) and
  `disposition_id` (Allowed, Logged for Monitor, Blocked for Challenge and Block;
  numeric values from the fixture), `firewall_rule {uid = construct, name = summary}` when a
  construct decided.
- Per Challenge or Block, one **Detection Finding** record: `class_uid 2004`,
  `category_uid 2`, `activity_id 1` (Create), `type_uid 200401`, `time`,
  `severity_id`, `confidence_score` and `confidence_id` (1–39 Low 1, 40–69
  Medium 2, 70–100 High 3), `finding_info {uid = event_id, title = decided_by
  msg, attacks [{tactic {uid, name}, technique {uid, name}}]}`, the same
  `attacks` at top level (the Security Control profile), `metadata` as above with
  `correlation_uid = group_id`, `is_alert true`.
- Exact enum values are taken from the 1.9.0 schema JSON fetched at
  implementation time and committed as a test fixture
  (`crates/vft-proxy/tests/fixtures/ocsf-1.9.0-*.json`). Tests check every
  required attribute is present and every enum value is allowed by the fixture.

### 3.7 Console (ui/)

- `ui/src/gen` types regenerated through ts-rs (new `Technique`, judgment
  fields); fixtures follow the engine's rules (tags from the deciding construct,
  confidence from a fixture copy of the table, IDs well formed).
- **Monitor:** a technique column (a chip with the technique ID, the name in the
  tooltip) and a confidence column.
- **Request details:** ATT&CK tactic and technique chips; confidence shown as
  "precision on dev: NN" with a short explanation; event and group IDs with copy
  buttons; a "View as OCSF" tab rendering the records the proxy would write,
  built by a TypeScript encoder that a shared JSON fixture keeps identical to
  the Rust one.
- Existing tokens, fonts and components only; both themes; axe clean; the initial
  JS budget (150 KB gz) holds; Playwright and Vitest suites extended.

## 4. Data flow

`Shield::inspect` → `Judgment {…, attack, confidence}` → chain update adds
`episode_start_ms` → proxy assigns `event_id`, derives `group_id` → JSONL line and,
when configured, OCSF 4002 (+ 2004) lines → console reads the same shapes from
fixtures today and from the B API later.

## 5. Error handling

- A construct with no table entry yields `confidence: None`; the OCSF finding
  then omits `confidence_score` and `confidence_id`.
- OCSF encoding failure counts as a write error on the OCSF sink and never
  affects the response or the JSONL sink.
- Unknown methods map to activity 99 (Other).

## 6. Testing and acceptance

- `cargo test --workspace` and `clippy -D warnings` green; `#![forbid(unsafe_code)]` kept.
- Dev A/B against main: ΔTP = ΔFP = 0, zero changed verdicts (the new fields only).
- Serve check: the full-corpus serve run's decisions are identical to main's.
- OCSF records validated against the committed 1.9.0 fixtures.
- Console: `npm run check` 0 errors, Vitest and Playwright (with axe, both themes)
  green, budget held, screenshots of Monitor and Request details in both themes.
- A results note `eval/RESULTS-A-attack-ocsf.md` with the confidence table and its
  source run.
