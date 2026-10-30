# C — Scoped exceptions: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operators can silence a known false positive narrowly, on the record and for a limited time, through an exceptions file with three tiers (ignore, log-only, skip-inspection); every touched request says so; the effect of one Referer exception is measured on dev and held-out.

**Architecture:** A new `vft-core::exceptions` module parses, validates and compiles a separate YAML file. The shield selects the live exceptions for a request once, gives each field its own `Disabled` off-set (global set plus matching exceptions' constructs), drops skip-inspection fields before normalization, and reuses the existing shadow second pass to record what each exception removed. The proxy and CLI pass the file through and write the new judgment fields to JSONL and OCSF; the console gets an Exceptions screen, a create-from-request form and touched-request markers.

**Tech Stack:** Rust (vft-core, vft-proxy, vft-cli, serde, serde_yaml, ts-rs behind the `ts` feature, proptest), Svelte 5 + Vite + Vitest + Playwright (ui/), Python 3 eval scripts.

**Spec:** `docs/superpowers/specs/2026-10-30-scoped-exceptions-design.md`.

## Global Constraints

- With no `--exceptions` flag every judgment, eval number and serve decision is identical to main (`db7177b`): the dev A/B shows zero changed cells and the full-corpus serve diff shows zero changed decisions.
- An exception never raises a request's score or verdict.
- `chain.*`, every `limit.*` construct and `intel.deny-listed` can never be excepted; decoders and gates are not detections and can never be excepted.
- `skip-inspection` needs a `field` with no `*` or `?` in its name, and serve prints one warning line per such entry at startup.
- `expires` is required, after `modified`, and at most 365 days after `modified`; `modified` is not before `created`; an entry with `expires <= as_of` is an error at load. Dates are `YYYY-MM-DD`, read as 00:00 UTC; `as_of == expires` is expired.
- `path_prefix` matches on segment boundaries against `Request::canonical_path()`: `/api` matches `/api` and `/api/x`, not `/apix`; `/` matches every path.
- `field.name` is an ASCII case-insensitive glob with `*` and `?` over the engine's field name.
- An invalid exceptions file stops `serve` from starting and makes `eval` exit non-zero.
- `#![forbid(unsafe_code)]` stays in every crate; `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` stay green.
- No new Rust crate dependencies; dates are computed with std only.
- No outside product names in code, UI or docs.
- Console: existing tokens, fonts and components only; both themes; axe clean at all impacts; initial JS ≤ 150 KB gz.
- Tune on dev only; held-out is scored once, in Task 5, with and without the Referer file.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Resolutions of spec ambiguities (binding)

- **Family wildcards** are `<name>.*` with `<name>` from this table, and expand to every eligible registered construct whose `family` is the mapped `Family` (so `sqli.*` includes `sig.classic-or` and `api.type-violation`, whose family is Sqli): `sqli`→Sqli, `xss`→Xss, `cmd`→CommandInjection, `path`→PathTraversal, `recon`→Recon, `honeypot`→Honeypot, `intel`→Intel, `anomaly`→Anomaly. Eligible = kind Sink, Latent or Signature, and not forbidden. Any other `<name>.*` is an `unknown-construct` error; a wildcard that expands to nothing is `empty-wildcard`.
- **`bench`** (the synthetic smoke benchmark) does not take `--exceptions`; it is not a result. `eval` and `serve` do. (Spec §5 amended in Task 5.)
- **Request-level constructs** are exactly `recon.sensitive-path-probe`, `honeypot.decoy-hit` and `intel.scanner-ua`. They are judged and attributed against exceptions with no `field` only.
- **Clock:** `Shield::with_exceptions(ex, ExceptionClock)`. `ExceptionClock::Fixed` (eval) uses the `as_of` the file was validated at for every request; `ExceptionClock::PerRequest` (serve) uses the `now_ms` passed to `Shield::inspect_at`. `Shield::inspect(req)` is `inspect_at(req, ex.as_of_ms())`.

## Environment (all tasks)

- Checkout: `M:\Projects\venusflytrap`, branch `c-exceptions` (no worktree; `ui/node_modules` is installed). Run every command from there.
- Corpus: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\ext\blazehttp\testcases`
- Split manifest: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\split\manifest.tsv`
- Main baseline binary (built from `db7177b`): `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\c\bin\main-db7177b.exe`
- Runs directory: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\c\runs`
- Python: `py -I -X utf8`.

## File map

| File | Responsibility |
|---|---|
| `crates/vft-core/src/exceptions.rs` (new) | File model, dates, globs, validation, compile, per-request selection and attribution |
| `crates/vft-core/tests/fixtures/exception-cases.json` (new) | Shared validation cases (Rust and TypeScript) |
| `crates/vft-core/tests/fixtures/construct-registry.json` (new, blessed) | Construct id, family and kind, for the TypeScript validator |
| `crates/vft-core/tests/exceptions_shared.rs` (new) | Runs the shared cases; checks/blesses the registry JSON |
| `crates/vft-core/src/graph/sinks/mod.rs` | `Disabled::with_ids` |
| `crates/vft-core/src/judgment.rs` | `Judgment.exceptions`, `Judgment.skipped`, `Contribution.exception` |
| `crates/vft-core/src/shield.rs` | `with_exceptions`, `inspect_at`, per-field off-sets, skip, observe-pass attribution |
| `crates/vft-proxy/src/{pipeline,audit,ocsf}.rs` | `inspect_at`, JSONL and OCSF fields |
| `crates/vft-cli/src/main.rs`, `crates/vft-cli/src/eval.rs` | `--exceptions`, `--as-of`, `exceptions check`, startup warnings |
| `eval/exceptions/referer-sql.yaml` (new), `eval/RESULTS-C-exceptions.md` (new) | Measured example and its results |
| `ui/src/lib/exceptions.ts` (new) | TypeScript validator, scope label, YAML emitter |
| `ui/src/screens/Exceptions.svelte` (new) | Active/Expired screen |
| `ui/src/screens/request/CreateException.svelte` (new) | Create-from-request form |

---

### Task 1: Exceptions file model, validation and compile

**Files:**
- Create: `crates/vft-core/src/exceptions.rs`
- Create: `crates/vft-core/tests/fixtures/exception-cases.json`
- Create: `crates/vft-core/tests/exceptions_shared.rs`
- Create (blessed by the test): `crates/vft-core/tests/fixtures/construct-registry.json`
- Modify: `crates/vft-core/src/lib.rs` (add `pub mod exceptions;` and `pub use exceptions::{ExceptionClock, Exceptions};`)
- Modify: `crates/vft-core/src/graph/sinks/mod.rs` (add `Disabled::with_ids`)

**Interfaces:**
- Produces (public): `ExceptionAction { Ignore, LogOnly, SkipInspection }` (serde kebab-case), `FieldLoc { Path, Query, Header, Cookie, Body }` (serde lowercase) with `fn location(self) -> Location`, `FieldMatch { loc, name }`, `ExceptionScope { methods: Vec<String>, path_prefix: String, field: Option<FieldMatch> }`, `ExceptionEntry { id, action, constructs: Vec<String>, scope, owner, reason, created, modified, expires }` (all `String` dates), `ExceptionsFile { version: u32, exceptions: Vec<ExceptionEntry> }`; all derive `Debug, Clone, PartialEq, Serialize, Deserialize`, `#[serde(deny_unknown_fields)]` on the structs, `#[cfg_attr(feature = "ts", derive(ts_rs::TS))]` on all five.
- `Issue { id: Option<String>, code: &'static str, msg: String }` with `Display` (`"{id}: {msg}"` or `msg`).
- `parse_date(&str) -> Option<u64>`, `format_date(u64) -> String`, `DAY_MS: u64 = 86_400_000`, `MAX_LIFETIME_DAYS: u64 = 365`.
- `expand_constructs(names: &[String]) -> Result<Vec<&'static str>, Vec<Issue>>` (sorted, unique).
- `validate_entry(e: &ExceptionEntry, as_of_ms: u64) -> Vec<Issue>`; `validate_file(f: &ExceptionsFile, as_of_ms: u64) -> Vec<Issue>`.
- `ExceptionClock { Fixed, PerRequest }` (`Debug, Clone, Copy, PartialEq, Eq`).
- `Exceptions` (`Debug, Clone, Default`): `from_yaml_str(s, as_of_ms) -> Result<Exceptions, Vec<Issue>>`, `load(path: &Path, as_of_ms) -> Result<Exceptions, Vec<Issue>>`, `compile(file: ExceptionsFile, as_of_ms) -> Result<Exceptions, Vec<Issue>>`, `is_empty()`, `as_of_ms()`, `entries() -> &[ExceptionEntry]`, `warnings() -> Vec<String>`.
- Crate-internal, used by Task 3: `Exceptions::select(&self, method: &str, canonical_path: &str, now_ms: u64) -> Selection<'_>`; `Selection::{is_empty, skip_for(&FieldRef) -> Option<&str>, removers_for(Option<&FieldRef>) -> Vec<usize>, removed_ids(&[usize]) -> impl Iterator<Item = &'static str>, has_removers, attribute(&Contribution) -> Option<(&str, ExceptionAction)>}`; `REQUEST_LEVEL: [&str; 3]`.
- `Disabled::with_ids(&self, ids: impl IntoIterator<Item = &'static str>) -> Disabled` (union, in `graph/sinks/mod.rs`).

Issue codes (exact strings): `parse`, `io`, `version`, `duplicate-id`, `id-format`, `required`, `date`, `modified-order`, `expires-order`, `expires-too-far`, `expired`, `method`, `path-prefix`, `field-name`, `unknown-construct`, `empty-wildcard`, `forbidden-target`, `not-a-detection`, `constructs-on-skip`, `constructs-missing`, `skip-needs-field`, `skip-wildcard`.

- [ ] **Step 1: Write the shared validation cases**

`crates/vft-core/tests/fixtures/exception-cases.json`. `base` is a valid entry; each case is `base` with `patch` applied as a shallow merge at the top level and then into `scope` (a `scope` key in `patch` merges into `base.scope`; `"field": null` clears it). `codes` is the sorted list of issue codes `validate_entry` must return.

```json
{
  "_comment": "Shared by crates/vft-core/tests/exceptions_shared.rs and ui/src/lib/exceptions.test.ts. Each case = base + patch (top-level merge; scope merges into base.scope). codes = sorted issue codes of validate_entry at as_of.",
  "as_of": "2026-10-30",
  "base": {
    "id": "referer-sql", "action": "ignore", "constructs": ["sqli.*"],
    "scope": { "methods": ["GET"], "path_prefix": "/", "field": { "loc": "header", "name": "referer" } },
    "owner": "dennis", "reason": "Search referers carry SQL-looking text",
    "created": "2026-10-30", "modified": "2026-10-30", "expires": "2026-11-30"
  },
  "cases": [
    { "name": "base is valid", "patch": {}, "codes": [] },
    { "name": "log-only is valid", "patch": { "action": "log-only" }, "codes": [] },
    { "name": "skip with exact field is valid", "patch": { "action": "skip-inspection", "constructs": [] }, "codes": [] },
    { "name": "explicit construct", "patch": { "constructs": ["sqli.union-select", "sig.classic-or"] }, "codes": [] },
    { "name": "no field, no methods", "patch": { "scope": { "methods": [], "field": null } }, "codes": [] },
    { "name": "glob field name", "patch": { "scope": { "field": { "loc": "query", "name": "utm_*" } } }, "codes": [] },
    { "name": "bad id", "patch": { "id": "Referer SQL" }, "codes": ["id-format"] },
    { "name": "empty owner", "patch": { "owner": "  " }, "codes": ["required"] },
    { "name": "empty reason", "patch": { "reason": "" }, "codes": ["required"] },
    { "name": "bad date", "patch": { "expires": "2026-02-30" }, "codes": ["date"] },
    { "name": "bad date format", "patch": { "created": "30/10/2026" }, "codes": ["date"] },
    { "name": "modified before created", "patch": { "created": "2026-10-31", "modified": "2026-10-30" }, "codes": ["modified-order"] },
    { "name": "expires not after modified", "patch": { "expires": "2026-10-30" }, "codes": ["expired", "expires-order"] },
    { "name": "expires too far", "patch": { "expires": "2027-10-31" }, "codes": ["expires-too-far"] },
    { "name": "expires exactly 365 days", "patch": { "expires": "2027-10-30" }, "codes": [] },
    { "name": "already expired", "patch": { "created": "2026-09-01", "modified": "2026-09-01", "expires": "2026-10-30" }, "codes": ["expired"] },
    { "name": "bad method", "patch": { "scope": { "methods": ["GE T"] } }, "codes": ["method"] },
    { "name": "path prefix without slash", "patch": { "scope": { "path_prefix": "api" } }, "codes": ["path-prefix"] },
    { "name": "empty field name", "patch": { "scope": { "field": { "loc": "header", "name": "" } } }, "codes": ["field-name"] },
    { "name": "unknown construct", "patch": { "constructs": ["sqli.nope"] }, "codes": ["unknown-construct"] },
    { "name": "unknown wildcard", "patch": { "constructs": ["ssrf.*"] }, "codes": ["unknown-construct"] },
    { "name": "limit is forbidden", "patch": { "constructs": ["limit.payload-truncated"] }, "codes": ["forbidden-target"] },
    { "name": "deny list is forbidden", "patch": { "constructs": ["intel.deny-listed"] }, "codes": ["forbidden-target"] },
    { "name": "ban is forbidden", "patch": { "constructs": ["chain.ban"] }, "codes": ["forbidden-target"] },
    { "name": "decoder is not a detection", "patch": { "constructs": ["decode.entity"] }, "codes": ["not-a-detection"] },
    { "name": "gate is not a detection", "patch": { "constructs": ["gate.cmd-position"] }, "codes": ["not-a-detection"] },
    { "name": "intel wildcard drops the deny list", "patch": { "constructs": ["intel.*"] }, "codes": [] },
    { "name": "constructs missing", "patch": { "constructs": [] }, "codes": ["constructs-missing"] },
    { "name": "constructs on skip", "patch": { "action": "skip-inspection" }, "codes": ["constructs-on-skip"] },
    { "name": "skip needs a field", "patch": { "action": "skip-inspection", "constructs": [], "scope": { "field": null } }, "codes": ["skip-needs-field"] },
    { "name": "skip with a glob", "patch": { "action": "skip-inspection", "constructs": [], "scope": { "field": { "loc": "header", "name": "x-*" } } }, "codes": ["skip-wildcard"] }
  ]
}
```

- [ ] **Step 2: Write the failing shared test**

`crates/vft-core/tests/exceptions_shared.rs`:

```rust
//! Shared exception-validation cases (also run by ui/src/lib/exceptions.test.ts),
//! and the construct registry JSON the console's validator reads.
//! Bless the registry: VFT_BLESS_TS=1 cargo test -p vft-core --test exceptions_shared

use serde_json::{json, Value};
use vft_core::exceptions::{parse_date, validate_entry, ExceptionEntry};

fn cases() -> Value {
    serde_json::from_str(include_str!("fixtures/exception-cases.json")).expect("cases parse")
}

fn apply(base: &Value, patch: &Value) -> Value {
    let mut out = base.clone();
    for (k, v) in patch.as_object().expect("patch is an object") {
        if k == "scope" {
            for (sk, sv) in v.as_object().expect("scope patch is an object") {
                out["scope"][sk] = sv.clone();
            }
        } else {
            out[k] = v.clone();
        }
    }
    out
}

#[test]
fn shared_cases_give_their_codes() {
    let c = cases();
    let as_of = parse_date(c["as_of"].as_str().unwrap()).unwrap();
    for case in c["cases"].as_array().unwrap() {
        let v = apply(&c["base"], &case["patch"]);
        let e: ExceptionEntry = serde_json::from_value(v).unwrap_or_else(|err| panic!("{}: {err}", case["name"]));
        let mut got: Vec<&str> = validate_entry(&e, as_of).iter().map(|i| i.code).collect();
        got.sort_unstable();
        got.dedup();
        let want: Vec<&str> = case["codes"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(got, want, "case {}", case["name"]);
    }
}

#[test]
fn construct_registry_json_is_current() {
    let want: Vec<Value> = vft_core::graph::sinks::constructs()
        .iter()
        .map(|c| json!({ "id": c.id, "family": c.family.map(|f| format!("{f:?}")), "kind": format!("{:?}", c.kind) }))
        .collect();
    let want = serde_json::to_string_pretty(&want).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/construct-registry.json");
    if std::env::var_os("VFT_BLESS_TS").is_some() {
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
    assert_eq!(have, want, "stale construct-registry.json (re-run with VFT_BLESS_TS=1)");
}
```

- [ ] **Step 3: Run it to make sure it fails**

Run: `cargo test -p vft-core --test exceptions_shared`
Expected: FAIL to compile (`vft_core::exceptions` not found).

- [ ] **Step 4: Add `Disabled::with_ids`**

In `crates/vft-core/src/graph/sinks/mod.rs`, inside `impl Disabled`:

```rust
    /// This set plus `ids` (scoped exceptions add their constructs per field).
    pub fn with_ids(&self, ids: impl IntoIterator<Item = &'static str>) -> Disabled {
        let mut s = self.0.clone();
        s.extend(ids);
        Disabled(s)
    }
```

- [ ] **Step 5: Write `exceptions.rs`**

```rust
//! Scoped exceptions (sub-project C): a separate file of narrow, owned,
//! expiring exceptions, validated at load and compiled for the shield.
//! Three tiers: `ignore` (constructs do not score in the scope), `log-only`
//! (they do not score but stay visible as 0-point evidence) and
//! `skip-inspection` (matching fields are not inspected at all).

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::graph::sinks::{self, ConstructKind};
use crate::judgment::{Contribution, Family, FieldRef};
use crate::request::Location;

pub const DAY_MS: u64 = 86_400_000;
pub const MAX_LIFETIME_DAYS: u64 = 365;

/// Judged and attributed against exceptions with no `field` only.
pub const REQUEST_LEVEL: [&str; 3] = [
    sinks::RECON_SENSITIVE_PATH.id,
    sinks::HONEYPOT_DECOY_HIT.id,
    sinks::INTEL_SCANNER_UA.id,
];

const FAMILY_WILDCARDS: &[(&str, Family)] = &[
    ("sqli", Family::Sqli),
    ("xss", Family::Xss),
    ("cmd", Family::CommandInjection),
    ("path", Family::PathTraversal),
    ("recon", Family::Recon),
    ("honeypot", Family::Honeypot),
    ("intel", Family::Intel),
    ("anomaly", Family::Anomaly),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum ExceptionAction {
    Ignore,
    LogOnly,
    SkipInspection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum FieldLoc {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

impl FieldLoc {
    pub fn location(self) -> Location {
        match self {
            FieldLoc::Path => Location::Path,
            FieldLoc::Query => Location::Query,
            FieldLoc::Header => Location::Header,
            FieldLoc::Cookie => Location::Cookie,
            FieldLoc::Body => Location::Body,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct FieldMatch {
    pub loc: FieldLoc,
    /// ASCII case-insensitive glob (`*`, `?`) over the engine's field name.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct ExceptionScope {
    /// Empty = any method.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Matched on segment boundaries against the canonical path.
    pub path_prefix: String,
    /// None = every field, plus the request-level constructs.
    #[serde(default)]
    pub field: Option<FieldMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct ExceptionEntry {
    pub id: String,
    pub action: ExceptionAction,
    /// Construct ids or family wildcards; empty for skip-inspection.
    #[serde(default)]
    pub constructs: Vec<String>,
    pub scope: ExceptionScope,
    pub owner: String,
    pub reason: String,
    pub created: String,
    pub modified: String,
    pub expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct ExceptionsFile {
    pub version: u32,
    #[serde(default)]
    pub exceptions: Vec<ExceptionEntry>,
}

/// One validation problem; `code` is a stable string shared with the console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub id: Option<String>,
    pub code: &'static str,
    pub msg: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.id {
            Some(id) => write!(f, "{id}: {}", self.msg),
            None => write!(f, "{}", self.msg),
        }
    }
}

fn issue(id: Option<&str>, code: &'static str, msg: impl Into<String>) -> Issue {
    Issue { id: id.map(str::to_string), code, msg: msg.into() }
}

// --- dates (std only; proleptic Gregorian, UTC) ---

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `YYYY-MM-DD` (1970..=9999) as ms at 00:00 UTC; None if malformed or not a real date.
pub fn parse_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let t = &s[r];
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok()).flatten()
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if y < 1970 || !(1..=12).contains(&m) || d == 0 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1];
    if d > dim {
        return None;
    }
    Some(days_from_civil(y as i64, m, d) as u64 * DAY_MS)
}

/// The UTC date of `ms` as `YYYY-MM-DD`.
pub fn format_date(ms: u64) -> String {
    let (y, m, d) = civil_from_days((ms / DAY_MS) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

// --- matching helpers ---

/// ASCII case-insensitive glob with `*` and `?`.
fn glob(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<u8>, Vec<u8>) = (pat.bytes().map(|b| b.to_ascii_lowercase()).collect(), s.bytes().map(|b| b.to_ascii_lowercase()).collect());
    let (mut pi, mut si, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Segment-boundary prefix match: `/api` matches `/api` and `/api/x`, not `/apix`.
fn prefix_matches(prefix: &str, path: &str) -> bool {
    let p = prefix.trim_end_matches('/');
    if p.is_empty() {
        return true;
    }
    path == p || (path.starts_with(p) && path[p.len()..].starts_with('/'))
}

fn eligible(c: &sinks::ConstructInfo) -> bool {
    matches!(c.kind, ConstructKind::Sink | ConstructKind::Latent | ConstructKind::Signature) && c.id != sinks::INTEL_DENY_LISTED.id
}

/// Expand ids and family wildcards to eligible registered constructs (sorted, unique).
pub fn expand_constructs(names: &[String]) -> Result<Vec<&'static str>, Vec<Issue>> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut issues = Vec::new();
    for n in names {
        if let Some(fam) = n.strip_suffix(".*") {
            match FAMILY_WILDCARDS.iter().find(|(w, _)| *w == fam) {
                None => issues.push(issue(None, "unknown-construct", format!("unknown family wildcard {n:?}"))),
                Some((_, f)) => {
                    let ids: Vec<&'static str> = sinks::constructs().iter().filter(|c| c.family == Some(*f) && eligible(c)).map(|c| c.id).collect();
                    if ids.is_empty() {
                        issues.push(issue(None, "empty-wildcard", format!("{n:?} names no exceptable construct")));
                    }
                    out.extend(ids);
                }
            }
            continue;
        }
        if n.starts_with("chain.") || n == sinks::INTEL_DENY_LISTED.id {
            issues.push(issue(None, "forbidden-target", format!("{n} can never be excepted")));
            continue;
        }
        match sinks::lookup(n) {
            None => issues.push(issue(None, "unknown-construct", format!("unknown construct id {n:?}"))),
            Some(c) if c.kind == ConstructKind::Limit => issues.push(issue(None, "forbidden-target", format!("{n} is a limit and can never be excepted"))),
            Some(c) if matches!(c.kind, ConstructKind::Decoder | ConstructKind::Gate) => {
                issues.push(issue(None, "not-a-detection", format!("{n} is a {:?}, not a detection", c.kind)))
            }
            Some(c) => out.push(c.id),
        }
    }
    out.sort_unstable();
    out.dedup();
    if issues.is_empty() { Ok(out) } else { Err(issues) }
}

/// Every problem with one entry at `as_of_ms`.
pub fn validate_entry(e: &ExceptionEntry, as_of_ms: u64) -> Vec<Issue> {
    let id = Some(e.id.as_str());
    let mut v = Vec::new();
    if e.id.is_empty() || e.id.len() > 64 || !e.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        v.push(issue(id, "id-format", "id must be 1-64 chars of [a-z0-9-]"));
    }
    if e.owner.trim().is_empty() {
        v.push(issue(id, "required", "owner is required"));
    }
    if e.reason.trim().is_empty() {
        v.push(issue(id, "required", "reason is required"));
    }
    let date = |name: &str, s: &str, v: &mut Vec<Issue>| {
        let d = parse_date(s);
        if d.is_none() {
            v.push(issue(id, "date", format!("{name} {s:?} is not a YYYY-MM-DD date")));
        }
        d
    };
    let (c, m, x) = (date("created", &e.created, &mut v), date("modified", &e.modified, &mut v), date("expires", &e.expires, &mut v));
    if let (Some(c), Some(m)) = (c, m) {
        if m < c {
            v.push(issue(id, "modified-order", "modified is before created"));
        }
    }
    if let (Some(m), Some(x)) = (m, x) {
        if x <= m {
            v.push(issue(id, "expires-order", "expires must be after modified"));
        } else if x - m > MAX_LIFETIME_DAYS * DAY_MS {
            v.push(issue(id, "expires-too-far", format!("expires is more than {MAX_LIFETIME_DAYS} days after modified")));
        }
    }
    if let Some(x) = x {
        if x <= as_of_ms {
            v.push(issue(id, "expired", format!("expired on {} (as of {})", e.expires, format_date(as_of_ms))));
        }
    }
    for meth in &e.scope.methods {
        if meth.is_empty() || !meth.bytes().all(|b| b.is_ascii_alphabetic()) {
            v.push(issue(id, "method", format!("bad method {meth:?}")));
        }
    }
    if !e.scope.path_prefix.starts_with('/') {
        v.push(issue(id, "path-prefix", "path_prefix must start with /"));
    }
    if let Some(f) = &e.scope.field {
        if f.name.is_empty() {
            v.push(issue(id, "field-name", "field.name is empty"));
        }
    }
    match e.action {
        ExceptionAction::SkipInspection => {
            if !e.constructs.is_empty() {
                v.push(issue(id, "constructs-on-skip", "skip-inspection takes no constructs"));
            }
            match &e.scope.field {
                None => v.push(issue(id, "skip-needs-field", "skip-inspection needs scope.field")),
                Some(f) if f.name.contains(['*', '?']) => v.push(issue(id, "skip-wildcard", "skip-inspection needs an exact field name")),
                Some(_) => {}
            }
        }
        ExceptionAction::Ignore | ExceptionAction::LogOnly => {
            if e.constructs.is_empty() {
                v.push(issue(id, "constructs-missing", "constructs is required"));
            } else if let Err(is) = expand_constructs(&e.constructs) {
                v.extend(is.into_iter().map(|i| Issue { id: Some(e.id.clone()), ..i }));
            }
        }
    }
    v
}

/// Every problem with a whole file at `as_of_ms`.
pub fn validate_file(f: &ExceptionsFile, as_of_ms: u64) -> Vec<Issue> {
    let mut v = Vec::new();
    if f.version != 1 {
        v.push(issue(None, "version", format!("unsupported version {}", f.version)));
    }
    let mut seen = HashSet::new();
    for e in &f.exceptions {
        if !seen.insert(e.id.as_str()) {
            v.push(issue(Some(&e.id), "duplicate-id", "duplicate id"));
        }
        v.extend(validate_entry(e, as_of_ms));
    }
    v
}

/// When an exception's expiry is checked: against the `as_of` the file was
/// validated at (eval), or against each request's `now_ms` (serve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClock {
    Fixed,
    PerRequest,
}

#[derive(Debug, Clone)]
pub(crate) struct Compiled {
    pub(crate) id: String,
    pub(crate) action: ExceptionAction,
    constructs: HashSet<&'static str>,
    methods: Vec<String>,
    prefix: String,
    field: Option<(Location, String)>,
    expires_ms: u64,
}

impl Compiled {
    fn field_matches(&self, f: Option<&FieldRef>) -> bool {
        match (&self.field, f) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some((loc, pat)), Some(f)) => f.loc == *loc && glob(pat, &f.name),
        }
    }
}

/// A validated, compiled exceptions file.
#[derive(Debug, Clone, Default)]
pub struct Exceptions {
    compiled: Vec<Compiled>,
    entries: Vec<ExceptionEntry>,
    as_of_ms: u64,
}

impl Exceptions {
    pub fn from_yaml_str(s: &str, as_of_ms: u64) -> Result<Exceptions, Vec<Issue>> {
        let file: ExceptionsFile = serde_yaml::from_str(s).map_err(|e| vec![issue(None, "parse", e.to_string())])?;
        Self::compile(file, as_of_ms)
    }

    pub fn load(path: &Path, as_of_ms: u64) -> Result<Exceptions, Vec<Issue>> {
        let s = std::fs::read_to_string(path).map_err(|e| vec![issue(None, "io", format!("{}: {e}", path.display()))])?;
        Self::from_yaml_str(&s, as_of_ms)
    }

    pub fn compile(file: ExceptionsFile, as_of_ms: u64) -> Result<Exceptions, Vec<Issue>> {
        let issues = validate_file(&file, as_of_ms);
        if !issues.is_empty() {
            return Err(issues);
        }
        let compiled = file
            .exceptions
            .iter()
            .map(|e| Compiled {
                id: e.id.clone(),
                action: e.action,
                constructs: expand_constructs(&e.constructs).unwrap_or_default().into_iter().collect(),
                methods: e.scope.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                prefix: e.scope.path_prefix.clone(),
                field: e.scope.field.as_ref().map(|f| (f.loc.location(), f.name.clone())),
                expires_ms: parse_date(&e.expires).unwrap_or(0),
            })
            .collect();
        Ok(Exceptions { compiled, entries: file.exceptions, as_of_ms })
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }
    pub fn as_of_ms(&self) -> u64 {
        self.as_of_ms
    }
    pub fn entries(&self) -> &[ExceptionEntry] {
        &self.entries
    }

    /// One line per skip-inspection entry, for serve's startup log.
    pub fn warnings(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| e.action == ExceptionAction::SkipInspection)
            .map(|e| {
                let f = e.scope.field.as_ref().map(|f| format!("{:?}:{}", f.loc, f.name).to_ascii_lowercase()).unwrap_or_default();
                format!("warning: exception {} skips inspection of {f} under {} until {}", e.id, e.scope.path_prefix, e.expires)
            })
            .collect()
    }

    /// The live exceptions whose method and path match this request.
    pub(crate) fn select(&self, method: &str, canonical_path: &str, now_ms: u64) -> Selection<'_> {
        let entries = self
            .compiled
            .iter()
            .filter(|c| now_ms < c.expires_ms)
            .filter(|c| c.methods.is_empty() || c.methods.iter().any(|m| m.eq_ignore_ascii_case(method)))
            .filter(|c| prefix_matches(&c.prefix, canonical_path))
            .collect();
        Selection { entries }
    }
}

/// The exceptions that apply to one request, in file order.
pub(crate) struct Selection<'a> {
    entries: Vec<&'a Compiled>,
}

impl<'a> Selection<'a> {
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The first skip-inspection exception matching `f`.
    pub(crate) fn skip_for(&self, f: &FieldRef) -> Option<&'a str> {
        self.entries.iter().copied().find(|c| c.action == ExceptionAction::SkipInspection && c.field_matches(Some(f))).map(|c| c.id.as_str())
    }

    pub(crate) fn has_removers(&self) -> bool {
        self.entries.iter().any(|c| c.action != ExceptionAction::SkipInspection)
    }

    /// Indexes of the ignore/log-only exceptions that apply to `f` (None = the
    /// request-level constructs, which only field-less exceptions reach).
    pub(crate) fn removers_for(&self, f: Option<&FieldRef>) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|&i| self.entries[i].action != ExceptionAction::SkipInspection && self.entries[i].field_matches(f))
            .collect()
    }

    pub(crate) fn removed_ids<'s>(&'s self, idx: &'s [usize]) -> impl Iterator<Item = &'static str> + 's {
        idx.iter().flat_map(move |&i| self.entries[i].constructs.iter().copied())
    }

    /// The exception (id, action) that removed `c` in the first pass, if any.
    pub(crate) fn attribute(&self, c: &Contribution) -> Option<(&'a str, ExceptionAction)> {
        let id = c.construct.as_deref()?;
        let f = if REQUEST_LEVEL.contains(&id) { None } else { c.field.as_ref() };
        self.entries
            .iter()
            .copied()
            .find(|e| e.action != ExceptionAction::SkipInspection && e.field_matches(f) && e.constructs.contains(id))
            .map(|e| (e.id.as_str(), e.action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AS_OF: &str = "2026-10-30";

    fn yaml(body: &str) -> String {
        format!("version: 1\nexceptions:\n{body}")
    }

    const REFERER: &str = "  - id: referer-sql\n    action: ignore\n    constructs: [sqli.*]\n    scope:\n      path_prefix: /api\n      field: { loc: header, name: Refer* }\n    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n";

    fn ex(body: &str) -> Exceptions {
        Exceptions::from_yaml_str(&yaml(body), parse_date(AS_OF).unwrap()).unwrap()
    }

    #[test]
    fn dates_round_trip_and_reject_impossible_days() {
        for s in ["1970-01-01", "2000-02-29", "2026-10-30", "2027-12-31"] {
            assert_eq!(format_date(parse_date(s).unwrap()), s);
        }
        assert_eq!(parse_date("1970-01-02"), Some(DAY_MS));
        for s in ["2026-02-29", "2100-02-29", "2026-13-01", "2026-00-10", "1969-12-31", "2026-1-01", "2026-10-3x"] {
            assert_eq!(parse_date(s), None, "{s}");
        }
    }

    #[test]
    fn glob_and_prefix_rules() {
        assert!(glob("Refer*", "referer") && glob("x-?d", "X-ID") && glob("*", "") && !glob("a?", "a"));
        assert!(glob("json:/user/*", "json:/user/id") && !glob("utm_*", "xutm_a"));
        assert!(prefix_matches("/", "/anything") && prefix_matches("/api", "/api") && prefix_matches("/api/", "/api/x"));
        assert!(!prefix_matches("/api", "/apix"));
    }

    #[test]
    fn sqli_wildcard_expands_by_family() {
        let ids = expand_constructs(&["sqli.*".into()]).unwrap();
        assert!(ids.contains(&"sqli.union-select") && ids.contains(&"sig.classic-or") && ids.contains(&"api.type-violation"));
        assert!(!ids.iter().any(|i| i.starts_with("limit.") || i.starts_with("decode.")));
        assert_eq!(expand_constructs(&["intel.*".into()]).unwrap(), vec!["intel.scanner-ua"]);
    }

    #[test]
    fn file_level_errors() {
        let as_of = parse_date(AS_OF).unwrap();
        let dup = yaml(&format!("{REFERER}{REFERER}"));
        let codes = |s: &str| Exceptions::from_yaml_str(s, as_of).unwrap_err().into_iter().map(|i| i.code).collect::<Vec<_>>();
        assert_eq!(codes(&dup), vec!["duplicate-id"]);
        assert_eq!(codes(&yaml(REFERER).replace("version: 1", "version: 2")), vec!["version"]);
        assert_eq!(codes(&yaml(&REFERER.replace("owner: o", "owner: o\n    extra: 1"))), vec!["parse"]);
        assert_eq!(codes(&yaml(&REFERER.replace("    reason: r\n", ""))), vec!["parse"]);
    }

    #[test]
    fn selection_respects_expiry_method_and_prefix() {
        let e = ex(&REFERER.replace("    scope:\n", "    scope:\n      methods: [get]\n"));
        let live = parse_date("2026-11-29").unwrap();
        assert!(!e.select("GET", "/api/search", live).is_empty());
        assert!(e.select("POST", "/api/search", live).is_empty());
        assert!(e.select("GET", "/apix", live).is_empty());
        assert!(e.select("GET", "/api", parse_date("2026-11-30").unwrap()).is_empty(), "as_of == expires is expired");
    }

    #[test]
    fn removers_and_attribution_follow_the_field() {
        let e = ex(REFERER);
        let sel = e.select("GET", "/api/x", parse_date(AS_OF).unwrap());
        let referer = FieldRef::header("Referer");
        assert_eq!(sel.removers_for(Some(&referer)), vec![0]);
        assert!(sel.removers_for(Some(&FieldRef::header("user-agent"))).is_empty());
        assert!(sel.removers_for(None).is_empty(), "a field-scoped exception never reaches request-level constructs");
        let c = |id: &str, f: FieldRef| Contribution {
            engine: "graph-taint", field: Some(f), construct: Some(id.into()), family: None,
            value: crate::lattice::FourValued::Dangerous, weight: 1.0, points: 0.0, shadow: false, exception: None,
        };
        assert_eq!(sel.attribute(&c("sqli.union-select", referer.clone())), Some(("referer-sql", ExceptionAction::Ignore)));
        assert_eq!(sel.attribute(&c("xss.script-tag", referer)), None);
    }

    #[test]
    fn skip_and_warnings() {
        let body = "  - id: skip-token\n    action: skip-inspection\n    scope:\n      path_prefix: /hook\n      field: { loc: header, name: x-signature }\n    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n";
        let e = ex(body);
        let sel = e.select("POST", "/hook", parse_date(AS_OF).unwrap());
        assert_eq!(sel.skip_for(&FieldRef::header("X-Signature")), Some("skip-token"));
        assert!(!sel.has_removers());
        assert_eq!(e.warnings().len(), 1);
        assert!(e.warnings()[0].contains("skip-token") && e.warnings()[0].contains("2026-11-30"));
    }
}
```

Note: `Contribution.exception` is added in Task 2; until then, drop `exception: None` from the test literal in `removers_and_attribution_follow_the_field` and re-add it in Task 2.

- [ ] **Step 6: Run the tests**

Run: `VFT_BLESS_TS=1 cargo test -p vft-core --test exceptions_shared` (writes `construct-registry.json`), then `cargo test -p vft-core --test exceptions_shared` and `cargo test -p vft-core exceptions::`
Expected: PASS (31 shared cases; 7 unit tests).

- [ ] **Step 7: Clippy and commit**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
```bash
git add crates/vft-core/src/exceptions.rs crates/vft-core/src/lib.rs crates/vft-core/src/graph/sinks/mod.rs crates/vft-core/tests/exceptions_shared.rs crates/vft-core/tests/fixtures/exception-cases.json crates/vft-core/tests/fixtures/construct-registry.json
git commit -m "feat(core): exceptions file model, validation and compile"
```

---

### Task 2: Judgment and contribution fields

**Files:**
- Modify: `crates/vft-core/src/judgment.rs` (`Judgment.exceptions: Vec<String>`, `Judgment.skipped: Vec<FieldRef>`, `Contribution.exception: Option<String>`)
- Modify every struct literal of `Judgment` and `Contribution` in the workspace (`grep -rn "Judgment {\|Contribution {" crates --include=*.rs`): `crates/vft-core/src/{judgment,shield,chain}.rs`, `crates/vft-proxy/src/ocsf.rs`, `crates/vft-cli/src/eval.rs`, and the Task 1 test literal in `exceptions.rs` (re-add `exception: None`)
- Modify: `crates/vft-core/tests/ts_bindings.rs` (add `ExceptionAction`, `FieldLoc`, `FieldMatch`, `ExceptionScope`, `ExceptionEntry`, `ExceptionsFile`)
- Regenerate: `ui/src/gen/*` (bless), and add `exception: null` / `exceptions: []`, `skipped: []` to every TypeScript `Contribution`/`Judgment` literal in `ui/src` so `npm run check` stays at 0 errors

**Interfaces:**
- Produces:
  ```rust
  // Judgment, after `confidence`:
  /// Ids of the exceptions that removed a construct or skipped a field on this request (sorted, unique).
  pub exceptions: Vec<String>,
  /// Fields a skip-inspection exception kept from inspection.
  pub skipped: Vec<FieldRef>,
  // Contribution, after `shadow`:
  /// The log-only exception that suppressed this contribution (then `shadow` is true and points 0).
  pub exception: Option<String>,
  ```
  Every existing construction sets `exceptions: Vec::new()`, `skipped: Vec::new()`, `exception: None`. No behaviour change.

- [ ] **Step 1: Write the failing test** in `judgment.rs` tests:

```rust
#[test]
fn new_fields_serialize_empty_by_default() {
    let v = serde_json::to_value(Judgment::allow()).unwrap();
    assert_eq!(v["exceptions"], serde_json::json!([]));
    assert_eq!(v["skipped"], serde_json::json!([]));
}
```

- [ ] **Step 2: Run it** — `cargo test -p vft-core new_fields_serialize_empty_by_default` — Expected: FAIL (no field `exceptions`).
- [ ] **Step 3: Add the three fields and update every literal** listed above. The JSONL audit's `ContribLine` is unchanged in this task.
- [ ] **Step 4: Add the six types to `ts_bindings.rs`** (`use vft_core::exceptions::{ExceptionAction, ExceptionEntry, ExceptionScope, ExceptionsFile, FieldLoc, FieldMatch};` and one `check::<T>` each), then bless: `VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings`.
- [ ] **Step 5: Update the TypeScript literals** in `ui/src/lib/api/history.ts` (every `Contribution` gets `exception: null`; every `Judgment` gets `exceptions: [], skipped: []`) and in any test file `npm run check` reports.
- [ ] **Step 6: Verify** — `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test -p vft-core --features ts --test ts_bindings`, and in `ui/`: `npm run check`, `npx vitest run`. All green.
- [ ] **Step 7: Commit**

```bash
git add -A crates ui/src
git commit -m "feat(core): judgment records exceptions and skipped fields"
```

---

### Task 3: Shield applies exceptions

**Files:**
- Modify: `crates/vft-core/src/shield.rs`
- Test: `crates/vft-core/src/shield.rs` (`#[cfg(test)] mod exception_tests`), `crates/vft-core/tests/exception_props.rs` (new, proptest)

**Interfaces:**
- Consumes: Task 1 `Exceptions`, `ExceptionClock`, `Selection`, `REQUEST_LEVEL`, `Disabled::with_ids`; Task 2 fields.
- Produces:
  - `Shield::with_exceptions(self, ex: Exceptions, clock: ExceptionClock) -> Shield`
  - `Shield::inspect_at(&self, req: &Request, now_ms: u64) -> Judgment`
  - `Shield::inspect(&self, req)` = `inspect_at(req, self.exceptions.as_of_ms())`
  - `Shield::inspect_stateful` calls `inspect_at(req, now_ms)` instead of `inspect(req)`
  - `Shield::exceptions(&self) -> &Exceptions`

**Behaviour (exact):**
1. `Shield` gains `exceptions: Exceptions`, `clock: ExceptionClock` (default `Fixed`), and `base_observe: Disabled` = `Disabled::resolve(&cfg.shield.disabled)` (always set; `observe: Option<Disabled>` stays as is for the no-exception path).
2. `inspect_counting_at(req, now_ms)`: `let t = match self.clock { Fixed => self.exceptions.as_of_ms(), PerRequest => now_ms }`; `let sel = self.exceptions.select(&req.method, &req.canonical_path(), t)`. If `sel.is_empty()`, run today's code unchanged (`inspect_view` with no selection, plus today's shadow observe pass).
3. Otherwise pass 1 is `inspect_view(req, &View { base: &self.disabled, sel: Some(&sel), remove: true })`. `View::off(f: Option<&FieldRef>)` returns `base.with_ids(sel.removed_ids(&sel.removers_for(f)))` when `remove`, cached in a `HashMap<Vec<usize>, Rc<Disabled>>` keyed by the remover indexes (the empty key maps to a clone of `base`); with `remove == false` it returns `base`. Inside `inspect_view`:
   - request-level `off` (decoders in `fields_with`, `intent_evidence`, `INTEL_SCANNER_UA`, `HONEYPOT_DECOY_HIT`, all `limit.*` and deny checks) = `view.off(None)`;
   - for each field from `fields_with`: if `view.skip(&FieldRef::of(&field))` is `Some`, push `FieldRef::of(&field)` to a local `skipped` vector and `continue` (no budget charge, no normalization); else build `gopts` with `disabled: &view.off(Some(&FieldRef::of(&field)))`;
   - the path loop uses `view.off(Some(&FieldRef::path()))` and is skipped entirely when `view.skip(&FieldRef::path())` is `Some` (then `FieldRef::path()` goes to `skipped`);
   - the returned `Judgment.skipped` is that vector.
4. If `sel.has_removers()` or `self.observe.is_some()`, run the observe pass `inspect_view(req, &View { base: &self.base_observe, sel: Some(&sel), remove: false })` (skips still apply). For each of its contributions `c`, in order:
   - if `c.construct` is in `self.shadow` → append `Contribution { points: 0.0, shadow: true, ..c }` (today's behaviour);
   - else if `sel.attribute(&c)` is `Some((id, action))` → record `id` as touched; if `action == LogOnly` append `Contribution { points: 0.0, shadow: true, exception: Some(id.into()), ..c }`; for `Ignore` append nothing.
5. Also record as touched the `sel.skip_for(f)` id of every `f` in `j.skipped`. `j.exceptions` = touched ids, sorted and deduplicated.
6. Score, verdict, `decided_by`, `attack`, `confidence` all come from pass 1 (already the case: `annotate()` runs inside `inspect_view`).

- [ ] **Step 1: Write the failing tests** (`exception_tests` in `shield.rs`):

```rust
#[cfg(test)]
mod exception_tests {
    use super::*;
    use crate::exceptions::{parse_date, ExceptionClock, Exceptions};

    const AS_OF: &str = "2026-10-30";

    fn entry(id: &str, action: &str, constructs: &str, scope: &str) -> String {
        let cs = if constructs.is_empty() { String::new() } else { format!("    constructs: [{constructs}]\n") };
        format!("  - id: {id}\n    action: {action}\n{cs}    scope:\n{scope}    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n")
    }
    fn shield_with(entries: &[String]) -> Shield {
        let y = format!("version: 1\nexceptions:\n{}", entries.concat());
        let ex = Exceptions::from_yaml_str(&y, parse_date(AS_OF).unwrap()).unwrap();
        Shield::new(Config::default()).with_exceptions(ex, ExceptionClock::Fixed)
    }
    fn referer_req() -> Request {
        let mut r = Request::get("/search");
        r.headers.push(("Referer".into(), "https://x.test/?q=1' union select password from users--".into()));
        r
    }
    const REFERER_SCOPE: &str = "      path_prefix: /\n      field: { loc: header, name: referer }\n";

    #[test]
    fn baseline_flags_the_referer() {
        let j = Shield::new(Config::default()).inspect(&referer_req());
        assert!(j.score > 0 && j.contributions.iter().any(|c| c.construct.as_deref().is_some_and(|i| i.starts_with("sqli."))), "{j:?}");
    }

    #[test]
    fn empty_exceptions_change_nothing() {
        let req = referer_req();
        let a = serde_json::to_value(Shield::new(Config::default()).inspect(&req)).unwrap();
        let b = serde_json::to_value(shield_with(&[]).inspect(&req)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn non_matching_scope_changes_nothing() {
        let req = referer_req();
        let other = entry("other", "ignore", "sqli.*", "      path_prefix: /admin\n");
        let a = serde_json::to_value(Shield::new(Config::default()).inspect(&req)).unwrap();
        let b = serde_json::to_value(shield_with(&[other]).inspect(&req)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ignore_removes_and_records_only_the_id() {
        let j = shield_with(&[entry("referer-sql", "ignore", "sqli.*", REFERER_SCOPE)]).inspect(&referer_req());
        assert!(!j.contributions.iter().any(|c| c.construct.as_deref().is_some_and(|i| i.starts_with("sqli.")) && c.field.as_ref().is_some_and(|f| f.name.eq_ignore_ascii_case("referer"))), "{j:?}");
        assert!(j.contributions.iter().all(|c| c.exception.is_none()));
        assert_eq!(j.exceptions, vec!["referer-sql".to_string()]);
        assert!(j.score < Shield::new(Config::default()).inspect(&referer_req()).score);
    }

    #[test]
    fn log_only_keeps_zero_point_evidence() {
        let j = shield_with(&[entry("referer-sql", "log-only", "sqli.*", REFERER_SCOPE)]).inspect(&referer_req());
        let logged: Vec<_> = j.contributions.iter().filter(|c| c.exception.as_deref() == Some("referer-sql")).collect();
        assert!(!logged.is_empty());
        assert!(logged.iter().all(|c| c.shadow && c.points == 0.0));
        assert_eq!(j.exceptions, vec!["referer-sql".to_string()]);
        let ignored = shield_with(&[entry("referer-sql", "ignore", "sqli.*", REFERER_SCOPE)]).inspect(&referer_req());
        assert_eq!((j.score, j.verdict), (ignored.score, ignored.verdict), "the tiers score alike");
    }

    #[test]
    fn skip_inspection_drops_the_field_and_records_it() {
        let j = shield_with(&[entry("skip-ref", "skip-inspection", "", REFERER_SCOPE)]).inspect(&referer_req());
        assert_eq!(j.skipped, vec![FieldRef { loc: crate::request::Location::Header, name: "Referer".into() }]);
        assert!(!j.contributions.iter().any(|c| c.field.as_ref().is_some_and(|f| f.name == "Referer")));
        assert_eq!(j.exceptions, vec!["skip-ref".to_string()]);
    }

    #[test]
    fn other_fields_are_still_judged() {
        let mut req = referer_req();
        req.query.push(("id".into(), "1 union select password from users".into()));
        let j = shield_with(&[entry("referer-sql", "ignore", "sqli.*", REFERER_SCOPE)]).inspect(&req);
        assert!(j.contributions.iter().any(|c| c.field.as_ref().is_some_and(|f| f.name == "id") && c.construct.as_deref() == Some("sqli.union-select")), "{j:?}");
    }

    #[test]
    fn field_less_exception_reaches_request_level_constructs() {
        let req = Request::get("/.env");
        assert!(Shield::new(Config::default()).inspect(&req).contributions.iter().any(|c| c.construct.as_deref() == Some("recon.sensitive-path-probe")));
        let j = shield_with(&[entry("env-probe", "log-only", "recon.*", "      path_prefix: /.env\n")]).inspect(&req);
        let c = j.contributions.iter().find(|c| c.construct.as_deref() == Some("recon.sensitive-path-probe")).unwrap();
        assert!(c.shadow && c.points == 0.0 && c.exception.as_deref() == Some("env-probe"));
    }

    #[test]
    fn expired_at_request_time_has_no_effect() {
        let y = format!("version: 1\nexceptions:\n{}", entry("referer-sql", "ignore", "sqli.*", REFERER_SCOPE));
        let ex = Exceptions::from_yaml_str(&y, parse_date(AS_OF).unwrap()).unwrap();
        let s = Shield::new(Config::default()).with_exceptions(ex, ExceptionClock::PerRequest);
        let after = s.inspect_at(&referer_req(), parse_date("2026-11-30").unwrap());
        let base = Shield::new(Config::default()).inspect(&referer_req());
        assert_eq!(serde_json::to_value(after).unwrap(), serde_json::to_value(base).unwrap());
        assert_eq!(s.inspect_at(&referer_req(), parse_date("2026-11-29").unwrap()).exceptions, vec!["referer-sql".to_string()]);
    }

    #[test]
    fn excepted_false_positive_does_not_feed_a_ban() {
        use crate::chain::ChainTracker;
        let cfg = Config::default();
        let s = shield_with(&[entry("referer-sql", "ignore", "sqli.*", REFERER_SCOPE)]);
        let mut chain = ChainTracker::new(&cfg.chain);
        let mut req = referer_req();
        req.src_ip = Some("192.0.2.7".parse().unwrap());
        for i in 0..10u64 {
            let j = s.inspect_stateful(&req, &mut chain, parse_date(AS_OF).unwrap() + i * 1000);
            assert!(!j.banned(), "round {i}: {j:?}");
        }
    }
}
```

(Adjust `ChainTracker::new` to its real constructor signature if it differs; check `chain.rs`.)

Also add `cache_gives_the_same_judgment`: `View` carries a `#[cfg(test)]`-only flag that bypasses the off-set cache (computing `base.with_ids(..)` for every field); for a request with `Referer`, `X-Forwarded-Referer` and `Referer-Policy` headers all carrying the union payload, one ignore exception on `header referer*`, and one `q` query field with the same payload, the serialized judgments with and without the cache are equal.

Property test `crates/vft-core/tests/exception_props.rs`:

```rust
//! An exception never raises a request's score or verdict.
use proptest::prelude::*;
use vft_core::exceptions::{parse_date, ExceptionClock, Exceptions};
use vft_core::{Config, Request, Shield};

const PAYLOADS: &[&str] = &[
    "1' or '1'='1", "1 union select a from b", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../../etc/passwd", "a; cat /etc/passwd", "$(id)", "garden hose", "javascript:alert(1)", "1;drop table t--",
];
const CONSTRUCTS: &[&str] = &["sqli.*", "xss.*", "cmd.*", "path.*", "anomaly.*", "sqli.union-select", "xss.script-tag"];
const ACTIONS: &[&str] = &["ignore", "log-only", "skip-inspection"];
const FIELDS: &[&str] = &["", "      field: { loc: query, name: q }\n", "      field: { loc: header, name: referer }\n", "      field: { loc: query, name: \"*\" }\n"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn never_raises(q in 0..PAYLOADS.len(), r in 0..PAYLOADS.len(), a in 0..ACTIONS.len(), c in 0..CONSTRUCTS.len(), f in 0..FIELDS.len()) {
        let mut req = Request::get("/search");
        req.query.push(("q".into(), PAYLOADS[q].into()));
        req.headers.push(("Referer".into(), PAYLOADS[r].into()));
        let action = ACTIONS[a];
        let field = if action == "skip-inspection" && !FIELDS[f].contains("name: q") && !FIELDS[f].contains("referer") { FIELDS[1] } else { FIELDS[f] };
        let cs = if action == "skip-inspection" { String::new() } else { format!("    constructs: [{}]\n", CONSTRUCTS[c]) };
        let y = format!("version: 1\nexceptions:\n  - id: p\n    action: {action}\n{cs}    scope:\n      path_prefix: /\n{field}    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n");
        let ex = Exceptions::from_yaml_str(&y, parse_date("2026-10-30").unwrap()).unwrap();
        let base = Shield::new(Config::default()).inspect(&req);
        let with = Shield::new(Config::default()).with_exceptions(ex, ExceptionClock::Fixed).inspect(&req);
        prop_assert!(with.score <= base.score, "score {} > {} for {y}", with.score, base.score);
        prop_assert!(with.verdict.rank() <= base.verdict.rank());
    }
}
```

If the property test finds a counterexample, do not weaken the test: report it (status DONE_WITH_CONCERNS) with the minimal case; it is a spec-level finding.

- [ ] **Step 2: Run them** — `cargo test -p vft-core exception_tests` and `cargo test -p vft-core --test exception_props` — Expected: FAIL to compile (`with_exceptions` missing).
- [ ] **Step 3: Implement** the behaviour above in `shield.rs`. Keep `inspect_view`'s existing comments; replace its `off: &Disabled` parameter with `view: &View<'_>` and derive `off` from it as described. Add `exceptions` and `clock` to `with_oracle`'s constructor with `Exceptions::default()` and `ExceptionClock::Fixed`.
- [ ] **Step 4: Run** — `cargo test --workspace` (all existing tests must pass unchanged), `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] **Step 5: Commit**

```bash
git add crates/vft-core/src/shield.rs crates/vft-core/tests/exception_props.rs
git commit -m "feat(core): shield applies scoped exceptions per field"
```

---

### Task 4: Proxy, records and CLI

**Files:**
- Modify: `crates/vft-proxy/src/pipeline.rs` (`decide` calls `self.shield.inspect_at(&request, now_ms)` at both call sites)
- Modify: `crates/vft-proxy/src/audit.rs` (`AuditLine` gains `exceptions: &'a [String]` and `skipped: Vec<String>` after `confidence`; `skipped` = `j.skipped.iter().map(FieldRef::label)`)
- Modify: `crates/vft-proxy/src/ocsf.rs` (4002 gains `unmapped: { "vft": { "exceptions": [...], "skipped_fields": [...] } }` when either list is non-empty; no other change)
- Modify: `crates/vft-proxy/tests/fixtures/ocsf-sample.json` (inputs accept optional `exceptions` and `skipped_fields` arrays; add a fifth case: an Allow with `exceptions: ["referer-sql"]`, whose expected output is one 4002 carrying the `unmapped` block and no 2004)
- Modify: `crates/vft-cli/src/main.rs`, `crates/vft-cli/src/eval.rs`

**Interfaces:**
- Consumes: Task 1 `Exceptions::load`, `parse_date`, `format_date`, `Issue`; Task 3 `with_exceptions`, `inspect_at`.
- Produces (CLI):
  - `eval --exceptions <file> [--as-of YYYY-MM-DD]`: loads with `as_of` = `--as-of` or today (UTC, from `std::time::SystemTime`), `ExceptionClock::Fixed`; prints `exceptions: <file> as of <date> (<n> entries)` to stderr before the run; any issue → print each and exit 2. `eval::run` and `eval::run_tcp` take the `Exceptions` and build every `Shield` with it (`Shield::new(cfg).with_exceptions(ex.clone(), ExceptionClock::Fixed)`).
  - `serve --exceptions <file>`: loads at the current time, `ExceptionClock::PerRequest`; prints each `warnings()` line to stderr; any issue → print each and exit non-zero before binding.
  - `venusflytrap exceptions check <file> [--as-of YYYY-MM-DD]`: parses; for each entry prints `<id>\t<action>\t<live|expired>\t<expanded constructs, comma-separated, or "-">`; then prints every issue of `validate_file`; exits 1 if any issue, else 0. "expired" means `expires <= as_of`.
  - `eval --as-of` without `--exceptions` is an error.

- [ ] **Step 1: Failing tests**
  - `audit.rs`: a judgment with `exceptions = ["referer-sql"]` and `skipped = [FieldRef::header("X-Sig")]` writes `"exceptions":["referer-sql"]` and `"skipped":["header:x-sig"]`; `Judgment::allow()` writes `[]` for both.
  - `ocsf.rs`: the shared sample's new case passes; a judgment with empty lists has no `unmapped` key; the existing fixture-validity test still passes (it checks `unmapped` is an allowed 4002 attribute).
  - `main.rs`: `exceptions check` on a temp file with one valid and one expired entry prints `live` and `expired` lines and returns exit code 1; on a valid file returns 0. Factor the command body into `fn exceptions_check(path: &Path, as_of_ms: u64, out: &mut impl Write) -> anyhow::Result<bool>` so it is testable without a process.
  - `pipeline.rs`: a `Pipeline` over a shield with a `PerRequest` Referer exception gives `exceptions == ["referer-sql"]` at a `now_ms` before expiry and `[]` after.
- [ ] **Step 2: Run** — `cargo test -p vft-proxy -p vft-cli` — Expected: FAIL.
- [ ] **Step 3: Implement** as specified. In `ocsf.rs`, set `unmapped` on the 4002 map only:

```rust
if !j.exceptions.is_empty() || !j.skipped.is_empty() {
    let skipped: Vec<String> = j.skipped.iter().map(|f| f.label()).collect();
    http.insert("unmapped".into(), json!({ "vft": { "exceptions": j.exceptions, "skipped_fields": skipped } }));
}
```

  Today's date in the CLI:

```rust
fn today_ms() -> u64 {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    ms - ms % vft_core::exceptions::DAY_MS
}
```

- [ ] **Step 4: Run** — `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`. Then in `ui/`: `npx vitest run src/lib/ocsf.test.ts` must still pass for the four old cases; the fifth fails until Task 6 (note it in the report, do not edit `ui/` here).
- [ ] **Step 5: Commit**

```bash
git add crates
git commit -m "feat(proxy,cli): --exceptions for eval and serve, exceptions check, audit and OCSF fields"
```

---

### Task 5: Verify no change; measure the Referer exception

**Files:**
- Create: `eval/exceptions/referer-sql.yaml`
- Create: `eval/RESULTS-C-exceptions.md`
- Modify: `docs/BENCHMARK.md` (one status line), `docs/superpowers/specs/2026-10-30-scoped-exceptions-design.md` (§5 CLI: "`eval` and `serve` take `--exceptions <file>`; `eval` also takes `--as-of`"; §3.2: add "a decoder or gate id (`not-a-detection`)"; §3.1: define family wildcards as in this plan's Resolutions)

- [ ] **Step 1: Write the example file**

```yaml
# Measured in eval/RESULTS-C-exceptions.md. Not enabled by default.
version: 1
exceptions:
  - id: referer-sql
    action: ignore
    constructs: [sqli.*]
    scope:
      path_prefix: /
      field: { loc: header, name: referer }
    owner: dennis
    reason: "Referer URLs of search pages carry SQL-looking text; 43 of 100 dev FPs (DQ2)"
    created: 2026-10-30
    modified: 2026-10-30
    expires: 2027-10-30
```

- [ ] **Step 2: Build and check** — `cargo build --release -p vft-cli`; `./target/release/venusflytrap exceptions check eval/exceptions/referer-sql.yaml --as-of 2026-10-30` prints one `live` line and exits 0.
- [ ] **Step 3: No-change A/B (dev)**

```bash
export VFT_CORPUS=... VFT_MANIFEST=... VFT_RUNS=...   # paths from the Environment section
MAIN_BIN=/c/Users/DENNIS~1/AppData/Local/Temp/claude/M--Projects-venusflytrap/da1b01dd-cef6-4b76-bba8-0e55e99fd9e4/scratchpad/c/bin/main-db7177b.exe
eval/ab_dev.sh c-nochange "" "" "$MAIN_BIN" ./target/release/venusflytrap
```
Expected: ΔTP 0, ΔFP 0, 0 changed rows.
- [ ] **Step 4: No-change serve diff** — run `eval --mode serve --sources distinct` and `--sources pooled:100` with both binaries on the full corpus (`--out` CSVs), compare with `py -I -X utf8 eval/compare_runs.py`; expected 0 changed decisions.
- [ ] **Step 5: Referer A/B (dev)** — `eval/ab_dev.sh c-referer "" "--exceptions eval/exceptions/referer-sql.yaml --as-of 2026-10-30"`. Record ΔTP, ΔFP, McNemar exact p, Wilson 95 % intervals for recall and FP rate (from the `-ab.txt` and the two JSON reports), and every changed row from `eval/changes.py`.
- [ ] **Step 6: Held-out, once** — `eval --mode library --manifest ... --side heldout` with and without the same flags; same statistics. Do not re-run held-out after looking at it.
- [ ] **Step 6b: Serve smoke** — write a scratch exceptions file (in the runs directory) holding the Referer entry plus one skip-inspection entry on `header x-signature` under `/hooks`. Start a throwaway upstream (`py -I -X utf8 -m http.server 18081 --bind 127.0.0.1` from an empty scratch directory) and `venusflytrap serve --bind 127.0.0.1:18080 --upstream http://127.0.0.1:18081 --exceptions <file> --audit <runs>/smoke.jsonl --ocsf <runs>/smoke-ocsf.jsonl --monitor-only` in the background; confirm stderr shows one `warning: exception … skips inspection` line. Send three requests with `curl`: a GET with a SQL-looking `Referer`, a POST to `/hooks/x` with an `X-Signature` header, and a plain GET. Check the JSONL lines carry `exceptions` `["referer-sql"]`, `skipped` `["header:x-signature"]` (with its exception id) and `[]`/`[]`; the OCSF 4002 records carry `unmapped.vft` for the first two only. Stop both processes. Record the results in the results note.
- [ ] **Step 7: Write `eval/RESULTS-C-exceptions.md`**: setup (binaries, commit, file, as-of), no-change results, Referer dev and held-out tables, changed rows (counts by construct, plus every lost TP listed), and one paragraph stating plainly what the exception costs in recall. End with: "The default configuration stays exception-free; shipping this exception by default is the owner's decision." Add the status line to `docs/BENCHMARK.md` and the three spec amendments.
- [ ] **Step 8: Commit**

```bash
git add eval/exceptions/referer-sql.yaml eval/RESULTS-C-exceptions.md docs/BENCHMARK.md docs/superpowers/specs/2026-10-30-scoped-exceptions-design.md
git commit -m "docs(eval): C no-change check and measured Referer exception"
```

---

### Task 6: Console — types, fixtures, validator, YAML, OCSF

**Files:**
- Create: `ui/src/lib/exceptions.ts`, `ui/src/lib/exceptions.test.ts`
- Modify: `ui/src/lib/api/types.ts` (re-export the six generated types; `HistoryRow` gains `excepted: boolean` — true when `judgment.exceptions` or `judgment.skipped` is non-empty)
- Modify: `ui/src/lib/api/source.ts` (`DataSource.exceptions(call: Call): Promise<ExceptionEntry[]>`; `FixtureSource` returns the fixture list after its usual latency/fault handling)
- Modify: `ui/src/lib/api/fixtures.ts` (`EXCEPTIONS: ExceptionEntry[]`: four entries relative to the fixture clock — `referer-sql` ignore live, `utm-xss` log-only live with a `query utm_*` glob, `hook-signature` skip-inspection live on `header x-signature` under `/hooks`, and one expired `legacy-search` ignore; dates computed from `now` with `formatDate`)
- Modify: `ui/src/lib/api/history.ts` (touched rows, below)
- Modify: `ui/src/lib/ocsf.ts` (same `unmapped` rule as Rust)

**Requirements:**
- `exceptions.ts` exports:
  - `parseDate(s: string): number | null`, `formatDate(ms: number): string` (UTC, same rules as Rust, including leap years and the 1970 floor);
  - `expandConstructs(names: string[]): { ids: string[]; codes: string[] }` using `crates/vft-core/tests/fixtures/construct-registry.json` (imported by relative path, as `ocsf.test.ts` imports the OCSF sample) and the same family-wildcard table;
  - `validateEntry(e: ExceptionEntry, asOfMs: number): { code: string; msg: string }[]` with exactly the Rust codes;
  - `scopeLabel(e)`: `"GET /search · header referer"` (methods joined with `,`, omitted when empty; field part omitted when null);
  - `liveAt(e, ms): boolean`;
  - `toYaml(e: ExceptionEntry): string`: a list item (`  - id: …`) that, prefixed with `version: 1\nexceptions:\n`, parses back with `Exceptions::from_yaml_str` to an equal entry. Quote `reason` and `owner` with JSON string syntax (valid YAML double-quoted scalars); dates and ids bare.
- `exceptions.test.ts` runs every case of `crates/vft-core/tests/fixtures/exception-cases.json` (same base + patch rule as the Rust test) and asserts the sorted unique codes; plus `toYaml` snapshots for one entry of each action; plus date round-trips.
- Rust round-trip guard: add to `crates/vft-core/tests/exceptions_shared.rs` a test that parses `ui/src/lib/__fixtures__/exceptions-yaml.txt` (written by a Vitest test from `toYaml` of the four fixture entries with `VFT_BLESS_TS`-style blessing: the Vitest test compares against the committed file; regenerate with `VFT_BLESS=1 npx vitest run src/lib/exceptions.test.ts`) and asserts each entry deserializes. Expired fixture entries are deserialized, not validated.
- `history.ts`: touched rows come from a separate generator `mulberry32(Math.imul(k, 40503) ^ 0x2c1b3c6d)` so the existing random stream (and every existing row) is unchanged:
  - benign rows with a query on `/api/search` get, with probability 0.06, a `Referer` field whose ignore exception removed its evidence: `exceptions: ['referer-sql']`, no extra contribution;
  - attack rows decided by `xss.event-handler` get, with probability 0.15, an extra log-only contribution `{ engine: 'graph-taint', field: { loc: 'Query', name: 'utm_source' }, construct: 'xss.event-handler', family: 'Xss', value: 'Suspicious', weight: 0.5, points: 0, shadow: true, exception: 'utm-xss' }` and `exceptions: ['utm-xss']`;
  - POST rows to `/hooks/…` do not exist today; add none. `hook-signature` is listed only.
  - `excepted` is set on the row from the judgment.
- `ocsf.ts`: 4002 gets `unmapped: { vft: { exceptions, skipped_fields } }` when either list is non-empty; `skipped_fields` uses the `loc:name` label with a lowercase location. The fifth shared-sample case from Task 4 now passes.
- Existing tests stay green; add a `history.test.ts` case asserting that rows 0..2000 are identical to before this task except for `excepted` and the two touched shapes (compare `verdict`, `score`, `construct`, `path` of every row against a snapshot computed with the touched generator disabled through an exported test hook `__setExceptionTouch(false)`).

- [ ] Steps: write the tests (validator, YAML, OCSF case, history stability) → run (fail) → implement → `npm run check` 0 errors, `npx vitest run` green → commit `feat(ui): exception types, fixtures, validator and YAML`.

---

### Task 7: Console — Exceptions screen

**Files:**
- Create: `ui/src/screens/Exceptions.svelte`, `ui/src/screens/exceptions/exceptions.test.ts`
- Modify: `ui/src/lib/state/router.svelte.ts` (route `/exceptions` → `'exceptions'`, NAV entry `{ name: 'exceptions', href: '/exceptions', label: 'Exceptions' }` after Monitor), `ui/src/App.svelte` (lazy screen + title "Exceptions"), `ui/src/lib/shell/NavRail.svelte` and `ui/src/lib/icons.ts` (a lucide icon, `ShieldOff`, exported through `icons.ts` like the others)

**Requirements:**
- Heading "Exceptions"; a tablist "Active" / "Expired" with counts, same tab component pattern as Request details' Evidence / "View as OCSF" tabs (roving tabindex, arrow keys).
- A table with columns: ID (mono), Action, Scope (`scopeLabel`), Constructs (comma-separated, wildcards as written), Owner, Reason, Expires (`in 12 days` / `expired 3 days ago`, the absolute date in `title`). Skip-inspection rows show a warning badge "Skips inspection" with the existing warning token colours.
- Selecting a row (click or Enter) opens a details panel listing every field of the entry, including created/modified, plus a "Copy YAML" button (`toYaml`). The screen reads `?id=<id>` from the URL: it switches to the tab holding that entry and opens its panel (Task 8 links here).
- Empty states use `EmptyState` ("No active exceptions" / "No expired exceptions"); load errors use `ErrorCard` with Retry, as other screens do.
- A one-line note under the heading: "Exceptions are read from the file passed with --exceptions. Changes take effect after a restart."
- Tests: tabs filter by `liveAt`; counts; badge on skip-inspection; keyboard selection opens the panel; Copy YAML writes `toYaml(entry)` to the clipboard mock; error state and Retry.

- [ ] Steps: tests → fail → implement → `npm run check`, `npx vitest run` → commit `feat(ui): Exceptions screen`.

---

### Task 8: Console — Request details and Monitor

**Files:**
- Create: `ui/src/screens/request/CreateException.svelte`
- Modify: `ui/src/screens/RequestDetails.svelte`, `ui/src/screens/request/request.test.ts`, `ui/src/screens/Monitor.svelte`, `ui/src/screens/monitor/monitor.test.ts`

**Requirements:**
- **Touched section** in Request details, shown when `judgment.exceptions` or `judgment.skipped` is non-empty, titled "Exceptions": each id as a link to `/exceptions` (selected row via `?id=<id>`; the Exceptions screen reads `id` and opens that row); log-only contributions render in the evidence list greyed with the suffix "suppressed by <id>" and are excluded from the points total; each skipped field is listed with a warning icon and the text "Not inspected (skip-inspection <id>)".
- **Create exception** button in the Request details header actions (next to Copy event ID). It opens `CreateException` as an inline panel (not a modal). Pre-fill: `id` = the deciding construct's text before its first `.`, a `-`, and the last non-empty segment of `row.path`, lowercased, every other character replaced by `-`, truncated to 64 (e.g. `sqli-search`; `exception` when there is no construct), action `log-only`, constructs `[decided_by.construct]` (empty for skip-inspection), methods `[row.method]`, path_prefix = `row.path`, field = `decided_by.field` mapped to the lowercase loc (null when none), created = modified = today, expires = today + 30 days, owner and reason empty.
  - Every input has a visible label; the action is a radio group with a one-line description per tier; choosing skip-inspection shows a warning paragraph ("Matching fields will not be inspected at all.") and clears constructs.
  - Validation runs `validateEntry` on change; issues show next to their inputs (`aria-describedby`), and the YAML output and Copy button appear only when there are no issues.
  - Output: a `<pre>` with `toYaml(entry)` and a "Copy YAML" button, plus the line "Paste this under exceptions: in your exceptions file. It takes effect after a restart with --exceptions."
- **Monitor:** on rows with `excepted`, a small icon after the verdict chip in the existing verdict cell, with `aria-label="Exception applied"` and the tooltip "An exception changed how this request was judged" (the row does not carry the ids; Request details lists them). Grid widths stay as they are.
- Tests: section renders for a touched fixture row and not for an untouched one; log-only greyed and excluded from the total; pre-fill values from a known fixture row; invalid owner shows the `required` message and hides the YAML; valid form shows YAML equal to `toYaml`; skip-inspection clears constructs and shows the warning; Monitor marker present only on `excepted` rows.

- [ ] Steps: tests → fail → implement → `npm run check`, `npx vitest run` → commit `feat(ui): exceptions on Request details and Monitor`.

---

### Task 9: Console — end-to-end, accessibility, budget, screenshots

**Files:**
- Modify: `ui/e2e/console.spec.ts`, `ui/scripts/screenshots.mjs` (if it lists routes)

**Requirements:**
- Playwright (system Edge, as configured): open `/exceptions`, switch tabs, open a row, copy YAML; open a touched request, see the Exceptions section, open Create exception, fill owner and reason, see YAML; Monitor shows the marker on a touched row. `expectNoAxe` (all impacts) and `expectScheme` on the Exceptions screen, the create form open, and a touched Request details, in both themes.
- `npm run build` then `npm run budget`: initial JS ≤ 150 KB gz (the Exceptions screen is lazy).
- Screenshots of the Exceptions screen, the create form and a touched request in both themes into the session scratchpad `c\shots\` (not committed).
- Final: `cargo test --workspace`, clippy, `npm run check`, `npx vitest run`, `npx playwright test` all green.

- [ ] Steps: add e2e → run → fix → budget → screenshots → commit `test(ui): exceptions end-to-end and accessibility`.
