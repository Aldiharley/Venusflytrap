# C — Scoped exceptions (design)

*Sub-project C of three (A → C → B), rank 3 of
`reports/Endpoint EDR lessons for Venusflytrap.md` (git-ignored). Approved by the
owner on 2026-10-30.*

## 1. Goal

Let an operator silence a known false positive narrowly, on the record, and for a
limited time, instead of disabling a construct everywhere:

- exceptions are data in their own file, each scoped by method, path prefix and
  field, with an owner, a reason and an expiry,
- three tiers: **ignore** (the constructs do not score in the scope),
  **log-only** (they do not score, but stay visible as 0-point evidence) and
  **skip-inspection** (matching fields are not inspected at all),
- every request an exception touched says so, in the judgment, the audit, OCSF
  and the console,
- the effect of one realistic exception is measured on dev and held-out.

The owner narrows the service spec's "per-route policy layers" non-goal
(`2026-10-25-operable-service-design.md` §2) to allow exactly this: scoped
exceptions. Per-route config overlays stay a non-goal.

## 2. Non-goals

- No default exceptions. With no `--exceptions` flag every judgment, eval number
  and serve decision is identical to main.
- No hot reload, no admin API, no request history, no impact preview (all B).
- No per-route config overlays (other thresholds, weights or limits per route).
- No exception on resource limits, bans or the deny list (§3.2).
- No outside product names in code, UI or docs.

## 3. The exceptions file

### 3.1 Format

```yaml
version: 1
exceptions:
  - id: referer-sql            # unique, [a-z0-9-]{1,64}
    action: ignore             # ignore | log-only | skip-inspection
    constructs: [sqli.*]       # construct ids or family wildcards (`<family>.*`)
    scope:
      methods: [GET, POST]     # optional; absent = any method
      path_prefix: /           # required; matched on the canonical path (§3.1)
      field: { loc: header, name: referer }   # optional
    owner: dennis
    reason: "Search-result referers carry SQL-looking text"
    created: 2026-10-30
    modified: 2026-10-30
    expires: 2026-11-30
```

- A family wildcard is `<name>.*` with `<name>` one of `sqli` (family Sqli),
  `xss` (Xss), `cmd` (CommandInjection), `path` (PathTraversal), `recon`
  (Recon), `honeypot` (Honeypot), `intel` (Intel) or `anomaly` (Anomaly). It
  expands to every exceptable construct of that family: kind Sink, Latent or
  Signature, and not forbidden (§3.2). The family is the construct's, not its
  id prefix, so `sqli.*` also covers `sig.classic-or` and `api.type-violation`.
  Any other `<name>.*` is an unknown-construct error; a wildcard that expands to
  nothing is an `empty-wildcard` error.
- `field.loc` is one of `path`, `query`, `header`, `cookie`, `body` (the
  `Location` enum). `field.name` is a case-insensitive glob over the field name
  as the engine names it (`referer`, `key:q`, `json:/user/id`), with `*` and `?`.
- `path_prefix` matches on segment boundaries against the canonical request
  path: `/api` matches `/api` and `/api/x`, not `/apix`. `/` matches every path.
  Any other prefix also needs the raw request path to be **plain**: it contains
  none of `%2f`, `%5c`, `%2e`, `%25` (ASCII case-insensitive), no `\`, no `;`,
  and no `.` or `..` segment. A request whose raw path is not plain gets no
  exception except those scoped to `/` (fail closed: canonicalisation can never
  carry a request such as `/admin/..%2fhooks` into a `/hooks` scope).
- Dates are `YYYY-MM-DD`, read as 00:00 UTC.

### 3.2 Validation

The file is validated at load. Any error stops `serve` from starting and makes
`eval`/`bench` exit non-zero, the same as an invalid `shield.yaml`. Errors:

- unknown `version`, unknown keys, a missing required key, a bad date or glob;
- a duplicate `id`;
- an unknown construct id, a decoder or gate id (`not-a-detection`), or a
  wildcard naming no family;
- a forbidden target: `chain.ban`, any `limit.*` construct or `intel.deny-listed`
  (directly or through a wildcard: the wildcard expands without them, and naming
  one directly is an error);
- `constructs` present on `skip-inspection`, or absent or empty on the others;
- `skip-inspection` without `field`, or with a wildcard in `field.name`;
- `expires` not after `modified`, or more than 365 days after it;
- `modified` before `created`;
- an entry already expired at load (`expires <= as_of`).

Each `skip-inspection` entry also prints one warning line at serve startup
naming its id, scope and expiry.

### 3.3 Matching and expiry

- An exception is **live** when `as_of < expires`. Serve evaluates it per request
  with the proxy clock (`now_ms`), so an entry stops applying at its expiry
  without a restart. `eval` and `bench` take `--as-of <date>` (default: the run
  date, printed in the run header) and use it for every row, so runs are
  reproducible.
- A live exception applies to a **field** when its method list (if any) contains
  the request method, its `path_prefix` matches (§3.1: a prefix other than `/`
  only on a plain raw path), and its `field` (if any) matches the field's
  location and name.
- An exception with no `field` applies to every field and also to the
  request-level constructs (`recon.sensitive-path-probe`, `honeypot.decoy-hit`,
  `intel.scanner-ua`).

## 4. Engine (vft-core)

### 4.1 Module

New `exceptions.rs`: the file model (serde), `validate`, and a compiled
`Exceptions` value (globs compiled once, wildcards expanded to registry ids,
entries indexed by action). `Shield::with_exceptions(ex: Exceptions)` attaches
it. A shield without exceptions takes exactly today's code path.

### 4.2 Inspection

1. Per request, select once the live exceptions whose method and path match.
   No match: inspect exactly as today.
2. **skip-inspection:** fields matching such an exception are dropped before
   normalization. Their `FieldRef`s go into the new `Judgment.skipped:
   Vec<FieldRef>`. Nothing is hidden silently: the "nothing hides body bytes"
   invariant becomes "nothing hides body bytes except an explicit, logged,
   expiring skip-inspection entry".
3. **ignore and log-only:** each field's off-set is the global `Disabled` set
   (`shield.disabled` plus `shield.shadow`) plus the constructs of every matching
   ignore or log-only exception. Off-sets are cached per distinct combination,
   so fields with the same matches share one set. Request-level constructs use
   the off-set of exceptions with no `field`. The request is judged exactly as
   if those constructs were disabled for those fields: score, lattice,
   corroboration, verdict, `decided_by`, ATT&CK tags and confidence all come
   from this pass.
4. **Observe pass:** when an ignore or log-only exception added constructs to
   the off-set of at least one field (or of the request-level checks), or
   `shield.shadow` is set, the request is inspected again with only
   `shield.disabled` off (the mechanism `shield.shadow` uses today, with
   skipped fields still skipped). For each contribution of that pass whose
   construct an exception removed for that field:
   - log-only: append it with `points: 0.0`, `shadow: true` and the new
     `exception: Some(id)`;
   - ignore: keep no contribution; record only the id.
   Contributions that global `shield.shadow` would have produced keep their
   current form (`exception: None`).
5. `Judgment.exceptions: Vec<String>`: the sorted, unique ids of every exception
   that removed at least one construct in the observe pass or skipped at least
   one field. An exception that matched but changed nothing is not listed.

Requests no exception's method and path scope touches pay nothing extra.

### 4.3 Invariants (tested)

- With no exceptions, judgments are byte-identical to main.
- An exception never raises a request's score or verdict (property test over
  generated requests and exceptions).
- An expired exception has no effect.
- A forbidden target can never be excepted.

## 5. Chain, proxy and records

- **Chain:** observes the exception-adjusted judgment, so an excepted false
  positive no longer counts toward a ban. Fast-tracked bans are unaffected.
- **JSONL audit:** each line gains `exceptions` (ids) and `skipped`
  (`"loc:name"` strings), always present and `[]` when empty, like `attack`.
  Existing fields are unchanged.
- **OCSF:** the HTTP Activity (4002) record carries
  `unmapped.vft.exceptions` and `unmapped.vft.skipped_fields` when non-empty.
  The 1.9.0 `policy` attribute is a single object describing the applied policy
  and is already implied by `firewall_rule`, so it is not reused for a list of
  exceptions. A Detection Finding (2004) is written only for Challenge and
  Block, as today; a log-only hit on an otherwise allowed request writes none.
  The console's TypeScript encoder follows the same rule, kept identical by the
  shared fixture.
- **CLI:** `eval` and `serve` take `--exceptions <file>`; `eval` also takes
  `--as-of <YYYY-MM-DD>`. `bench` (the synthetic smoke test) takes neither. New `vft exceptions check <file>
  [--as-of <date>]` validates the file and prints each entry with its live or
  expired state and expanded construct list; it exits non-zero on any error.
- `eval/ab_dev.sh` already takes per-side flags, so a measurement passes
  `--exceptions` on side B only.

## 6. Console (ui/)

Existing tokens, fonts and components only; both themes; axe clean at all
impacts; the initial JS budget (150 KB gz) holds.

- **Exceptions screen** (new nav entry): Active and Expired tabs over a fixture
  read through `FixtureSource`. Columns: id, action (skip-inspection carries a
  warning badge), scope (`GET /search · header referer`), constructs, owner,
  reason, expiry ("in 12 days", "expired 3 days ago"). Selecting a row opens a
  details panel with every field of the entry.
- **Create exception** (action on Request details): a form pre-filled from the
  request: path as `path_prefix`, the method, the deciding contribution's field
  and construct, action log-only, expiry 30 days after today, created and
  modified today. Owner and reason are required. It validates with a
  TypeScript port of §3.2, kept identical to the Rust rules by a shared JSON
  fixture of valid and invalid entries. The output is a ready-to-paste YAML
  entry with a Copy button and one line saying it takes effect after a restart
  with `--exceptions`.
- **Touched requests:** Monitor shows an "exception" marker on rows with a
  non-empty `exceptions` or `skipped`. Request details lists each exception by
  id, shows log-only contributions greyed as "suppressed by <id>", and lists
  skipped fields with a warning.
- Fixtures follow the engine's rules (ids, scopes and touched requests
  consistent with a fixture exceptions file).

## 7. Measurement

- `eval/exceptions/referer-sql.yaml`: the example above, the only exception
  measured in C.
- Dev A/B: main against branch plus the file. Report ΔTP, ΔFP, McNemar exact
  p, Wilson 95 % intervals for recall and FP rate, and every changed row
  (`eval/changes.py`).
- Then held-out, scored once with and without the file.
- Results in `eval/RESULTS-C-exceptions.md`, plus a status line in
  `docs/BENCHMARK.md`. The default config stays exception-free; whether to
  ship the exception by default is the owner's call afterwards.

## 8. Testing and acceptance

- `cargo test --workspace` and `clippy -D warnings` green;
  `#![forbid(unsafe_code)]` kept.
- No `--exceptions`: the dev A/B shows zero changed cells and the full-corpus
  serve diff shows zero changed decisions against main.
- Unit tests: each tier; each scope part (method, prefix with segment
  boundaries, field glob, no field and request-level constructs); expiry at the
  boundary (`as_of == expires` is expired); every validation error in §3.2;
  forbidden targets directly and through wildcards; off-set caching gives the
  same judgment as uncached.
- Property test: an exception never raises score or verdict.
- `vft exceptions check` on valid, invalid and expired files.
- Serve smoke with the Referer file: audit and OCSF carry the fields; the
  skip-inspection startup warning prints.
- Console: `npm run check` 0 errors, Vitest (including the shared validation
  and OCSF fixtures) and Playwright with axe in both themes green, budget held,
  screenshots of the Exceptions screen, the create form and a touched request
  in both themes.
