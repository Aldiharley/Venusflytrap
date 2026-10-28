# SP6b part 1: report

Branch `sp6b-console` (from `main` 01b1484). Nothing has been pushed, and `main` is untouched. Plan: `2026-10-28-sp6b-part1-plan.md`.

## Commits

| Commit | Task |
|---|---|
| a012f41 | docs: SP6b part 1 plan |
| 1da20a7 | 1. Wire types from `ui/src/gen`; ban views built from `BanRecord`; judgment fixtures |
| 4fceb28 | 2. `DataSource` abort and error contract; stale-response guards; route outlet `{:catch}` |
| 76db6ad | 3. "Apply (R)" keeps grid focus in Safari and Firefox (`mousedown` fix) |
| 1240710 | 4. Monitor screen on fixtures |
| e373a8c | 5. Request details screen with the SP2 "why" panel |
| (this) | 6. This report |

## What was built

**1. Generated wire types.** `ui/src/lib/api/types.ts` now re-exports everything in `ui/src/gen`: `Verdict`, `Stage`, `FourValued`, `Location`, `Family`, `CauseKind`, `BanCause`, `BanRecord`, `FieldRef`, `Contribution`, `Cause`, `Judgment`, `ChainOutcome`, the option types, and `Source`, which is re-exported as `OptionSource`. The only types it still defines are view types. `views.ts` builds `BanView` and `BanEntry` from a `BanRecord`: `manual` means the cause is `Manual`, and an `until_ms` at or above `Number.MAX_SAFE_INTEGER` (for example u64::MAX) means permanent. The fixtures now hold `BanRecord`s, and the board and bans list are built from them. A new deterministic history generator, `api/history.ts`, stores one request every 10 s, derived from its index alone. It produces `Judgment`s that follow `shield.rs`:
- `decided_by` comes from `cause_for` or `ban_cause`, with the same option keys and message formats;
- scored points sum to the score to within 0.05;
- shadow contributions carry 0 points;
- the top contribution is the one that decides.

A type-level test (`expectTypeOf`) pins the re-exports to the generated types.

**2. Error and abort contract.**
- Every `DataSource` method requires `{ signal: AbortSignal }`.
- Every failure rejects with a `SourceError` that has a `kind` (`aborted`, `network`, `unauthorized`, `forbidden`, `not_found`, `bad_request`, `conflict`, `invalid`, `server`), the HTTP `status` and a `detail` (`pos`/`len` for query errors, `need` for 403). `toSourceError` normalises fetch `TypeError`s and DOM `AbortError`s.
- `FixtureSource` honours the signal and has two test options: `latencyMs` (simulated latency) and `fault` (inject a fault per method).
- `Latest` aborts a screen's previous call and turns superseded or aborted results into `null`, so a stale response can never land.
- Dashboard and Topology load through `Latest` and show an inline `ErrorCard` (status, plain message, Retry; UX §1.1). On error they keep the last data and mark it stale.
- `app.start` aborts its calls on `stop()`, resolves quietly when it has been superseded, and rejects with a typed error otherwise.
- The route outlet's `{#await}` has a `{:catch}`: "This screen could not be loaded" with Retry. Retry re-runs the import and puts focus back on the `h1`, which also fixes the SP6a minor "Retry drops focus to body".

**3. Apply (R).** `onmousedown={(e) => e.preventDefault()}` on the button. Safari and Firefox on macOS do not focus a button when it is clicked, so focus used to drop to `<body>`, the grid unfroze and the bar unmounted before the click landed. A test checks that the mousedown is default-prevented, that focus stays on the cell, and that the click re-sorts and keeps focus on the same key.

**4. Monitor (`/monitor`).**
- **Query language (`lib/query.ts`):** `field:value` terms joined by AND, `-` to negate, a trailing `*` for a prefix match, quoted values, `score`/`config_rev` with `>= <= > <`, and an optional `AND`. It produces tokens for highlighting and errors with position and length.
- **Query bar:** a combobox (`aria-expanded`, `aria-activedescendant`). It suggests field names, and values with counts taken from a `group_by` query over the current range. Down arrow opens it, Enter accepts, Esc closes, and `/` focuses the bar.
- **Controls:**
  - time-range presets 15 m / 1 h / 24 h / 7 d;
  - group-by chips (`aria-pressed`);
  - result header with the count, the "Allows are sampled at 1 %" note, auto-refresh 10 s / 1 min / Off, the Updated time, and Copy query URL.
- **Results grid:** `role="grid"` with one tab stop and the arrow / Home / End / Ctrl+Home / PageUp / PageDown keys, through a shared `lib/grid.ts`.
  - Enter or a click on a value adds `field:value`; Shift adds the negation.
  - Enter on the time opens the request; Enter on "Decided by" opens the setting; O opens the source.
  - Blocked rows use the `row-blocked` background plus an inset bar; sampled Allows are marked.
  - Load more uses the cursor.
  - In grouped mode the grid shows value and count, and a row drills into the ungrouped query.
- **Refresh and states:**
  - Auto-refresh pauses while focus is in the grid or past page 1; a polite "N new results — Show" appears instead.
  - The history-writer drop notice is shown.
  - Empty state with Widen range; 400 errors inline under the bar; other errors in an error card.
- **URL:** everything is in the URL (`q`, `range` or `from&to`, `group_by`, `refresh`). Opening a request stores the row id in history state, so Back refocuses that row.
- **Layout:** the grid uses a fixed layout that fits 1440 px, measured in Edge at `scrollWidth` = `clientWidth` = 1144. Long mono values wrap to two lines, with the full value in `title`.

**5. Request details (`/requests/{id}`).**
- **Header and banner:** breadcrumb; an `h1` with the verdict chip and id, which takes focus on load; the request line; a meta list (time, source link, IP, host, inspection µs, upstream, config rev); the sampled banner.
- **Why panel:**
  - The UX sentence for each `decided_by.kind`. Detection reads, for example: "Blocked: score 94 reached `scoring.block_at` = 90 (override). Top evidence: `sqli.union-select` in `query:id`."
  - Below the sentence, a list of every `decided_by` field: kind, option key with its value, source and rev, field, construct, and the engine message.
  - Deep links: `/settings?highlight=<key>`, and `…highlight=shield.disabled&construct=<id>`. The construct link is left out for `chain.*` ids.
- **Score gauge:** follows design system §4 and is `aria-hidden`, with the sentence "Score 94 of 100. Bands at rev 12: Monitor ≥ 40, Challenge ≥ 70, Block ≥ 90."
- **Contributions table:**
  - Sorted by points, with the top row tagged "top".
  - Shadow rows come last, tagged "Shadow · not scored", at 0.0 points, with a note about `shield.shadow`.
  - The footer reads "Σ points (shadow rows excluded) 94.0 = score 94", and switches to ≈ when the engine's sum differs from the rounded score.
- **Other sections:** chain outcome; source timeline with links, plus "All requests from this source"; raw vs decoded field values, or "Field values not stored"; the 404 copy from UX §6.
- **Actions:** Open setting and Open source are live. Ban source and Disable construct are shown disabled, with the reason as visible text.

## Verification (tails)

`npm test` (run with the local junction config; see Deviations):

```
 Test Files  25 passed (25)
      Tests  220 passed (220)
   Duration  38.42s
```

`npm run check`:

```
COMPLETED 4331 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS
```

`npm run build && npm run budget`:

```
initial JS 35.6 KB gz (budget 150)
chunk src/screens/Chains.svelte 3.0 KB gz (budget 80)
chunk src/screens/Dashboard.svelte 4.1 KB gz (budget 80)
chunk src/screens/Monitor.svelte 8.3 KB gz (budget 80)
chunk src/screens/Placeholder.svelte 0.4 KB gz (budget 80)
chunk src/screens/RequestDetails.svelte 6.9 KB gz (budget 80)
chunk src/screens/Topology.svelte 7.1 KB gz (budget 80)
```

`npm run e2e` (system Edge, production CSP via `vite preview`):

```
  ok 17 › monitor: / focuses the query, Enter runs it, the grid adds filters and opens a request (1.1s)
  ok 18 › request details in light: no serious axe violations, no CSP violations (2.1s)
  ok 19 › request details in dark: no serious axe violations, no CSP violations (2.1s)
  19 passed (1.1m)
```

The e2e suite now includes axe in light and dark for `/monitor`, `/monitor?q=-verdict:allow construct:sqli.*` (highlighted query plus blocked rows) and Request details. It also has a keyboard path: `/` → query → Enter → grid filter → Enter on a time cell → Request details with the `h1` focused and the setting link present → Back refocuses the row.

`cargo test -p vft-core --features ts --test ts_bindings`: `test generated_types_are_current ... ok`. Nothing the bindings cover was changed; the run confirms `ui/src/gen` is current.

## Measured JS sizes (gzip)

| | Size |
|---|---|
| Initial (entry + static imports) | 35.6 KB (SP6a: 29.3) |
| Monitor route chunk | 8.3 KB (+ 1.9 KB CSS) |
| Request details route chunk | 6.9 KB (+ 1.2 KB CSS) |
| Shared `Link` chunk (Svelte runtime and Lucide, loaded with the first route) | 20.4 KB |

## Deviations

1. **Test runner configuration (environment only, not committed).** With `ui/node_modules` as a junction to the main checkout, Vite resolves modules to their real path outside the worktree and refuses to serve them (`Cannot find module '/@fs/M:/Projects/venusflytrap/ui/node_modules/@testing-library/svelte/src/vitest.js'`). Unit tests therefore ran as `npx vitest run --config vitest.junction.config.ts`, using an untracked config that merges `vite.config.ts` and adds `server.fs.allow` for the main checkout's `node_modules`. `npm run check`, `build`, `budget` and `e2e` ran exactly as written. In a normal checkout `npm test` needs nothing extra.
2. **Highlighted query input technique.** At rest, the input is `opacity: 0` over a highlighted mirror layer. While focused, its text is transparent and only the caret and selection are drawn. axe flattens transparent text to the background and would report it, so the at-rest state, which the e2e scans, is clean. The focused state was not scanned. The text a user sees is always the mirror, at the design-system syntax contrast. Under `forced-colors` the mirror is hidden and the input text is shown.
3. **Range in the URL** is `range=15m|1h|24h|7d` (it slides with auto-refresh), or an absolute `from&to`. Custom from/to inputs are not built.
4. **Provisional view types.** `HistoryRow`, `HistoryQuery`, `HistoryPage`, `RequestDetail` and `Bands` are hand-written; SP4/SP5 own them. `RequestDetail` carries `setting {key, value, source, rev}` and `ban`. The real API may instead take these from `/options` and `/sources`.
5. **Permanent bans.** `BanRecord.until_ms` has no permanent value, so any value ≥ `MAX_SAFE_INTEGER` is read as permanent. SP5 must agree on this (u64::MAX works).
6. **Upstream column** is headed "HTTP", with the full name in `title`. "not forwarded" shows as "—" plus screen-reader text, so that 13 columns fit at 1440.
7. **Mutations** (ban, disable construct) are disabled buttons with visible text. They need the admin API and a modal (no new dependencies are allowed, and Bits UI is not installed).
8. **`/` shortcut** is implemented on Monitor only. There is no global shortcut layer yet.

## Deferred

- Monitor responsive variants: @1024 (host, latency and upstream in an expandable row detail) and @768 (list rows).
- Custom from/to range inputs.
- Automatic retry with backoff for 5xx and network errors (manual Retry is there).
- The 401 session modal; the error card says "sign in again".
- Ban and Disable-construct modals and their mutations; the "View in Monitor `config_rev:N`" step of the UX §12 flow; Settings deep-link handling. The setting links currently land on the Settings placeholder.
- Request details @1024/@768 single-column ordering. Below 1280 px only the gauge stacks under the why panel.
- Source, Honeypot & bans, Settings and Keys screens (SP6b part 2).
- A global `?` help and a single-key shortcut toggle (WCAG 2.1.4); `/` currently cannot be turned off.
- Running axe with the query input focused (see deviation 2).

## Concerns

- The Monitor grid renders about 1,300 cells. In jsdom, component tests take 1–6 s each, so `monitor.test.ts` raises its timeout to 20 s; one earlier run on a loaded machine timed out at 5 s. Axe on `/monitor` takes about 12 s in e2e. Row virtualisation would help if `limit` grows towards 1000.
- The browser pane would not draw reliably during the visual check. Layout was verified by measuring in Edge (no horizontal overflow at 1440; clipped cells listed). Only a few low-resolution screenshots were taken, so a side-by-side review against the `Monitor` and `RequestDetails` canvas boards in both themes is still owed (console spec §9).
- The background preview I started left an orphaned `vite preview` child process after its npm wrapper stopped. I stopped it by PID before e2e. No server or background process is left running.
