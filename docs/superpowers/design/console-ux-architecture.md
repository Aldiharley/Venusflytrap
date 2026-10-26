# Venusflytrap console — information architecture and screen layouts

Status: layout specification for SP6. Source of truth for data is the program design (`specs/2026-10-25-operable-service-design.md`, §5.2, §5.8–§5.10). The console shows only what those endpoints and frames provide. Field names marked † are named by purpose in the spec but have no exact name yet. §14 lists them as spec gaps to close before SP6.

## 1. Conventions

| Item | Rule |
|---|---|
| Grid @1440×900 | Top bar 56 px. Nav rail 216 px (icon and label). Content area 1224 × 844 with 24 px padding and a 12-column grid (24 px gutter, about 76 px per column). |
| @1024 | Nav becomes a 72 px rail with the icon and a short label underneath, so labels are never hidden. Content uses 8 columns. |
| @768 | Nav moves into a "Menu" drawer opened from the top bar. Content uses 4 columns with 16 px padding. Side regions stack below the main region. Widths under 768 px reuse this layout and are not a design target. |
| Themes | Light follows ref 2: warm-grey ground, translucent off-white cards, soft drop shadows, copper glow for structure. Dark follows ref 1: charcoal frosted glass, inner and outer shadows, blue glow for structure, gold for selection. `prefers-color-scheme` picks the default. The top-bar toggle (Light / Dark / System) overrides it, and only that preference is kept in `localStorage`. |
| Verdict encoding | Allow = circle ✓ "Allow", line solid. Monitor = eye "Monitor", line long-dash. Challenge = triangle ! "Challenge", line dash-dot. Block = octagon × "Block", line dotted. Every verdict carries a text label, a glyph, a dash pattern and a hue. Hues never reuse the theme accent. |
| Stage encoding | A numbered step badge plus its label: 1 Recon, 2 Enumeration, 3 Exploitation, 4 Exfiltration. "Clean" is a hollow badge. |
| Focus | 2 px solid ring plus a 4 px soft glow (the ref 1 focus style), with at least 3:1 contrast in both themes. The ring is never removed. |
| Permission gating | `GET /api/v1/endpoints` supplies the permission for each route. The session supplies the user's permission (†, gap G1). A control the user lacks permission for is still shown, disabled, with "Requires Operator" or "Requires Admin" as visible text and in `aria-describedby`. Controls are not hidden, except that the Keys nav item is hidden from users below Admin. |
| Data freshness | Every REST-fed region shows "Updated hh:mm:ss". A region is stale when its data is older than twice its refresh interval. Live data is stale when no frame or heartbeat has arrived for 20 s (15 s heartbeat plus 5 s grace). |

### 1.1 Shared states (every screen applies these; per-screen notes add to them)

| State | Presentation |
|---|---|
| Loading | Skeleton blocks at the final size, so the layout never shifts. Charts show an empty axis frame. The region carries `aria-busy="true"`. A spinner appears only after 300 ms. |
| Empty | An empty-state tile (ref 1) inside the region: one sentence saying why it is empty and one next action, e.g. "No blocks in the last hour. Widen the range." |
| Error | An inline error card in the region, never a full-page error: HTTP status, a plain message and a Retry button. 401 opens the session modal (§2.4) and keeps the URL. 403 shows the permission the action needs. 5xx or a network failure shows Retry with backoff. |
| Stale | The region dims to 70% with a hatched overlay and an "Updated N s ago · Retry" chip. Values stay readable and are never blanked. |
| Live reconnecting | Top-bar Live pill reads "Reconnecting" (the SSE client resends `Last-Event-ID`). Live regions freeze at their last values and show the stale treatment. |
| `Resync` frame | Live regions discard local state and show "Re-syncing" until the next `Snapshot` arrives, then announce "Live view re-synced" politely. |
| Dropped events | The `dropped_total` reported by `Snapshot`/`Counters` and the drops in `GET /status` feed a top-bar chip ("Dropped 0" in neutral styling). When it increases, the chip turns to warning styling with a triangle glyph, and live screens show a dismissible notice: "N events were dropped. The live board reconciles every 30 s. History may be incomplete for this period." The notice links to Dashboard › dropped-event counters. |

## 2. Global shell

### 2.1 Top bar (56 px, full width; follows the ref 2 status bar)

| Region | Fields → source | @1024 / @768 |
|---|---|---|
| Brand + host | Product name, `version` → `GET /status` | @768: the Menu button replaces the nav rail |
| Quick jump | Text input "Request id or source key" → routes to `/requests/{id}` or `/sources/{key}` | @768: icon button that opens the input in a popover |
| Status pills | Worst state (OK / Warn / Degraded / Critical; text + glyph) ← Status frame / `GET /status` worst-state rollup†. Live (Connected / Reconnecting / Offline). `config_rev`. Dropped `dropped_total`. | @768: all collapse into one "Status" pill that opens a popover list |
| Right cluster | Theme toggle (radiogroup), shortcuts help (?), permission badge (Viewer / Operator / Admin) and Sign out (`DELETE /api/v1/session`) | Unchanged |

Clicking the worst-state pill opens a popover listing component states† from `GET /status`, with each state named in text.

### 2.2 Navigation (left rail; order is also the Tab order)

Dashboard · Traffic topology · Monitor · Attack chains · Honeypot & bans · Settings · Keys (Admin only). Request details and Source are detail routes reached from other screens and have no nav entry; when one is open, its parent (Monitor or Attack chains) is marked `aria-current`. The rail footer repeats the Live state as text.

### 2.3 Toasts

Toasts sit bottom-right in a stack of at most 3, inside a region labelled "Notifications". Success and info use `aria-live="polite"`, dismiss after 6 s and pause while hovered or focused. Errors use `role="alert"` and stay until dismissed. A toast never contains the only path to an action: "Saved · rev 13 · View revision" also appears in the relevant screen's history.

### 2.4 Modal (Bits UI Dialog; frosted surface with a diffused shadow, per ref 1)

| Rule | Value |
|---|---|
| Focus | Moves to the first field, or to Cancel in destructive dialogs. Focus is trapped while open and returns to the invoking control on close. |
| Close | Esc and Cancel. Both are disabled while a mutation is in flight, and the confirm button then shows a loading state. |
| Destructive confirm | Names the object and its impact, e.g. "Disable `sqli.union-select`? It decided 412 requests in the last 24 h." The confirm button repeats the verb: "Disable construct". |
| Session modal | Accepts an API key and calls `POST /api/v1/session`. The key is never stored by the page. On success the user returns to the same URL. |

Skip link "Skip to content" is the first focusable element. Shortcuts: `/` focuses the screen's primary search, `g` then a letter navigates, `?` opens help. Single-key shortcuts can be turned off in help (WCAG 2.1.4).

## 3. Dashboard (`/`)

**Question:** Is the service healthy, and is anything attacking us right now?
**Feeds:** one `GET /api/v1/dashboard?from&to` (default the last hour, refreshed every 60 s), plus live `Counters` and `Status` from `GET /api/v1/live?streams=status`.

| Region | @1440 placement | Fields → source |
|---|---|---|
| Worst-state banner | cols 1–12, 48 px | Worst state† and failing components† ← Status. Shown only when not OK; links to the component list. |
| KPI rail (ref 2 left rail) | cols 1–3, full height, 2×3 tiles | RPS by verdict (4 values) ← `Counters.rps_by_verdict`. Active bans count ← dashboard `active_bans`†. Honeypot hits ← `honeypot_hits`†. Dropped ← `dropped_total` and `Status` drops per consumer. |
| Requests over time | cols 4–12, 320 px | uPlot stacked area by verdict ← dashboard `requests_by_verdict`†, from 100% rollups |
| Sources by stage | cols 4–7 | Horizontal bars, one per stage, each labelled with stage and count ← `sources_by_stage`† |
| Top constructs | cols 8–12 | Construct id, family and count (top 10) ← `top_constructs`† |
| Top targeted paths | cols 4–7 | Path prefix, count and verdict mix (top 10) ← `top_paths`† |
| Topology teaser | cols 8–12 | Static thumbnail with the link "Open traffic topology" |

- **Range control:** a 1 h / 6 h / 24 h / 7 d segmented control in the content header. It is kept in the URL as `?from&to`.
- **@1024:** the KPI rail becomes a 4-across tile row above the chart. Chart and lists fill 8 columns.
- **@768:** everything stacks into one column in this order: banner, tiles (2 across), chart, then the lists.
- **Actions:** none that mutate.
  - Every bar or row is a link: a construct opens `/monitor?q=construct:<id>`, a path opens `q=path:<prefix>`, a stage opens `/chains?stage=<s>`.
  - All these links are Viewer level.
- **States:** when there is no traffic yet, each region shows "No requests recorded since start". Dropped events also appear as KPI tile text.
- **Accessibility:**
  - Each chart has a "Show as table" toggle, with time buckets as rows and verdicts as columns.
  - Tiles are `<dl>`.
  - Tab order runs banner → range → tiles → chart → lists.

## 4. Traffic topology (`/topology`) — hero view

**Question:** Where is traffic coming from, what is the shield doing with it, and where are attackers ending up?
**Feeds:**
- Live `GET /api/v1/live?streams=board,blocks,status`: `Snapshot`/`Delta` (`SourceView`s, `blocks`) and `Counters`.
- `GET /api/v1/dashboard` (every 60 s) for `top_paths`†.
- `GET /api/v1/options` for honeypot decoy paths (keys in section `honeypot`†).
- `GET /api/v1/bans`.

**Scene:** a fixed isometric scene, 1:1 at 1176×700, built from pre-rendered props (hashed WebP in `img-src 'self'`, lazy route chunk ≤ 80 KB of JS). Nodes are buttons positioned over the props. A single SVG overlay draws the flow lines, and nothing is force-laid-out.

| Node (left → right) | Prop | Count shown → source |
|---|---|---|
| Clean sources | Low antenna cluster | Allow + Monitor rps → `Counters.rps_by_verdict`. Not per-source: the board excludes clean sources. |
| Recon cluster | Scanner dish cluster | Number of `SourceView` with `stage` ∈ {Recon, Enumeration} and no `ban` |
| Exploitation cluster | Red-lit cluster | Number of `SourceView` with `stage` ∈ {Exploitation, Exfiltration} and no `ban` |
| Shield tower (centre) | Tower on platform (the ref 2 centre piece) | Total rps, `config_rev`, worst state |
| Route groups 1–5 | Five app blocks | Top 5 path prefixes and their counts → `top_paths`† (60 s) |
| Honeypot pods | Decoy pods, one per decoy path (max 6; "+N more" otherwise) | Hits per decoy†. Pod lights for 2 s on a `blocks` item whose cause is Honeypot†. |
| Quarantine pen | Fenced pen | Active bans → `GET /bans` count, updated by `SourceView.ban` changes |

| Edge | Verdict lines | Volume → source |
|---|---|---|
| Each cluster → tower | Recon/exploitation: requests passed and blocked. Clean: allow and monitor. | Recon/exploitation: Δ`requests` and Δ`blocked` summed per cluster over a 5 s window. Clean: `Counters`. |
| Tower → route group | Allow, Monitor (traffic forwarded upstream) | `top_paths` verdict mix† |
| Tower → honeypot pods | Block (honeypot) | Rate of honeypot `blocks` |
| Tower → quarantine | Block (ban) | Rate of `blocks` whose cause is Ban† |
| Tower → "dropped at edge" stub | Challenge, Block (detection) | `Counters` challenge and block |

**Line rules:**
- Stroke width and dash speed come from five volume steps: 0, under 1, 1–10, 10–100 and over 100 rps. A step is never interpolated, so the legend stays exact.
- A line at 0 rps is drawn faint and static.
- Each line carries a numeric rps label at its midpoint (hidden below 1024 px).

**Layout:**

| Region | @1440 |
|---|---|
| Scene | cols 1–12 minus right control rail; 700 px tall |
| Right view rail (ref 2) | 48 px floating column: Table view toggle, pause animation, zoom +/−, reset view |
| Legend (bottom-right, ref 2) | Verdict line patterns with glyph and label, the five volume steps, stage badges |
| Status strip (top-left inside scene) | Live state, `seq`† age, `dropped_total` |

- **@1024:** the scene scales to 952 wide (all props are vector-positioned in percentages) and the legend collapses to a "Legend" button.
- **@768:** the scene is replaced by the table view by default (the scene stays available via the toggle, inside a horizontal scroller with "Scroll the scene" as visible text). Detail cards become a bottom sheet.

**Floating detail card** (hover or focus; a frosted card in the style of ref 2's "Sector C1" card):

| Node | Card contents |
|---|---|
| Cluster | Count, top 5 sources by `last_seen` (`key`, stage badge, `requests`, `blocked`, `top_constructs[0]`), "Open source", "Show in Attack chains" |
| Tower | `rps_by_verdict` as four labelled values, `config_rev`, worst state, "Open dashboard" |
| Route group | Prefix, count, verdict mix, "Open in Monitor" (`q=path:<prefix>*`) |
| Honeypot pod | Decoy path, hits†, last hitting source, "Open Honeypot & bans" |
| Quarantine | Active bans, the 5 soonest to expire (`key`, TTL), "Manage bans" |

- **Actions:** all navigational (Viewer). No mutation happens in the scene; banning is done on the Source page.
- **Keyboard and focus:**
  - Nodes form one roving-tabindex group with a single Tab stop in this order: Clean → Recon → Exploitation → Tower → Route 1–5 → Honeypot pods → Quarantine. Arrow keys move along that order.
  - Focusing a node opens its card (`aria-describedby` points to the card). Enter pins the card and moves focus into it. Esc closes it and returns focus to the node.
  - Tab leaves the scene for the view rail.
  - Each node's accessible name includes its count and rate, e.g. "Exploitation cluster, 7 sources, 42 requests per second, 31 blocked".
- **Accessible alternative:** the "Table view" toggle (`aria-pressed`) swaps the scene for two tables, Nodes (node, kind, count, rps) and Flows (from, to, verdict, rps). The choice is kept in the URL as `?view=table`. The table is the default when `prefers-reduced-motion` is set.
- **Reduced motion:** dashes are static, cards appear without fading and pods stop pulsing (a "Hit" text badge shows for 10 s instead). The Pause control does the same for anyone.
- **States:**
  - Empty: the scene renders with all lines faint and the note "No traffic yet".
  - Live stale or reconnecting: lines turn grey and hatched, with "Live paused" over the tower.
  - Dropped events: the global notice appears. Lines keep drawing because `Counters` is authoritative.

## 5. Monitor (`/monitor`)

**Question:** Which requests match X, and how are they distributed?
**Feeds:** `POST /api/v1/history/query {q, from, to, group_by?, limit, cursor?}`.

| Region | @1440 | Fields |
|---|---|---|
| Query bar | cols 1–9, 48 px | `q` text. Suggestions come from a `group_by` query over the current range and show counts, e.g. typing `construct:` lists `sqli.union-select (412)`. Syntax errors (400) show inline under the bar. |
| Time range | cols 10–12 | Presets 15 m / 1 h / 24 h / 7 d and custom `from`/`to`. A range is always required. |
| Group-by chips | cols 1–12 | `src`, `path`, `construct`, `stage`, `verdict` (toggle buttons, `aria-pressed`) |
| Result header | cols 1–12 | Row count, "Allows sampled at 1%" note, auto-refresh 10 s / 1 min / Off, Updated time |
| Results table | cols 1–12, about 600 px | `ts`, verdict chip, `score`, `src_key`, `method`, `host`, `path`, `construct`, `stage`, `decided_option`, `config_rev`, `latency_us`, `upstream_status`, "sampled" marker on sampled Allows. When grouped, the table shows group value and count only. |
| Pager | bottom | "Load more" (cursor). Page size `limit` is 100 (max 1000). |

- **Interactions:**
  - Clicking or pressing Enter on a cell value adds `field:value` to `q`. Shift+Enter adds the negated `-field:value`.
  - A grouped row drills into an ungrouped query with that filter.
  - Every change is pushed to the URL (`?q&from&to&group_by&refresh`).
- **@1024:** `host`, `latency_us` and `upstream_status` move into an expandable row detail.
- **@768:**
  - The table becomes a list of rows, each showing verdict, `ts`, `src_key`, `path` and `construct`.
  - The time range moves into the query bar row as a select.
  - Chips scroll horizontally.
- **Actions:** all Viewer.
  - Open a request (row Enter).
  - Copy the query URL.
  - Open the source of a row.
- **States:**
  - Auto-refresh pauses while focus is in the table or the user has paged past the first page. In that case "N new results — Show" is announced politely and rows never reorder under focus.
  - The history-writer drop count (`Status` drops for `consumer=history`†) shows above the table: "History writer dropped N events since start; counts may be low."
  - Empty: "No requests match `q` in this range", with a Widen range button.
- **Keyboard and focus:**
  - `/` → query bar. Down arrow opens suggestions (combobox pattern).
  - Tab order runs bar → range → chips → refresh → table (`role="grid"`, arrows between cells) → pager.

## 6. Request details (`/requests/{id}`)

**Question:** Why did this request get this verdict, and which setting decided it?
**Feeds:** `GET /api/v1/requests/{id}` (full judgment, `decided_by`, source timeline), `GET /api/v1/options` for option values and source, and `GET /api/v1/config/revisions` for the bands at the deciding `config_rev` (gap G4).

| Region | @1440 | Fields |
|---|---|---|
| Header | cols 1–12 | Verdict chip, `id`, `ts_ms`, `method` `host` `path`, `src` (link), `ip`, `latency_us`, `upstream_status`, `config_rev` |
| Why panel | cols 1–7 | `decided_by.msg` rendered as a sentence by `kind` (examples follow this table) |
| Score gauge | cols 8–12 | Semicircle gauge (ref 2 style) with band arcs for monitor, challenge and block, taken from `scoring.monitor_at`/`challenge_at`/`block_at` at that rev, and a needle at `score` |
| Contributions table | cols 1–12 | `engine`, `field.loc:field.name`, `construct`, `value` (FourValued as text), `weight`, `points`. Sorted by `points` descending. A footer shows "Σ points ≈ score". |
| Chain outcome | cols 1–6 | `judgment.chain` stage and event; `normalized_layers` |
| Source timeline | cols 7–12 | The last N requests from this source (from the response), linking to each |

Example "why" sentences:

> Blocked: score 94 reached `scoring.block_at` = 90 (override). Top evidence: `sqli.union-select` in `query:id`.

The setting reference is a link to `/settings?highlight=scoring.block_at`. When `decided_by.construct` is present, a second link "Construct `sqli.union-select`" goes to `/settings?highlight=shield.disabled&construct=sqli.union-select`.

| Kind | Sentence |
|---|---|
| Honeypot | "Request hit decoy `<path>`." |
| Ban | "Source banned until hh:mm." |
| IntelDeny | "Source on intel deny list." |
| Limit | "Fail-closed: `limit.payload-truncated` (`<option_key>`)." |
| Allowlisted | "Source allow-listed." |
| NoEvidence | "No evidence; allowed." |

- **@1024:** the gauge moves under the why panel, and the panel spans 8 columns.
- **@768:** single column in this order: header, why, gauge, contributions (as cards), chain, timeline.
- **Actions:**

  | Action | Perm | Behaviour |
  |---|---|---|
  | Open source | Viewer | → `/sources/{src}` |
  | Open setting | Viewer | Deep link as above |
  | Ban source | Operator | Opens the ban modal with TTL 1 h / 6 h / 24 h / Permanent → `POST /bans` |
  | Disable this construct | Admin | Destructive modal showing impact (count from history `construct:<id>` over 24 h), then `PATCH /config` adding the construct to `shield.disabled`. On success: toast with the new rev. |

- **States:**
  - 404: "Request not found. Rows older than `history.retention_days` are removed." A Monitor link follows.
  - Sampled Allow: a banner reads "Sampled request (1% of Allows)".
  - Snippets: shown only if `history.store_snippets` is on. Otherwise the text "Field values not stored" appears.
- **Accessible alternative:** next to the gauge, a `<p>` reads "Score 94 of 100. Bands at rev 12: Monitor ≥ 40, Challenge ≥ 70, Block ≥ 90." The gauge SVG is `aria-hidden`.
- **Focus:** on load, focus goes to `h1` (verdict and id). Tab order runs why links → actions → contributions table.

## 7. Attack chains — live (`/chains`), the primary live screen

**Question:** Which sources are progressing through the kill chain, how far have they got, and are they contained?
**Feeds:** live `board` stream (`Snapshot` then `Delta.upserts`/`removes`), capped at 500 sources and ordered by stage, then recency.

| Region | @1440 | Fields |
|---|---|---|
| Toolbar | cols 1–12 | Filter by minimum stage, "Banned only", key search, row count "N of ≤ 500", Live state, `dropped_total` |
| Grid (`role="grid"`) | cols 1–12, fills the height with virtual rows of 44 px | Columns listed below |
| Pending-order bar | sticky bottom | "Order paused while you navigate — 12 updates. Apply (R)" |

Grid columns:
1. Source: `key`, with `ip` as secondary text.
2. Recon.
3. Enumeration.
4. Exploitation.
5. Exfiltration.
6. Requests / Blocked: `requests`, `blocked`.
7. Honeypot: `honeypot_hits`.
8. Ban: badge "Banned · 42 min left" from `ban`†, or "Permanent".
9. Last seen: `last_seen`, relative time.

Each stage cell shows the first-reached time and a count taken from `stage_path` (gap G5). An unreached cell reads "—". The current `stage` cell is emphasised with its step badge.

- **Row motion:** rows reorder with a keyed FLIP animation (none under reduced motion). While focus is inside the grid, order is frozen and values still update in place. Applying the new order keeps focus on the same `key`.
- **Removed sources:** a row removed by `removes` while focused stays as "Source left the board" until focus moves.
- **@1024:** Requests/Blocked and Honeypot merge into one "Activity" column, and Last seen becomes secondary text under Source.
- **@768:** the grid becomes a list of cards. Each card shows the source key, a 4-step progress row (badges 1–4 filled up to the current stage, with text "Stage 3 of 4: Exploitation"), the ban badge and the activity line.
- **Actions:** Open source (Viewer; Enter or click on a row). Ban and lift are not done here; the row's Source page has them.
- **States:**
  - Empty: "No source has reached Recon in the chain window."
  - Snapshot loading: a skeleton of 10 rows.
  - Resync: the grid dims and rebuilds from the new `Snapshot`, keeping focus by `key` where it still exists.
  - Live stale: "Board last updated hh:mm:ss", and TTL countdowns keep running on the client.
- **Keyboard:**
  - One Tab stop. Arrow keys move between cells, Home/End jump to the row ends, Ctrl+Home goes to the first row, PageUp/PageDown move 10 rows.
  - Enter opens the source. R applies the pending order.
- **Screen readers:** cell names read like "Exploitation: reached 14:02, 9 events". The TTL countdown updates visually every second but its text changes only once a minute (`aria-live="off"`).

## 8. Source (`/sources/{key}`)

**Question:** What has this source done, where is it in the chain, and should it be banned?
**Feeds:** `GET /api/v1/sources/{key}` (chain state, chain events, ban), plus `history/query` with `q=src:<key>`. While open, live `board` upserts filtered to this `key` keep the page current.

| Region | @1440 | Fields |
|---|---|---|
| Header | cols 1–12 | `key`, `ip`, stage badge, ban badge (reason†, until†, offences†), `first_seen`, `last_seen`, `requests`, `blocked`, `honeypot_hits` |
| Kill-chain timeline | cols 1–8, 220 px | d3-scale SVG: four stage lanes against time, one marker per chain event (shape by stage), ban spans shaded with a "Banned" label |
| Top constructs | cols 9–12 | `top_constructs` (id, count), each linking to Monitor |
| Requests | cols 1–12 | The Monitor table component, pre-filtered `src:<key>` and locked (shown as a chip) |

- **@1024:** top constructs move under the timeline.
- **@768:** single column. The timeline defaults to its table form.
- **Actions** (all through the ban modal):

  | Action | Perm | Call |
  |---|---|---|
  | Ban | Operator | `POST /bans {key, ttl}` |
  | Extend | Operator | `POST /bans` with the existing key and a new TTL† |
  | Lift | Operator | `DELETE /bans/{key}`, confirmed in a modal |

  Auto-ban policy text sits beside the controls: "Auto-bans: honeypot hit, exfiltration block, or 3 exploitation blocks in 10 min; 1 h doubling to 24 h."
- **States:**
  - 404 or not on the board: "No chain state; the window has expired." Requests and the ban still show.
  - A live update to this source flashes the header briefly (no flash under reduced motion) and politely announces "Stage changed to Exploitation".
- **Accessible alternative:** the timeline has "Show as table", with columns `ts`, stage, request id link.
- **Focus:** on load, focus goes to `h1`. Tab order runs header actions → timeline toggle → constructs → requests.

## 9. Honeypot & bans (`/honeypot`)

**Question:** Are the decoys being hit, and who is quarantined, for how long?
**Feeds:** `GET /api/v1/options` (honeypot section†), `GET /api/v1/dashboard` `honeypot_hits`† series, `history/query` grouped by `path` with a honeypot cause filter (gap G6), `GET /api/v1/bans`, and live `board` for ban changes.

| Region | @1440 | Fields |
|---|---|---|
| Decoy list | cols 1–4 | Decoy path, hits in range, last hit time. A link "Edit decoys" goes to Settings highlighting the honeypot key. |
| Hits over time | cols 5–12, 240 px | uPlot bars ← `honeypot_hits`† |
| Bans table | cols 1–12 | `key`, reason†, since†, expires / TTL countdown, offences†, manual or auto†. Sortable and filterable. |
| Manual ban form | Collapsible panel above the table | Source key (IPv4 /32 or IPv6 /64, validated client-side), TTL (1 h / 6 h / 24 h / Permanent) |

- **@1024:** the decoy list sits above the chart.
- **@768:** single column, and the bans table becomes cards.
- **Actions:**

  | Action | Perm |
  |---|---|
  | Lift (row) | Operator, with confirm modal |
  | Extend (row) | Operator |
  | Manual ban | Operator |
  | Edit decoys | Viewer (navigation); saving the setting is Admin |

- **States:** empty bans reads "No active bans". With no decoys configured, the panel says "No decoys configured" and links to Settings.
- **Accessible alternative:** the chart has a table toggle. The countdown follows the screen-reader rule from §7.

## 10. Settings (`/settings`)

**Question:** What is configured, what differs from defaults, and how do I change it safely?
**Feeds:**
- `GET /api/v1/options`: descriptors with `key`, `kind`, bounds, `section`, help markdown, expertise level, `Apply::Live|Restart`, `sensitive`, effective value, default, and source (default / base / override).
- `POST /config/validate`, `PATCH /config {base_rev, set, unset}`.
- `GET /config/revisions`, `GET /constructs`.

| Region | @1440 | Contents |
|---|---|---|
| Section index | cols 1–2, sticky | Section names, each with a changed-count badge |
| Filter bar | cols 3–12 | Key or help text search, expertise filter (Basic / Advanced / Expert), "Changed from default only" |
| Option list | cols 3–9 | One row per option: label and `key`, control by `kind` (number with bounds, toggle, select, list editor; the construct multi-select for `shield.disabled` comes from `/constructs`), help (expandable), markers "Changed from default", "Source: override/base", "Restart required" (for `Restart` options), and "Sensitive · redacted" (read-only) |
| Pending-changes drawer | cols 10–12, sticky | Diff preview (key: old → new, and unsets), Validate, Save, Discard |
| Tabs | Above the list | Options / Revision history (rev, time, keys changed, author key id†) |

- **Deep link:** `?highlight=<key>` (and `&construct=<id>` for `shield.disabled`) does the following:
  - clears filters that would hide the option;
  - scrolls to the row and focuses its control;
  - outlines the row and announces "Highlighted: scoring.block_at".
- **@1024:** the section index becomes a select above the list, and the drawer becomes a sticky bottom bar ("3 pending changes — Review") that opens a side sheet.
- **@768:** single column, and the review opens as a full-screen dialog.
- **Actions:**

  | Action | Perm | Behaviour |
  |---|---|---|
  | Edit values locally | Viewer | Viewers see controls read-only. Editing a draft starts at Operator. |
  | Validate | Operator | `POST /config/validate`. Per-key issues show inline under each field (`aria-invalid`, `aria-describedby`) and as a summary list with jump links. |
  | Save | Admin | `PATCH /config`. 422 places per-key errors inline and keeps the draft. 409 shows "Config changed to rev M since you loaded rev N", offers Reload and re-apply my changes, and re-diffs. Success shows the toast "Saved · rev M" and, if needed, a "Restart required" banner. |
  | Reset to default | Admin | Adds an `unset` entry for the key |

- **States:**
  - When another operator applies a change while this page is open, the page shows "Rev N+1 applied elsewhere — reload".
  - A Warn state about rejected keys (from Status) shows as a banner listing the keys.
- **Focus:** on load, focus goes to the filter search, unless `highlight` is present. The drawer is a labelled region. Opening review moves focus to its heading.

## 11. Keys (`/keys`) — Admin only

**Question:** Who can access the admin API, with what permission, and until when?
**Feeds:** `GET`/`POST /api/v1/keys`, `DELETE /api/v1/keys/{id}`.

| Region | @1440 | Fields |
|---|---|---|
| Keys table | cols 1–9 | `id`, permission, created†, expires (relative time, with a warning glyph under 7 days), label†, last used† |
| Create panel | cols 10–12 | Permission (Viewer / Operator / Admin radio), TTL (1 d / 7 d / 30 d / 90 d; 90 is the maximum), label† |

- **Create:** opens a modal showing `vft_<id>_<secret>` once, in a monospace field with a Copy button. The checkbox "I have stored this key" must be ticked before Close is enabled. Esc is disabled for this dialog only, with that stated in the dialog text.
- **Revoke:** a destructive modal names the key id and permission → `DELETE`. Revoking the key behind the current session warns that the user will be signed out.
- **Responsive:** @1024 the create panel moves above the table. @768 the table becomes cards.
- **States:** a 403 for non-Admins reached by URL shows the "Requires Admin" page. Empty: "Only the bootstrap key exists" (if listed).

## 12. Cross-screen flows

| Flow | Steps | Focus and back behaviour |
|---|---|---|
| Blocked request → why → setting | 1. Monitor with `q=verdict:block`. 2. Enter on a row opens Request details, with focus on `h1`. 3. Tab to the why sentence and Enter on `scoring.block_at` opens `/settings?highlight=scoring.block_at`, which focuses the control. 4. Edit, then Validate (Operator). 5. Save (Admin) gives toast "rev 13". 6. "View in Monitor" opens `q=config_rev:13` (gap G7), and the next judgment shows `config_rev` 13. | Back returns to Request details with focus on the link, then to Monitor with the row focused (focus is keyed by `id` and kept in history state). |
| Topology card → source | 1. Focus the Exploitation cluster (arrow keys), which opens its card. 2. Enter pins the card and moves focus to its first source. 3. Enter opens `/sources/{key}`. | Back restores `?view` and refocuses the cluster node with the card closed. |
| Grid row → source | 1. On Attack chains, arrow to a row. 2. Enter opens `/sources/{key}`. | Back restores the filters and focuses the same `key` row, or the nearest row if that one left the board. |
| Request → source → ban | Request details → Open source → Ban (Operator) → the quarantine counter in Topology and the grid badge update within 1 s via `board`. | — |

## 13. Journey — "an exploitation burst starts"

1. An operator has Dashboard open. Within 1 s the `Counters` Block value in the KPI rail climbs from 0.4 to 38 rps, and the tile text reads "Block 38/s".
2. The live `board` delivers `Delta.upserts` for six sources reaching Exploitation. The "Sources by stage" bar for Exploitation updates on the next dashboard refresh, and the top-bar status stays OK because the service itself is healthy.
3. The operator presses `g t` for Traffic topology. The Exploitation cluster shows "6", and its edge to the tower carries a thick dotted Block line labelled "31/s" beside a thinner solid Allow line.
4. Arrow keys move to the Exploitation cluster and its card opens. It lists `203.0.113.7`, stage 3 Exploitation, 240 requests, 188 blocked, top construct `sqli.union-select`.
5. One source hits `/wp-admin.bak`. The honeypot pod shows a "Hit" badge (reduced motion is on), the auto-ban fires, and the quarantine pen goes from 0 to 1 while that source leaves the cluster count.
6. The top-bar Dropped chip turns to warning styling with "Dropped 214" (the history writer lagged under the flood). A notice explains that the board reconciles within 30 s and history may be incomplete.
7. The operator presses `g c` for Attack chains. Focus enters the grid and the order freezes. Row 1 is `203.0.113.7`, with Exploitation reached at 14:02 and 9 events and Exfiltration "—". Row 2 carries a "Banned · 59 min left" badge.
8. Enter on row 1 opens Source. The timeline shows Recon at 13:58 and Exploitation at 14:02. Top constructs lists `sqli.union-select (171)`.
9. In the Requests table the operator opens one Block. The why sentence reads "Blocked: score 97 reached `scoring.block_at` = 90 (default). Top evidence: `sqli.union-select` in `query:id`." The contributions confirm it.
10. Back on Source, the operator (Operator permission) bans for 24 h, and the modal confirms "Ban 203.0.113.7 for 24 h?" The result: toast "Banned until 14:07 tomorrow", the grid badge updates, and the quarantine count in Topology becomes 2.
11. The operator checks Dashboard › Top targeted paths, sees `/api/search` as the target, and opens Monitor with `q=path:/api/search* stage:exploitation` to check whether other /24s are probing. Grouping by `src` shows 2 more sources, which are banned the same way.
12. After 30 s the board reconciliation runs and the Dropped chip stops rising. The operator leaves Attack chains open, since it is the primary live screen.

## 14. Spec gaps to close before SP6

| # | Needed by | Gap | Proposed addition |
|---|---|---|---|
| G1 | Shell gating | The current user's permission is not exposed | `GET /api/v1/session` → `{perm, key_id, expires}` (Public / any) |
| G2 | Dashboard, Topology | `/dashboard` response shape is unnamed | Name the fields `requests_by_verdict`, `sources_by_stage`, `top_constructs`, `top_paths{prefix, count, by_verdict[4]}`, `honeypot_hits`, `active_bans`, `dropped` |
| G3 | Shell, Settings | `StatusRecord` fields are unnamed | `{worst, components[{name, state, msg}], drops{consumer: n}, config_rev, version, restart_required}` |
| G4 | Request details gauge | The bands of the deciding rev need a revisions walk | Include `bands{monitor_at, challenge_at, block_at}` in `GET /requests/{id}` |
| G5 | Chains grid cells | Per-stage count is not in `SourceView` | Add `stage_counts: [u32; 4]`, or define the count as occurrences in `stage_path` |
| G6 | Honeypot hits per decoy | The `q` whitelist has no cause field | Add `cause:` (CauseKind) and `config_rev:` (also needed by G7) to the DSL |
| G7 | Flow verification | Filtering by `config_rev` | Same addition as G6 |
| G8 | Bans, Topology | `BanView`, `BlockLite` and extend semantics are undefined | `BanView{until, reason, offences, manual}`; `BlockLite{id, ts_ms, key, path, cause_kind, construct}`; extend = `POST /bans` upsert |
| G9 | Topology recon/exploit edges | Per-cluster rates are derived from `SourceView` deltas | Acceptable as derived; label "approx." in the table view |
| G10 | Keys table | created / last used / label are not specified | Add them to the key list response |
