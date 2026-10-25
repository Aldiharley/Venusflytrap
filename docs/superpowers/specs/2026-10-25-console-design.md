# Venusflytrap console — design spec (SP6)

*Date: 2026-10-25 · Status: draft for review · Parent: `docs/superpowers/specs/2026-10-25-operable-service-design.md` (§5.8 admin API, §5.9 live channel, §5.10 console, §6 SP6). This spec fixes the console's look, screens and data needs. The implementation plan for SP6 is written when SP6 starts, after SP2–SP5 land.*

## 1. Goal

An operator console that answers three questions fast and accessibly:

1. **Is the shield healthy and what is it stopping right now?** (dashboard, traffic topology, live attack chains)
2. **Why was this request blocked, and which setting decided it?** (monitor → request details → jump to setting)
3. **What do I change?** (bans, constructs, settings, keys)

The look comes from two owner-supplied references; the content is Venusflytrap's own. No outside product names, logos or assets appear in the console.

## 2. Decisions (owner-approved)

| # | Decision |
|---|---|
| D1 | **Two themes.** Light follows reference 2 (warm-grey isometric operations board); dark follows reference 1 (charcoal frosted-glass kit). Default follows `prefers-color-scheme`; a manual toggle overrides it. |
| D2 | **Hero "Traffic topology" view.** A fixed isometric scene of pre-rendered props with live SVG overlay lines, floating detail cards, and a one-toggle table view with the same information. |
| D3 | **Scene composition.** Internet edge → source clusters grouped by kill-chain stage (Clean / Recon / Exploitation) → the Venusflytrap shield tower → the top 5 route groups (busiest path prefixes) → honeypot decoy pods → a quarantine pen of banned sources. Lines are coloured and patterned by verdict. |
| D4 | **The accessible stage grid stays the primary live attack-chain screen.** The map is a hero view, not the only way to see live state. |
| D5 | **Props are generated once as a fixed kit** (8 transparent WebP files) and shipped as static assets. No 3D engine at runtime. |
| D6 | Svelte 5 + Vite + Bits UI, ≤ 150 KB initial JS gzipped, axe-core zero serious/critical violations in both themes, keyboard-complete, never colour alone (parent spec §5.10). |

## 3. Sources of truth

| Artefact | Owns | Location |
|---|---|---|
| UX architecture | Screens, regions, data-field mapping, permissions, states, keyboard and focus models, flows, journey | `docs/superpowers/design/console-ux-architecture.md` |
| Visual design system | Colour tokens (both themes, computed contrast), elevation, glows, type, motion, 20 component specs, topology overlay styling, ready-to-paste CSS custom properties | `docs/superpowers/design/console-design-system.md` |
| Mockups | Five representative screens plus a component sheet, both themes | Design canvas "Venusflytrap Console Design" (`https://claude.ai/artifact/HuxfLvbmg8onvbXXmVu1sj`, private); sources in `docs/superpowers/design/canvas/project/` |
| Prop kit | The 8 isometric props, their prompts and generation records | `ui/assets/props/*.webp`, `ui/assets/props/manifest.json` |

When these disagree, the order of precedence is: this spec → the UX architecture (layout, behaviour, copy) → the design system (styling) → the mockups (illustration only; sample data).

## 4. Screens

| Screen | Route | Mocked | One-line purpose |
|---|---|---|---|
| Shell | — | yes (all boards) | Top status bar (worst state, config rev, live state + dropped count, enforce switch, theme), 72 px nav rail, toasts, modal |
| Dashboard | `/` | no | One batched `/dashboard` call: verdicts over time, sources by stage, top constructs and paths, honeypot hits, bans, drops |
| Traffic topology | `/topology` | yes, light + dark | §5 |
| Monitor | `/monitor` | yes, light | `field:value` query with highlighting and counted suggestions, group-by, sampled-Allow notice, blocked-row styling, link to the deciding option |
| Request details | `/requests/{id}` | yes, dark | Score gauge on the deciding revision's bands, the `decided_by` sentence, jump to setting, contributions table, source timeline, raw vs decoded field |
| Attack chains (live) | `/chains` | yes, dark | Table grid of sources × Recon / Enumeration / Exploitation / Exfiltration; first-reached time and count per cell; ban cause and TTL; rows never reorder under focus ("Apply (R)") |
| Source | `/sources/{key}` | no | Kill-chain timeline, the source's requests (pre-filtered monitor), ban / lift |
| Honeypot & bans | `/honeypot` | no | Decoy paths, hits over time, bans table with lift / extend / manual ban |
| Settings | `/settings` | no | Rendered from `/api/v1/options`: sections, expertise filter, changed and override markers, inline 422 errors, diff preview, restart-required badge, deep-link highlight |
| Keys | `/keys` | no | Admin only: create scoped expiring key (shown once), list, revoke |

Unmocked screens are fully specified in the UX architecture; they reuse the shell and components already on the canvas.

## 5. Traffic topology view

- **Scene.** A fixed 960 × 720 isometric scene on the base plate. Nodes: Internet edge (1), source pods (3, one per stage cluster), junction boxes (2), shield tower (1), route blocks (5), honeypot pods (≥ 1, one per configured decoy, at most 4 shown), quarantine pen (1). Positions are fixed per node type; data never moves props.
- **Data mapping.** Cluster membership and counts come from the live `BoardState` (`SourceView.stage`); route groups and volumes from the `/dashboard` `top_paths` aggregate (G2); honeypot hits and bans from `BlockLite` / `BanView` (G8). Per-cluster rates are derived from board deltas and labelled "approx." in the table view (G9).
- **Lines.** A static base stroke carries the meaning (verdict colour + dash pattern + width step). A moving packet stroke carries motion only and disappears under reduced motion or "Pause animation". Five fixed volume steps; never interpolated. Exact values: design system §5.
- **Interaction.** Every node is a focusable button (Tab / arrow keys). Focus or hover opens the floating detail card; Enter pins it. The card's actions are "Show in grid" (→ `/chains` filtered) and "Open source" (→ `/sources/{key}`).
- **Accessibility.** The table view is in the URL (`?view=table`), carries every number the map shows, and is the default under `prefers-reduced-motion`. Props are decorative (`alt=""`); nodes are named by their label chips.
- **Stale / reconnecting.** All lines switch to the idle stroke, packets stop, a hatch overlay covers the scene, and the top bar's live pill shows the state.

## 6. Visual system (summary)

- Tokens live in `ui/src/styles/tokens.css`, copied from the design system's CSS block; a CI test recomputes every contrast ratio from that file (text ≥ 4.5:1; lines, focus rings and control borders ≥ 3:1).
- Verdicts use glyph + word (circle-check / eye / triangle / octagon); stages use numbered shapes (circle 1, square 2, diamond 3, hexagon 4; Clean is a hollow circle); evidence uses the shield family. Monitor is violet and Recon is teal so no semantic hue reuses the blue accent.
- Fonts: Inter 4 Variable and JetBrains Mono (both SIL OFL 1.1), self-hosted woff2 with system fallbacks. No CDNs (strict CSP). The mockups load them from Google Fonts for convenience only.
- Glass falls back to solid surfaces when `backdrop-filter` is unsupported or reduced transparency is requested; `text-muted` is never used on glass over the topology canvas.

## 7. Assets

| Prop | File | Size | Use |
|---|---|---|---|
| Edge gateway | `edge-gateway.webp` | 15 KB | Internet edge |
| Source pod | `source-pod.webp` | 20 KB | Stage clusters ×3 |
| Shield tower | `shield-tower.webp` | 51 KB | Venusflytrap |
| Route block | `route-block.webp` | 43 KB | Route groups ×5 |
| Honeypot flytrap | `honeypot-flytrap.webp` | 29 KB | Decoys |
| Quarantine cage | `quarantine-cage.webp` | 42 KB | Banned sources |
| Base plate | `base-plate.webp` | 24 KB | Scene ground |
| Junction box | `junction-box.webp` | 24 KB | Line junctions |

Total ≈ 249 KB, 512 px max side, real alpha. Generated with the Higgsfield CLI (Nano Banana Pro, 2k renders, background removal), 24 renders + 8 cut-outs for 56 credits; every prompt and job id is in `manifest.json`. The 2k originals stay out of version control (`ui/assets/props/raw/` and `ui/assets/props/picks/` are added to `.gitignore`). `manifest.json` records the owner's generation URLs, so it is committed only with those URLs stripped. Contact shadows are restored in CSS (design system §5) because background removal drops them.

## 8. Required amendments to the parent spec (from the UX architecture, G1–G10)

These close data gaps the screens depend on. They belong to the sub-projects named; each is a small, additive API change.

| Gap | Needed by | Amendment | Owner |
|---|---|---|---|
| G1 | Shell permission gating | `GET /api/v1/session` → `{perm, key_id, expires}` (Public) | SP5 |
| G2 | Dashboard, topology | Name the `/dashboard` fields: `requests_by_verdict`, `sources_by_stage`, `top_constructs`, `top_paths{prefix, count, by_verdict[4]}`, `honeypot_hits`, `active_bans`, `dropped` | SP4/SP5 |
| G3 | Shell, settings | `StatusRecord = {worst, components[{name, state, msg}], drops{consumer: n}, config_rev, version, restart_required}` | SP3 |
| G4 | Request-details gauge | `GET /api/v1/requests/{id}` includes `bands{monitor_at, challenge_at, block_at}` of the deciding revision | SP4/SP5 |
| G5 | Chains grid cells | `SourceView.stage_counts: [u32; 4]` | SP5 |
| G6 | Honeypot hits per decoy | Add `cause:` (CauseKind) to the history query whitelist | SP4 |
| G7 | "Confirm new config_rev" flow | Add `config_rev:` to the history query whitelist | SP4 |
| G8 | Bans, topology | `BanView{until, reason, offences, manual}`; `BlockLite{id, ts_ms, key, path, cause_kind, construct}`; extend = `POST /api/v1/bans` upsert | SP5 |
| G9 | Topology edge rates | Accept derived per-cluster rates; label them "approx." in the table view | SP6 (no API change) |
| G10 | Keys table | Key list returns `created`, `last_used`, `label` | SP5 |

The parent spec's SP4/SP5 sections are updated with these when those sub-projects are planned.

## 9. Acceptance (adds to parent spec §6 SP6)

- Every acceptance item of parent spec SP6 (JS budget, axe in both themes, keyboard path blocked-request → why → setting → saved/422 → new `config_rev`, no CSP violations, board update ≤ 1 s after a replayed honeypot hit).
- Topology table view shows every number the map shows (test compares both renderings of one fixture).
- Under `prefers-reduced-motion` and "Pause animation", no element animates and no information is lost (packet strokes hidden; base strokes and counts unchanged).
- Contrast CI test passes on `tokens.css` for both themes.
- Prop assets ≤ 300 KB total and served same-origin with `Cache-Control: immutable`.
- Each mocked screen's implementation is reviewed side by side with its canvas board before merge.

## 10. Not covered yet

- Mockups for Dashboard, Source, Honeypot & bans, Settings and Keys (specified, not drawn).
- A specialist review of the mockups themselves (the specs were specialist-written; the drawn boards have not been reviewed or visually checked).
- Mobile layouts below 768 px (the UX architecture defines collapse rules down to 768 px only).

## 11. Open questions

1. **Generated-asset licence.** The props come from Higgsfield. Before committing them to an Apache-2.0 repository, confirm that the account's terms grant ownership or a redistribution licence for generated images. Recommendation: check the plan's terms; if unclear, keep the props out of the repo and load them from a separately licensed asset bundle.
2. **Dashboard vs topology as landing page.** The UX architecture lands on Dashboard. Recommendation: keep Dashboard as `/` and put a topology thumbnail on it that links to `/topology`.
