# Venusflytrap console: visual design system

Status: token and component specification for SP6, to be implemented as `ui/src/styles/tokens.css`. It is a companion to `console-ux-architecture.md`, which owns layout, behaviour and copy; this document owns colour, depth, type, motion and component styling. Light theme takes its style from reference 2 (a warm-grey isometric operations board), and dark from reference 1 (a charcoal frosted-glass kit). Only the style is taken, never the content.

Every contrast ratio below was computed with the WCAG 2.x relative-luminance formula against the **solid** surface value. For glass, the ratio was also checked against the worst-case composite (§1.6).

## 1. Colour

### 1.1 Surfaces, text, borders, focus, accent, attention

| Token `--vf-…` | Light | Dark | Use | Text pairing → ratio (L / D) |
|---|---|---|---|---|
| `surface-base` | `#D6D1CB` | `#17191D` | App ground, topology canvas | text-primary 11.30 / 15.15 |
| `surface-sunken` | `#CAC4BD` | `#101215` | Wells, tracks, nav rail, gauge track | text-primary 9.91 / 16.15; text-muted 4.60 / 7.30 |
| `surface-raised` | `#EEEBE7` | `#252B36` | Cards, tiles, tables, top bar (solid fallback) | text-primary 14.42 / 12.24 |
| `surface-raised-glass` | `rgb(238 235 231 / .80)` | `rgb(37 43 54 / .88)` | Same, with backdrop blur | composite on base: `#E9E6E1` / `#232933` |
| `surface-overlay` | `#F7F5F2` | `#2D3442` | Popovers, modals, detail card (solid) | text-primary 15.75 / 10.75 |
| `surface-overlay-glass` | `rgb(247 245 242 / .88)` | `rgb(45 52 66 / .94)` | Same, with blur | see §1.6 |
| `surface-input` | `#F7F5F2` | `#101215` | Inputs, query bar | text-primary 15.75 / 16.15 |
| `surface-scrim` | `rgb(30 27 24 / .40)` | `rgb(5 6 8 / .64)` | Modal backdrop | — |
| `text-primary` | `#1E1B18` | `#ECEEF2` | Body, values, titles | 14.42 / 12.24 on raised |
| `text-secondary` | `#48423C` | `#B9BFCA` | Labels, captions, small-caps labels | 8.34 / 7.69 on raised; 6.53 / 9.53 on base |
| `text-muted` | `#565049` | `#9AA2B0` | Timestamps, counts in menus (solid surfaces only) | 6.70 / 5.53 on raised; 7.31 / 4.86 on overlay |
| `text-disabled` | `#8C847B` | `#6C7585` | Disabled labels (WCAG-exempt) | 3.10 / 3.06 on raised |
| `text-on-accent` | `#FFFFFF` | `#0A1430` | Text on accent fills | 7.10 / 7.50 |
| `text-on-attention` | `#231804` | `#231804` | Text on gold fills | 8.95 / 9.84 |
| `text-on-danger` | `#FFFFFF` | `#2A0705` | Text on danger fills | 6.54 / 8.13 |
| `border-hairline` | `rgb(30 27 24 / .12)` | `rgb(255 255 255 / .08)` | 0.5 px card edge (decorative) | — |
| `border-subtle` | `rgb(30 27 24 / .20)` | `rgb(255 255 255 / .14)` | 1 px dividers, row rules (decorative) | — |
| `border-strong` | `#7A7269` | `#77808F` | Boundaries of inputs, switches, sliders, checkboxes | UI 3:1 → 3.98 / 3.57 raised; 3.12 / 4.42 base; 4.35 / 3.13 overlay |
| `edge-highlight` | `rgb(255 255 255 / .70)` | `rgb(255 255 255 / .08)` | 1 px inner top light (neumorphic lip) | — |
| `focus-ring` | `#2353B3` | `#76A6FF` | 2 px focus outline | UI 3:1 → 4.68 / 7.27 base; 5.97 / 5.87 raised; 6.52 / 5.16 overlay |
| `accent` | `#2353B3` | `#76A6FF` | Primary action, links, on-state, active nav | as text: 5.97 / 5.87 raised; 4.68 / 7.27 base |
| `accent-hover` | `#1D4799` | `#93B9FF` | Hover fill | on-accent 8.70 / 9.19 |
| `accent-active` | `#173A7D` | `#5A8FF0` | Pressed fill | on-accent 10.84 / 5.73 |
| `accent-soft` | `#D9E3F6` | `#1E2C47` | Hover rows, selected menu item, ghost hover | accent 5.50 / 7.05; text-primary 13.28 / 12.00 |
| `attention` | `#7A4F00` | `#E6BD68` | Selected outline, "needs you" text and icon | 6.00 / 8.02 raised; 4.70 / 9.93 base |
| `attention-fill` | `#E9B04A` | `#E6BD68` | Slider thumbs, selected-segment fill | text-on-attention 8.95 / 9.84 |
| `attention-soft` | `#F4E2C0` | `#3A2F14` | Selected row, attention banner | attention 5.60 / 7.42 |
| `danger` | `#B3261E` | `#FF8A80` | Destructive button fill, destructive text | 5.50 / 6.23 as text on raised |
| `danger-hover` | `#96201A` | `#FFA59D` | Destructive hover | on-danger 8.34 / 9.83 |
| `row-hover` | `#E2E6EE` | `#2A3550` | Table row hover | text-primary 13.70 / 10.49 |
| `row-selected` | `#F3E6CC` | `#342D1D` | Table row selected | 13.88 / 11.75 |
| `row-blocked` | `#F2DEDA` | `#33201F` | Row whose verdict is Block | 13.25 / 13.22 |

### 1.2 Verdict and kill-chain stage

Each set has `-fg` (text, icon, chip border), `-bg` (chip fill) and, for verdicts, `-line` (topology stroke). The ratios given are fg on bg, then fg on surface-raised.

| Token | Light fg / bg | Dark fg / bg | Glyph (Lucide, ISC licence, inlined) | fg/bg L · D | fg/raised L · D |
|---|---|---|---|---|---|
| `verdict-allow` | `#1D6B3A` / `#D3EAD9` | `#7FD99D` / `#173528` | `circle-check` (circle ✓) | 5.14 · 7.81 | 5.49 · 8.33 |
| `verdict-monitor` | `#4337A3` / `#E1DDF6` | `#B0A9FF` / `#29275A` | `eye` | 6.86 · 6.50 | 7.64 · 6.74 |
| `verdict-challenge` | `#8A4F00` / `#F5E2BF` | `#F2C46B` / `#3B2E10` | `triangle-alert` (triangle !) | 5.16 · 8.13 | 5.52 · 8.72 |
| `verdict-block` | `#A3221A` / `#F6D5D1` | `#FF928A` / `#4A1F1C` | `octagon-x` (octagon ×) | 5.48 · 6.47 | 6.31 · 6.59 |
| `stage-none` ("Clean") | `#55504A` / `#E1DDD8` | `#B9BFCA` / `#2B303A` | hollow circle badge "–" | 5.90 · 7.17 | 6.71 · 7.69 |
| `stage-recon` | `#0F5F6B` / `#CFE7EA` | `#6CCFD8` / `#14343A` | circle badge "1" | 5.67 · 7.30 | 6.16 · 7.82 |
| `stage-enumeration` | `#6E5600` / `#F0E5B5` | `#E9D06A` / `#373214` | square badge "2" | 5.54 · 8.41 | 5.90 · 9.27 |
| `stage-exploitation` | `#9A440A` / `#F7DBC5` | `#FFAA6B` / `#44280E` | diamond badge "3" | 4.96 · 7.21 | 5.51 · 7.59 |
| `stage-exfiltration` | `#9C1A3C` / `#F5D2DC` | `#FF92B4` / `#47182B` | hexagon badge "4" | 5.76 · 6.99 | 6.73 · 6.78 |

Verdict lines (stroke on `surface-base`, 3:1 required): allow `#2A7444` / `#5FC27F` (3.76 / 7.97), monitor `#5A4FC0` / `#9B93FF` (4.18 / 6.71), challenge `#9A5C00` / `#E0AE4C` (3.54 / 8.66), block `#C0322A` / `#FF6F65` (3.71 / 6.46). The same colours draw the gauge bands on `surface-sunken` (all ≥ 3.11 L, ≥ 6.89 D). No verdict or stage hue reuses `accent`. Monitor is violet and Recon is teal for that reason.

### 1.3 Health and evidence (aliases, with their own glyphs)

| Token | Value = | Glyph | Label |
|---|---|---|---|
| `health-ok-fg/bg` | verdict-allow | `circle-check` | OK |
| `health-warn-fg/bg` | verdict-challenge | `triangle-alert` | Warn |
| (Degraded) | verdict-challenge | `circle-gauge` (half-filled circle) | Degraded |
| `health-error-fg/bg` | verdict-block | `octagon-alert` | Critical / Error |
| `evidence-none-fg/bg` | stage-none | `circle-dashed` | None |
| `evidence-safe-fg/bg` | verdict-allow | `shield-check` | Safe |
| `evidence-suspicious-fg/bg` | verdict-challenge | `shield-question` | Suspicious |
| `evidence-dangerous-fg/bg` | verdict-block | `shield-x` | Dangerous |

Evidence always uses the shield family, so it never reads as a verdict even where the hues are the same. The ratios are inherited from the source set.

### 1.4 Data-viz and syntax

| Token | Light | Dark | Ratio on `surface-input` L / D |
|---|---|---|---|
| `syntax-field` (`src:`) | = accent | = accent | 6.52 / 7.74 |
| `syntax-operator` (`AND`, `>=`, `:`) | = attention | = attention | 6.55 / 10.58 |
| `syntax-value` | = text-primary | = text-primary | 15.75 / 16.15 |
| `syntax-string` | = stage-exploitation-fg | = stage-exploitation-fg | 6.02 / 10.02 |
| `syntax-number` | = verdict-allow-fg | = verdict-allow-fg | 6.00 / 11.00 |
| `syntax-error` | = danger + 1.5 px wavy underline | = danger | 6.01 / 8.22 |
| `chart-grid` | `rgb(30 27 24 / .10)` | `rgb(255 255 255 / .07)` | decorative |
| `hatch` (stale overlay) | `repeating-linear-gradient(135deg, rgb(30 27 24/.10) 0 2px, transparent 2px 8px)` | the same with `rgb(255 255 255/.08)` | decorative |

### 1.5 Ground texture

Dark: a self-hosted 128 px tiling noise PNG (`/assets/noise-128.png`, about 6 KB) at `--vf-texture-opacity: .035`, blended `overlay` on `surface-base`. Light uses the same tile at `.025`. No data-URI images are used, so CSP stays `img-src 'self'`.

### 1.6 Frosted-glass rules (contrast-safe)

1. Glass is applied by `background: var(--vf-surface-raised-glass); backdrop-filter: var(--vf-glass-filter)` with `--vf-glass-filter: blur(16px) saturate(1.15)`. A 1 px `border-hairline` and `edge-highlight` inset always outline it.
2. **Fallback:** `@supports not (backdrop-filter: blur(1px))` and `@media (prefers-reduced-transparency: reduce)` swap the glass tokens for the solid tokens (CSS block below). `forced-colors: active` uses `Canvas` / `CanvasText`.
3. Alpha was chosen for the worst case: a glass panel over a fully white prop in dark (a composite of `#3D424B` raised and `#383F4C` overlay) and over near-black in light (`#C4C1BE`). Results: text-primary ≥ 8.69 / 9.56, text-secondary ≥ 5.47. **Rule:** `text-muted` is not used on glass placed over the topology canvas (worst case 3.93). Use `text-secondary` there. Elsewhere glass sits on `surface-base`, where all text tokens pass.

## 2. Elevation and glow

| Token | Light | Dark |
|---|---|---|
| `shadow-1` (soft: tiles, buttons, chips on map) | `0 1px 2px rgb(60 48 36/.10), 0 2px 6px rgb(60 48 36/.08), inset 0 1px 0 rgb(255 255 255/.70), inset 0 -1px 0 rgb(60 48 36/.06)` | `0 1px 2px rgb(0 0 0/.40), 0 2px 8px rgb(0 0 0/.28), inset 0 1px 0 rgb(255 255 255/.06), inset 0 -1px 0 rgb(0 0 0/.30)` |
| `shadow-2` (medium: cards, toasts, top bar, popover) | `0 2px 4px rgb(60 48 36/.10), 0 8px 20px rgb(60 48 36/.14), inset 0 1px 0 rgb(255 255 255/.75), inset 0 -1px 0 rgb(60 48 36/.08)` | `0 2px 4px rgb(0 0 0/.40), 0 10px 24px rgb(0 0 0/.40), inset 0 1px 0 rgb(255 255 255/.08), inset 0 -1px 0 rgb(0 0 0/.35)` |
| `shadow-3` (deep: modal, detail card) | `0 4px 8px rgb(60 48 36/.12), 0 24px 48px rgb(60 48 36/.22), inset 0 1px 0 rgb(255 255 255/.80), inset 0 -1px 0 rgb(60 48 36/.10)` | `0 6px 12px rgb(0 0 0/.45), 0 28px 56px rgb(0 0 0/.55), inset 0 1px 0 rgb(255 255 255/.10), inset 0 -1px 0 rgb(0 0 0/.40)` |
| `shadow-inset` (sunken wells, pressed) | `inset 0 2px 4px rgb(60 48 36/.16), inset 0 -1px 0 rgb(255 255 255/.60)` | `inset 0 2px 5px rgb(0 0 0/.55), inset 0 -1px 0 rgb(255 255 255/.05)` |
| `glow-focus` | `0 0 0 4px rgb(35 83 179/.22)` | `0 0 0 4px rgb(118 166 255/.30), 0 0 12px rgb(118 166 255/.35)` |
| `glow-hover` | `0 0 10px rgb(35 83 179/.22)` | `0 0 12px rgb(118 166 255/.35)` |
| `glow-selected` | `0 0 0 1.5px #7A4F00, 0 0 12px rgb(233 176 74/.45)` | `0 0 0 1.5px #E6BD68, 0 0 14px rgb(230 189 104/.40)` |
| `glow-line-active` (SVG `filter`) | `drop-shadow(0 0 2px rgb(240 138 46/.75)) drop-shadow(0 0 8px rgb(240 138 46/.35))` | `drop-shadow(0 0 2px rgb(230 189 104/.80)) drop-shadow(0 0 8px rgb(230 189 104/.35))` |
| `glow-alert` (pulse peak) | `0 0 0 1px #C0322A, 0 0 16px 2px rgb(192 50 42/.45)` | `0 0 0 1px #FF6F65, 0 0 18px 2px rgb(255 111 101/.50)` |

The focus indicator is always `outline: 2px solid var(--vf-focus-ring); outline-offset: 2px; box-shadow: var(--vf-glow-focus)` combined with the element's own shadow. The 2 px solid ring carries the 3:1 requirement, and the glow is decoration.

## 3. Shape, spacing, type, icons, motion

| Group | Tokens |
|---|---|
| Radius | `radius-xs 4px` (chips, badges, small tags) · `radius-sm 8px` (inputs, nav items, node labels, menu rows) · `radius-md 12px` (cards, KPI tiles, toasts, detail card) · `radius-lg 18px` (modals, buttons as pills at 36 px) · `radius-pill 999px` (health pills, switches) |
| Border width | `bw-hair 0.5px` (decorative; becomes 1 px at `resolution < 2dppx` with alpha ×0.6) · `bw-std 1px` · `bw-strong 1.5px` (selected, inputs on error) · `bw-focus 2px` |
| Spacing | `space-1 4` · `space-2 8` · `space-3 12` (dense tables only) · `space-4 16` · `space-5 24` · `space-6 32` · `space-7 48` (px) |
| Sizes | Control heights `32 / 36 / 44` (sm / md / lg); table row `40` (dense `32`); top bar `56`; nav `216` / rail `72`; minimum hit target 24×24, 44 for primary touch |
| Icons | `icon-sm 14px` (in chips and dense rows; stroke 1.25) · `icon-md 18px` (buttons, nav; stroke 1.5) · `icon-lg 22px` (empty states, modal header; stroke 1.5). Colour is `currentColor`. |

**Font.** UI uses **Inter 4 Variable** (SIL OFL 1.1), self-hosted as `/assets/inter-var-latin.woff2` (Latin subset, about 50 KB) with `font-display: swap`. Code and query use **JetBrains Mono 2.304** (OFL 1.1), self-hosted `jbmono-latin.woff2` at about 40 KB. Both satisfy `font-src 'self'`. Fallback stacks: `system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Liberation Sans", Arial, sans-serif` and `ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`. The fallbacks alone are acceptable if the font budget is cut.

| Style | Size / line height | Weight | Notes |
|---|---|---|---|
| `label-caps` | 11 / 16 | 600 | `text-transform: uppercase; letter-spacing: .06em`. Small-caps labels (ref 2). Always `text-secondary` or darker. |
| `text-xs` | 12 / 16 | 400 | Meta, legend |
| `text-sm` | 13 / 18 | 400 | Tables, chips (600) |
| `text-md` | 14 / 20 | 400 | Default UI body |
| `title-sm` | 16 / 24 | 600 | Card titles |
| `title-md` | 20 / 28 | 600 | Section headers |
| `title-lg` | 24 / 32 | 600 | Page titles |
| `kpi-sm` | 28 / 32 | 600 | Tile values (compact) |
| `kpi-md` | 40 / 44 | 600 | KPI tiles, gauge centre |
| `kpi-lg` | 56 / 56 | 500 | Hero figure (ref 2 "95.8%") |
| `mono-sm` | 13 / 20 | 450 | Query bar, ids, paths |

All numerals in KPIs, tables, gauges, timers and TTLs use `font-variant-numeric: tabular-nums slashed-zero` (Inter `tnum`, `zero`). Units are set at 0.5× the value size in `text-secondary`, aligned to the baseline.

**Motion**

| Token | Default | Reduced motion |
|---|---|---|
| `dur-instant` | 80ms | 0ms |
| `dur-fast` | 150ms (hover, press) | 0ms |
| `dur-base` | 220ms (popover, toast, toggle knob) | 0ms (opacity changes apply instantly) |
| `dur-slow` | 360ms (modal, keyed row reorder) | 0ms |
| `dur-pulse` | 1600ms (alert glow, ping) | — (`animation: none`; static glow at peak) |
| `flow-1 … flow-4` | 2400 / 1600 / 1000 / 600ms per packet cycle | `animation: none`; packets hidden |
| `ease-standard` | `cubic-bezier(.2, 0, 0, 1)` | — |
| `ease-enter` | `cubic-bezier(.05, .7, .1, 1)` | — |
| `ease-exit` | `cubic-bezier(.3, 0, 1, 1)` | — |
| `ease-flow` | `linear` | — |

Under reduced motion, no `transform` is used for feedback (for example, press translate). The user-facing "Pause animation" control applies the reduced values by setting `[data-motion="off"]` on `<html>`.

## 4. Components

Common state rules: **hover** uses `dur-fast`. **Focus-visible** adds the ring from §2. **Disabled** sets `text-disabled`, removes shadows and glows, keeps the `border-strong` outline at 50 % alpha, and uses `cursor: not-allowed`. A permission-gated control shows its "Requires Admin" note in `text-secondary`, never in disabled colour. **Loading** sets `aria-busy`, adds a 14 px spinner (static 3/4 ring under reduced motion), and locks the width. **Error** uses a `bw-strong` border in `danger`, a `triangle-alert` 14 px icon and a message in `text-sm danger`.

| Component | Anatomy | Default | Hover | Active / selected | Other states |
|---|---|---|---|---|---|
| **Button: primary** | [icon-md] label `text-md 500`, md 36 px, padding 0 16, `radius-lg` | bg `accent`, fg `text-on-accent`, `shadow-1` | bg `accent-hover` + `glow-hover` | bg `accent-active`, `shadow-inset`, translateY(1px) | Disabled bg `surface-sunken`. Loading: spinner replaces icon, label stays. Error: returns to default; message goes inline or to a toast. |
| **Button: secondary** | same | bg `surface-raised`, 1px `border-strong`, fg `text-primary`, `shadow-1` | bg `accent-soft`, border `accent` | `shadow-inset` | — |
| **Button: danger** | same, with `octagon-x` or `ban` icon | bg `danger`, fg `text-on-danger`, `shadow-1` | bg `danger-hover`, `glow-alert` at 50 % | `shadow-inset` | Never the default focus in a dialog |
| **Button: ghost** | same, no padding at sm | transparent, fg `accent` | bg `accent-soft` | bg `accent-soft` + `shadow-inset` | — |
| **Verdict chip** | glyph `icon-sm` + label `text-sm 600 caps .04em`; h 24 (sm 20), padding 0 8, gap 4, `radius-xs` | bg `verdict-*-bg`, fg `-fg`, 1px border `color-mix(fg 35%, transparent)` | (when it is a filter) border fg 100 % | `aria-pressed`: `bw-strong` fg border + `shadow-inset` | Glyph and word always present; never a bare dot |
| **Stage chip** | badge 16 px (shape per §1.2, numeral `text-xs 700`) + label + 4 pips (4×4 px, `radius-xs`) filled up to the stage | bg `stage-*-bg`, fg `-fg`; "Clean" badge hollow, 1.5 px border | as verdict chip | as verdict chip | Under 768 px the label may drop, keeping badge + numeral + `aria-label` |
| **Health pill** | glyph `icon-sm` + label + optional detail `text-xs`; h 24, padding 0 10, `radius-pill` | bg `health-*-bg`, fg `-fg`, `shadow-1` | if it opens a popover: border fg | — | Critical adds `glow-alert` pulse (`dur-pulse`) |
| **KPI tile** | `label-caps` + status glyph (top right) · value `kpi-md` + unit · delta `text-xs` with ↑/↓ glyph and sign · optional sparkline 24 px · 2 px bottom bar in the semantic `-line` colour; padding 16, `radius-md` | `surface-raised-glass`, `shadow-1`, hairline border | `shadow-2`, translateY(-1px) (if it links) | — | Loading: skeleton blocks `surface-sunken` with shimmer at 12 % (static under reduced motion). Error: value "—", "Unavailable" `text-secondary` + warn glyph. Stale: §1.4 hatch, opacity .7. |
| **Score gauge** | 180° arc, 160×96 viewBox. Track 10 px `surface-sunken` + `shadow-inset`. An outer 4 px band ring draws Monitor, Challenge and Block from `monitor_at` / `challenge_at` / `block_at` in their `-line` colours, with band ends as 2 px ticks in `text-primary` labelled `text-xs` tabular. Allow zone = track only. Value arc 10 px, round caps, in the colour of the band the score falls in; needle 2 px `text-primary` + 6 px hub. Centre: `kpi-md` score, verdict chip below. | static | — | — | Loading: track only plus skeleton number. SVG `aria-hidden`; the sentence alternative is in the UX doc. |
| **Sparkline** | 1.5 px stroke `text-secondary` (or the semantic `-line`), area fill at 12 % alpha, last-point dot r 3 with 1.5 px `surface-raised` ring; no axes; h 24–32 | — | Crosshair 1 px `border-strong` + value tooltip | — | Empty: dashed 1 px baseline `border-subtle` |
| **Query input** | [search icon-md] mono-sm text with token highlighting (§1.4) · [counted chip] · [clear]; h 36, `radius-sm`, `surface-input`, 1px `border-strong`, `shadow-inset` | — | border `text-secondary` | focus: border `accent` + ring | Error: wavy `syntax-error` under the bad token, plus a message below. Loading: spinner in place of the clear button. |
| **Suggestion popover** | `surface-overlay-glass`, `shadow-3`, `radius-md`, padding 4; rows 32 px `radius-sm`: kind glyph · suggestion (matched part 600) · count `text-muted` tabular right | — | row bg `accent-soft` | `aria-selected` row: `accent-soft` + 2 px inset left bar `accent` | Empty: "No matches" `text-secondary`. Max 8 rows; scroll inside the popover. |
| **Enforce / Monitor switch** | `role="switch"`; track 44×24 `radius-pill`, knob 18 px; visible state text + glyph beside it ("Enforce" `shield-check` / "Monitor" `eye`) | on: track `accent`, knob `text-on-accent`, `glow-hover`; off: track `surface-sunken` + 1px `border-strong`, knob `text-muted` | `glow-hover` | knob slides 20 px (`dur-base`) | Disabled per common rule. Switching to Monitor opens the destructive modal. |
| **Threshold slider** | Track 4 px `surface-sunken` + `shadow-inset`; under it a 3 px band strip in verdict `-line` colours, split at the current thresholds; ticks every 10 (1 px `border-strong`), labels at 0/25/50/75/100 `text-xs` tabular; two thumbs 18 px (`monitor`/`challenge`/`block` keys as needed) | thumb `attention-fill`, 1.5px `attention` border, `shadow-1` | thumb `glow-selected` | dragging: value bubble above (`surface-overlay`, `text-sm` tabular, `radius-xs`) | Keys ±1 / PgUp-PgDn ±10; thumbs cannot cross (gap ≥ 1). Error (422): track border `danger` + message. Changed-from-default: 4 px `attention` dot on the label. |
| **Table row** | h 40, padding 0 12, 1px `border-subtle` bottom; cells `text-sm`, numbers right-aligned tabular | transparent | bg `row-hover` + `inset 0 0 0 1px rgb(accent/.35)` | selected: bg `row-selected` + inset 1.5px `attention` + `glow-selected` at 50 % | **Blocked**: bg `row-blocked` + 3 px inset left bar `verdict-block-line`; the verdict chip is still required. Focus: inset 2 px ring. |
| **Floating detail card** | 320 w, padding 16, `radius-md`, `surface-overlay-glass`, `shadow-3`, 10 px caret toward the node. Header: status chip + `title-sm` + node glyph. Meta `text-xs text-secondary`. Sparkline 288×32. Rows of `label-caps` / value. Footer: secondary + primary buttons (sm), right-aligned, gap 8 | enters with fade + 4 px rise (`dur-base`, `ease-enter`) | — | pinned: `glow-selected` | Offset 16 px from the node, flips to stay inside the canvas. Loading: skeleton rows. |
| **Toast** | 360 w, padding 12 16, `radius-md`, `surface-raised-glass`, `shadow-2`, 3 px inset left bar + glyph in the semantic fg; text `text-md`; optional action (ghost) and close | bottom-right, 24 px inset, max 3 stacked with 8 px gap | close and action show hover | — | Info → accent, success → allow, warn → challenge, error → block (`role="alert"`, no auto-dismiss). Others dismiss after 6 s, paused on hover or focus. |
| **Modal (destructive confirm)** | 440 w, padding 24, `radius-lg`, `surface-overlay-glass` (always solid when over the map), `shadow-3`, `surface-scrim`. Header: `octagon-alert` icon-lg `danger` + `title-md` question ("Ban 203.0.113.7 for 24 h?"). Body `text-md`. Footer: Cancel (secondary, **initial focus**) · confirm (danger, verb label) | scale .98→1 + fade (`dur-slow`) | — | confirm loading: spinner, both buttons disabled | Error: inline error band (`verdict-block-bg`/fg) above the footer; the dialog stays open. Esc = Cancel. |
| **Empty-state tile** | `surface-raised`, `radius-md`, padding 24, centred: 40 px icon well (`surface-sunken`, `radius-sm`, `shadow-inset`, icon-lg `text-secondary`) · one sentence `text-md text-secondary` · optional ghost button | — | — | — | Never uses semantic colour |
| **Legend** | Title `label-caps`; rows (h 24): 32 px line sample with the exact width, colour and dash pattern + glyph `icon-sm` + label `text-xs`; then the 5 volume steps as widths with labels; then stage badges | `surface-raised-glass`, `shadow-1`, `radius-md`, padding 12 | — | — | Collapses to a "Legend" button below 1024 px |
| **Top status bar** | h 56, padding 0 16, `surface-raised-glass`, `shadow-2`, hairline bottom; groups separated by 1px `border-subtle` 24 px tall. Each status item: glyph `icon-sm` + `label-caps` over value `text-sm 500` (ref 2) | sticky | items that open popovers: bg `accent-soft` | open: `shadow-inset` | Worst state uses a health pill; Dropped rising → warn styling; Live "Reconnecting" → warn pill with spinner |
| **Side navigation** | 216 w (rail 72), `surface-sunken`, padding 8; section `label-caps text-muted`; item h 40, `radius-sm`, icon-md + `text-md 500` (rail: 11 px label under the icon) | fg `text-secondary` | bg `surface-raised`, `shadow-1`, fg `text-primary` | `aria-current`: bg `accent-soft`, fg `text-primary` 600, 2 px inset left bar `accent`, icon `accent` | Disabled per common rule; footer repeats Live state as text |

## 5. Isometric topology overlay

**Projection.** 30° isometric (tan 30° = 0.577). Plates are rhombi with height = width × 0.577. All overlay geometry is SVG in the same coordinate space as the 1176×700 scene.

**Lines.** Each edge is drawn as two strokes. The **base stroke** carries meaning: verdict colour, pattern and width, and it is static. The **packet stroke** is motion only: the same path, dash `2 22`, round cap, colour `--vf-line-packet` (`rgb(255 255 255/.85)` light, `rgb(255 255 255/.75)` dark), with `stroke-dashoffset` animated from 24 to 0 over the `flow-n` duration, `ease-flow`, running from source to target. Under reduced motion, or when paused, packets are hidden, so no meaning is lost.

| Verdict | Base pattern (`stroke-dasharray`) | Cap | Width per volume step 0 / <1 / 1–10 / 10–100 / >100 rps |
|---|---|---|---|
| Allow | solid | butt | 1 / 1.5 / 2 / 3 / 4 px |
| Monitor | `12 6` long dash | butt | same |
| Challenge | `10 4 2 4` dash-dot | butt | same |
| Block | `0 6` dotted (1 px wider than the others) | round | 2 / 2.5 / 3 / 4 / 5 px |

- **Volume steps** map to packet speed: 0 rps has no packets and draws the base at `--vf-line-idle` (`#7A7269` / `#77808F`, 3.12 / 4.42), 1 px. The other steps use `flow-1` to `flow-4`. Steps are never interpolated.
- **Selected or hovered path:** an extra halo stroke is drawn under the base, at width + 4 px in `--vf-line-active` (`#B85A0A` copper / `#E6BD68` gold, 3.07 / 9.93) with `filter: var(--vf-glow-line-active)`. This is the ref 2 orange glow in light and the ref 1 gold in dark.
- **Alert** (honeypot hit, new ban): the target node plate gets `glow-alert`, pulsing 3× over `dur-pulse` and then static for 10 s. Under reduced motion, a "Hit" text badge shows for 10 s instead.
- **Stale or reconnecting:** all base strokes switch to `line-idle`, the packets stop, and the `hatch` overlay covers the scene.
- **Rate label:** a midpoint chip, `text-xs` tabular "31/s", using the node-label style at h 20.

**Node label chips.** These follow ref 2's floating tags: h 24, padding 0 8, `radius-sm`, `surface-raised-glass`, `shadow-1`, hairline border, `text-xs 600 text-primary` name + count `text-xs` tabular. A status glyph (`icon-sm`, semantic fg) leads when the node is in alert. Each chip is anchored 12 px above the prop top, with a 1 px `border-strong` leader to the plate centre. Hover adds `shadow-2` + `glow-hover`, focus adds the ring, and the pinned state adds `glow-selected`.

**Props on both themes.** The props are pre-rendered in white and warm-grey clay. Assets must be WebP or PNG with a real alpha channel, rendered at 2×, at most 512 px. The current `shield-tower-v1.png` has an opaque `#d8d4cf` ground and must be alpha-matted before use. Contact shadow is baked at ≤ 25 % opacity.

| Layer | Light | Dark |
|---|---|---|
| Plate (top face) | `#E4E0DB`, 1px `edge-highlight` on the two upper edges | `#2A2F38`, 1px `rgb(255 255 255/.08)` upper edges |
| Plate side faces (6 px) | left `#CFC9C2`, right `#C2BBB3` | left `#1F232A`, right `#191C22` |
| Plate shadow | `filter: drop-shadow(0 10px 14px rgb(60 48 36/.20))` | `drop-shadow(0 10px 18px rgb(0 0 0/.60))` |
| Prop filter | `drop-shadow(0 6px 8px rgb(60 48 36/.16))` | `brightness(.86) contrast(1.04) drop-shadow(0 0 .5px rgb(255 255 255/.35)) drop-shadow(0 8px 12px rgb(0 0 0/.55))`. The rim light separates the silhouette, and the dimming stops white glare on charcoal. |
| Ambient pool (active node only) | `radial-gradient(closest-side, rgb(240 138 46/.14), transparent)` under the plate | `radial-gradient(closest-side, rgb(230 189 104/.12), transparent)` |
| Node states | hover: plate `shadow-2` + `glow-hover`; selected: plate outline 1.5 px `attention` + `glow-selected`; alert: `glow-alert` | same tokens |

Plates are decorative (1.15 / 1.31 against base). Nodes are identified by their label chips and accessible names, never by plate or prop colour.

## 6. CSS custom properties (ready to paste)

```css
:root {
  color-scheme: light;
  /* surfaces */
  --vf-surface-base: #D6D1CB; --vf-surface-sunken: #CAC4BD; --vf-surface-raised: #EEEBE7; --vf-surface-overlay: #F7F5F2;
  --vf-surface-raised-glass: rgb(238 235 231 / .80); --vf-surface-overlay-glass: rgb(247 245 242 / .88);
  --vf-surface-input: #F7F5F2; --vf-surface-scrim: rgb(30 27 24 / .40);
  --vf-glass-filter: blur(16px) saturate(1.15); --vf-texture-opacity: .025;
  /* text */
  --vf-text-primary: #1E1B18; --vf-text-secondary: #48423C; --vf-text-muted: #565049; --vf-text-disabled: #8C847B;
  --vf-text-on-accent: #FFFFFF; --vf-text-on-attention: #231804; --vf-text-on-danger: #FFFFFF;
  /* borders + focus */
  --vf-border-hairline: rgb(30 27 24 / .12); --vf-border-subtle: rgb(30 27 24 / .20); --vf-border-strong: #7A7269;
  --vf-edge-highlight: rgb(255 255 255 / .70); --vf-focus-ring: #2353B3;
  /* accent / attention / danger */
  --vf-accent: #2353B3; --vf-accent-hover: #1D4799; --vf-accent-active: #173A7D; --vf-accent-soft: #D9E3F6;
  --vf-attention: #7A4F00; --vf-attention-fill: #E9B04A; --vf-attention-soft: #F4E2C0;
  --vf-danger: #B3261E; --vf-danger-hover: #96201A;
  --vf-row-hover: #E2E6EE; --vf-row-selected: #F3E6CC; --vf-row-blocked: #F2DEDA;
  /* verdicts */
  --vf-verdict-allow-fg: #1D6B3A; --vf-verdict-allow-bg: #D3EAD9; --vf-verdict-allow-line: #2A7444;
  --vf-verdict-monitor-fg: #4337A3; --vf-verdict-monitor-bg: #E1DDF6; --vf-verdict-monitor-line: #5A4FC0;
  --vf-verdict-challenge-fg: #8A4F00; --vf-verdict-challenge-bg: #F5E2BF; --vf-verdict-challenge-line: #9A5C00;
  --vf-verdict-block-fg: #A3221A; --vf-verdict-block-bg: #F6D5D1; --vf-verdict-block-line: #C0322A;
  /* kill-chain stages */
  --vf-stage-none-fg: #55504A; --vf-stage-none-bg: #E1DDD8;
  --vf-stage-recon-fg: #0F5F6B; --vf-stage-recon-bg: #CFE7EA;
  --vf-stage-enumeration-fg: #6E5600; --vf-stage-enumeration-bg: #F0E5B5;
  --vf-stage-exploitation-fg: #9A440A; --vf-stage-exploitation-bg: #F7DBC5;
  --vf-stage-exfiltration-fg: #9C1A3C; --vf-stage-exfiltration-bg: #F5D2DC;
  /* topology */
  --vf-line-idle: #7A7269; --vf-line-active: #B85A0A; --vf-line-packet: rgb(255 255 255 / .85);
  --vf-plate-top: #E4E0DB; --vf-plate-left: #CFC9C2; --vf-plate-right: #C2BBB3;
  --vf-plate-shadow: drop-shadow(0 10px 14px rgb(60 48 36 / .20));
  --vf-prop-filter: drop-shadow(0 6px 8px rgb(60 48 36 / .16));
  --vf-ambient: radial-gradient(closest-side, rgb(240 138 46 / .14), transparent);
  --vf-chart-grid: rgb(30 27 24 / .10);
  --vf-hatch: repeating-linear-gradient(135deg, rgb(30 27 24 / .10) 0 2px, transparent 2px 8px);
  /* elevation + glow */
  --vf-shadow-1: 0 1px 2px rgb(60 48 36 / .10), 0 2px 6px rgb(60 48 36 / .08), inset 0 1px 0 rgb(255 255 255 / .70), inset 0 -1px 0 rgb(60 48 36 / .06);
  --vf-shadow-2: 0 2px 4px rgb(60 48 36 / .10), 0 8px 20px rgb(60 48 36 / .14), inset 0 1px 0 rgb(255 255 255 / .75), inset 0 -1px 0 rgb(60 48 36 / .08);
  --vf-shadow-3: 0 4px 8px rgb(60 48 36 / .12), 0 24px 48px rgb(60 48 36 / .22), inset 0 1px 0 rgb(255 255 255 / .80), inset 0 -1px 0 rgb(60 48 36 / .10);
  --vf-shadow-inset: inset 0 2px 4px rgb(60 48 36 / .16), inset 0 -1px 0 rgb(255 255 255 / .60);
  --vf-glow-focus: 0 0 0 4px rgb(35 83 179 / .22);
  --vf-glow-hover: 0 0 10px rgb(35 83 179 / .22);
  --vf-glow-selected: 0 0 0 1.5px #7A4F00, 0 0 12px rgb(233 176 74 / .45);
  --vf-glow-line-active: drop-shadow(0 0 2px rgb(240 138 46 / .75)) drop-shadow(0 0 8px rgb(240 138 46 / .35));
  --vf-glow-alert: 0 0 0 1px #C0322A, 0 0 16px 2px rgb(192 50 42 / .45);

  /* ---- theme-independent ---- */
  --vf-health-ok-fg: var(--vf-verdict-allow-fg); --vf-health-ok-bg: var(--vf-verdict-allow-bg);
  --vf-health-warn-fg: var(--vf-verdict-challenge-fg); --vf-health-warn-bg: var(--vf-verdict-challenge-bg);
  --vf-health-error-fg: var(--vf-verdict-block-fg); --vf-health-error-bg: var(--vf-verdict-block-bg);
  --vf-evidence-none-fg: var(--vf-stage-none-fg); --vf-evidence-none-bg: var(--vf-stage-none-bg);
  --vf-evidence-safe-fg: var(--vf-verdict-allow-fg); --vf-evidence-safe-bg: var(--vf-verdict-allow-bg);
  --vf-evidence-suspicious-fg: var(--vf-verdict-challenge-fg); --vf-evidence-suspicious-bg: var(--vf-verdict-challenge-bg);
  --vf-evidence-dangerous-fg: var(--vf-verdict-block-fg); --vf-evidence-dangerous-bg: var(--vf-verdict-block-bg);
  --vf-syntax-field: var(--vf-accent); --vf-syntax-operator: var(--vf-attention); --vf-syntax-value: var(--vf-text-primary);
  --vf-syntax-string: var(--vf-stage-exploitation-fg); --vf-syntax-number: var(--vf-verdict-allow-fg); --vf-syntax-error: var(--vf-danger);
  --vf-radius-xs: 4px; --vf-radius-sm: 8px; --vf-radius-md: 12px; --vf-radius-lg: 18px; --vf-radius-pill: 999px;
  --vf-bw-hair: .5px; --vf-bw-std: 1px; --vf-bw-strong: 1.5px; --vf-bw-focus: 2px;
  --vf-space-1: 4px; --vf-space-2: 8px; --vf-space-3: 12px; --vf-space-4: 16px; --vf-space-5: 24px; --vf-space-6: 32px; --vf-space-7: 48px;
  --vf-control-sm: 32px; --vf-control-md: 36px; --vf-control-lg: 44px; --vf-row-h: 40px; --vf-row-h-dense: 32px;
  --vf-topbar-h: 56px; --vf-nav-w: 216px; --vf-nav-rail-w: 72px;
  --vf-icon-sm: 14px; --vf-icon-md: 18px; --vf-icon-lg: 22px;
  --vf-font-sans: "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Liberation Sans", Arial, sans-serif;
  --vf-font-mono: "JetBrains Mono", ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --vf-fs-label: 11px; --vf-lh-label: 16px; --vf-fs-xs: 12px; --vf-lh-xs: 16px; --vf-fs-sm: 13px; --vf-lh-sm: 18px;
  --vf-fs-md: 14px; --vf-lh-md: 20px; --vf-fs-title-sm: 16px; --vf-lh-title-sm: 24px; --vf-fs-title-md: 20px; --vf-lh-title-md: 28px;
  --vf-fs-title-lg: 24px; --vf-lh-title-lg: 32px; --vf-fs-kpi-sm: 28px; --vf-lh-kpi-sm: 32px; --vf-fs-kpi-md: 40px; --vf-lh-kpi-md: 44px;
  --vf-fs-kpi-lg: 56px; --vf-lh-kpi-lg: 56px;
  --vf-fw-regular: 400; --vf-fw-medium: 500; --vf-fw-semibold: 600; --vf-fw-bold: 700;
  --vf-tracking-caps: .06em; --vf-numeric: tabular-nums slashed-zero;
  --vf-dur-instant: 80ms; --vf-dur-fast: 150ms; --vf-dur-base: 220ms; --vf-dur-slow: 360ms; --vf-dur-pulse: 1600ms;
  --vf-flow-1: 2400ms; --vf-flow-2: 1600ms; --vf-flow-3: 1000ms; --vf-flow-4: 600ms;
  --vf-ease-standard: cubic-bezier(.2, 0, 0, 1); --vf-ease-enter: cubic-bezier(.05, .7, .1, 1);
  --vf-ease-exit: cubic-bezier(.3, 0, 1, 1); --vf-ease-flow: linear;
  --vf-motion-play: running;
}

[data-theme="dark"] {
  color-scheme: dark;
  --vf-surface-base: #17191D; --vf-surface-sunken: #101215; --vf-surface-raised: #252B36; --vf-surface-overlay: #2D3442;
  --vf-surface-raised-glass: rgb(37 43 54 / .88); --vf-surface-overlay-glass: rgb(45 52 66 / .94);
  --vf-surface-input: #101215; --vf-surface-scrim: rgb(5 6 8 / .64); --vf-texture-opacity: .035;
  --vf-text-primary: #ECEEF2; --vf-text-secondary: #B9BFCA; --vf-text-muted: #9AA2B0; --vf-text-disabled: #6C7585;
  --vf-text-on-accent: #0A1430; --vf-text-on-attention: #231804; --vf-text-on-danger: #2A0705;
  --vf-border-hairline: rgb(255 255 255 / .08); --vf-border-subtle: rgb(255 255 255 / .14); --vf-border-strong: #77808F;
  --vf-edge-highlight: rgb(255 255 255 / .08); --vf-focus-ring: #76A6FF;
  --vf-accent: #76A6FF; --vf-accent-hover: #93B9FF; --vf-accent-active: #5A8FF0; --vf-accent-soft: #1E2C47;
  --vf-attention: #E6BD68; --vf-attention-fill: #E6BD68; --vf-attention-soft: #3A2F14;
  --vf-danger: #FF8A80; --vf-danger-hover: #FFA59D;
  --vf-row-hover: #2A3550; --vf-row-selected: #342D1D; --vf-row-blocked: #33201F;
  --vf-verdict-allow-fg: #7FD99D; --vf-verdict-allow-bg: #173528; --vf-verdict-allow-line: #5FC27F;
  --vf-verdict-monitor-fg: #B0A9FF; --vf-verdict-monitor-bg: #29275A; --vf-verdict-monitor-line: #9B93FF;
  --vf-verdict-challenge-fg: #F2C46B; --vf-verdict-challenge-bg: #3B2E10; --vf-verdict-challenge-line: #E0AE4C;
  --vf-verdict-block-fg: #FF928A; --vf-verdict-block-bg: #4A1F1C; --vf-verdict-block-line: #FF6F65;
  --vf-stage-none-fg: #B9BFCA; --vf-stage-none-bg: #2B303A;
  --vf-stage-recon-fg: #6CCFD8; --vf-stage-recon-bg: #14343A;
  --vf-stage-enumeration-fg: #E9D06A; --vf-stage-enumeration-bg: #373214;
  --vf-stage-exploitation-fg: #FFAA6B; --vf-stage-exploitation-bg: #44280E;
  --vf-stage-exfiltration-fg: #FF92B4; --vf-stage-exfiltration-bg: #47182B;
  --vf-line-idle: #77808F; --vf-line-active: #E6BD68; --vf-line-packet: rgb(255 255 255 / .75);
  --vf-plate-top: #2A2F38; --vf-plate-left: #1F232A; --vf-plate-right: #191C22;
  --vf-plate-shadow: drop-shadow(0 10px 18px rgb(0 0 0 / .60));
  --vf-prop-filter: brightness(.86) contrast(1.04) drop-shadow(0 0 .5px rgb(255 255 255 / .35)) drop-shadow(0 8px 12px rgb(0 0 0 / .55));
  --vf-ambient: radial-gradient(closest-side, rgb(230 189 104 / .12), transparent);
  --vf-chart-grid: rgb(255 255 255 / .07);
  --vf-hatch: repeating-linear-gradient(135deg, rgb(255 255 255 / .08) 0 2px, transparent 2px 8px);
  --vf-shadow-1: 0 1px 2px rgb(0 0 0 / .40), 0 2px 8px rgb(0 0 0 / .28), inset 0 1px 0 rgb(255 255 255 / .06), inset 0 -1px 0 rgb(0 0 0 / .30);
  --vf-shadow-2: 0 2px 4px rgb(0 0 0 / .40), 0 10px 24px rgb(0 0 0 / .40), inset 0 1px 0 rgb(255 255 255 / .08), inset 0 -1px 0 rgb(0 0 0 / .35);
  --vf-shadow-3: 0 6px 12px rgb(0 0 0 / .45), 0 28px 56px rgb(0 0 0 / .55), inset 0 1px 0 rgb(255 255 255 / .10), inset 0 -1px 0 rgb(0 0 0 / .40);
  --vf-shadow-inset: inset 0 2px 5px rgb(0 0 0 / .55), inset 0 -1px 0 rgb(255 255 255 / .05);
  --vf-glow-focus: 0 0 0 4px rgb(118 166 255 / .30), 0 0 12px rgb(118 166 255 / .35);
  --vf-glow-hover: 0 0 12px rgb(118 166 255 / .35);
  --vf-glow-selected: 0 0 0 1.5px #E6BD68, 0 0 14px rgb(230 189 104 / .40);
  --vf-glow-line-active: drop-shadow(0 0 2px rgb(230 189 104 / .80)) drop-shadow(0 0 8px rgb(230 189 104 / .35));
  --vf-glow-alert: 0 0 0 1px #FF6F65, 0 0 18px 2px rgb(255 111 101 / .50);
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --vf-surface-base: #17191D; --vf-surface-sunken: #101215; --vf-surface-raised: #252B36; --vf-surface-overlay: #2D3442;
    --vf-surface-raised-glass: rgb(37 43 54 / .88); --vf-surface-overlay-glass: rgb(45 52 66 / .94);
    --vf-surface-input: #101215; --vf-surface-scrim: rgb(5 6 8 / .64); --vf-texture-opacity: .035;
    --vf-text-primary: #ECEEF2; --vf-text-secondary: #B9BFCA; --vf-text-muted: #9AA2B0; --vf-text-disabled: #6C7585;
    --vf-text-on-accent: #0A1430; --vf-text-on-attention: #231804; --vf-text-on-danger: #2A0705;
    --vf-border-hairline: rgb(255 255 255 / .08); --vf-border-subtle: rgb(255 255 255 / .14); --vf-border-strong: #77808F;
    --vf-edge-highlight: rgb(255 255 255 / .08); --vf-focus-ring: #76A6FF;
    --vf-accent: #76A6FF; --vf-accent-hover: #93B9FF; --vf-accent-active: #5A8FF0; --vf-accent-soft: #1E2C47;
    --vf-attention: #E6BD68; --vf-attention-fill: #E6BD68; --vf-attention-soft: #3A2F14;
    --vf-danger: #FF8A80; --vf-danger-hover: #FFA59D;
    --vf-row-hover: #2A3550; --vf-row-selected: #342D1D; --vf-row-blocked: #33201F;
    --vf-verdict-allow-fg: #7FD99D; --vf-verdict-allow-bg: #173528; --vf-verdict-allow-line: #5FC27F;
    --vf-verdict-monitor-fg: #B0A9FF; --vf-verdict-monitor-bg: #29275A; --vf-verdict-monitor-line: #9B93FF;
    --vf-verdict-challenge-fg: #F2C46B; --vf-verdict-challenge-bg: #3B2E10; --vf-verdict-challenge-line: #E0AE4C;
    --vf-verdict-block-fg: #FF928A; --vf-verdict-block-bg: #4A1F1C; --vf-verdict-block-line: #FF6F65;
    --vf-stage-none-fg: #B9BFCA; --vf-stage-none-bg: #2B303A;
    --vf-stage-recon-fg: #6CCFD8; --vf-stage-recon-bg: #14343A;
    --vf-stage-enumeration-fg: #E9D06A; --vf-stage-enumeration-bg: #373214;
    --vf-stage-exploitation-fg: #FFAA6B; --vf-stage-exploitation-bg: #44280E;
    --vf-stage-exfiltration-fg: #FF92B4; --vf-stage-exfiltration-bg: #47182B;
    --vf-line-idle: #77808F; --vf-line-active: #E6BD68; --vf-line-packet: rgb(255 255 255 / .75);
    --vf-plate-top: #2A2F38; --vf-plate-left: #1F232A; --vf-plate-right: #191C22;
    --vf-plate-shadow: drop-shadow(0 10px 18px rgb(0 0 0 / .60));
    --vf-prop-filter: brightness(.86) contrast(1.04) drop-shadow(0 0 .5px rgb(255 255 255 / .35)) drop-shadow(0 8px 12px rgb(0 0 0 / .55));
    --vf-ambient: radial-gradient(closest-side, rgb(230 189 104 / .12), transparent);
    --vf-chart-grid: rgb(255 255 255 / .07);
    --vf-hatch: repeating-linear-gradient(135deg, rgb(255 255 255 / .08) 0 2px, transparent 2px 8px);
    --vf-shadow-1: 0 1px 2px rgb(0 0 0 / .40), 0 2px 8px rgb(0 0 0 / .28), inset 0 1px 0 rgb(255 255 255 / .06), inset 0 -1px 0 rgb(0 0 0 / .30);
    --vf-shadow-2: 0 2px 4px rgb(0 0 0 / .40), 0 10px 24px rgb(0 0 0 / .40), inset 0 1px 0 rgb(255 255 255 / .08), inset 0 -1px 0 rgb(0 0 0 / .35);
    --vf-shadow-3: 0 6px 12px rgb(0 0 0 / .45), 0 28px 56px rgb(0 0 0 / .55), inset 0 1px 0 rgb(255 255 255 / .10), inset 0 -1px 0 rgb(0 0 0 / .40);
    --vf-shadow-inset: inset 0 2px 5px rgb(0 0 0 / .55), inset 0 -1px 0 rgb(255 255 255 / .05);
    --vf-glow-focus: 0 0 0 4px rgb(118 166 255 / .30), 0 0 12px rgb(118 166 255 / .35);
    --vf-glow-hover: 0 0 12px rgb(118 166 255 / .35);
    --vf-glow-selected: 0 0 0 1.5px #E6BD68, 0 0 14px rgb(230 189 104 / .40);
    --vf-glow-line-active: drop-shadow(0 0 2px rgb(230 189 104 / .80)) drop-shadow(0 0 8px rgb(230 189 104 / .35));
    --vf-glow-alert: 0 0 0 1px #FF6F65, 0 0 18px 2px rgb(255 111 101 / .50);
  }
}

/* Solid fallback: no backdrop-filter, or less transparency requested. :root:root:root (0,3,0) outranks the theme selectors (0,2,0). */
@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  :root:root:root { --vf-surface-raised-glass: var(--vf-surface-raised); --vf-surface-overlay-glass: var(--vf-surface-overlay); --vf-glass-filter: none; }
}
@media (prefers-reduced-transparency: reduce) {
  :root:root:root { --vf-surface-raised-glass: var(--vf-surface-raised); --vf-surface-overlay-glass: var(--vf-surface-overlay); --vf-glass-filter: none; }
}

/* Reduced motion (and the in-app Pause control) */
@media (prefers-reduced-motion: reduce) {
  :root { --vf-dur-instant: 0ms; --vf-dur-fast: 0ms; --vf-dur-base: 0ms; --vf-dur-slow: 0ms; --vf-motion-play: paused; }
}
[data-motion="off"] { --vf-dur-instant: 0ms; --vf-dur-fast: 0ms; --vf-dur-base: 0ms; --vf-dur-slow: 0ms; --vf-motion-play: paused; }
/* Components read --vf-motion-play: pulses and packets use animation-play-state: var(--vf-motion-play),
   and packet strokes are display:none while it is paused. */

@media (forced-colors: active) {
  :root:root:root { --vf-focus-ring: Highlight; --vf-border-strong: CanvasText; --vf-surface-raised-glass: Canvas; --vf-surface-overlay-glass: Canvas; }
}
```

The dark block appears twice on purpose: `[data-theme="dark"]` is the manual choice, and the media query is "System". Generate both from a single source (`tokens.dark.css` included twice at build time) so they cannot drift. A CI test should parse `tokens.css`, recompute every ratio in §1, and fail below 4.5 for text or 3.0 for UI and lines.
