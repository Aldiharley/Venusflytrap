# SP6a — Console Shell on Fixtures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A buildable Svelte 5 console in `ui/` with the design tokens, both themes, the global shell, the shared components and three screens — Dashboard, Traffic topology (hero) and Attack chains (primary live screen) — all rendered from deterministic fixtures behind a `DataSource` interface, passing axe, CSP and bundle-budget checks.

**Architecture:** A Vite SPA with a ~60-line History-API router and lazy route chunks. All data flows through one `DataSource` interface; this plan ships only `FixtureSource` (deterministic, seeded, with a simulated live feed). Screens read a single rune-based `app` state object. Topology and chains logic lives in pure TypeScript modules (`model.ts`, `grid.ts`) that both the visual and the table renderings consume, so they cannot disagree. Styling comes only from `tokens.css` (verbatim from the design system) plus component-scoped CSS; there are no inline `style` attributes, so the strict CSP holds.

**Tech Stack:** Node 24, npm 11, Svelte 5.57.2, Vite 8.3.4, @sveltejs/vite-plugin-svelte 7.3.1, TypeScript 6.0.3, svelte-check 4.7.6, Vitest 5.0.4 + jsdom 30.1.2 + @testing-library/svelte 5.4.2, Playwright 1.64.0 (system Edge channel) + @axe-core/playwright 4.13.0, @lucide/svelte 1.56.0, @fontsource-variable/inter 5.3.0, @fontsource/jetbrains-mono 5.3.0.

**Specs:** `docs/superpowers/specs/2026-10-25-console-design.md` (precedence: this spec → `docs/superpowers/design/console-ux-architecture.md` for layout, behaviour and copy → `docs/superpowers/design/console-design-system.md` for styling → canvas boards in `docs/superpowers/design/canvas/project/*.dc.html` for illustration). Parent: `docs/superpowers/specs/2026-10-25-operable-service-design.md` §5.10 and §6 ("The SP6 shell, routing and design tokens may start against SP2's generated types with mocked fixtures").

## Global Constraints

- Every dependency is pinned to an exact version (the list above). Each was published at least two weeks before 2026-10-27. Nothing is loaded from a CDN.
- The CSP the admin listener will send must hold: `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. Consequences: no inline `<script>`, no `<style>` in `index.html`, **no static `style="…"` attributes in any component** (dynamic values only through Svelte `style:prop={…}` directives, which set CSSOM properties at runtime), no `data:` fonts (`build.assetsInlineLimit: 0`).
- Budgets: initial JS ≤ 150 KB gzipped; no lazy route chunk over 80 KB gzipped (`npm run budget`).
- Accessibility: axe-core reports zero serious or critical violations on every screen in light and dark; every interactive element is keyboard-reachable with the 2 px focus ring; verdicts and stages always carry glyph and text (never colour alone); under `prefers-reduced-motion` or `[data-motion="off"]` nothing animates and no information is lost.
- Copy and behaviour follow the UX architecture; colours, sizes, shadows and motion come only from `--vf-*` tokens.
- Data shapes in `ui/src/lib/api/types.ts` mirror the SP2 plan's wire types (`Judgment`, `Cause`, `Contribution`, …) and the UX architecture's gap fixes G1–G10 for SP3–SP5 view types. They are provisional; when SP2 Task 9 lands, the core types are re-exported from `ui/src/gen`.
- No network calls: `FixtureSource` is the only `DataSource` in this plan.
- `ui/assets/props/*` and `ui/assets/scenes/*` stay **uncommitted** until the owner confirms the Higgsfield licence. The app loads them through `import.meta.glob`, so a checkout without them still builds (images are simply absent).
- Commits: one per task on branch `sp6a-console-shell` in a worktree, only after the owner approves executing this plan. No push and no change to `main` without approval.

## Decisions this plan takes (owner to confirm before execution)

| # | Decision | Why |
|---|---|---|
| E1 | Scope: shell + Dashboard + Traffic topology + Attack chains. Monitor, Request details, Source, Honeypot & bans, Settings and Keys render an honest placeholder ("specified; arrives with plan SP6b") and are planned next. | Keeps one plan reviewable; covers the hero view and the primary live screen. |
| E2 | Charts in this plan are hand-drawn SVG (one stacked area, bars), not uPlot. | No canvas means they are testable in jsdom and smaller. uPlot comes in with SP6b's zoomable time series. Deviates from parent spec §5.10, so it needs the owner's OK. |
| E3 | A hand-written History-API router (no dependency). | Seven routes and two parameterised ones; no library is needed. |
| E4 | No Bits UI yet: nothing in this scope needs Dialog, Popover or Combobox. It arrives with the modal and suggestion popover in SP6b. | YAGNI. |
| E5 | Below 1024 px the 72 px rail stays (the 768 px "Menu" drawer needs Dialog and lands in SP6b). | Follows E4. |
| E6 | Honeypot pods: at most 4 in the scene (console spec §5), with a "+N more" chip on the last pod. | The console spec outranks the UX doc's "max 6". |
| E7 | Topology flows: Clean uses `Counters` Allow/Monitor; recon, exploitation and quarantine rates are derived from board deltas and labelled "approx." (G9); the "Stopped at shield" stub carries Challenge and the Block remainder. | Matches UX §4 edges with the data this plan has. |
| E8 | `?static` in the URL stops the fixture live feed (for deterministic tests and review screenshots). | Test stability. |
| E9 | The ground noise texture (design system §1.5) is deferred. | Decorative at 2.5–3.5 % opacity; needs an asset. |

## File Structure

```
ui/
  package.json, package-lock.json, vite.config.ts, svelte.config.js, tsconfig.json, index.html,
  playwright.config.ts, .gitignore
  scripts/check-budget.mjs              budget gate over dist/.vite/manifest.json
  src/main.ts                           fonts, tokens, theme, mount
  src/App.svelte                        shell + lazy route outlet
  src/test-setup.ts                     jsdom polyfills (matchMedia)
  src/styles/tokens.css                 verbatim design-system §6 (+ "Inter Variable" family)
  src/styles/base.css                   reset, type, focus ring, buttons, tables, glass, sr-only
  src/styles/tokens.test.ts             contrast + dark-block parity
  src/lib/api/types.ts                  wire and view types
  src/lib/api/source.ts                 DataSource interface + FixtureSource
  src/lib/api/fixtures.ts               deterministic fixtures (makeFixtures)
  src/lib/api/rng.ts                    mulberry32
  src/lib/api/fixtures.test.ts
  src/lib/format.ts (+ .test.ts)        rps, counts, times, TTL text
  src/lib/assets.ts                     prop and scene URLs via import.meta.glob
  src/lib/icons.ts                      the Lucide icons used, in one place
  src/lib/state/theme.svelte.ts (+ .test.ts)
  src/lib/state/router.svelte.ts (+ .test.ts)
  src/lib/state/app.svelte.ts           session, status, counters, board, live state, clock
  src/lib/components/Link.svelte, VerdictChip.svelte, StageChip.svelte, HealthPill.svelte,
                     KpiTile.svelte, EmptyState.svelte, Region.svelte, ToastStack.svelte,
                     toasts.svelte.ts, components.test.ts
  src/lib/shell/TopBar.svelte, NavRail.svelte, ThemeToggle.svelte, shell.test.ts
  src/screens/Dashboard.svelte, dashboard/StackedArea.svelte, dashboard/series.ts (+ .test.ts)
  src/screens/Topology.svelte, topology/geometry.ts, topology/model.ts (+ .test.ts),
              topology/Scene.svelte, topology/DetailCard.svelte, topology/TableView.svelte,
              topology/Legend.svelte, topology/topology.test.ts
  src/screens/Chains.svelte, chains/grid.ts (+ .test.ts), chains/chains.test.ts
  src/screens/Placeholder.svelte
  e2e/console.spec.ts
```

## Environment for every task

```bash
# Git Bash, from the worktree root; all npm commands run in ui/.
cd ui
node --version   # v24.x
```

The props (`ui/assets/props/*.webp`) and scenes (`ui/assets/scenes/*.webp`) are untracked files in the owner's main checkout. Copy them into the worktree once, before Task 1: `cp -r <main-checkout>/ui/assets <worktree>/ui/` (never `git add` them).

---

### Task 1: Scaffold the app and the budget gate

**Files:**
- Create: `ui/package.json`, `ui/vite.config.ts`, `ui/svelte.config.js`, `ui/tsconfig.json`, `ui/index.html`, `ui/.gitignore`, `ui/src/main.ts`, `ui/src/App.svelte`, `ui/src/test-setup.ts`, `ui/src/app.test.ts`, `ui/scripts/check-budget.mjs`

**Interfaces:**
- Produces: `npm run build | test | check | budget | e2e`; `dist/.vite/manifest.json`.

- [ ] **Step 1: Write the config files**

`ui/package.json`:

```json
{
  "name": "venusflytrap-console",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview --port 4173 --strictPort",
    "check": "svelte-check --tsconfig ./tsconfig.json --fail-on-warnings",
    "test": "vitest run",
    "budget": "node scripts/check-budget.mjs",
    "e2e": "playwright test"
  },
  "dependencies": {
    "@fontsource-variable/inter": "5.3.0",
    "@fontsource/jetbrains-mono": "5.3.0",
    "@lucide/svelte": "1.56.0"
  },
  "devDependencies": {
    "@axe-core/playwright": "4.13.0",
    "@playwright/test": "1.64.0",
    "@sveltejs/vite-plugin-svelte": "7.3.1",
    "@testing-library/svelte": "5.4.2",
    "jsdom": "30.1.2",
    "svelte": "5.57.2",
    "svelte-check": "4.7.6",
    "typescript": "6.0.3",
    "vite": "8.3.4",
    "vitest": "5.0.4"
  }
}
```

`ui/vite.config.ts`:

```ts
/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// The admin listener's policy (parent spec §5.8). `vite preview` serves it so the
// e2e suite sees exactly what production will enforce.
export const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  build: { target: 'es2022', manifest: true, assetsInlineLimit: 0 },
  preview: {
    headers: {
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    setupFiles: ['src/test-setup.ts'],
  },
});
```

`ui/svelte.config.js`:

```js
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default { preprocess: vitePreprocess() };
```

`ui/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "strict": true,
    "noEmit": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "skipLibCheck": true,
    "types": ["vite/client"]
  },
  "include": ["src/**/*.ts", "src/**/*.svelte", "e2e/**/*.ts", "vite.config.ts", "playwright.config.ts"]
}
```

`ui/index.html` (no inline script or style):

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Venusflytrap console</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

`ui/.gitignore`:

```
node_modules/
dist/
test-results/
playwright-report/
```

`ui/src/main.ts` (Task 2 adds fonts, tokens and theme):

```ts
import { mount } from 'svelte';
import App from './App.svelte';

const target = document.getElementById('app');
if (target) mount(App, { target });
```

`ui/src/App.svelte` (replaced in Task 4):

```svelte
<main>
  <h1>Venusflytrap console</h1>
</main>
```

`ui/src/test-setup.ts`:

```ts
// jsdom has no matchMedia; components read prefers-color-scheme and prefers-reduced-motion.
if (!window.matchMedia) {
  window.matchMedia = (query: string): MediaQueryList =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
```

`ui/scripts/check-budget.mjs`:

```js
// Budget gate (parent spec §5.10): initial JS <= 150 KB gz, each lazy chunk <= 80 KB gz.
import { readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const manifest = JSON.parse(readFileSync('dist/.vite/manifest.json', 'utf8'));
const gz = (file) => gzipSync(readFileSync(`dist/${file}`)).length;
const kb = (n) => (n / 1024).toFixed(1);

const entry = Object.values(manifest).find((c) => c.isEntry);
if (!entry) throw new Error('no entry chunk in the manifest');
const seen = new Set();
const walk = (chunk) => {
  if (seen.has(chunk.file)) return;
  seen.add(chunk.file);
  for (const key of chunk.imports ?? []) walk(manifest[key]);
};
walk(entry);
const initial = [...seen].filter((f) => f.endsWith('.js')).reduce((sum, f) => sum + gz(f), 0);
let failed = initial > 150 * 1024;
console.log(`initial JS ${kb(initial)} KB gz (budget 150)${failed ? '  OVER' : ''}`);
for (const [key, chunk] of Object.entries(manifest)) {
  if (!chunk.isDynamicEntry) continue;
  const size = gz(chunk.file);
  const over = size > 80 * 1024;
  failed ||= over;
  console.log(`chunk ${key} ${kb(size)} KB gz (budget 80)${over ? '  OVER' : ''}`);
}
process.exit(failed ? 1 : 0);
```

- [ ] **Step 2: Write the smoke test** (`ui/src/app.test.ts`)

```ts
import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import App from './App.svelte';

test('the app renders a level-1 heading', () => {
  render(App);
  expect(screen.getByRole('heading', { level: 1 })).toBeTruthy();
});
```

- [ ] **Step 3: Install and run everything**

Run: `npm install` → Expected: `package-lock.json` created, no `ERESOLVE` errors.
Run: `npm test` → Expected: 1 passed.
Run: `npm run check` → Expected: `0 errors and 0 warnings`.
Run: `npm run build && npm run budget` → Expected: `initial JS` well under 150 KB, exit 0.

- [ ] **Step 4: Commit**

```bash
git add ui/package.json ui/package-lock.json ui/vite.config.ts ui/svelte.config.js ui/tsconfig.json ui/index.html ui/.gitignore ui/src ui/scripts
git commit -m "feat(ui): scaffold the console app with a bundle budget gate"
```

---

### Task 2: Tokens, base styles, fonts, theme state

**Files:**
- Create: `ui/src/styles/tokens.css`, `ui/src/styles/base.css`, `ui/src/styles/tokens.test.ts`, `ui/src/lib/state/theme.svelte.ts`, `ui/src/lib/state/theme.test.ts`
- Modify: `ui/src/main.ts`

**Interfaces:**
- Produces: `theme: { pref: 'light' | 'dark' | 'system'; set(p): void; apply(): void }` (persists only `pref`, in `localStorage['vft-theme']`); `motion: { paused: boolean; set(paused: boolean): void }` (sets `data-motion="off"` on `<html>`); global classes `.sr-only`, `.num`, `.label-caps`, `.glass`, `.btn`, `.btn-primary`, `.btn-ghost`, `.card`, `.data-table`.

- [ ] **Step 1: Create `tokens.css`**

Copy the CSS block of `docs/superpowers/design/console-design-system.md` §6 (from `:root {` through the final `}` of `@media (forced-colors: active)`) verbatim into `ui/src/styles/tokens.css`, with one change: the `--vf-font-sans` value starts with `"Inter Variable", ` (the family name the self-hosted variable font registers), i.e.

```css
  --vf-font-sans: "Inter Variable", "Inter", system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Liberation Sans", Arial, sans-serif;
```

- [ ] **Step 2: Write the failing token tests** (`ui/src/styles/tokens.test.ts`)

```ts
import { describe, expect, test } from 'vitest';
import css from './tokens.css?raw';

function block(re: RegExp): Map<string, string> {
  const m = css.match(re);
  if (!m) throw new Error(`block not found: ${re}`);
  const out = new Map<string, string>();
  for (const d of m[1].matchAll(/--vf-([a-z0-9-]+):\s*([^;]+);/g)) out.set(d[1], d[2].trim());
  return out;
}

const light = block(/^:root\s*\{([\s\S]*?)\n\}/m);
const dark = block(/\[data-theme="dark"\]\s*\{([\s\S]*?)\n\}/);
const systemDark = block(/:root:not\(\[data-theme="light"\]\)\s*\{([\s\S]*?)\n\s*\}/);

function resolve(t: Map<string, string>, name: string): string {
  let v = t.get(name) ?? light.get(name);
  for (let i = 0; v?.startsWith('var(') && i < 5; i++) {
    const ref = v.slice('var(--vf-'.length, -1);
    v = t.get(ref) ?? light.get(ref);
  }
  if (!v || !/^#[0-9A-Fa-f]{6}$/.test(v)) throw new Error(`${name} is not a solid hex colour: ${v}`);
  return v;
}

function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// [foreground, background, minimum] — design system §1.1–§1.2 and §5.
const PAIRS: [string, string, number][] = [
  ...['surface-raised', 'surface-base', 'surface-overlay'].flatMap((bg): [string, string, number][] => [
    ['text-primary', bg, 4.5],
    ['text-secondary', bg, 4.5],
  ]),
  ['text-muted', 'surface-raised', 4.5],
  ['text-muted', 'surface-overlay', 4.5],
  ['text-muted', 'surface-sunken', 4.5],
  ['text-on-accent', 'accent', 4.5],
  ['text-on-attention', 'attention-fill', 4.5],
  ['text-on-danger', 'danger', 4.5],
  ['accent', 'surface-raised', 4.5],
  ['attention', 'surface-raised', 4.5],
  ['danger', 'surface-raised', 4.5],
  ...['allow', 'monitor', 'challenge', 'block'].flatMap((v): [string, string, number][] => [
    [`verdict-${v}-fg`, `verdict-${v}-bg`, 4.5],
    [`verdict-${v}-fg`, 'surface-raised', 4.5],
    [`verdict-${v}-line`, 'surface-base', 3],
  ]),
  ...['none', 'recon', 'enumeration', 'exploitation', 'exfiltration'].flatMap((s): [string, string, number][] => [
    [`stage-${s}-fg`, `stage-${s}-bg`, 4.5],
    [`stage-${s}-fg`, 'surface-raised', 4.5],
  ]),
  ['focus-ring', 'surface-base', 3],
  ['focus-ring', 'surface-raised', 3],
  ['focus-ring', 'surface-overlay', 3],
  ['border-strong', 'surface-raised', 3],
  ['border-strong', 'surface-base', 3],
  ['line-idle', 'surface-base', 3],
  ['line-active', 'surface-base', 3],
];

describe.each([
  ['light', light],
  ['dark', dark],
])('%s theme', (_, t) => {
  test.each(PAIRS)('%s on %s >= %d:1', (fg, bg, min) => {
    expect(contrast(resolve(t, fg), resolve(t, bg))).toBeGreaterThanOrEqual(min);
  });
});

test('the System dark block equals the manual dark block', () => {
  expect(Object.fromEntries(systemDark)).toEqual(Object.fromEntries(dark));
});
```

Add `ui/src/vite-env.d.ts` so `?raw` imports type-check:

```ts
/// <reference types="vite/client" />
```

- [ ] **Step 3: Run the token tests**

Run: `npm test -- tokens` → Expected: all pass. A failing pair is a design-system finding: report the pair, both hex values and the computed ratio to the owner; do not edit a token to make it pass without the owner's decision.

- [ ] **Step 4: Write `base.css`**

```css
*, *::before, *::after { box-sizing: border-box; }
html {
  font-family: var(--vf-font-sans);
  font-size: var(--vf-fs-md);
  line-height: var(--vf-lh-md);
  color: var(--vf-text-primary);
  background: var(--vf-surface-base);
  -webkit-text-size-adjust: 100%;
}
body { margin: 0; min-height: 100vh; }
h1, h2, h3, p, dl, dd, figure { margin: 0; }
h1 { font-size: var(--vf-fs-title-lg); line-height: var(--vf-lh-title-lg); font-weight: 600; }
h2 { font-size: var(--vf-fs-title-md); line-height: var(--vf-lh-title-md); font-weight: 600; }
h3 { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); font-weight: 600; }
a { color: var(--vf-accent); }
button, input, select { font: inherit; color: inherit; }
:focus-visible {
  outline: var(--vf-bw-focus) solid var(--vf-focus-ring);
  outline-offset: 2px;
  box-shadow: var(--vf-glow-focus);
}
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.num { font-variant-numeric: var(--vf-numeric); }
.mono { font-family: var(--vf-font-mono); font-size: var(--vf-fs-sm); }
.label-caps {
  font-size: var(--vf-fs-label); line-height: var(--vf-lh-label); font-weight: 600;
  text-transform: uppercase; letter-spacing: var(--vf-tracking-caps); color: var(--vf-text-secondary);
}
.secondary { color: var(--vf-text-secondary); }
.glass {
  background: var(--vf-surface-raised-glass);
  backdrop-filter: var(--vf-glass-filter);
  -webkit-backdrop-filter: var(--vf-glass-filter);
  border: var(--vf-bw-hair) solid var(--vf-border-hairline);
}
.card {
  background: var(--vf-surface-raised-glass);
  backdrop-filter: var(--vf-glass-filter);
  -webkit-backdrop-filter: var(--vf-glass-filter);
  border: var(--vf-bw-hair) solid var(--vf-border-hairline);
  border-radius: var(--vf-radius-md);
  box-shadow: var(--vf-shadow-1);
  padding: var(--vf-space-4);
}
.btn {
  display: inline-flex; align-items: center; gap: var(--vf-space-2);
  height: var(--vf-control-md); padding: 0 var(--vf-space-4);
  border-radius: var(--vf-radius-lg); border: var(--vf-bw-std) solid var(--vf-border-strong);
  background: var(--vf-surface-raised); color: var(--vf-text-primary);
  box-shadow: var(--vf-shadow-1); cursor: pointer; text-decoration: none;
  font-weight: 500; transition: background var(--vf-dur-fast) var(--vf-ease-standard);
}
.btn:hover { background: var(--vf-accent-soft); border-color: var(--vf-accent); }
.btn:active { box-shadow: var(--vf-shadow-inset); }
.btn-sm { height: var(--vf-control-sm); padding: 0 var(--vf-space-3); font-size: var(--vf-fs-sm); }
.btn-primary { background: var(--vf-accent); color: var(--vf-text-on-accent); border-color: transparent; }
.btn-primary:hover { background: var(--vf-accent-hover); box-shadow: var(--vf-shadow-1), var(--vf-glow-hover); }
.btn-ghost { background: transparent; border-color: transparent; box-shadow: none; color: var(--vf-accent); }
.btn-ghost:hover { background: var(--vf-accent-soft); }
.btn[aria-pressed='true'] { background: var(--vf-accent-soft); box-shadow: var(--vf-shadow-inset); }
.data-table { width: 100%; border-collapse: collapse; font-size: var(--vf-fs-sm); }
.data-table th {
  text-align: left; font-size: var(--vf-fs-label); text-transform: uppercase;
  letter-spacing: var(--vf-tracking-caps); color: var(--vf-text-secondary); font-weight: 600;
  padding: var(--vf-space-2) var(--vf-space-3); border-bottom: var(--vf-bw-std) solid var(--vf-border-subtle);
}
.data-table td {
  height: var(--vf-row-h); padding: 0 var(--vf-space-3);
  border-bottom: var(--vf-bw-std) solid var(--vf-border-subtle);
}
.data-table td.n, .data-table th.n { text-align: right; font-variant-numeric: var(--vf-numeric); }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition-duration: 0ms !important; animation-duration: 0ms !important; }
}
```

- [ ] **Step 5: Write the failing theme tests** (`ui/src/lib/state/theme.test.ts`)

```ts
import { beforeEach, expect, test } from 'vitest';
import { motion, theme } from './theme.svelte';

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.motion;
});

test('light and dark set data-theme and persist only the preference', () => {
  theme.set('dark');
  expect(document.documentElement.dataset.theme).toBe('dark');
  expect(localStorage.getItem('vft-theme')).toBe('dark');
  theme.set('light');
  expect(document.documentElement.dataset.theme).toBe('light');
  expect(localStorage.length).toBe(1);
});

test('system removes data-theme so prefers-color-scheme decides', () => {
  theme.set('dark');
  theme.set('system');
  expect(document.documentElement.dataset.theme).toBeUndefined();
  expect(localStorage.getItem('vft-theme')).toBe('system');
});

test('pause sets data-motion off and resume clears it', () => {
  motion.set(true);
  expect(document.documentElement.dataset.motion).toBe('off');
  motion.set(false);
  expect(document.documentElement.dataset.motion).toBeUndefined();
});
```

- [ ] **Step 6: Implement `theme.svelte.ts`**

```ts
export type ThemePref = 'light' | 'dark' | 'system';
const KEY = 'vft-theme';

function stored(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

class Theme {
  pref = $state<ThemePref>(stored());

  set(p: ThemePref) {
    this.pref = p;
    try {
      localStorage.setItem(KEY, p);
    } catch {
      // Storage blocked: the choice lasts for this page only.
    }
    this.apply();
  }

  apply() {
    const root = document.documentElement;
    if (this.pref === 'system') delete root.dataset.theme;
    else root.dataset.theme = this.pref;
  }
}

class Motion {
  paused = $state(false);

  set(paused: boolean) {
    this.paused = paused;
    if (paused) document.documentElement.dataset.motion = 'off';
    else delete document.documentElement.dataset.motion;
  }

  /** True when nothing may animate: the OS setting or the in-app Pause. */
  get reduced(): boolean {
    return this.paused || window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }
}

export const theme = new Theme();
export const motion = new Motion();
```

- [ ] **Step 7: Load fonts, tokens and theme in `main.ts`**

```ts
import '@fontsource-variable/inter';
import '@fontsource/jetbrains-mono/400.css';
import './styles/tokens.css';
import './styles/base.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { theme } from './lib/state/theme.svelte';

theme.apply();
const target = document.getElementById('app');
if (target) mount(App, { target });
```

- [ ] **Step 8: Run everything**

Run: `npm test && npm run check && npm run build && npm run budget` → Expected: green; `dist/assets` contains `.woff2` files (fonts are self-hosted, not inlined).

- [ ] **Step 9: Commit**

```bash
git add ui/src
git commit -m "feat(ui): design tokens, base styles, self-hosted fonts and theme state"
```

---

### Task 3: Types, fixtures and the `DataSource`

**Files:**
- Create: `ui/src/lib/api/types.ts`, `ui/src/lib/api/rng.ts`, `ui/src/lib/api/fixtures.ts`, `ui/src/lib/api/source.ts`, `ui/src/lib/api/fixtures.test.ts`, `ui/src/lib/format.ts`, `ui/src/lib/format.test.ts`

**Interfaces:**
- Produces: every type below; `makeFixtures(now: number): Fixtures`; `interface DataSource`; `class FixtureSource implements DataSource` with `new FixtureSource({ now?: () => number; live?: boolean; tickMs?: number })`; formatting helpers `fmtRps`, `fmtCount`, `fmtClock`, `fmtAgo`, `banText`.

- [ ] **Step 1: Write `types.ts`**

```ts
// Wire types mirrored from the SP2 plan (vft-core). Replace with re-exports from
// ui/src/gen once SP2 Task 9 lands.
export type Verdict = 'Allow' | 'Monitor' | 'Challenge' | 'Block';
export type Stage = 'Recon' | 'Enumeration' | 'Exploitation' | 'Exfiltration';
export type FourValued = 'None' | 'Safe' | 'Suspicious' | 'Dangerous';
export type Location = 'Path' | 'Query' | 'Header' | 'Cookie' | 'Body';
export type Family =
  | 'Sqli' | 'Xss' | 'CommandInjection' | 'PathTraversal' | 'Recon' | 'Ssrf'
  | 'Honeypot' | 'Intel' | 'Limit' | 'Anomaly';
export type CauseKind =
  | 'NoEvidence' | 'Detection' | 'Honeypot' | 'IntelDeny' | 'Ban'
  | 'ChainEscalation' | 'Limit' | 'Allowlisted';
export type BanCause = 'Honeypot' | 'Exfiltration' | 'RepeatedExploitation' | 'Manual';

export interface FieldRef { loc: Location; name: string }
export interface Contribution {
  engine: string; field: FieldRef | null; construct: string | null; family: Family | null;
  value: FourValued; weight: number; points: number;
}
export interface Cause {
  kind: CauseKind; option_key: string; construct: string | null; field: FieldRef | null; msg: string;
}

// View types for SP3-SP5 (UX architecture §14, gaps G1-G10). Provisional.
export type Perm = 'Viewer' | 'Operator' | 'Admin';
export type Health = 'Ok' | 'Warn' | 'Degraded' | 'Critical';
export type LiveState = 'Connected' | 'Reconnecting' | 'Offline';

export interface Session { perm: Perm; key_id: string; expires_ms: number } // G1
export interface StatusRecord {                                              // G3
  worst: Health;
  components: { name: string; state: Health; msg: string }[];
  drops: Record<string, number>;
  config_rev: number;
  version: string;
  restart_required: boolean;
}
/** Requests per second by verdict, in VERDICTS order. */
export interface Counters { rps_by_verdict: [number, number, number, number]; dropped_total: number }
export interface Dashboard {                                                 // G2
  from_ms: number;
  to_ms: number;
  bucket_ms: number;
  /** One count array per verdict, in VERDICTS order; all the same length. */
  requests_by_verdict: [number[], number[], number[], number[]];
  sources_by_stage: { Clean: number } & Record<Stage, number>;
  top_constructs: { id: string; family: Family; count: number }[];
  top_paths: { prefix: string; count: number; by_verdict: [number, number, number, number] }[];
  honeypot_hits: { path: string; count: number; last_ts_ms: number | null; last_src: string | null }[];
  active_bans: number;
  dropped: number;
}
export interface BanView { until_ms: number | null; reason: BanCause; offences: number; manual: boolean } // G8
export interface BanEntry extends BanView { key: string; since_ms: number }
export interface SourceView {                                                // G5
  key: string;
  ip: string;
  stage: Stage | null;
  stage_path: { stage: Stage; first_ts_ms: number }[];
  /** Events per stage, in STAGES order. */
  stage_counts: [number, number, number, number];
  requests: number;
  blocked: number;
  honeypot_hits: number;
  top_constructs: string[];
  first_seen_ms: number;
  last_seen_ms: number;
  ban: BanView | null;
}
export type LiveFrame =
  | { kind: 'counters'; counters: Counters }
  | { kind: 'board'; board: SourceView[] }
  | { kind: 'state'; live: LiveState };

export const VERDICTS: readonly Verdict[] = ['Allow', 'Monitor', 'Challenge', 'Block'];
export const STAGES: readonly Stage[] = ['Recon', 'Enumeration', 'Exploitation', 'Exfiltration'];
```

- [ ] **Step 2: Write `rng.ts`**

```ts
/** Deterministic PRNG for fixtures (mulberry32). Returns floats in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed | 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
```

- [ ] **Step 3: Write the failing fixture and format tests**

`ui/src/lib/api/fixtures.test.ts`:

```ts
import { expect, test } from 'vitest';
import { makeFixtures } from './fixtures';
import { FixtureSource } from './source';
import { STAGES } from './types';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);

test('fixtures are deterministic', () => {
  const [a, b] = [makeFixtures(NOW), makeFixtures(NOW)];
  expect(a.board).toEqual(b.board);
  expect(a.dashboard(NOW - 3_600_000, NOW)).toEqual(b.dashboard(NOW - 3_600_000, NOW));
});

test('board is consistent with its own stage paths', () => {
  for (const s of makeFixtures(NOW).board) {
    if (s.stage === null) continue;
    expect(s.stage_path.at(-1)?.stage).toBe(s.stage);
    expect(s.blocked).toBeLessThanOrEqual(s.requests);
    expect(s.stage_counts[STAGES.indexOf(s.stage)]).toBeGreaterThan(0);
  }
});

test('dashboard aggregates agree with the board', () => {
  const f = makeFixtures(NOW);
  const d = f.dashboard(NOW - 3_600_000, NOW);
  expect(d.active_bans).toBe(f.board.filter((s) => s.ban).length);
  for (const stage of STAGES) {
    expect(d.sources_by_stage[stage]).toBe(f.board.filter((s) => s.stage === stage).length);
  }
  const lens = d.requests_by_verdict.map((a) => a.length);
  expect(new Set(lens).size).toBe(1);
  expect(d.top_paths).toHaveLength(5);
});

test('a static FixtureSource emits no frames', async () => {
  const src = new FixtureSource({ now: () => NOW, live: false });
  let frames = 0;
  const stop = src.subscribe(() => frames++);
  await new Promise((r) => setTimeout(r, 30));
  stop();
  expect(frames).toBe(0);
  expect((await src.board()).length).toBeGreaterThan(8);
});

test('a live FixtureSource emits counters and board frames', async () => {
  const src = new FixtureSource({ now: () => NOW, live: true, tickMs: 5 });
  const kinds = new Set<string>();
  const stop = src.subscribe((f) => kinds.add(f.kind));
  await new Promise((r) => setTimeout(r, 40));
  stop();
  expect(kinds.has('counters') && kinds.has('board')).toBe(true);
});
```

`ui/src/lib/format.test.ts`:

```ts
import { expect, test } from 'vitest';
import { banText, fmtAgo, fmtCount, fmtRps } from './format';

test('rates', () => {
  expect(fmtRps(0)).toBe('0/s');
  expect(fmtRps(0.42)).toBe('0.4/s');
  expect(fmtRps(4.06)).toBe('4.1/s');
  expect(fmtRps(38.2)).toBe('38/s');
  expect(fmtRps(412.3)).toBe('412/s');
});

test('counts and ages', () => {
  expect(fmtCount(182400)).toBe('182,400');
  expect(fmtAgo(12_000)).toBe('12 s ago');
  expect(fmtAgo(4 * 60_000)).toBe('4 min ago');
  expect(fmtAgo(2 * 3_600_000)).toBe('2 h ago');
});

test('ban text changes once a minute', () => {
  const now = 1_000_000;
  expect(banText({ until_ms: null }, now)).toBe('Banned · Permanent');
  expect(banText({ until_ms: now + 42 * 60_000 + 30_000 }, now)).toBe('Banned · 42 min left');
  expect(banText({ until_ms: now + 125 * 60_000 }, now)).toBe('Banned · 2 h 5 min left');
  expect(banText({ until_ms: now + 20_000 }, now)).toBe('Banned · < 1 min left');
  expect(banText({ until_ms: now - 1 }, now)).toBe('Ban expired');
});
```

- [ ] **Step 4: Run them to see them fail**

Run: `npm test -- fixtures format` → Expected: FAIL, cannot resolve `./fixtures`, `./format`.

- [ ] **Step 5: Implement `format.ts`**

```ts
const nf = new Intl.NumberFormat('en-US');

export function fmtRps(n: number): string {
  if (n <= 0) return '0/s';
  if (n < 10) return `${n.toFixed(1)}/s`;
  return `${Math.round(n)}/s`;
}

export function fmtCount(n: number): string {
  return nf.format(Math.round(n));
}

export function fmtClock(ms: number): string {
  return new Date(ms).toLocaleTimeString('en-GB', { hour12: false });
}

export function fmtAgo(ms: number): string {
  if (ms < 60_000) return `${Math.max(0, Math.floor(ms / 1000))} s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)} min ago`;
  return `${Math.floor(ms / 3_600_000)} h ago`;
}

/** Ban badge text. Minute granularity, so screen readers hear it change at most once a minute. */
export function banText(ban: { until_ms: number | null }, now: number): string {
  if (ban.until_ms === null) return 'Banned · Permanent';
  const left = ban.until_ms - now;
  if (left <= 0) return 'Ban expired';
  const min = Math.floor(left / 60_000);
  if (min < 1) return 'Banned · < 1 min left';
  if (min < 60) return `Banned · ${min} min left`;
  return `Banned · ${Math.floor(min / 60)} h ${min % 60} min left`;
}
```

- [ ] **Step 6: Implement `fixtures.ts`**

```ts
import { mulberry32 } from './rng';
import type {
  BanEntry, BanView, Counters, Dashboard, Family, Session, SourceView, Stage, StatusRecord,
} from './types';
import { STAGES } from './types';

const MIN = 60_000;
const HOUR = 60 * MIN;

/** Decoy paths: the engine's default `honeypot.decoy_paths`. */
export const DECOYS = ['/.git/config', '/admin/backup.zip', '/wp-admin/secret', '/phpmyadmin/', '/_internal/debug'];

type Row = [
  key: string, ip: string, stage: Stage,
  path: [Stage, number][], counts: [number, number, number, number],
  requests: number, blocked: number, honeypot: number, constructs: string[], lastAgo: number,
  ban: null | { inMs: number | null; reason: BanView['reason']; offences: number; manual: boolean },
];

const ROWS: Row[] = [
  ['203.0.113.7', '203.0.113.7', 'Exploitation', [['Recon', 7 * MIN], ['Exploitation', 3 * MIN]], [4, 0, 9, 0], 240, 188, 0, ['sqli.union-select', 'sqli.boolean-tautology'], 2_000, null],
  ['198.51.100.23', '198.51.100.23', 'Exfiltration', [['Recon', 22 * MIN], ['Exploitation', 12 * MIN], ['Exfiltration', 9 * MIN]], [3, 0, 14, 2], 512, 470, 0, ['sqli.union-select', 'sqli.fn-load-file'], 5_000, null],
  ['192.0.2.144', '192.0.2.144', 'Exploitation', [['Exploitation', 4 * MIN]], [0, 0, 6, 0], 131, 97, 0, ['xss.event-handler'], 9_000, null],
  ['203.0.113.51', '203.0.113.51', 'Exploitation', [['Recon', 30 * MIN], ['Exploitation', 18 * MIN]], [2, 0, 5, 0], 88, 61, 1, ['cmd.chained-command'], 40_000, { inMs: 59 * MIN, reason: 'Honeypot', offences: 1, manual: false }],
  ['198.51.100.9', '198.51.100.9', 'Recon', [['Recon', 6 * MIN]], [5, 0, 0, 0], 46, 3, 0, ['recon.sensitive-path-probe'], 3_000, null],
  ['192.0.2.77', '192.0.2.77', 'Enumeration', [['Recon', 15 * MIN], ['Enumeration', 11 * MIN]], [2, 6, 0, 0], 310, 22, 0, ['intel.scanner-ua'], 1_000, null],
  ['2001:db8:4f::/64', '2001:db8:4f::17', 'Recon', [['Recon', 2 * MIN]], [3, 0, 0, 0], 19, 0, 0, ['recon.sensitive-path-probe'], 12_000, null],
  ['203.0.113.200', '203.0.113.200', 'Exploitation', [['Exploitation', 50 * MIN]], [0, 0, 3, 0], 64, 64, 2, ['path.directory-traversal'], 8 * MIN, { inMs: 42 * MIN, reason: 'RepeatedExploitation', offences: 2, manual: false }],
  ['198.51.100.140', '198.51.100.140', 'Recon', [['Recon', 40 * MIN]], [1, 0, 0, 0], 7, 1, 0, ['recon.sensitive-path-probe'], 25 * MIN, null],
  ['192.0.2.12', '192.0.2.12', 'Exploitation', [['Recon', 55 * MIN], ['Exploitation', 44 * MIN]], [1, 0, 2, 0], 40, 40, 0, ['sqli.stacked-query'], 30 * MIN, { inMs: null, reason: 'Manual', offences: 1, manual: true }],
  ['203.0.113.99', '203.0.113.99', 'Recon', [['Recon', 9 * MIN]], [2, 0, 0, 0], 12, 2, 0, ['recon.sensitive-path-probe'], 50_000, null],
];

const TOP_CONSTRUCTS: { id: string; family: Family; count: number }[] = [
  { id: 'sqli.union-select', family: 'Sqli', count: 412 },
  { id: 'xss.event-handler', family: 'Xss', count: 233 },
  { id: 'cmd.chained-command', family: 'CommandInjection', count: 118 },
  { id: 'path.directory-traversal', family: 'PathTraversal', count: 97 },
  { id: 'recon.sensitive-path-probe', family: 'Recon', count: 88 },
  { id: 'sqli.boolean-tautology', family: 'Sqli', count: 61 },
  { id: 'xss.script-tag', family: 'Xss', count: 44 },
  { id: 'honeypot.decoy-hit', family: 'Honeypot', count: 19 },
  { id: 'intel.scanner-ua', family: 'Intel', count: 17 },
  { id: 'limit.payload-truncated', family: 'Limit', count: 3 },
];

/** Per hour. */
const TOP_PATHS: Dashboard['top_paths'] = [
  { prefix: '/api/search', count: 182_400, by_verdict: [171_000, 6_200, 1_400, 3_800] },
  { prefix: '/login', count: 96_300, by_verdict: [90_100, 3_900, 600, 1_700] },
  { prefix: '/api/items', count: 64_800, by_verdict: [62_900, 1_100, 300, 500] },
  { prefix: '/static', count: 51_200, by_verdict: [51_150, 40, 0, 10] },
  { prefix: '/account', count: 23_900, by_verdict: [22_800, 600, 120, 380] },
];

/** Per hour, aligned with DECOYS. */
const DECOY_HITS: [number, number | null, string | null][] = [
  [9, 4 * MIN, '203.0.113.51'], [6, 11 * MIN, '203.0.113.200'], [3, 26 * MIN, '203.0.113.200'], [1, 48 * MIN, '192.0.2.144'], [0, null, null],
];

export const BASE_RPS: Counters['rps_by_verdict'] = [412.3, 18.6, 4.1, 38.2];

export interface Fixtures {
  session: Session;
  status: StatusRecord;
  counters: Counters;
  board: SourceView[];
  bans: BanEntry[];
  decoys: string[];
  dashboard(from: number, to: number): Dashboard;
}

export function makeFixtures(now: number): Fixtures {
  const board: SourceView[] = ROWS.map(([key, ip, stage, path, counts, requests, blocked, honeypot, constructs, lastAgo, ban]) => ({
    key, ip, stage,
    stage_path: path.map(([s, ago]) => ({ stage: s, first_ts_ms: now - ago })),
    stage_counts: counts,
    requests, blocked, honeypot_hits: honeypot, top_constructs: constructs,
    first_seen_ms: now - Math.max(...path.map(([, ago]) => ago)) - MIN,
    last_seen_ms: now - lastAgo,
    ban: ban && { until_ms: ban.inMs === null ? null : now + ban.inMs, reason: ban.reason, offences: ban.offences, manual: ban.manual },
  }));
  const bans: BanEntry[] = board
    .filter((s) => s.ban)
    .map((s) => ({ key: s.key, since_ms: s.last_seen_ms, ...(s.ban as BanView) }));

  const dashboard = (from: number, to: number): Dashboard => {
    const buckets = 60;
    const bucket_ms = Math.max(1, Math.floor((to - from) / buckets));
    const perBucket = bucket_ms / MIN;
    const rnd = mulberry32(7);
    const series = BASE_RPS.map((rps, v) =>
      Array.from({ length: buckets }, (_, i) => {
        const wave = 1 + 0.08 * Math.sin(i / 7 + v) + 0.04 * (rnd() - 0.5);
        const burst = v === 3 && i > 44 && i < 52 ? 2.4 : 1;
        return Math.round(rps * 60 * perBucket * wave * burst);
      }),
    ) as Dashboard['requests_by_verdict'];
    const scale = (to - from) / HOUR;
    const byStage = Object.fromEntries(STAGES.map((s) => [s, board.filter((b) => b.stage === s).length]));
    return {
      from_ms: from,
      to_ms: to,
      bucket_ms,
      requests_by_verdict: series,
      sources_by_stage: { Clean: 1832, ...byStage } as Dashboard['sources_by_stage'],
      top_constructs: TOP_CONSTRUCTS.map((c) => ({ ...c, count: Math.round(c.count * scale) })),
      top_paths: TOP_PATHS.map((p) => ({
        prefix: p.prefix,
        count: Math.round(p.count * scale),
        by_verdict: p.by_verdict.map((n) => Math.round(n * scale)) as [number, number, number, number],
      })),
      honeypot_hits: DECOYS.map((path, i) => ({
        path,
        count: Math.round(DECOY_HITS[i][0] * scale),
        last_ts_ms: DECOY_HITS[i][1] === null ? null : now - (DECOY_HITS[i][1] as number),
        last_src: DECOY_HITS[i][2],
      })),
      active_bans: bans.length,
      dropped: 0,
    };
  };

  return {
    session: { perm: 'Admin', key_id: 'k_7f3a', expires_ms: now + 7 * 24 * HOUR },
    status: {
      worst: 'Ok',
      components: ['proxy', 'history', 'live', 'intel'].map((name) => ({ name, state: 'Ok' as const, msg: '' })),
      drops: { history: 0, live: 0, jsonl: 0 },
      config_rev: 12,
      version: '0.1.0',
      restart_required: false,
    },
    counters: { rps_by_verdict: [...BASE_RPS] as Counters['rps_by_verdict'], dropped_total: 0 },
    board,
    bans,
    decoys: DECOYS,
    dashboard,
  };
}
```

- [ ] **Step 7: Implement `source.ts`**

```ts
import { BASE_RPS, makeFixtures, type Fixtures } from './fixtures';
import { mulberry32 } from './rng';
import type { BanEntry, Counters, Dashboard, LiveFrame, Session, SourceView, StatusRecord } from './types';

/** Everything the console reads. SP5 adds an HTTP + SSE implementation. */
export interface DataSource {
  session(): Promise<Session>;
  status(): Promise<StatusRecord>;
  counters(): Promise<Counters>;
  dashboard(from: number, to: number): Promise<Dashboard>;
  board(): Promise<SourceView[]>;
  bans(): Promise<BanEntry[]>;
  decoys(): Promise<string[]>;
  /** Live frames until the returned function is called. */
  subscribe(onFrame: (f: LiveFrame) => void): () => void;
}

export interface FixtureOptions {
  now?: () => number;
  /** Simulate the live feed (counters jitter, board activity). */
  live?: boolean;
  tickMs?: number;
}

export class FixtureSource implements DataSource {
  private readonly now: () => number;
  private readonly live: boolean;
  private readonly tickMs: number;
  private readonly f: Fixtures;
  private board_: SourceView[];

  constructor(opts: FixtureOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.live = opts.live ?? true;
    this.tickMs = opts.tickMs ?? 1000;
    this.f = makeFixtures(this.now());
    this.board_ = this.f.board;
  }

  async session() { return this.f.session; }
  async status() { return this.f.status; }
  async counters() { return this.f.counters; }
  async dashboard(from: number, to: number) { return this.f.dashboard(from, to); }
  async board() { return this.board_; }
  async bans() { return this.f.bans; }
  async decoys() { return this.f.decoys; }

  subscribe(onFrame: (f: LiveFrame) => void): () => void {
    if (!this.live) return () => {};
    const rnd = mulberry32(11);
    const timer = setInterval(() => {
      const rps = BASE_RPS.map((r) => Math.max(0, r * (1 + 0.1 * (rnd() - 0.5)))) as Counters['rps_by_verdict'];
      onFrame({ kind: 'counters', counters: { rps_by_verdict: rps, dropped_total: 0 } });
      const now = this.now();
      this.board_ = this.board_.map((s) => {
        if (s.stage === null || s.last_seen_ms < now - 5 * 60_000) return s;
        const hot = s.stage === 'Exploitation' || s.stage === 'Exfiltration';
        const add = Math.round((hot ? 6 : 1.5) * rnd() * (this.tickMs / 1000));
        if (add === 0) return s;
        const blocked = s.ban ? add : Math.round(add * (hot ? 0.8 : 0.1));
        return { ...s, requests: s.requests + add, blocked: s.blocked + blocked, last_seen_ms: now };
      });
      onFrame({ kind: 'board', board: this.board_ });
    }, this.tickMs);
    return () => clearInterval(timer);
  }
}
```

- [ ] **Step 8: Run the tests**

Run: `npm test && npm run check` → Expected: green.

- [ ] **Step 9: Commit**

```bash
git add ui/src/lib
git commit -m "feat(ui): wire and view types, deterministic fixtures, DataSource"
```

---

### Task 4: App state, router, shell

**Files:**
- Create: `ui/src/lib/state/app.svelte.ts`, `ui/src/lib/state/router.svelte.ts`, `ui/src/lib/state/router.test.ts`, `ui/src/lib/icons.ts`, `ui/src/lib/assets.ts`, `ui/src/lib/components/Link.svelte`, `ui/src/lib/components/HealthPill.svelte`, `ui/src/lib/components/toasts.svelte.ts`, `ui/src/lib/components/ToastStack.svelte`, `ui/src/lib/shell/TopBar.svelte`, `ui/src/lib/shell/NavRail.svelte`, `ui/src/lib/shell/ThemeToggle.svelte`, `ui/src/lib/shell/shell.test.ts`, `ui/src/screens/Placeholder.svelte`
- Modify: `ui/src/App.svelte`, `ui/src/app.test.ts`

**Interfaces:**
- Produces:
  - `router: { path: string; search: URLSearchParams; route: Route; navigate(href: string, replace?: boolean): void }`, `type RouteName = 'dashboard' | 'topology' | 'monitor' | 'chains' | 'honeypot' | 'settings' | 'keys' | 'request' | 'source' | 'notfound'`, `interface Route { name: RouteName; param: string | null }`, `match(path: string): Route`, `NAV: { name: RouteName; href: string; label: string; adminOnly?: boolean }[]`.
  - `app: { src: DataSource | null; session; status; counters; board; prevBoard; boardAt; prevBoardAt; live: LiveState; lastFrameAt: number; now: number; stale: boolean; start(src: DataSource): Promise<void>; stop(): void }`.
  - `toasts.push({ tone: 'info' | 'success' | 'warn' | 'error'; text: string })`.
  - `propUrl(name: PropName): string | undefined`, `sceneUrl(name: SceneName): string | undefined`.
  - `<Link href class? current?>` (intercepts plain left clicks), `<HealthPill health detail?>`.

- [ ] **Step 1: Write the failing router test** (`router.test.ts`)

```ts
import { expect, test } from 'vitest';
import { match, router } from './router.svelte';

test('routes match, including parameters', () => {
  expect(match('/')).toEqual({ name: 'dashboard', param: null });
  expect(match('/topology')).toEqual({ name: 'topology', param: null });
  expect(match('/requests/r_42')).toEqual({ name: 'request', param: 'r_42' });
  expect(match('/sources/2001%3Adb8%3A4f%3A%3A%2F64')).toEqual({ name: 'source', param: '2001:db8:4f::/64' });
  expect(match('/nope')).toEqual({ name: 'notfound', param: null });
});

test('navigate updates path, search and history', () => {
  router.navigate('/chains?stage=Exploitation');
  expect(router.route.name).toBe('chains');
  expect(router.search.get('stage')).toBe('Exploitation');
  expect(location.pathname).toBe('/chains');
});
```

- [ ] **Step 2: Implement `router.svelte.ts`**

```ts
export type RouteName =
  | 'dashboard' | 'topology' | 'monitor' | 'chains' | 'honeypot' | 'settings' | 'keys'
  | 'request' | 'source' | 'notfound';
export interface Route { name: RouteName; param: string | null }

const TABLE: [RegExp, RouteName][] = [
  [/^\/$/, 'dashboard'],
  [/^\/topology$/, 'topology'],
  [/^\/monitor$/, 'monitor'],
  [/^\/chains$/, 'chains'],
  [/^\/honeypot$/, 'honeypot'],
  [/^\/settings$/, 'settings'],
  [/^\/keys$/, 'keys'],
  [/^\/requests\/([^/]+)$/, 'request'],
  [/^\/sources\/([^/]+)$/, 'source'],
];

export function match(path: string): Route {
  for (const [re, name] of TABLE) {
    const m = path.match(re);
    if (m) return { name, param: m[1] === undefined ? null : decodeURIComponent(m[1]) };
  }
  return { name: 'notfound', param: null };
}

export const NAV: { name: RouteName; href: string; label: string; adminOnly?: boolean }[] = [
  { name: 'dashboard', href: '/', label: 'Dashboard' },
  { name: 'topology', href: '/topology', label: 'Traffic topology' },
  { name: 'monitor', href: '/monitor', label: 'Monitor' },
  { name: 'chains', href: '/chains', label: 'Attack chains' },
  { name: 'honeypot', href: '/honeypot', label: 'Honeypot & bans' },
  { name: 'settings', href: '/settings', label: 'Settings' },
  { name: 'keys', href: '/keys', label: 'Keys', adminOnly: true },
];

/** Detail routes mark their parent as current in the nav (UX §2.2). */
export const PARENT: Partial<Record<RouteName, RouteName>> = { request: 'monitor', source: 'chains' };

class Router {
  path = $state(location.pathname);
  search = $state(new URLSearchParams(location.search));
  route = $derived(match(this.path));

  constructor() {
    window.addEventListener('popstate', () => this.sync());
  }

  navigate(href: string, replace = false) {
    if (replace) history.replaceState(null, '', href);
    else history.pushState(null, '', href);
    this.sync();
  }

  private sync() {
    this.path = location.pathname;
    this.search = new URLSearchParams(location.search);
  }
}

export const router = new Router();
```

- [ ] **Step 3: Implement `app.svelte.ts`**

```ts
import type { DataSource } from '../api/source';
import type { Counters, LiveFrame, LiveState, Session, SourceView, StatusRecord } from '../api/types';

/** Live data is stale after 20 s without a frame (15 s heartbeat + 5 s grace, UX §1). */
const STALE_MS = 20_000;

class AppState {
  src: DataSource | null = null;
  session = $state<Session | null>(null);
  status = $state<StatusRecord | null>(null);
  counters = $state<Counters | null>(null);
  board = $state<SourceView[]>([]);
  prevBoard: SourceView[] = [];
  boardAt = 0;
  prevBoardAt = 0;
  live = $state<LiveState>('Offline');
  lastFrameAt = $state(0);
  now = $state(Date.now());
  stale = $derived(this.live !== 'Connected' || this.now - this.lastFrameAt > STALE_MS);
  private stops: (() => void)[] = [];

  async start(src: DataSource) {
    this.src = src;
    const [session, status, counters, board] = await Promise.all([
      src.session(), src.status(), src.counters(), src.board(),
    ]);
    this.session = session;
    this.status = status;
    this.counters = counters;
    this.board = board;
    this.boardAt = Date.now();
    this.live = 'Connected';
    this.lastFrameAt = Date.now();
    this.stops.push(src.subscribe((f) => this.onFrame(f)));
    const clock = setInterval(() => (this.now = Date.now()), 1000);
    this.stops.push(() => clearInterval(clock));
  }

  stop() {
    for (const s of this.stops.splice(0)) s();
  }

  private onFrame(f: LiveFrame) {
    this.lastFrameAt = Date.now();
    if (f.kind === 'counters') this.counters = f.counters;
    else if (f.kind === 'board') {
      this.prevBoard = this.board;
      this.prevBoardAt = this.boardAt;
      this.board = f.board;
      this.boardAt = Date.now();
    } else this.live = f.live;
  }
}

export const app = new AppState();
```

- [ ] **Step 4: Icons, assets, Link, HealthPill, toasts, placeholder**

`ui/src/lib/icons.ts` (every icon the console uses, in one place):

```ts
export {
  CircleCheck, Eye, TriangleAlert, OctagonX, OctagonAlert, CircleGauge,
  LayoutDashboard, Network, ListFilter, Workflow, ShieldBan, Settings, KeyRound,
  Sun, Moon, Monitor as MonitorIcon, Radio, Table2, Pause, Play, X,
} from '@lucide/svelte';
```

If `npm run check` reports a missing export, the icon was renamed upstream: find its current name with `ls node_modules/@lucide/svelte/dist/icons | grep -i <word>` and re-export it under the old local name (for example `export { NewName as TriangleAlert }`).

`ui/src/lib/assets.ts`:

```ts
// Generated art is untracked until its licence is confirmed (console spec §11), so it is
// globbed: a checkout without it still builds and the images are simply absent.
const props = import.meta.glob('../../assets/props/*.webp', { eager: true, query: '?url', import: 'default' }) as Record<string, string>;
const scenes = import.meta.glob('../../assets/scenes/*.webp', { eager: true, query: '?url', import: 'default' }) as Record<string, string>;

export type PropName =
  | 'base-plate' | 'edge-gateway' | 'source-pod' | 'shield-tower' | 'route-block'
  | 'honeypot-flytrap' | 'quarantine-cage' | 'junction-box';
export type SceneName = 'quiet' | 'disconnected' | 'not-built' | 'no-results';

export const propUrl = (name: PropName): string | undefined => props[`../../assets/props/${name}.webp`];
export const sceneUrl = (name: SceneName): string | undefined => scenes[`../../assets/scenes/${name}.webp`];
```

`ui/src/lib/components/Link.svelte`:

```svelte
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { router } from '../state/router.svelte';

  let { href, class: cls = '', current = false, children, ...rest }:
    { href: string; class?: string; current?: boolean; children: Snippet; [k: string]: unknown } = $props();

  function onclick(e: MouseEvent) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    router.navigate(href);
  }
</script>

<a {href} class={cls} aria-current={current ? 'page' : undefined} {onclick} {...rest}>{@render children()}</a>
```

`ui/src/lib/components/HealthPill.svelte`:

```svelte
<script lang="ts">
  import type { Health } from '../api/types';
  import { CircleCheck, CircleGauge, OctagonAlert, TriangleAlert } from '../icons';

  let { health, detail = '' }: { health: Health; detail?: string } = $props();
  const GLYPH = { Ok: CircleCheck, Warn: TriangleAlert, Degraded: CircleGauge, Critical: OctagonAlert };
  const TONE = { Ok: 'ok', Warn: 'warn', Degraded: 'warn', Critical: 'error' };
  const Glyph = $derived(GLYPH[health]);
</script>

<span class="pill {TONE[health]}">
  <Glyph size={14} strokeWidth={1.5} aria-hidden="true" />
  <span>{health === 'Ok' ? 'OK' : health}</span>
  {#if detail}<span class="detail">{detail}</span>{/if}
</span>

<style>
  .pill {
    display: inline-flex; align-items: center; gap: var(--vf-space-1);
    height: 24px; padding: 0 10px; border-radius: var(--vf-radius-pill);
    font-size: var(--vf-fs-sm); font-weight: 600; box-shadow: var(--vf-shadow-1);
  }
  .ok { background: var(--vf-health-ok-bg); color: var(--vf-health-ok-fg); }
  .warn { background: var(--vf-health-warn-bg); color: var(--vf-health-warn-fg); }
  .error { background: var(--vf-health-error-bg); color: var(--vf-health-error-fg); }
  .detail { font-size: var(--vf-fs-xs); font-weight: 400; }
</style>
```

`ui/src/lib/components/toasts.svelte.ts`:

```ts
export type Tone = 'info' | 'success' | 'warn' | 'error';
export interface Toast { id: number; tone: Tone; text: string }

class Toasts {
  items = $state<Toast[]>([]);
  private next = 1;

  push(t: { tone: Tone; text: string }) {
    const toast = { id: this.next++, ...t };
    this.items = [...this.items, toast].slice(-3);
    if (t.tone !== 'error') setTimeout(() => this.dismiss(toast.id), 6000);
  }

  dismiss(id: number) {
    this.items = this.items.filter((t) => t.id !== id);
  }
}

export const toasts = new Toasts();
```

`ui/src/lib/components/ToastStack.svelte`:

```svelte
<script lang="ts">
  import { X } from '../icons';
  import { toasts } from './toasts.svelte';
</script>

<section class="stack" aria-label="Notifications">
  {#each toasts.items as t (t.id)}
    <div class="toast glass {t.tone}" role={t.tone === 'error' ? 'alert' : 'status'} aria-live={t.tone === 'error' ? undefined : 'polite'}>
      <span>{t.text}</span>
      <button class="btn btn-ghost btn-sm" aria-label="Dismiss notification" onclick={() => toasts.dismiss(t.id)}>
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  {/each}
</section>

<style>
  .stack { position: fixed; right: var(--vf-space-5); bottom: var(--vf-space-5); display: grid; gap: var(--vf-space-2); z-index: 20; }
  .toast {
    width: 360px; display: flex; align-items: center; justify-content: space-between; gap: var(--vf-space-2);
    padding: var(--vf-space-3) var(--vf-space-4); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-2);
  }
  .info { box-shadow: inset 3px 0 0 var(--vf-accent), var(--vf-shadow-2); }
  .success { box-shadow: inset 3px 0 0 var(--vf-verdict-allow-fg), var(--vf-shadow-2); }
  .warn { box-shadow: inset 3px 0 0 var(--vf-verdict-challenge-fg), var(--vf-shadow-2); }
  .error { box-shadow: inset 3px 0 0 var(--vf-verdict-block-fg), var(--vf-shadow-2); }
</style>
```

`ui/src/screens/Placeholder.svelte` (EmptyState arrives in Task 5; this placeholder is self-contained):

```svelte
<script lang="ts">
  import { sceneUrl } from '../lib/assets';

  let { title }: { title: string } = $props();
  const img = sceneUrl('not-built');
</script>

<h1 tabindex="-1">{title}</h1>
<div class="card empty">
  {#if img}<img src={img} alt="" width="256" />{/if}
  <p class="secondary">This screen is specified in the UX architecture and arrives with console plan SP6b.</p>
</div>

<style>
  h1 { margin-bottom: var(--vf-space-5); }
  .empty { display: grid; justify-items: center; gap: var(--vf-space-4); padding: var(--vf-space-6); text-align: center; }
  img { height: auto; filter: var(--vf-prop-filter); }
</style>
```

- [ ] **Step 5: Shell components**

`ui/src/lib/shell/ThemeToggle.svelte`:

```svelte
<script lang="ts">
  import { MonitorIcon, Moon, Sun } from '../icons';
  import { theme, type ThemePref } from '../state/theme.svelte';

  const OPTIONS: { value: ThemePref; label: string; Icon: typeof Sun }[] = [
    { value: 'light', label: 'Light', Icon: Sun },
    { value: 'dark', label: 'Dark', Icon: Moon },
    { value: 'system', label: 'System', Icon: MonitorIcon },
  ];
</script>

<fieldset class="seg">
  <legend class="sr-only">Theme</legend>
  {#each OPTIONS as o (o.value)}
    <label class:on={theme.pref === o.value}>
      <input type="radio" name="vft-theme" value={o.value} checked={theme.pref === o.value} onchange={() => theme.set(o.value)} />
      <o.Icon size={14} aria-hidden="true" />
      <span>{o.label}</span>
    </label>
  {/each}
</fieldset>

<style>
  .seg { display: inline-flex; gap: 2px; margin: 0; padding: 2px; border: 0; border-radius: var(--vf-radius-pill); background: var(--vf-surface-sunken); box-shadow: var(--vf-shadow-inset); }
  label { position: relative; display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 28px; padding: 0 10px; border-radius: var(--vf-radius-pill); font-size: var(--vf-fs-sm); color: var(--vf-text-secondary); cursor: pointer; }
  label.on { background: var(--vf-surface-raised); color: var(--vf-text-primary); box-shadow: var(--vf-shadow-1); }
  input { position: absolute; opacity: 0; inset: 0; margin: 0; cursor: pointer; }
  label:has(input:focus-visible) { outline: var(--vf-bw-focus) solid var(--vf-focus-ring); outline-offset: 2px; }
</style>
```

`ui/src/lib/shell/TopBar.svelte`:

```svelte
<script lang="ts">
  import HealthPill from '../components/HealthPill.svelte';
  import { fmtCount } from '../format';
  import { Radio, TriangleAlert } from '../icons';
  import { app } from '../state/app.svelte';
  import { router } from '../state/router.svelte';
  import ThemeToggle from './ThemeToggle.svelte';

  let jump = $state('');

  function onJump(e: SubmitEvent) {
    e.preventDefault();
    const v = jump.trim();
    if (!v) return;
    // A source key is an IP or prefix; anything else is a request id.
    const isSource = /^[0-9a-f:.]+(\/\d+)?$/i.test(v) && /[.:]/.test(v);
    router.navigate(isSource ? `/sources/${encodeURIComponent(v)}` : `/requests/${encodeURIComponent(v)}`);
    jump = '';
  }

  const dropped = $derived(app.counters?.dropped_total ?? 0);
  const liveLabel = $derived(app.stale && app.live === 'Connected' ? 'Stale' : app.live);
</script>

<header class="bar glass">
  <div class="brand">
    <span class="name">Venusflytrap</span>
    {#if app.status}<span class="ver secondary">v{app.status.version}</span>{/if}
  </div>
  <form class="jump" role="search" onsubmit={onJump}>
    <label class="sr-only" for="quick-jump">Request id or source key</label>
    <input id="quick-jump" class="mono" placeholder="Request id or source key" bind:value={jump} autocomplete="off" />
  </form>
  <ul class="status" aria-label="Service status">
    <li>
      <span class="label-caps">State</span>
      {#if app.status}<HealthPill health={app.status.worst} />{:else}<span>—</span>{/if}
    </li>
    <li>
      <span class="label-caps">Live</span>
      <span class="val" class:warn={liveLabel !== 'Connected'}><Radio size={14} aria-hidden="true" /> {liveLabel}</span>
    </li>
    <li>
      <span class="label-caps">Config</span>
      <span class="val num">rev {app.status?.config_rev ?? '—'}</span>
    </li>
    <li>
      <span class="label-caps">Dropped</span>
      <span class="val num" class:warn={dropped > 0}>
        {#if dropped > 0}<TriangleAlert size={14} aria-hidden="true" />{/if}
        {fmtCount(dropped)}
      </span>
    </li>
  </ul>
  <div class="right">
    <ThemeToggle />
    {#if app.session}<span class="perm label-caps">{app.session.perm}</span>{/if}
  </div>
</header>

<style>
  .bar {
    position: sticky; top: 0; z-index: 10; height: var(--vf-topbar-h);
    display: flex; align-items: center; gap: var(--vf-space-5); padding: 0 var(--vf-space-4);
    box-shadow: var(--vf-shadow-2); border-width: 0 0 var(--vf-bw-hair) 0;
  }
  .brand { display: flex; align-items: baseline; gap: var(--vf-space-2); }
  .name { font-weight: 600; font-size: var(--vf-fs-title-sm); }
  .ver { font-size: var(--vf-fs-xs); }
  .jump input {
    width: 260px; height: var(--vf-control-md); padding: 0 var(--vf-space-3);
    border-radius: var(--vf-radius-sm); border: var(--vf-bw-std) solid var(--vf-border-strong);
    background: var(--vf-surface-input); box-shadow: var(--vf-shadow-inset);
  }
  .status { display: flex; gap: var(--vf-space-5); margin: 0; padding: 0; list-style: none; }
  .status li { display: grid; gap: 2px; padding-left: var(--vf-space-4); border-left: var(--vf-bw-std) solid var(--vf-border-subtle); }
  .status li:first-child { border-left: 0; padding-left: 0; }
  .val { display: inline-flex; align-items: center; gap: var(--vf-space-1); font-size: var(--vf-fs-sm); font-weight: 500; }
  .val.warn { color: var(--vf-health-warn-fg); }
  .right { margin-left: auto; display: flex; align-items: center; gap: var(--vf-space-4); }
  .perm { padding: 2px 8px; border-radius: var(--vf-radius-xs); background: var(--vf-surface-sunken); }
  @media (max-width: 1279px) { .jump input { width: 180px; } .status { gap: var(--vf-space-3); } }
</style>
```

`ui/src/lib/shell/NavRail.svelte`:

```svelte
<script lang="ts">
  import Link from '../components/Link.svelte';
  import { KeyRound, LayoutDashboard, ListFilter, Network, Settings, ShieldBan, Workflow } from '../icons';
  import { app } from '../state/app.svelte';
  import { NAV, PARENT, router, type RouteName } from '../state/router.svelte';

  const ICON: Record<string, typeof Network> = {
    dashboard: LayoutDashboard, topology: Network, monitor: ListFilter, chains: Workflow,
    honeypot: ShieldBan, settings: Settings, keys: KeyRound,
  };
  const current = $derived<RouteName>(PARENT[router.route.name] ?? router.route.name);
  const items = $derived(NAV.filter((n) => !n.adminOnly || app.session?.perm === 'Admin'));
</script>

<nav class="rail" aria-label="Main">
  <ul>
    {#each items as n (n.name)}
      {@const Icon = ICON[n.name]}
      <li>
        <Link href={n.href} class="item" current={current === n.name}>
          <Icon size={18} strokeWidth={1.5} aria-hidden="true" />
          <span>{n.label}</span>
        </Link>
      </li>
    {/each}
  </ul>
  <p class="foot secondary">Live: {app.stale && app.live === 'Connected' ? 'Stale' : app.live}</p>
</nav>

<style>
  .rail { width: var(--vf-nav-w); padding: var(--vf-space-2); background: var(--vf-surface-sunken); display: flex; flex-direction: column; }
  ul { margin: 0; padding: 0; list-style: none; display: grid; gap: 2px; }
  .rail :global(.item) {
    display: flex; align-items: center; gap: var(--vf-space-3); height: 40px; padding: 0 var(--vf-space-3);
    border-radius: var(--vf-radius-sm); color: var(--vf-text-secondary); text-decoration: none; font-weight: 500;
  }
  .rail :global(.item:hover) { background: var(--vf-surface-raised); color: var(--vf-text-primary); box-shadow: var(--vf-shadow-1); }
  .rail :global(.item[aria-current='page']) {
    background: var(--vf-accent-soft); color: var(--vf-text-primary); font-weight: 600;
    box-shadow: inset 2px 0 0 var(--vf-accent);
  }
  .rail :global(.item[aria-current='page'] svg) { color: var(--vf-accent); }
  .foot { margin-top: auto; padding: var(--vf-space-3); font-size: var(--vf-fs-xs); }
  @media (max-width: 1439px) {
    .rail { width: var(--vf-nav-rail-w); }
    .rail :global(.item) { flex-direction: column; justify-content: center; height: 56px; gap: 2px; padding: 0; font-size: 11px; text-align: center; }
    .foot { padding: var(--vf-space-1); text-align: center; }
  }
</style>
```

- [ ] **Step 6: Replace `App.svelte`**

```svelte
<script lang="ts">
  import { onMount, tick, type Component } from 'svelte';
  import { FixtureSource } from './lib/api/source';
  import ToastStack from './lib/components/ToastStack.svelte';
  import NavRail from './lib/shell/NavRail.svelte';
  import TopBar from './lib/shell/TopBar.svelte';
  import { app } from './lib/state/app.svelte';
  import { router, type RouteName } from './lib/state/router.svelte';

  type Screen = () => Promise<{ default: Component<any> }>;
  const placeholder: Screen = () => import('./screens/Placeholder.svelte');
  const SCREENS: Record<RouteName, Screen> = {
    dashboard: placeholder,
    topology: placeholder,
    chains: placeholder,
    monitor: placeholder,
    honeypot: placeholder,
    settings: placeholder,
    keys: placeholder,
    request: placeholder,
    source: placeholder,
    notfound: placeholder,
  };
  const TITLES: Record<RouteName, string> = {
    dashboard: 'Dashboard', topology: 'Traffic topology', chains: 'Attack chains', monitor: 'Monitor',
    honeypot: 'Honeypot & bans', settings: 'Settings', keys: 'Keys', request: 'Request details',
    source: 'Source', notfound: 'Page not found',
  };

  let ready = $state(false);
  onMount(() => {
    const live = !new URLSearchParams(location.search).has('static');
    app.start(new FixtureSource({ live })).then(() => (ready = true));
    return () => app.stop();
  });

  // Move focus to the new screen's heading after navigation (UX: focus goes to h1).
  let first = true;
  $effect(() => {
    void router.path;
    if (first) { first = false; return; }
    tick().then(() => document.querySelector<HTMLElement>('main h1')?.focus());
  });
  $effect(() => { document.title = `${TITLES[router.route.name]} · Venusflytrap`; });
</script>

<a class="skip btn" href="#main">Skip to content</a>
<TopBar />
<div class="body">
  <NavRail />
  <main id="main" tabindex="-1">
    {#if ready}
      {#await SCREENS[router.route.name]() then mod}
        <mod.default title={TITLES[router.route.name]} param={router.route.param} />
      {/await}
    {:else}
      <h1 tabindex="-1">{TITLES[router.route.name]}</h1>
    {/if}
  </main>
</div>
<ToastStack />

<style>
  .skip { position: absolute; left: var(--vf-space-2); top: -60px; z-index: 30; }
  .skip:focus { top: var(--vf-space-2); }
  .body { display: flex; min-height: calc(100vh - var(--vf-topbar-h)); }
  main { flex: 1; min-width: 0; padding: var(--vf-space-5); }
  main:focus { outline: none; }
</style>
```

Update `ui/src/app.test.ts` to await the async mount:

```ts
import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import App from './App.svelte';

test('the app renders a level-1 heading', async () => {
  render(App);
  expect(await screen.findByRole('heading', { level: 1 })).toBeTruthy();
});
```

- [ ] **Step 7: Write the shell tests** (`ui/src/lib/shell/shell.test.ts`)

```ts
import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import App from '../../App.svelte';
import { router } from '../state/router.svelte';

test('nav marks the current route and detail routes mark their parent', async () => {
  router.navigate('/topology');
  render(App);
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByRole('link', { name: /Traffic topology/ }).getAttribute('aria-current')).toBe('page');
  router.navigate('/sources/203.0.113.7');
  await screen.findByRole('heading', { level: 1, name: 'Source' });
  expect(within(nav).getByRole('link', { name: /Attack chains/ }).getAttribute('aria-current')).toBe('page');
});

test('the theme radio group switches data-theme', async () => {
  render(App);
  await fireEvent.click(await screen.findByLabelText('Dark'));
  expect(document.documentElement.dataset.theme).toBe('dark');
  await fireEvent.click(screen.getByLabelText('System'));
  expect(document.documentElement.dataset.theme).toBeUndefined();
});

test('the skip link targets main', async () => {
  render(App);
  expect((await screen.findByRole('link', { name: 'Skip to content' })).getAttribute('href')).toBe('#main');
});
```

- [ ] **Step 8: Run everything**

Run: `npm test && npm run check && npm run build && npm run budget` → Expected: green.

- [ ] **Step 9: Commit**

```bash
git add ui/src
git commit -m "feat(ui): app state, router and the global shell"
```

---

### Task 5: Shared display components

**Files:**
- Create: `ui/src/lib/components/VerdictChip.svelte`, `StageChip.svelte`, `KpiTile.svelte`, `EmptyState.svelte`, `Region.svelte`, `components.test.ts`
- Modify: `ui/src/screens/Placeholder.svelte` (use `EmptyState`)

**Interfaces:**
- Produces: `<VerdictChip verdict size?>`, `<StageChip stage: Stage | null>` (null = Clean), `<KpiTile label value unit? tone? stale? href?>`, `<EmptyState message scene? action?: {label, href}>`, `<Region title updatedAt? stale? busy? children actions?>`.

- [ ] **Step 1: Write the failing tests** (`components.test.ts`)

```ts
import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import EmptyState from './EmptyState.svelte';
import KpiTile from './KpiTile.svelte';
import StageChip from './StageChip.svelte';
import VerdictChip from './VerdictChip.svelte';

test.each(['Allow', 'Monitor', 'Challenge', 'Block'] as const)('verdict %s has glyph and word', (v) => {
  const { container } = render(VerdictChip, { props: { verdict: v } });
  expect(container.textContent).toContain(v);
  expect(container.querySelector('svg')).toBeTruthy();
});

test('stage chips show number, label and pips; null is Clean', () => {
  const { container } = render(StageChip, { props: { stage: 'Exploitation' } });
  expect(container.textContent).toContain('3');
  expect(container.textContent).toContain('Exploitation');
  expect(container.querySelectorAll('.pip.on')).toHaveLength(3);
  const clean = render(StageChip, { props: { stage: null } });
  expect(clean.container.textContent).toContain('Clean');
});

test('KPI tile is a definition list entry', () => {
  const { container } = render(KpiTile, { props: { label: 'Block', value: '38', unit: '/s', tone: 'block' } });
  expect(screen.getByText('Block').tagName).toBe('DT');
  expect(container.querySelector('dd')?.textContent).toBe('38/s');
});

test('empty state shows one sentence and an action', () => {
  render(EmptyState, { props: { message: 'No traffic yet.', action: { label: 'Open dashboard', href: '/' } } });
  expect(screen.getByText('No traffic yet.')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Open dashboard' })).toBeTruthy();
});
```

- [ ] **Step 2: Run them to see them fail**

Run: `npm test -- components` → Expected: FAIL, cannot resolve `./EmptyState.svelte`.

- [ ] **Step 3: Implement**

`VerdictChip.svelte`:

```svelte
<script lang="ts">
  import type { Verdict } from '../api/types';
  import { CircleCheck, Eye, OctagonX, TriangleAlert } from '../icons';

  let { verdict, size = 'md' }: { verdict: Verdict; size?: 'sm' | 'md' } = $props();
  const GLYPH = { Allow: CircleCheck, Monitor: Eye, Challenge: TriangleAlert, Block: OctagonX };
  const Glyph = $derived(GLYPH[verdict]);
</script>

<span class="chip {verdict.toLowerCase()} {size}">
  <Glyph size={14} strokeWidth={1.5} aria-hidden="true" />{verdict}
</span>

<style>
  .chip {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 24px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); font-size: var(--vf-fs-sm); font-weight: 600; text-transform: uppercase;
    letter-spacing: .04em; border: var(--vf-bw-std) solid; white-space: nowrap;
  }
  .sm { height: 20px; }
  .allow { background: var(--vf-verdict-allow-bg); color: var(--vf-verdict-allow-fg); border-color: color-mix(in srgb, var(--vf-verdict-allow-fg) 35%, transparent); }
  .monitor { background: var(--vf-verdict-monitor-bg); color: var(--vf-verdict-monitor-fg); border-color: color-mix(in srgb, var(--vf-verdict-monitor-fg) 35%, transparent); }
  .challenge { background: var(--vf-verdict-challenge-bg); color: var(--vf-verdict-challenge-fg); border-color: color-mix(in srgb, var(--vf-verdict-challenge-fg) 35%, transparent); }
  .block { background: var(--vf-verdict-block-bg); color: var(--vf-verdict-block-fg); border-color: color-mix(in srgb, var(--vf-verdict-block-fg) 35%, transparent); }
</style>
```

`StageChip.svelte`:

```svelte
<script lang="ts">
  import { STAGES, type Stage } from '../api/types';

  let { stage, compact = false }: { stage: Stage | null; compact?: boolean } = $props();
  const n = $derived(stage === null ? 0 : STAGES.indexOf(stage) + 1);
  const cls = $derived(stage === null ? 'none' : stage.toLowerCase());
</script>

<span class="chip {cls}" aria-label={stage === null ? 'Clean' : `Stage ${n} of 4: ${stage}`}>
  <span class="badge" aria-hidden="true">{n === 0 ? '–' : n}</span>
  {#if !compact}<span aria-hidden="true">{stage ?? 'Clean'}</span>{/if}
  <span class="pips" aria-hidden="true">
    {#each [1, 2, 3, 4] as i (i)}<span class="pip" class:on={i <= n}></span>{/each}
  </span>
</span>

<style>
  .chip {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 24px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); font-size: var(--vf-fs-sm); font-weight: 600; white-space: nowrap;
  }
  /* The numeral sits upright on top; the shape (circle 1, square 2, diamond 3, hexagon 4,
     hollow circle for Clean) is drawn by ::before so it can rotate or clip independently. */
  .badge {
    position: relative; display: inline-grid; place-items: center; width: 16px; height: 16px;
    font-size: var(--vf-fs-xs); font-weight: 700; line-height: 1;
  }
  .badge::before { content: ''; position: absolute; inset: 0; border: 1.5px solid currentColor; }
  .recon .badge::before, .none .badge::before { border-radius: 50%; }
  .enumeration .badge::before { border-radius: 2px; }
  .exploitation .badge::before { inset: 2px; transform: rotate(45deg); border-radius: 1px; }
  .exfiltration .badge::before {
    border: 0; background: color-mix(in srgb, currentColor 28%, transparent);
    clip-path: polygon(25% 0, 75% 0, 100% 50%, 75% 100%, 25% 100%, 0 50%);
  }
  .pips { display: inline-flex; gap: 2px; margin-left: 2px; }
  .pip { width: 4px; height: 4px; border-radius: 1px; background: color-mix(in srgb, currentColor 25%, transparent); }
  .pip.on { background: currentColor; }
  .none { background: var(--vf-stage-none-bg); color: var(--vf-stage-none-fg); }
  .recon { background: var(--vf-stage-recon-bg); color: var(--vf-stage-recon-fg); }
  .enumeration { background: var(--vf-stage-enumeration-bg); color: var(--vf-stage-enumeration-fg); }
  .exploitation { background: var(--vf-stage-exploitation-bg); color: var(--vf-stage-exploitation-fg); }
  .exfiltration { background: var(--vf-stage-exfiltration-bg); color: var(--vf-stage-exfiltration-fg); }
</style>
```

`KpiTile.svelte` (renders a `<div>` containing a `<dt>`/`<dd>` pair; callers wrap tiles in a `<dl>`):

```svelte
<script lang="ts">
  let {
    label, value, unit = '', tone = 'neutral', stale = false, note = '',
  }: { label: string; value: string; unit?: string; tone?: 'allow' | 'monitor' | 'challenge' | 'block' | 'neutral'; stale?: boolean; note?: string } = $props();
</script>

<div class="tile card {tone}" class:stale>
  <dt class="label-caps">{label}</dt>
  <dd class="value num">{value}{#if unit}<span class="unit">{unit}</span>{/if}</dd>
  {#if note}<dd class="note secondary">{note}</dd>{/if}
</div>

<style>
  .tile { position: relative; display: grid; gap: var(--vf-space-1); overflow: hidden; }
  .tile::after { content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 2px; background: var(--vf-border-subtle); }
  .allow::after { background: var(--vf-verdict-allow-line); }
  .monitor::after { background: var(--vf-verdict-monitor-line); }
  .challenge::after { background: var(--vf-verdict-challenge-line); }
  .block::after { background: var(--vf-verdict-block-line); }
  .value { font-size: var(--vf-fs-kpi-sm); line-height: var(--vf-lh-kpi-sm); font-weight: 600; margin: 0; }
  .unit { font-size: .5em; color: var(--vf-text-secondary); margin-left: 2px; }
  .note { font-size: var(--vf-fs-xs); margin: 0; }
  .stale { opacity: .7; background-image: var(--vf-hatch); }
</style>
```

`EmptyState.svelte`:

```svelte
<script lang="ts">
  import { sceneUrl, type SceneName } from '../assets';
  import Link from './Link.svelte';

  let { message, scene, action }: { message: string; scene?: SceneName; action?: { label: string; href: string } } = $props();
  const img = $derived(scene ? sceneUrl(scene) : undefined);
</script>

<div class="empty">
  {#if img}<img src={img} alt="" width="200" />{/if}
  <p class="secondary">{message}</p>
  {#if action}<Link href={action.href} class="btn btn-ghost">{action.label}</Link>{/if}
</div>

<style>
  .empty { display: grid; justify-items: center; gap: var(--vf-space-3); padding: var(--vf-space-5); text-align: center; }
  img { height: auto; filter: var(--vf-prop-filter); }
</style>
```

`Region.svelte`:

```svelte
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { fmtClock } from '../format';

  let {
    title, updatedAt = 0, stale = false, busy = false, children, actions,
  }: { title: string; updatedAt?: number; stale?: boolean; busy?: boolean; children: Snippet; actions?: Snippet } = $props();
  const id = `r-${Math.random().toString(36).slice(2, 8)}`;
</script>

<section class="card region" class:stale aria-labelledby={id} aria-busy={busy}>
  <header>
    <h2 {id} class="title">{title}</h2>
    {#if actions}<div class="actions">{@render actions()}</div>{/if}
    {#if updatedAt}<span class="updated secondary num">Updated {fmtClock(updatedAt)}</span>{/if}
  </header>
  {@render children()}
</section>

<style>
  .region { display: grid; gap: var(--vf-space-3); align-content: start; }
  header { display: flex; align-items: center; gap: var(--vf-space-3); }
  .title { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); }
  .actions { margin-left: auto; display: flex; gap: var(--vf-space-2); }
  .updated { font-size: var(--vf-fs-xs); margin-left: auto; }
  .actions + .updated { margin-left: 0; }
  .stale { opacity: .7; background-image: var(--vf-hatch); }
</style>
```

Replace `Placeholder.svelte` with:

```svelte
<script lang="ts">
  import EmptyState from '../lib/components/EmptyState.svelte';

  let { title }: { title: string } = $props();
</script>

<h1 tabindex="-1">{title}</h1>
<div class="card">
  <EmptyState scene="not-built" message="This screen is specified in the UX architecture and arrives with console plan SP6b." action={{ label: 'Open dashboard', href: '/' }} />
</div>

<style>
  h1 { margin-bottom: var(--vf-space-5); }
</style>
```

- [ ] **Step 4: Run everything**

Run: `npm test && npm run check` → Expected: green.

- [ ] **Step 5: Commit**

```bash
git add ui/src
git commit -m "feat(ui): verdict, stage, KPI, empty-state and region components"
```

---

### Task 6: Dashboard

**Files:**
- Create: `ui/src/screens/Dashboard.svelte`, `ui/src/screens/dashboard/series.ts`, `ui/src/screens/dashboard/series.test.ts`, `ui/src/screens/dashboard/StackedArea.svelte`, `ui/src/screens/dashboard/dashboard.test.ts`
- Modify: `ui/src/App.svelte` (`dashboard: () => import('./screens/Dashboard.svelte')`)

**Interfaces:**
- Consumes: `app`, `router`, `DataSource.dashboard`, `KpiTile`, `Region`, `EmptyState`, `Link`, `VerdictChip`, `StageChip`, `propUrl`.
- Produces: `stackedPaths(series: number[][], w: number, h: number): { d: string; max: number }[]` (one closed path per series, bottom series first); range presets `RANGES = { '1h', '6h', '24h', '7d' }` kept in the URL as `?from&to`.

- [ ] **Step 1: Write the failing tests**

`series.test.ts`:

```ts
import { expect, test } from 'vitest';
import { stackedPaths } from './series';

test('stacked paths cover the cumulative maximum', () => {
  const p = stackedPaths([[1, 2], [3, 4]], 100, 50);
  expect(p).toHaveLength(2);
  expect(p[1].max).toBe(6);
  expect(p[0].d.startsWith('M0,')).toBe(true);
  expect(p[1].d.endsWith('Z')).toBe(true);
});

test('all-zero series do not divide by zero', () => {
  const p = stackedPaths([[0, 0], [0, 0]], 100, 50);
  expect(p[0].d).not.toContain('NaN');
});
```

`dashboard.test.ts`:

```ts
import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { beforeAll, expect, test } from 'vitest';
import { FixtureSource } from '../../lib/api/source';
import { app } from '../../lib/state/app.svelte';
import Dashboard from '../Dashboard.svelte';

beforeAll(async () => {
  await app.start(new FixtureSource({ live: false }));
});

test('KPI rail, chart table toggle and lists render from fixtures', async () => {
  render(Dashboard, { props: { title: 'Dashboard' } });
  expect(await screen.findByText('sqli.union-select')).toBeTruthy();
  const chart = screen.getByRole('region', { name: 'Requests over time' });
  await fireEvent.click(within(chart).getByRole('button', { name: 'Show as table' }));
  expect(within(chart).getByRole('table')).toBeTruthy();
  expect(screen.getAllByRole('link', { name: /\/api\/search/ }).length).toBeGreaterThan(0);
});
```

- [ ] **Step 2: Run them to see them fail**

Run: `npm test -- series dashboard` → Expected: FAIL, cannot resolve `./series`.

- [ ] **Step 3: Implement `series.ts`**

```ts
/** Closed SVG area paths for stacked series (index 0 at the bottom). */
export function stackedPaths(series: number[][], w: number, h: number): { d: string; max: number }[] {
  const n = series[0]?.length ?? 0;
  const tops: number[][] = [];
  let acc = new Array<number>(n).fill(0);
  for (const s of series) {
    acc = acc.map((v, i) => v + (s[i] ?? 0));
    tops.push([...acc]);
  }
  const max = Math.max(1, ...acc);
  const x = (i: number) => (n <= 1 ? 0 : (i / (n - 1)) * w);
  const y = (v: number) => h - (v / max) * h;
  return tops.map((top, k) => {
    const bottom = k === 0 ? new Array<number>(n).fill(0) : tops[k - 1];
    // Every path starts at x = 0 ("M0,…").
    const up = top.map((v, i) => `${i === 0 ? 'M0' : `L${x(i).toFixed(1)}`},${y(v).toFixed(1)}`).join(' ');
    const down = bottom
      .map((v, i) => [i, v] as const)
      .reverse()
      .map(([i, v]) => `L${x(i).toFixed(1)},${y(v).toFixed(1)}`)
      .join(' ');
    return { d: `${up} ${down} Z`, max: Math.max(0, ...top) };
  });
}
```

- [ ] **Step 4: Implement `StackedArea.svelte`**

```svelte
<script lang="ts">
  import { VERDICTS } from '../../lib/api/types';
  import { fmtClock, fmtCount } from '../../lib/format';
  import { stackedPaths } from './series';

  let { series, from, bucketMs }: { series: number[][]; from: number; bucketMs: number } = $props();
  let asTable = $state(false);
  const W = 800, H = 280;
  const paths = $derived(stackedPaths(series, W, H));
</script>

<div class="wrap">
  <button class="btn btn-sm toggle" aria-pressed={asTable} onclick={() => (asTable = !asTable)}>Show as table</button>
  {#if asTable}
    <!-- A scrolling region must be keyboard-focusable (axe scrollable-region-focusable). -->
    <div class="scroll" tabindex="0" role="region" aria-label="Requests over time, as a table">
      <table class="data-table">
        <thead><tr><th>Time</th>{#each VERDICTS as v (v)}<th class="n">{v}</th>{/each}</tr></thead>
        <tbody>
          {#each series[0] as _, i (i)}
            <tr><td class="num">{fmtClock(from + i * bucketMs)}</td>{#each series as s, k (k)}<td class="n">{fmtCount(s[i])}</td>{/each}</tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true">
      {#each [0.25, 0.5, 0.75] as g (g)}<line class="grid" x1="0" x2={W} y1={H * g} y2={H * g} />{/each}
      {#each paths as p, k (k)}<path class="area {VERDICTS[k].toLowerCase()}" d={p.d} />{/each}
    </svg>
    <ul class="legend">
      {#each VERDICTS as v, k (v)}
        <li><span class="sw {v.toLowerCase()}"></span>{v} <span class="num secondary">{fmtCount(series[k].reduce((a, b) => a + b, 0))}</span></li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .wrap { position: relative; display: grid; gap: var(--vf-space-2); }
  .toggle { justify-self: end; }
  svg { width: 100%; height: 280px; display: block; }
  .grid { stroke: var(--vf-chart-grid); stroke-width: 1; }
  .area { stroke-width: 1; }
  .area.allow { fill: color-mix(in srgb, var(--vf-verdict-allow-line) 40%, transparent); stroke: var(--vf-verdict-allow-line); }
  .area.monitor { fill: color-mix(in srgb, var(--vf-verdict-monitor-line) 50%, transparent); stroke: var(--vf-verdict-monitor-line); }
  .area.challenge { fill: color-mix(in srgb, var(--vf-verdict-challenge-line) 60%, transparent); stroke: var(--vf-verdict-challenge-line); }
  .area.block { fill: color-mix(in srgb, var(--vf-verdict-block-line) 70%, transparent); stroke: var(--vf-verdict-block-line); }
  .legend { display: flex; gap: var(--vf-space-4); margin: 0; padding: 0; list-style: none; font-size: var(--vf-fs-xs); }
  .sw { display: inline-block; width: 12px; height: 12px; margin-right: 4px; vertical-align: -2px; border-radius: 2px; }
  .sw.allow { background: var(--vf-verdict-allow-line); }
  .sw.monitor { background: var(--vf-verdict-monitor-line); }
  .sw.challenge { background: var(--vf-verdict-challenge-line); }
  .sw.block { background: var(--vf-verdict-block-line); }
  .scroll { max-height: 320px; overflow: auto; }
</style>
```

The chart hides behind `aria-hidden`; the legend carries totals in text and the table toggle carries every value (UX §3).

- [ ] **Step 5: Implement `Dashboard.svelte`**

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { STAGES, VERDICTS, type Dashboard } from '../lib/api/types';
  import { propUrl } from '../lib/assets';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import KpiTile from '../lib/components/KpiTile.svelte';
  import Link from '../lib/components/Link.svelte';
  import Region from '../lib/components/Region.svelte';
  import StageChip from '../lib/components/StageChip.svelte';
  import { fmtCount, fmtRps } from '../lib/format';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import StackedArea from './dashboard/StackedArea.svelte';

  let { title }: { title: string } = $props();
  const RANGES: [string, number][] = [['1 h', 3_600_000], ['6 h', 6 * 3_600_000], ['24 h', 24 * 3_600_000], ['7 d', 7 * 24 * 3_600_000]];

  let data = $state<Dashboard | null>(null);
  let updatedAt = $state(0);

  const span = $derived.by(() => {
    const from = Number(router.search.get('from'));
    const to = Number(router.search.get('to'));
    return from && to && to > from ? to - from : RANGES[0][1];
  });

  async function load() {
    if (!app.src) return;
    const to = Date.now();
    data = await app.src.dashboard(to - span, to);
    updatedAt = Date.now();
  }

  onMount(() => {
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  });
  $effect(() => { void span; load(); });

  function pick(ms: number) {
    const to = Date.now();
    router.navigate(`/?from=${to - ms}&to=${to}`, true);
  }

  const rps = $derived(app.counters?.rps_by_verdict ?? [0, 0, 0, 0]);
  const maxStage = $derived(data ? Math.max(1, ...STAGES.map((s) => data!.sources_by_stage[s])) : 1);
  const honeypotTotal = $derived(data ? data.honeypot_hits.reduce((a, h) => a + h.count, 0) : 0);
  const tower = propUrl('shield-tower');
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
  <div class="seg" role="group" aria-label="Time range">
    {#each RANGES as [label, ms] (label)}
      <button class="btn btn-sm" aria-pressed={span === ms} onclick={() => pick(ms)}>{label}</button>
    {/each}
  </div>
</header>

{#if app.status && app.status.worst !== 'Ok'}
  <p class="banner card" role="status">Service state: {app.status.worst}. {app.status.components.filter((c) => c.state !== 'Ok').map((c) => c.name).join(', ')}</p>
{/if}

<div class="grid">
  <dl class="kpis" aria-label="Live counters">
    {#each VERDICTS as v, i (v)}
      <KpiTile label={v} value={fmtRps(rps[i]).replace('/s', '')} unit="/s" tone={v.toLowerCase() as 'allow'} stale={app.stale} />
    {/each}
    <KpiTile label="Active bans" value={fmtCount(data?.active_bans ?? 0)} />
    <KpiTile label="Honeypot hits" value={fmtCount(honeypotTotal)} note="in range" />
    <KpiTile label="Dropped" value={fmtCount(app.counters?.dropped_total ?? 0)} note={`history ${fmtCount(app.status?.drops.history ?? 0)}`} />
  </dl>

  <div class="chart">
    <Region title="Requests over time" {updatedAt} busy={!data}>
      {#if data}
        <StackedArea series={data.requests_by_verdict} from={data.from_ms} bucketMs={data.bucket_ms} />
      {:else}
        <div class="skeleton"></div>
      {/if}
    </Region>
  </div>

  <div class="stages">
    <Region title="Sources by stage" {updatedAt}>
      {#if data}
        <ul class="bars">
          {#each STAGES as s (s)}
            <li>
              <Link href={`/chains?stage=${s}`} class="bar-row">
                <StageChip stage={s} />
                <span class="track" aria-hidden="true"><span class="fill {s.toLowerCase()}" style:width={`${(data.sources_by_stage[s] / maxStage) * 100}%`}></span></span>
                <span class="num">{fmtCount(data.sources_by_stage[s])}</span>
              </Link>
            </li>
          {/each}
        </ul>
        <p class="secondary small">Clean sources: {fmtCount(data.sources_by_stage.Clean)}</p>
      {/if}
    </Region>
  </div>

  <div class="constructs">
    <Region title="Top constructs" {updatedAt}>
      {#if data && data.top_constructs.length}
        <table class="data-table">
          <thead><tr><th>Construct</th><th>Family</th><th class="n">Count</th></tr></thead>
          <tbody>
            {#each data.top_constructs as c (c.id)}
              <tr>
                <td><Link href={`/monitor?q=${encodeURIComponent(`construct:${c.id}`)}`} class="mono">{c.id}</Link></td>
                <td>{c.family}</td>
                <td class="n">{fmtCount(c.count)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if data}
        <EmptyState scene="quiet" message="No requests recorded since start." />
      {/if}
    </Region>
  </div>

  <div class="paths">
    <Region title="Top targeted paths" {updatedAt}>
      {#if data}
        <table class="data-table">
          <thead><tr><th>Path prefix</th><th class="n">Requests</th><th class="n">Blocked</th></tr></thead>
          <tbody>
            {#each data.top_paths as p (p.prefix)}
              <tr>
                <td><Link href={`/monitor?q=${encodeURIComponent(`path:${p.prefix}*`)}`} class="mono">{p.prefix}</Link></td>
                <td class="n">{fmtCount(p.count)}</td>
                <td class="n">{fmtCount(p.by_verdict[2] + p.by_verdict[3])}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </Region>
  </div>

  <div class="teaser">
    <Region title="Traffic topology">
      <Link href="/topology" class="teaser-link">
        {#if tower}<img src={tower} alt="" width="120" />{/if}
        <span>Open traffic topology</span>
      </Link>
    </Region>
  </div>
</div>

<style>
  .head { display: flex; align-items: center; gap: var(--vf-space-4); margin-bottom: var(--vf-space-5); }
  .seg { margin-left: auto; display: inline-flex; gap: var(--vf-space-1); }
  .banner { margin-bottom: var(--vf-space-4); background: var(--vf-attention-soft); color: var(--vf-attention); }
  .grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: var(--vf-space-5); }
  .kpis { grid-column: 1 / 4; grid-row: 1 / 4; display: grid; grid-template-columns: 1fr 1fr; gap: var(--vf-space-3); align-content: start; margin: 0; }
  .chart { grid-column: 4 / 13; }
  .stages, .paths { grid-column: 4 / 8; }
  .constructs, .teaser { grid-column: 8 / 13; }
  .skeleton { height: 280px; border-radius: var(--vf-radius-sm); background: var(--vf-surface-sunken); }
  .bars { margin: 0; padding: 0; list-style: none; display: grid; gap: var(--vf-space-2); }
  .bars :global(.bar-row) { display: grid; grid-template-columns: 150px 1fr 48px; align-items: center; gap: var(--vf-space-3); color: inherit; text-decoration: none; }
  .track { height: 8px; border-radius: 4px; background: var(--vf-surface-sunken); box-shadow: var(--vf-shadow-inset); overflow: hidden; }
  .fill { display: block; height: 100%; }
  .fill.recon { background: var(--vf-stage-recon-fg); }
  .fill.enumeration { background: var(--vf-stage-enumeration-fg); }
  .fill.exploitation { background: var(--vf-stage-exploitation-fg); }
  .fill.exfiltration { background: var(--vf-stage-exfiltration-fg); }
  .small { font-size: var(--vf-fs-xs); }
  .teaser :global(.teaser-link) { display: flex; align-items: center; gap: var(--vf-space-4); font-weight: 600; }
  .teaser img { height: auto; filter: var(--vf-prop-filter); }
  @media (max-width: 1439px) {
    .kpis { grid-column: 1 / 13; grid-row: auto; grid-template-columns: repeat(4, 1fr); }
    .chart { grid-column: 1 / 13; }
    .stages, .paths { grid-column: 1 / 7; }
    .constructs, .teaser { grid-column: 7 / 13; }
  }
</style>
```

Note on the bar fill: its width uses a `style:width` directive (runtime CSSOM), not a `style` attribute, which keeps it inside the CSP.

- [ ] **Step 6: Wire the route, run everything**

In `App.svelte` set `dashboard: () => import('./screens/Dashboard.svelte'),`.

Run: `npm test && npm run check && npm run build && npm run budget` → Expected: green; a `Dashboard-*.js` dynamic chunk under 80 KB gz.

- [ ] **Step 7: Commit**

```bash
git add ui/src
git commit -m "feat(ui): dashboard on fixtures with an accessible stacked-area chart"
```

---

### Task 7: Traffic topology (hero view)

**Files:**
- Create: `ui/src/screens/topology/geometry.ts`, `model.ts`, `model.test.ts`, `Scene.svelte`, `DetailCard.svelte`, `TableView.svelte`, `Legend.svelte`, `topology.test.ts`; `ui/src/screens/Topology.svelte`
- Modify: `ui/src/App.svelte` (`topology: () => import('./screens/Topology.svelte')`)

**Interfaces:**
- Produces:
  - `geometry.ts`: `SCENE = { w: 960, h: 720 }`, `PLATE`, `BOX: Record<NodeId, Box>`, `ANCHOR: Record<NodeId, [number, number]>`, `type NodeId = 'clean' | 'recon' | 'exploit' | 'tower' | 'route0'…'route4' | 'hp0'…'hp3' | 'quarantine'` plus decorative `'edge' | 'jA' | 'jB'`.
  - `model.ts`: `interface TopoNode { id; kind: 'cluster' | 'tower' | 'route' | 'honeypot' | 'quarantine'; label; countText; rateText; name; prop; box; approx: boolean }`, `interface TopoFlow { id; from; to; verdict: Verdict; rps; rateText; step: 0 | 1 | 2 | 3 | 4; d; mid: [number, number]; approx: boolean }`, `buildModel(input: ModelInput): { nodes: TopoNode[]; flows: TopoFlow[] }`, `volumeStep(rps): 0 | 1 | 2 | 3 | 4`, `clusterRates(prev, next, dtMs)`.

- [ ] **Step 1: Write `geometry.ts`** (coordinates from `docs/superpowers/design/canvas/project/Main.dc.html`)

```ts
import type { PropName } from '../../lib/assets';

export const SCENE = { w: 960, h: 720 } as const;
export interface Box { x: number; y: number; w: number; prop: PropName }

export type NodeId =
  | 'clean' | 'recon' | 'exploit' | 'tower'
  | 'route0' | 'route1' | 'route2' | 'route3' | 'route4'
  | 'hp0' | 'hp1' | 'hp2' | 'hp3' | 'quarantine';
export type DecorId = 'edge' | 'jA' | 'jB';

export const PLATE: Box = { x: 30, y: 120, w: 900, prop: 'base-plate' };

export const BOX: Record<NodeId | DecorId, Box> = {
  edge: { x: 40, y: 250, w: 70, prop: 'edge-gateway' },
  clean: { x: 150, y: 262, w: 64, prop: 'source-pod' },
  recon: { x: 170, y: 352, w: 64, prop: 'source-pod' },
  exploit: { x: 190, y: 442, w: 64, prop: 'source-pod' },
  jA: { x: 300, y: 350, w: 54, prop: 'junction-box' },
  tower: { x: 400, y: 170, w: 150, prop: 'shield-tower' },
  jB: { x: 560, y: 300, w: 46, prop: 'junction-box' },
  route0: { x: 600, y: 160, w: 68, prop: 'route-block' },
  route1: { x: 660, y: 220, w: 68, prop: 'route-block' },
  route2: { x: 720, y: 280, w: 68, prop: 'route-block' },
  route3: { x: 780, y: 340, w: 68, prop: 'route-block' },
  route4: { x: 840, y: 400, w: 68, prop: 'route-block' },
  hp0: { x: 560, y: 432, w: 64, prop: 'honeypot-flytrap' },
  hp1: { x: 640, y: 492, w: 64, prop: 'honeypot-flytrap' },
  hp2: { x: 720, y: 552, w: 64, prop: 'honeypot-flytrap' },
  hp3: { x: 800, y: 492, w: 64, prop: 'honeypot-flytrap' },
  quarantine: { x: 420, y: 500, w: 130, prop: 'quarantine-cage' },
};

/** Line end points (plate centres). */
export const ANCHOR: Record<NodeId | DecorId | 'stub', [number, number]> = {
  edge: [90, 400], clean: [182, 290], recon: [202, 376], exploit: [222, 466],
  jA: [327, 374], tower: [470, 350], jB: [583, 320],
  route0: [634, 236], route1: [694, 294], route2: [754, 352], route3: [814, 410], route4: [874, 470],
  hp0: [592, 478], hp1: [672, 538], hp2: [752, 598], hp3: [832, 538],
  quarantine: [485, 548], stub: [330, 230],
};

/** Roving-tabindex order (UX §4): Clean → Recon → Exploitation → Tower → Routes → Pods → Quarantine. */
export const ORDER: NodeId[] = ['clean', 'recon', 'exploit', 'tower', 'route0', 'route1', 'route2', 'route3', 'route4', 'hp0', 'hp1', 'hp2', 'hp3', 'quarantine'];

export const pct = (v: number, of: number) => `${((v / of) * 100).toFixed(3)}%`;
```

- [ ] **Step 2: Write the failing model tests** (`model.test.ts`)

```ts
import { expect, test } from 'vitest';
import { makeFixtures } from '../../lib/api/fixtures';
import { buildModel, clusterRates, volumeStep, type ModelInput } from './model';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);

function input(): ModelInput {
  const f = makeFixtures(NOW);
  const later = f.board.map((s) => (s.stage === 'Exploitation' && !s.ban ? { ...s, requests: s.requests + 10, blocked: s.blocked + 8 } : s));
  return {
    counters: f.counters,
    board: later,
    rates: clusterRates(f.board, later, 1000),
    dashboard: f.dashboard(NOW - 3_600_000, NOW),
    status: f.status,
    now: NOW,
  };
}

test('volume steps are fixed and never interpolated', () => {
  expect([0, 0.5, 1, 9.9, 10, 99, 100, 500].map(volumeStep)).toEqual([0, 1, 2, 2, 3, 3, 4, 4]);
});

test('cluster rates come from board deltas', () => {
  const r = input().rates;
  expect(r.exploit.passed + r.exploit.blocked).toBeCloseTo(20, 5); // two unbanned Exploitation sources x 10 req/s
  expect(r.exploit.blocked).toBeCloseTo(16, 5);
});

test('nodes follow the roving order and name their numbers', () => {
  const m = buildModel(input());
  expect(m.nodes.map((n) => n.id)).toEqual(['clean', 'recon', 'exploit', 'tower', 'route0', 'route1', 'route2', 'route3', 'route4', 'hp0', 'hp1', 'hp2', 'hp3', 'quarantine']);
  const exploit = m.nodes.find((n) => n.id === 'exploit')!;
  expect(exploit.name).toMatch(/^Exploitation cluster, \d+ sources, /);
  expect(m.nodes.find((n) => n.id === 'quarantine')!.countText).toBe('3');
});

test('more than four decoys put "+N more" on the last pod', () => {
  const m = buildModel(input());
  expect(m.nodes.find((n) => n.id === 'hp3')!.label).toContain('+1 more');
});

test('flows carry verdict, rate text and a path', () => {
  const m = buildModel(input());
  expect(m.flows.length).toBeGreaterThan(10);
  for (const f of m.flows) {
    expect(f.d).toMatch(/^M[\d.-]+,[\d.-]+ L[\d.-]+,[\d.-]+$/);
    expect(f.rateText.endsWith('/s')).toBe(true);
  }
});
```

- [ ] **Step 3: Run them to see them fail**

Run: `npm test -- model` → Expected: FAIL, cannot resolve `./model`.

- [ ] **Step 4: Implement `model.ts`**

```ts
import type { Counters, Dashboard, SourceView, StatusRecord, Verdict } from '../../lib/api/types';
import type { PropName } from '../../lib/assets';
import { fmtCount, fmtRps } from '../../lib/format';
import { ANCHOR, BOX, type Box, type NodeId } from './geometry';

export type Step = 0 | 1 | 2 | 3 | 4;
export const volumeStep = (rps: number): Step => (rps <= 0 ? 0 : rps < 1 ? 1 : rps < 10 ? 2 : rps < 100 ? 3 : 4);

export interface Rates { recon: { passed: number; blocked: number }; exploit: { passed: number; blocked: number }; quarantine: number }

const isRecon = (s: SourceView) => !s.ban && (s.stage === 'Recon' || s.stage === 'Enumeration');
const isExploit = (s: SourceView) => !s.ban && (s.stage === 'Exploitation' || s.stage === 'Exfiltration');

/** Per-second rates derived from two board snapshots (G9: approximate). */
export function clusterRates(prev: SourceView[], next: SourceView[], dtMs: number): Rates {
  const before = new Map(prev.map((s) => [s.key, s]));
  const sec = Math.max(dtMs, 1) / 1000;
  const r: Rates = { recon: { passed: 0, blocked: 0 }, exploit: { passed: 0, blocked: 0 }, quarantine: 0 };
  for (const s of next) {
    const p = before.get(s.key);
    if (!p) continue;
    const req = Math.max(0, s.requests - p.requests) / sec;
    const blk = Math.max(0, s.blocked - p.blocked) / sec;
    if (s.ban) r.quarantine += req;
    else if (isRecon(s)) { r.recon.passed += req - blk; r.recon.blocked += blk; }
    else if (isExploit(s)) { r.exploit.passed += req - blk; r.exploit.blocked += blk; }
  }
  return r;
}

export interface ModelInput {
  counters: Counters;
  board: SourceView[];
  rates: Rates;
  dashboard: Dashboard | null;
  status: StatusRecord | null;
  now: number;
}

export interface TopoNode {
  id: NodeId;
  kind: 'cluster' | 'tower' | 'route' | 'honeypot' | 'quarantine';
  label: string;
  countText: string;
  rateText: string;
  /** Accessible name: label, count and rate (UX §4). */
  name: string;
  prop: PropName;
  box: Box;
  approx: boolean;
  /** Present only for nodes with data behind them. */
  ref: string | null;
}

export interface TopoFlow {
  id: string;
  from: string;
  to: string;
  verdict: Verdict;
  rps: number;
  rateText: string;
  step: Step;
  d: string;
  mid: [number, number];
  approx: boolean;
}

const MAX_PODS = 4;

function seg(a: [number, number], b: [number, number], offset: number): { d: string; mid: [number, number] } {
  const [dx, dy] = [b[0] - a[0], b[1] - a[1]];
  const len = Math.hypot(dx, dy) || 1;
  const [nx, ny] = [(-dy / len) * offset, (dx / len) * offset];
  const p = (q: [number, number]) => `${(q[0] + nx).toFixed(1)},${(q[1] + ny).toFixed(1)}`;
  return { d: `M${p(a)} L${p(b)}`, mid: [(a[0] + b[0]) / 2 + nx, (a[1] + b[1]) / 2 + ny] };
}

export function buildModel(i: ModelInput): { nodes: TopoNode[]; flows: TopoFlow[] } {
  const [allow, monitor, challenge, block] = i.counters.rps_by_verdict;
  const total = allow + monitor + challenge + block;
  const rangeSec = i.dashboard ? Math.max(1, (i.dashboard.to_ms - i.dashboard.from_ms) / 1000) : 3600;
  const recon = i.board.filter(isRecon);
  const exploit = i.board.filter(isExploit);
  const banned = i.board.filter((s) => s.ban);
  const paths = (i.dashboard?.top_paths ?? []).slice(0, 5);
  const hits = i.dashboard?.honeypot_hits ?? [];
  const extra = Math.max(0, hits.length - MAX_PODS);
  const hpRates = hits.slice(0, MAX_PODS).map((h) => h.count / rangeSec);

  const node = (id: NodeId, kind: TopoNode['kind'], label: string, countText: string, unit: string, rps: number, approx: boolean, ref: string | null): TopoNode => {
    const rateText = fmtRps(rps);
    return {
      id, kind, label, countText, rateText, approx, ref, prop: BOX[id].prop, box: BOX[id],
      name: `${label}, ${countText} ${unit}, ${rateText.replace('/s', ' requests per second')}${approx ? ' (approx.)' : ''}`,
    };
  };

  const nodes: TopoNode[] = [
    node('clean', 'cluster', 'Clean sources', fmtCount(allow + monitor), 'requests per second forwarded', allow + monitor, false, null),
    node('recon', 'cluster', 'Recon cluster', String(recon.length), 'sources', i.rates.recon.passed + i.rates.recon.blocked, true, 'Recon'),
    node('exploit', 'cluster', 'Exploitation cluster', String(exploit.length), 'sources', i.rates.exploit.passed + i.rates.exploit.blocked, true, 'Exploitation'),
    node('tower', 'tower', 'Venusflytrap', `rev ${i.status?.config_rev ?? '—'}`, 'config', total, false, null),
    ...([0, 1, 2, 3, 4] as const).map((k) => {
      const p = paths[k];
      return node(`route${k}`, 'route', p ? p.prefix : `Route ${k + 1}`, p ? fmtCount(p.count) : '0', 'requests in range', p ? (p.by_verdict[0] + p.by_verdict[1]) / rangeSec : 0, false, p?.prefix ?? null);
    }),
    ...([0, 1, 2, 3] as const).map((k) => {
      const h = hits[k];
      const more = k === MAX_PODS - 1 && extra > 0 ? ` (+${extra} more)` : '';
      return node(`hp${k}`, 'honeypot', h ? `${h.path}${more}` : `Decoy ${k + 1}`, h ? fmtCount(h.count) : '0', 'hits in range', hpRates[k] ?? 0, false, h?.path ?? null);
    }),
    node('quarantine', 'quarantine', 'Quarantine', String(banned.length), 'banned sources', i.rates.quarantine, true, null),
  ];

  const flows: TopoFlow[] = [];
  const add = (from: string, to: string, a: [number, number], b: [number, number], lines: [Verdict, number][], approx: boolean) => {
    const shown = lines.filter(([, r]) => r > 0);
    const list = shown.length ? shown : lines.slice(0, 1);
    list.forEach(([verdict, rps], k) => {
      const { d, mid } = seg(a, b, (k - (list.length - 1) / 2) * 4);
      flows.push({ id: `${from}-${to}-${verdict}`, from, to, verdict, rps, rateText: fmtRps(rps), step: volumeStep(rps), d, mid, approx });
    });
  };
  const A = ANCHOR;
  add('Internet', 'Clean sources', A.edge, A.clean, [['Allow', allow], ['Monitor', monitor]], false);
  add('Internet', 'Recon cluster', A.edge, A.recon, [['Allow', i.rates.recon.passed], ['Block', i.rates.recon.blocked]], true);
  add('Internet', 'Exploitation cluster', A.edge, A.exploit, [['Allow', i.rates.exploit.passed], ['Block', i.rates.exploit.blocked]], true);
  add('Clean sources', 'Junction', A.clean, A.jA, [['Allow', allow], ['Monitor', monitor]], false);
  add('Recon cluster', 'Junction', A.recon, A.jA, [['Allow', i.rates.recon.passed], ['Block', i.rates.recon.blocked]], true);
  add('Exploitation cluster', 'Junction', A.exploit, A.jA, [['Allow', i.rates.exploit.passed], ['Block', i.rates.exploit.blocked]], true);
  add('Junction', 'Venusflytrap', A.jA, A.tower, [['Allow', allow], ['Monitor', monitor], ['Challenge', challenge], ['Block', block]], false);
  add('Venusflytrap', 'Upstream', A.tower, A.jB, [['Allow', allow], ['Monitor', monitor]], false);
  paths.forEach((p, k) => {
    add('Upstream', p.prefix, A.jB, A[`route${k}` as NodeId], [['Allow', p.by_verdict[0] / rangeSec], ['Monitor', p.by_verdict[1] / rangeSec]], false);
  });
  hits.slice(0, MAX_PODS).forEach((h, k) => {
    add('Venusflytrap', h.path, A.tower, A[`hp${k}` as NodeId], [['Block', hpRates[k]]], false);
  });
  add('Venusflytrap', 'Quarantine', A.tower, A.quarantine, [['Block', i.rates.quarantine]], true);
  const detected = Math.max(0, block - hpRates.reduce((a, b) => a + b, 0) - i.rates.quarantine);
  add('Venusflytrap', 'Stopped at shield', A.tower, A.stub, [['Challenge', challenge], ['Block', detected]], true);
  return { nodes, flows };
}
```

- [ ] **Step 5: Implement the views**

`Legend.svelte`:

```svelte
<script lang="ts">
  import { CircleCheck, Eye, OctagonX, TriangleAlert } from '../../lib/icons';
  const ROWS = [
    { v: 'allow', label: 'Allow', Icon: CircleCheck },
    { v: 'monitor', label: 'Monitor', Icon: Eye },
    { v: 'challenge', label: 'Challenge', Icon: TriangleAlert },
    { v: 'block', label: 'Block', Icon: OctagonX },
  ];
  const STEPS = ['0', '< 1/s', '1–10/s', '10–100/s', '> 100/s'];
</script>

<aside class="legend glass" aria-label="Legend">
  <h2 class="label-caps">Lines</h2>
  <ul>
    {#each ROWS as r (r.v)}
      <li><svg width="32" height="8" aria-hidden="true"><path d="M2,4 L30,4" class="base v-{r.v} s3" /></svg><r.Icon size={14} aria-hidden="true" />{r.label}</li>
    {/each}
  </ul>
  <h2 class="label-caps">Volume</h2>
  <ul>
    {#each STEPS as s, k (s)}
      <li><svg width="32" height="8" aria-hidden="true"><path d="M2,4 L30,4" class="base v-allow s{k}" /></svg>{s}</li>
    {/each}
  </ul>
</aside>

<style>
  .legend { position: absolute; right: var(--vf-space-4); bottom: var(--vf-space-4); padding: var(--vf-space-3); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-1); display: grid; gap: var(--vf-space-1); }
  h2 { margin-top: var(--vf-space-1); }
  ul { margin: 0; padding: 0; list-style: none; display: grid; gap: 2px; font-size: var(--vf-fs-xs); }
  li { display: flex; align-items: center; gap: var(--vf-space-2); height: 20px; }
  @media (max-width: 1023px) { .legend { display: none; } }
</style>
```

The `.base`, `.v-*` and `.s*` stroke classes are global (defined once in `Scene.svelte` with `:global`), so the legend draws exactly what the scene draws.

`DetailCard.svelte`:

```svelte
<script lang="ts">
  import type { SourceView } from '../../lib/api/types';
  import Link from '../../lib/components/Link.svelte';
  import StageChip from '../../lib/components/StageChip.svelte';
  import { banText, fmtCount, fmtRps } from '../../lib/format';
  import { pct, SCENE } from './geometry';
  import type { TopoNode } from './model';

  let {
    node, board, rps, pinned, now, onclose,
  }: { node: TopoNode; board: SourceView[]; rps: [number, number, number, number]; pinned: boolean; now: number; onclose: () => void } = $props();

  const right = $derived(node.box.x > SCENE.w * 0.55);
  const members = $derived(
    board
      .filter((s) => !s.ban && (node.ref === 'Recon' ? s.stage === 'Recon' || s.stage === 'Enumeration' : s.stage === 'Exploitation' || s.stage === 'Exfiltration'))
      .sort((a, b) => b.last_seen_ms - a.last_seen_ms)
      .slice(0, 5),
  );
  const soonest = $derived(
    board.filter((s) => s.ban).sort((a, b) => (a.ban!.until_ms ?? Infinity) - (b.ban!.until_ms ?? Infinity)).slice(0, 5),
  );

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') { e.stopPropagation(); onclose(); }
  }
</script>

<!-- Escape closes the card from anywhere inside it (UX §4); the group is a popover, not a widget. -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
  id="node-card"
  class="card detail"
  class:pinned
  role="group"
  aria-label={`${node.label} details`}
  style:left={right ? undefined : pct(node.box.x + node.box.w + 16, SCENE.w)}
  style:right={right ? pct(SCENE.w - node.box.x + 16, SCENE.w) : undefined}
  style:top={pct(node.box.y, SCENE.h)}
  {onkeydown}
>
  <h3>{node.label}</h3>
  <p class="meta secondary">{node.countText} · {node.rateText}{node.approx ? ' (approx.)' : ''}</p>

  {#if node.kind === 'cluster' && node.ref}
    <ul class="rows">
      {#each members as s (s.key)}
        <li><span class="mono">{s.key}</span><StageChip stage={s.stage} compact /><span class="num">{fmtCount(s.requests)} / {fmtCount(s.blocked)}</span><span class="mono secondary">{s.top_constructs[0] ?? ''}</span></li>
      {/each}
    </ul>
    <footer>
      <Link href={`/chains?stage=${node.ref}`} class="btn btn-sm">Show in Attack chains</Link>
      {#if members[0]}<Link href={`/sources/${encodeURIComponent(members[0].key)}`} class="btn btn-sm btn-primary">Open source</Link>{/if}
    </footer>
  {:else if node.kind === 'tower'}
    <dl class="kv">
      {#each ['Allow', 'Monitor', 'Challenge', 'Block'] as v, k (v)}<div><dt class="label-caps">{v}</dt><dd class="num">{fmtRps(rps[k])}</dd></div>{/each}
    </dl>
    <footer><Link href="/" class="btn btn-sm btn-primary">Open dashboard</Link></footer>
  {:else if node.kind === 'route' && node.ref}
    <footer><Link href={`/monitor?q=${encodeURIComponent(`path:${node.ref}*`)}`} class="btn btn-sm btn-primary">Open in Monitor</Link></footer>
  {:else if node.kind === 'honeypot'}
    <footer><Link href="/honeypot" class="btn btn-sm btn-primary">Open Honeypot &amp; bans</Link></footer>
  {:else if node.kind === 'quarantine'}
    <ul class="rows">
      {#each soonest as s (s.key)}<li><span class="mono">{s.key}</span><span>{banText(s.ban!, now)}</span></li>{/each}
    </ul>
    <footer><Link href="/honeypot" class="btn btn-sm btn-primary">Manage bans</Link></footer>
  {/if}
</div>

<style>
  .detail { position: absolute; z-index: 5; width: 320px; display: grid; gap: var(--vf-space-2); background: var(--vf-surface-overlay-glass); box-shadow: var(--vf-shadow-3); }
  .pinned { box-shadow: var(--vf-shadow-3), var(--vf-glow-selected); }
  .meta { font-size: var(--vf-fs-xs); }
  .rows { margin: 0; padding: 0; list-style: none; display: grid; gap: var(--vf-space-1); font-size: var(--vf-fs-xs); }
  .rows li { display: flex; align-items: center; gap: var(--vf-space-2); flex-wrap: wrap; }
  .kv { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--vf-space-2); margin: 0; }
  .kv dd { margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: var(--vf-space-2); }
</style>
```

`TableView.svelte`:

```svelte
<script lang="ts">
  import type { TopoFlow, TopoNode } from './model';
  import VerdictChip from '../../lib/components/VerdictChip.svelte';

  let { nodes, flows }: { nodes: TopoNode[]; flows: TopoFlow[] } = $props();
</script>

<div class="tables">
  <table class="data-table">
    <caption class="label-caps">Nodes</caption>
    <thead><tr><th>Node</th><th>Kind</th><th class="n">Count</th><th class="n">Rate</th></tr></thead>
    <tbody>
      {#each nodes as n (n.id)}
        <tr><td>{n.label}</td><td>{n.kind}</td><td class="n">{n.countText}</td><td class="n">{n.rateText}{n.approx ? ' (approx.)' : ''}</td></tr>
      {/each}
    </tbody>
  </table>
  <table class="data-table">
    <caption class="label-caps">Flows</caption>
    <thead><tr><th>From</th><th>To</th><th>Verdict</th><th class="n">Rate</th></tr></thead>
    <tbody>
      {#each flows as f (f.id)}
        <tr><td>{f.from}</td><td>{f.to}</td><td><VerdictChip verdict={f.verdict} size="sm" /></td><td class="n">{f.rateText}{f.approx ? ' (approx.)' : ''}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .tables { display: grid; grid-template-columns: 1fr 1fr; gap: var(--vf-space-5); }
  caption { text-align: left; padding-bottom: var(--vf-space-2); }
  @media (max-width: 1023px) { .tables { grid-template-columns: 1fr; } }
</style>
```

`Scene.svelte`:

```svelte
<script lang="ts">
  import { tick } from 'svelte';
  import type { SourceView } from '../../lib/api/types';
  import { propUrl } from '../../lib/assets';
  import { BOX, PLATE, SCENE, pct, type DecorId } from './geometry';
  import type { TopoFlow, TopoNode } from './model';
  import DetailCard from './DetailCard.svelte';

  let {
    nodes, flows, board, rps, stale, now,
  }: { nodes: TopoNode[]; flows: TopoFlow[]; board: SourceView[]; rps: [number, number, number, number]; stale: boolean; now: number } = $props();

  let active = $state(0);
  let open = $state<string | null>(null);
  let pinned = $state(false);
  const buttons: HTMLButtonElement[] = [];
  const DECOR: DecorId[] = ['edge', 'jA', 'jB'];
  const openNode = $derived(nodes.find((n) => n.id === open) ?? null);
  const plate = propUrl(PLATE.prop);

  function focusAt(i: number) {
    active = (i + nodes.length) % nodes.length;
    buttons[active]?.focus();
  }

  async function onkeydown(e: KeyboardEvent, i: number) {
    const k = e.key;
    if (k === 'ArrowRight' || k === 'ArrowDown') { e.preventDefault(); focusAt(i + 1); }
    else if (k === 'ArrowLeft' || k === 'ArrowUp') { e.preventDefault(); focusAt(i - 1); }
    else if (k === 'Home') { e.preventDefault(); focusAt(0); }
    else if (k === 'End') { e.preventDefault(); focusAt(nodes.length - 1); }
    else if (k === 'Enter') {
      e.preventDefault();
      open = nodes[i].id;
      pinned = true;
      await tick();
      document.querySelector<HTMLElement>('#node-card a, #node-card button')?.focus();
    } else if (k === 'Escape') { open = null; pinned = false; }
  }

  function close() {
    pinned = false;
    open = null;
    buttons[active]?.focus();
  }

  function onfocusout(e: FocusEvent) {
    const to = e.relatedTarget as Node | null;
    const card = document.getElementById('node-card');
    if (!pinned && !(to && card?.contains(to))) open = null;
  }
</script>

<div class="scene" class:stale role="group" aria-label="Traffic topology scene">
  {#if plate}<img class="plate" src={plate} alt="" style:left={pct(PLATE.x, SCENE.w)} style:top={pct(PLATE.y, SCENE.h)} style:width={pct(PLATE.w, SCENE.w)} />{/if}

  <svg class="lines" viewBox="0 0 {SCENE.w} {SCENE.h}" aria-hidden="true">
    {#each flows as f (f.id)}
      {#if openNode && (f.from === openNode.label || f.to === openNode.label)}<path class="halo" d={f.d} />{/if}
      <path class="base v-{f.verdict.toLowerCase()} s{f.step}" d={f.d} />
      {#if f.step > 0}<path class="packet f{f.step}" d={f.d} />{/if}
    {/each}
  </svg>

  {#each DECOR as id (id)}
    {@const url = propUrl(BOX[id].prop)}
    {#if url}<img class="prop" src={url} alt="" style:left={pct(BOX[id].x, SCENE.w)} style:top={pct(BOX[id].y, SCENE.h)} style:width={pct(BOX[id].w, SCENE.w)} />{/if}
  {/each}

  {#each flows as f (f.id)}
    {#if f.step > 0}<span class="rate num" aria-hidden="true" style:left={pct(f.mid[0], SCENE.w)} style:top={pct(f.mid[1], SCENE.h)}>{f.rateText}</span>{/if}
  {/each}

  {#each nodes as n, i (n.id)}
    {@const url = propUrl(n.prop)}
    {#if url}<img class="prop" src={url} alt="" style:left={pct(n.box.x, SCENE.w)} style:top={pct(n.box.y, SCENE.h)} style:width={pct(n.box.w, SCENE.w)} />{/if}
    <button
      bind:this={buttons[i]}
      class="node"
      class:open={open === n.id}
      tabindex={i === active ? 0 : -1}
      aria-label={n.name}
      aria-describedby={open === n.id ? 'node-card' : undefined}
      style:left={pct(n.box.x, SCENE.w)}
      style:top={pct(n.box.y, SCENE.h)}
      style:width={pct(n.box.w, SCENE.w)}
      style:height={pct(n.box.w * 0.9, SCENE.h)}
      onfocus={() => { active = i; if (!pinned) open = n.id; }}
      onfocusout={onfocusout}
      onmouseenter={() => { if (!pinned) open = n.id; }}
      onmouseleave={() => { if (!pinned) open = null; }}
      onclick={() => {
        if (pinned && open === n.id) pinned = false;
        else { open = n.id; pinned = true; }
      }}
      onkeydown={(e) => onkeydown(e, i)}
    >
      <span class="chip" aria-hidden="true">{n.label} <span class="num count">{n.countText}</span></span>
    </button>
  {/each}

  {#if openNode}
    <DetailCard node={openNode} {board} {rps} {pinned} {now} onclose={close} />
  {/if}

  {#if stale}<div class="hatch" aria-hidden="true"><span class="paused card">Live paused</span></div>{/if}
</div>

<style>
  .scene { position: relative; width: 100%; aspect-ratio: 960 / 720; max-height: 720px; border-radius: var(--vf-radius-md); overflow: hidden; background: var(--vf-surface-base); }
  .plate { position: absolute; height: auto; filter: var(--vf-plate-shadow); }
  .prop { position: absolute; height: auto; filter: var(--vf-prop-filter); pointer-events: none; }
  .lines { position: absolute; inset: 0; width: 100%; height: 100%; }
  .node { position: absolute; padding: 0; border: 0; background: transparent; cursor: pointer; border-radius: var(--vf-radius-sm); }
  .node:hover .chip, .node.open .chip { box-shadow: var(--vf-shadow-2), var(--vf-glow-hover); }
  .chip {
    position: absolute; left: 50%; top: -12px; transform: translate(-50%, -100%); white-space: nowrap;
    height: 24px; padding: 0 var(--vf-space-2); display: inline-flex; align-items: center; gap: var(--vf-space-1);
    border-radius: var(--vf-radius-sm); background: var(--vf-surface-raised-glass); backdrop-filter: var(--vf-glass-filter);
    border: var(--vf-bw-hair) solid var(--vf-border-hairline); box-shadow: var(--vf-shadow-1);
    font-size: var(--vf-fs-xs); font-weight: 600; color: var(--vf-text-primary);
  }
  .count { font-weight: 400; }
  .rate {
    position: absolute; transform: translate(-50%, -50%); height: 20px; padding: 0 6px; display: inline-flex; align-items: center;
    border-radius: var(--vf-radius-sm); background: var(--vf-surface-raised-glass); font-size: var(--vf-fs-xs);
    color: var(--vf-text-secondary); pointer-events: none;
  }
  .hatch { position: absolute; inset: 0; background-image: var(--vf-hatch); display: grid; place-items: start center; padding-top: 20%; }
  .paused { font-weight: 600; }

  :global(.base) { fill: none; stroke-linecap: butt; }
  :global(.base.v-allow) { stroke: var(--vf-verdict-allow-line); }
  :global(.base.v-monitor) { stroke: var(--vf-verdict-monitor-line); stroke-dasharray: 12 6; }
  :global(.base.v-challenge) { stroke: var(--vf-verdict-challenge-line); stroke-dasharray: 10 4 2 4; }
  :global(.base.v-block) { stroke: var(--vf-verdict-block-line); stroke-dasharray: 0 6; stroke-linecap: round; }
  :global(.base.s0) { stroke: var(--vf-line-idle); stroke-width: 1; }
  :global(.base.s1) { stroke-width: 1.5; }
  :global(.base.s2) { stroke-width: 2; }
  :global(.base.s3) { stroke-width: 3; }
  :global(.base.s4) { stroke-width: 4; }
  :global(.base.v-block.s1) { stroke-width: 2.5; }
  :global(.base.v-block.s2) { stroke-width: 3; }
  :global(.base.v-block.s3) { stroke-width: 4; }
  :global(.base.v-block.s4) { stroke-width: 5; }
  .halo { fill: none; stroke: var(--vf-line-active); stroke-width: 8; opacity: .55; filter: var(--vf-glow-line-active); }
  .packet {
    fill: none; stroke: var(--vf-line-packet); stroke-width: 2; stroke-linecap: round; stroke-dasharray: 2 22;
    animation: flow var(--dur) linear infinite; animation-play-state: var(--vf-motion-play);
  }
  .f1 { --dur: var(--vf-flow-1); } .f2 { --dur: var(--vf-flow-2); } .f3 { --dur: var(--vf-flow-3); } .f4 { --dur: var(--vf-flow-4); }
  @keyframes flow { from { stroke-dashoffset: 24; } to { stroke-dashoffset: 0; } }
  :global([data-motion='off']) .packet { display: none; }
  @media (prefers-reduced-motion: reduce) { .packet { display: none; } }
  .stale :global(.base) { stroke: var(--vf-line-idle); }
  .stale .packet { display: none; }
  @media (max-width: 1023px) { .rate { display: none; } }
</style>
```

`Topology.svelte`:

```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import type { Dashboard } from '../lib/api/types';
  import { Pause, Play, Table2 } from '../lib/icons';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import { motion } from '../lib/state/theme.svelte';
  import Legend from './topology/Legend.svelte';
  import { buildModel, clusterRates } from './topology/model';
  import Scene from './topology/Scene.svelte';
  import TableView from './topology/TableView.svelte';

  let { title }: { title: string } = $props();
  let dashboard = $state<Dashboard | null>(null);

  async function load() {
    if (!app.src) return;
    const to = Date.now();
    dashboard = await app.src.dashboard(to - 3_600_000, to);
  }
  onMount(() => {
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  });

  const view = $derived(router.search.get('view') ?? (motion.reduced ? 'table' : 'map'));
  const model = $derived(
    buildModel({
      counters: app.counters ?? { rps_by_verdict: [0, 0, 0, 0], dropped_total: 0 },
      board: app.board,
      rates: clusterRates(app.prevBoard, app.board, app.boardAt - app.prevBoardAt),
      dashboard,
      status: app.status,
      now: app.now,
    }),
  );

  function setView(v: 'map' | 'table') {
    const p = new URLSearchParams(router.search);
    p.set('view', v);
    router.navigate(`/topology?${p}`, true);
  }
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
  <p class="secondary status">Live: {app.stale ? 'paused' : app.live} · dropped {app.counters?.dropped_total ?? 0}</p>
</header>

<div class="layout">
  <div class="stage">
    {#if view === 'table'}
      <TableView nodes={model.nodes} flows={model.flows} />
    {:else}
      <Scene nodes={model.nodes} flows={model.flows} board={app.board} rps={app.counters?.rps_by_verdict ?? [0, 0, 0, 0]} stale={app.stale} now={app.now} />
      <Legend />
      {#if model.flows.every((f) => f.step === 0)}<p class="note card">No traffic yet</p>{/if}
    {/if}
  </div>
  <div class="rail glass" role="toolbar" aria-label="View controls" aria-orientation="vertical">
    <button class="btn btn-ghost" aria-pressed={view === 'table'} onclick={() => setView(view === 'table' ? 'map' : 'table')}>
      <Table2 size={18} aria-hidden="true" /><span class="sr-only">Table view</span>
    </button>
    <button class="btn btn-ghost" aria-pressed={motion.paused} onclick={() => motion.set(!motion.paused)}>
      {#if motion.paused}<Play size={18} aria-hidden="true" />{:else}<Pause size={18} aria-hidden="true" />{/if}
      <span class="sr-only">Pause animation</span>
    </button>
  </div>
</div>

<style>
  .head { display: flex; align-items: baseline; gap: var(--vf-space-4); margin-bottom: var(--vf-space-4); }
  .status { font-size: var(--vf-fs-sm); }
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 48px; gap: var(--vf-space-3); }
  .stage { position: relative; }
  .rail { display: grid; align-content: start; gap: var(--vf-space-1); padding: var(--vf-space-1); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-1); }
  .rail .btn { width: 40px; padding: 0; justify-content: center; }
  .note { position: absolute; left: 50%; top: var(--vf-space-4); transform: translateX(-50%); }
</style>
```

- [ ] **Step 6: Write the view test** (`topology.test.ts`)

```ts
import { render, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import { expect, test } from 'vitest';
import { makeFixtures } from '../../lib/api/fixtures';
import { buildModel, clusterRates } from './model';
import Scene from './Scene.svelte';
import TableView from './TableView.svelte';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);

function model() {
  const f = makeFixtures(NOW);
  const later = f.board.map((s) => (s.stage === 'Exploitation' ? { ...s, requests: s.requests + 10, blocked: s.blocked + 8 } : s));
  return {
    f,
    m: buildModel({ counters: f.counters, board: later, rates: clusterRates(f.board, later, 1000), dashboard: f.dashboard(NOW - 3_600_000, NOW), status: f.status, now: NOW }),
  };
}

test('the table view carries every number the map shows', () => {
  const { f, m } = model();
  const map = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: false, now: NOW } });
  const mapText = map.container.textContent ?? '';
  const names = [...map.container.querySelectorAll('button.node')].map((b) => b.getAttribute('aria-label') ?? '');
  const table = render(TableView, { props: { nodes: m.nodes, flows: m.flows } });
  const tableText = table.container.textContent ?? '';
  for (const n of m.nodes) {
    expect(names.some((x) => x.includes(n.countText))).toBe(true);
    expect(tableText).toContain(n.countText);
    expect(tableText).toContain(n.rateText);
  }
  for (const f of m.flows.filter((x) => x.step > 0)) {
    expect(mapText).toContain(f.rateText);
    expect(tableText).toContain(f.rateText);
  }
});

test('nodes form one roving tab stop and arrows move along the order', async () => {
  const { f, m } = model();
  const { container } = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: false, now: NOW } });
  const buttons = [...container.querySelectorAll<HTMLButtonElement>('button.node')];
  expect(buttons.filter((b) => b.tabIndex === 0)).toHaveLength(1);
  buttons[0].focus();
  buttons[0].dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
  await tick();
  expect(document.activeElement).toBe(buttons[1]);
  expect(within(container).getByRole('group', { name: /Recon cluster details/ })).toBeTruthy();
});

test('stale scenes stop packets and say so', () => {
  const { f, m } = model();
  const { container } = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: true, now: NOW } });
  expect(container.textContent).toContain('Live paused');
  expect(container.querySelector('.scene.stale')).toBeTruthy();
});
```

- [ ] **Step 7: Wire the route, run everything**

In `App.svelte` set `topology: () => import('./screens/Topology.svelte'),`.

Run: `npm test && npm run check && npm run build && npm run budget` → Expected: green; the Topology chunk under 80 KB gz.

Visual check (owner review gate, console spec §9): run `npm run dev`, open `/topology?static` in light and dark, and compare with the topology board in the design canvas (`https://claude.ai/artifact/HuxfLvbmg8onvbXXmVu1sj`). Record differences in the task report; fix those that contradict the design system.

- [ ] **Step 8: Commit**

```bash
git add ui/src
git commit -m "feat(ui): traffic topology hero view with keyboard nodes and a table twin"
```

---

### Task 8: Attack chains grid (primary live screen)

**Files:**
- Create: `ui/src/screens/chains/grid.ts`, `grid.test.ts`, `chains.test.ts`; `ui/src/screens/Chains.svelte`
- Modify: `ui/src/App.svelte` (`chains: () => import('./screens/Chains.svelte')`)

**Interfaces:**
- Produces: `sortKeys(rows: SourceView[]): string[]` (stage desc, then `last_seen_ms` desc, max 500); `reconcile(order: string[], rows: SourceView[], frozen: boolean): { order: string[]; pending: number }`; `moveCell(pos: Cell, key: string, mods: { ctrl: boolean }, dims: { rows: number; cols: number }): Cell | null` with `type Cell = { r: number; c: number }`; `stageCellText(s: SourceView, stage: Stage): string`.

- [ ] **Step 1: Write the failing logic tests** (`grid.test.ts`)

```ts
import { expect, test } from 'vitest';
import { makeFixtures } from '../../lib/api/fixtures';
import { moveCell, reconcile, sortKeys, stageCellText } from './grid';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);
const board = makeFixtures(NOW).board;

test('rows sort by stage, then recency', () => {
  const keys = sortKeys(board);
  expect(keys[0]).toBe('198.51.100.23'); // the only Exfiltration source
  const ranks = keys.map((k) => board.find((s) => s.key === k)!.stage);
  expect(ranks.indexOf('Recon')).toBeGreaterThan(ranks.lastIndexOf('Exploitation'));
});

test('a frozen grid keeps its order and counts pending changes', () => {
  const order = sortKeys(board);
  const bumped = board.map((s) => (s.key === '198.51.100.9' ? { ...s, stage: 'Exfiltration' as const, last_seen_ms: NOW } : s));
  const frozen = reconcile(order, bumped, true);
  expect(frozen.order).toEqual(order);
  expect(frozen.pending).toBeGreaterThan(0);
  const applied = reconcile(order, bumped, false);
  expect(applied.order[0]).toBe('198.51.100.9');
  expect(applied.pending).toBe(0);
});

test('new sources wait while frozen; removed ones stay in place', () => {
  const order = sortKeys(board);
  const next = [...board.slice(1), { ...board[0], key: '203.0.113.250', ip: '203.0.113.250' }];
  const r = reconcile(order, next, true);
  expect(r.order).toEqual(order);
  expect(r.order).toContain(board[0].key);
  expect(r.pending).toBeGreaterThanOrEqual(1);
});

test('grid keyboard model', () => {
  const dims = { rows: 11, cols: 9 };
  expect(moveCell({ r: 0, c: 0 }, 'ArrowRight', { ctrl: false }, dims)).toEqual({ r: 0, c: 1 });
  expect(moveCell({ r: 0, c: 8 }, 'ArrowRight', { ctrl: false }, dims)).toEqual({ r: 0, c: 8 });
  expect(moveCell({ r: 3, c: 4 }, 'Home', { ctrl: false }, dims)).toEqual({ r: 3, c: 0 });
  expect(moveCell({ r: 3, c: 4 }, 'Home', { ctrl: true }, dims)).toEqual({ r: 0, c: 0 });
  expect(moveCell({ r: 3, c: 4 }, 'PageDown', { ctrl: false }, dims)).toEqual({ r: 10, c: 4 });
  expect(moveCell({ r: 3, c: 4 }, 'x', { ctrl: false }, dims)).toBeNull();
});

test('stage cells read first-reached time and count', () => {
  const s = board.find((x) => x.key === '203.0.113.7')!;
  expect(stageCellText(s, 'Exploitation')).toMatch(/^\d\d:\d\d · 9$/);
  expect(stageCellText(s, 'Exfiltration')).toBe('—');
});
```

- [ ] **Step 2: Run them to see them fail**

Run: `npm test -- grid` → Expected: FAIL, cannot resolve `./grid`.

- [ ] **Step 3: Implement `grid.ts`**

```ts
import { STAGES, type SourceView, type Stage } from '../../lib/api/types';

const MAX_ROWS = 500;
const rank = (s: SourceView) => (s.stage === null ? -1 : STAGES.indexOf(s.stage));

export function sortKeys(rows: SourceView[]): string[] {
  return [...rows]
    .sort((a, b) => rank(b) - rank(a) || b.last_seen_ms - a.last_seen_ms)
    .slice(0, MAX_ROWS)
    .map((s) => s.key);
}

/**
 * While frozen (focus inside the grid) the displayed order never changes: values update in
 * place, removed sources keep their row, and new sources wait. `pending` counts the rows
 * whose position would change on apply, plus the waiting ones.
 */
export function reconcile(order: string[], rows: SourceView[], frozen: boolean): { order: string[]; pending: number } {
  const target = sortKeys(rows);
  if (!frozen) return { order: target, pending: 0 };
  const present = new Set(target);
  const kept = order.filter((k) => present.has(k));
  const targetKept = target.filter((k) => order.includes(k));
  const moved = kept.reduce((n, k, i) => n + (targetKept[i] === k ? 0 : 1), 0);
  const added = target.filter((k) => !order.includes(k)).length;
  const removed = order.length - kept.length;
  return { order, pending: moved + added + removed };
}

export interface Cell { r: number; c: number }

export function moveCell(p: Cell, key: string, mods: { ctrl: boolean }, dims: { rows: number; cols: number }): Cell | null {
  const clampR = (r: number) => Math.max(0, Math.min(dims.rows - 1, r));
  const clampC = (c: number) => Math.max(0, Math.min(dims.cols - 1, c));
  switch (key) {
    case 'ArrowRight': return { r: p.r, c: clampC(p.c + 1) };
    case 'ArrowLeft': return { r: p.r, c: clampC(p.c - 1) };
    case 'ArrowDown': return { r: clampR(p.r + 1), c: p.c };
    case 'ArrowUp': return { r: clampR(p.r - 1), c: p.c };
    case 'Home': return mods.ctrl ? { r: 0, c: 0 } : { r: p.r, c: 0 };
    case 'End': return mods.ctrl ? { r: dims.rows - 1, c: dims.cols - 1 } : { r: p.r, c: dims.cols - 1 };
    case 'PageDown': return { r: clampR(p.r + 10), c: p.c };
    case 'PageUp': return { r: clampR(p.r - 10), c: p.c };
    default: return null;
  }
}

export function stageCellText(s: SourceView, stage: Stage): string {
  const reached = s.stage_path.find((p) => p.stage === stage);
  if (!reached) return '—';
  const t = new Date(reached.first_ts_ms).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
  return `${t} · ${s.stage_counts[STAGES.indexOf(stage)]}`;
}
```

- [ ] **Step 4: Implement `Chains.svelte`**

```svelte
<script lang="ts">
  import { untrack } from 'svelte';
  import { STAGES, type SourceView, type Stage } from '../lib/api/types';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import StageChip from '../lib/components/StageChip.svelte';
  import { banText, fmtAgo, fmtCount } from '../lib/format';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import { moveCell, reconcile, sortKeys, stageCellText, type Cell } from './chains/grid';

  let { title }: { title: string } = $props();
  const COLS = ['Source', ...STAGES, 'Requests / Blocked', 'Honeypot', 'Ban', 'Last seen'];

  let minStage = $state<Stage | ''>((router.search.get('stage') as Stage) ?? '');
  let bannedOnly = $state(false);
  let search = $state('');
  let frozen = $state(false);
  let order = $state<string[]>([]);
  let pending = $state(0);
  let pos = $state<Cell>({ r: 0, c: 0 });
  let table: HTMLTableElement | undefined = $state();

  const rows = $derived(
    app.board.filter((s) =>
      s.stage !== null &&
      (!minStage || STAGES.indexOf(s.stage) >= STAGES.indexOf(minStage)) &&
      (!bannedOnly || s.ban) &&
      (!search || s.key.includes(search) || s.ip.includes(search)),
    ),
  );
  const byKey = $derived(new Map(app.board.map((s) => [s.key, s])));

  // Depends on rows and frozen only: `order` is read untracked, or writing it would re-run
  // this effect forever.
  $effect(() => {
    const current = untrack(() => order);
    const r = reconcile(current.length ? current : sortKeys(rows), rows, frozen);
    order = r.order;
    pending = r.pending;
  });

  function onfocusin(e: FocusEvent) {
    frozen = true;
    const td = (e.target as HTMLElement).closest('td');
    if (td) pos = { r: Number(td.dataset.r), c: Number(td.dataset.c) };
  }

  function apply() {
    const focusedKey = order[pos.r];
    order = sortKeys(rows);
    pending = 0;
    const i = order.indexOf(focusedKey);
    pos = { r: i >= 0 ? i : 0, c: pos.c };
    queueMicrotask(focusCell);
  }

  function focusCell() {
    table?.querySelector<HTMLElement>(`[data-r="${pos.r}"][data-c="${pos.c}"]`)?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      const key = order[pos.r];
      if (key) router.navigate(`/sources/${encodeURIComponent(key)}`);
      return;
    }
    if (e.key === 'r' || e.key === 'R') { apply(); return; }
    const next = moveCell(pos, e.key, { ctrl: e.ctrlKey }, { rows: order.length, cols: COLS.length });
    if (!next) return;
    e.preventDefault();
    pos = next;
    focusCell();
  }

  function cell(s: SourceView | undefined, c: number, now: number): string {
    if (!s) return c === 0 ? 'Source left the board' : '';
    if (c >= 1 && c <= 4) return stageCellText(s, STAGES[c - 1]);
    if (c === 5) return `${fmtCount(s.requests)} / ${fmtCount(s.blocked)}`;
    if (c === 6) return fmtCount(s.honeypot_hits);
    if (c === 7) return s.ban ? banText(s.ban, now) : '—';
    if (c === 8) return fmtAgo(now - s.last_seen_ms);
    return s.key;
  }
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
</header>

<div class="toolbar card">
  <label>Minimum stage
    <select bind:value={minStage}>
      <option value="">Any</option>
      {#each STAGES as s (s)}<option value={s}>{s}</option>{/each}
    </select>
  </label>
  <label class="check"><input type="checkbox" bind:checked={bannedOnly} /> Banned only</label>
  <label>Source <input class="mono" bind:value={search} placeholder="Key or IP" /></label>
  <span class="secondary num count">{order.length} of ≤ 500</span>
  <span class="secondary">Live: {app.stale ? 'paused' : app.live} · dropped {app.counters?.dropped_total ?? 0}</span>
</div>

{#if order.length === 0}
  <div class="card"><EmptyState scene="quiet" message="No source has reached Recon in the chain window." /></div>
{:else}
  <div class="scroll card">
    <table
      bind:this={table}
      class="data-table grid"
      role="grid"
      aria-label="Sources by kill-chain stage"
      aria-rowcount={order.length + 1}
      {onfocusin}
      onfocusout={(e) => { if (!table?.contains(e.relatedTarget as Node)) frozen = false; }}
      {onkeydown}
    >
      <thead>
        <tr>{#each COLS as c (c)}<th scope="col">{c}</th>{/each}</tr>
      </thead>
      <tbody>
        {#each order as key, r (key)}
          {@const s = byKey.get(key)}
          <tr class:banned={s?.ban} aria-rowindex={r + 2}>
            {#each COLS as colName, c (colName)}
              <td
                role="gridcell"
                data-r={r}
                data-c={c}
                tabindex={r === pos.r && c === pos.c ? 0 : -1}
                class:n={c >= 5 && c <= 6}
                class:current={s && c >= 1 && c <= 4 && s.stage === STAGES[c - 1]}
                aria-label={c >= 1 && c <= 4 ? `${colName}: ${cell(s, c, app.now) === '—' ? 'not reached' : `reached ${cell(s, c, app.now).replace(' · ', ', ')} events`}` : undefined}
              >
                {#if c === 0 && s}
                  <span class="mono">{s.key}</span>{#if s.ip !== s.key}<span class="secondary ip"> {s.ip}</span>{/if}
                {:else if s && c >= 1 && c <= 4 && s.stage === STAGES[c - 1]}
                  <StageChip stage={s.stage} compact /> <span class="num">{cell(s, c, app.now)}</span>
                {:else if c === 7 && s?.ban}
                  <span class="ban">{cell(s, c, app.now)}</span>
                {:else}
                  <span class="num">{cell(s, c, app.now)}</span>
                {/if}
              </td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if frozen && pending > 0}
  <div class="pending glass" role="status">
    Order paused while you navigate — {pending} updates.
    <button class="btn btn-sm btn-primary" onclick={apply}>Apply (R)</button>
  </div>
{/if}

<style>
  .head { margin-bottom: var(--vf-space-4); }
  .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--vf-space-4); margin-bottom: var(--vf-space-4); }
  .toolbar label { display: inline-flex; align-items: center; gap: var(--vf-space-2); font-size: var(--vf-fs-sm); }
  .toolbar select, .toolbar input:not([type]) {
    height: var(--vf-control-sm); padding: 0 var(--vf-space-2); border-radius: var(--vf-radius-sm);
    border: var(--vf-bw-std) solid var(--vf-border-strong); background: var(--vf-surface-input);
  }
  .count { margin-left: auto; }
  .scroll { overflow: auto; max-height: calc(100vh - 260px); padding: 0; }
  .grid td { white-space: nowrap; }
  .grid td:focus-visible { outline-offset: -2px; box-shadow: none; }
  .grid tr:hover td { background: var(--vf-row-hover); }
  td.current { font-weight: 600; }
  .ban { padding: 2px 6px; border-radius: var(--vf-radius-xs); background: var(--vf-verdict-block-bg); color: var(--vf-verdict-block-fg); font-weight: 600; }
  .ip { font-size: var(--vf-fs-xs); }
  .pending { position: sticky; bottom: var(--vf-space-4); margin-top: var(--vf-space-3); display: flex; align-items: center; justify-content: space-between; gap: var(--vf-space-3); padding: var(--vf-space-2) var(--vf-space-4); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-2); }
</style>
```

- [ ] **Step 5: Write the screen test** (`chains.test.ts`)

```ts
import { fireEvent, render, screen } from '@testing-library/svelte';
import { beforeAll, expect, test } from 'vitest';
import { FixtureSource } from '../../lib/api/source';
import { app } from '../../lib/state/app.svelte';
import { router } from '../../lib/state/router.svelte';
import Chains from '../Chains.svelte';

beforeAll(async () => {
  await app.start(new FixtureSource({ live: false }));
});

test('one tab stop, arrows move, Enter opens the source', async () => {
  router.navigate('/chains');
  render(Chains, { props: { title: 'Attack chains' } });
  const grid = screen.getByRole('grid');
  const stops = grid.querySelectorAll('[tabindex="0"]');
  expect(stops).toHaveLength(1);
  (stops[0] as HTMLElement).focus();
  await fireEvent.keyDown(grid, { key: 'ArrowDown' });
  expect(document.activeElement?.getAttribute('data-r')).toBe('1');
  await fireEvent.keyDown(grid, { key: 'Enter' });
  expect(router.route.name).toBe('source');
});

test('ban badges use minute granularity', () => {
  router.navigate('/chains');
  render(Chains, { props: { title: 'Attack chains' } });
  expect(screen.getAllByText(/Banned · (\d+ min left|Permanent)/).length).toBeGreaterThanOrEqual(2);
});
```

- [ ] **Step 6: Wire the route, run everything**

In `App.svelte` set `chains: () => import('./screens/Chains.svelte'),`.

Run: `npm test && npm run check && npm run build && npm run budget` → Expected: green.

- [ ] **Step 7: Commit**

```bash
git add ui/src
git commit -m "feat(ui): attack-chains grid with frozen order and a grid keyboard model"
```

---

### Task 9: End-to-end — axe, CSP, keyboard, reduced motion

**Files:**
- Create: `ui/playwright.config.ts`, `ui/e2e/console.spec.ts`, `ui/README.md`

**Interfaces:**
- Consumes: the built app served by `vite preview` with the production CSP header.

- [ ] **Step 1: Write `playwright.config.ts`**

```ts
import { defineConfig } from '@playwright/test';

// Uses the system Microsoft Edge (or Chrome via PW_CHANNEL=chrome), so no browser download is needed.
export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  use: { baseURL: 'http://localhost:4173', channel: process.env.PW_CHANNEL ?? 'msedge', viewport: { width: 1440, height: 900 } },
  webServer: { command: 'npm run build && npm run preview', url: 'http://localhost:4173', reuseExistingServer: false, timeout: 120_000 },
});
```

- [ ] **Step 2: Write `e2e/console.spec.ts`**

```ts
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const ROUTES = ['/', '/topology', '/topology?view=table', '/chains', '/monitor'];

async function collectCsp(page: Page) {
  const violations: string[] = [];
  page.on('console', (m) => {
    if (/Content Security Policy|Refused to/i.test(m.text())) violations.push(m.text());
  });
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      (window as unknown as { __csp: string[] }).__csp ??= [];
      (window as unknown as { __csp: string[] }).__csp.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  return async () => [...violations, ...((await page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp ?? [])) as string[])];
}

for (const scheme of ['light', 'dark'] as const) {
  for (const route of ROUTES) {
    test(`${route} in ${scheme}: no serious axe violations, no CSP violations`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      const csp = await collectCsp(page);
      await page.goto(`${route}${route.includes('?') ? '&' : '?'}static`);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      await page.waitForLoadState('networkidle');
      const results = await new AxeBuilder({ page }).analyze();
      const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
      expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
      expect(await csp()).toEqual([]);
    });
  }
}

test('topology: keyboard reaches a node, opens and pins its card, Escape closes', async ({ page }) => {
  await page.goto('/topology?static');
  const clean = page.getByRole('button', { name: /^Clean sources/ });
  await clean.focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('button', { name: /^Recon cluster/ })).toBeFocused();
  await expect(page.getByRole('group', { name: 'Recon cluster details' })).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('group', { name: 'Recon cluster details' }).getByRole('link').first()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: /^Recon cluster/ })).toBeFocused();
});

test('reduced motion defaults topology to the table and hides packets', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/topology?static');
  await expect(page.getByRole('table').first()).toBeVisible();
  await page.goto('/topology?static&view=map');
  const packets = page.locator('path.packet');
  for (const p of await packets.all()) await expect(p).toBeHidden();
});

test('theme toggle persists across reloads', async ({ page }) => {
  await page.goto('/?static');
  await page.getByLabel('Dark').check();
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});
```

- [ ] **Step 3: Run the suite**

Run: `npm run e2e` → Expected: all pass. A failing axe rule is fixed in the component (never by disabling the rule); a CSP violation is fixed by removing the inline style or script that caused it.

- [ ] **Step 4: Write `ui/README.md`**

```markdown
# Venusflytrap console

Svelte 5 + Vite SPA. In this stage every screen reads deterministic fixtures through
`src/lib/api/source.ts` (`FixtureSource`); SP5 adds the HTTP + SSE source.

    npm install
    npm run dev          # http://localhost:5173 (append ?static to stop the simulated live feed)
    npm test             # unit and component tests (Vitest + jsdom)
    npm run check        # svelte-check, warnings fail
    npm run build && npm run budget   # initial JS <= 150 KB gz, each route chunk <= 80 KB gz
    npm run e2e          # Playwright on system Edge: axe (light + dark), CSP, keyboard, reduced motion

Generated art (`assets/props`, `assets/scenes`) is not committed until its licence is
confirmed; the app builds without it and simply omits the images.
```

- [ ] **Step 5: Full verification**

Run: `npm test && npm run check && npm run build && npm run budget && npm run e2e` → Expected: green; paste the `budget` output into the task report.

- [ ] **Step 6: Commit**

```bash
git add ui/playwright.config.ts ui/e2e ui/README.md
git commit -m "test(ui): end-to-end axe, CSP, keyboard and reduced-motion checks"
```

---

## Acceptance map

| Acceptance item (console spec §9 / parent §6 SP6) | In this plan |
|---|---|
| Initial JS ≤ 150 KB gz; route chunks ≤ 80 KB | Task 1 `check-budget.mjs`, run in Tasks 2, 4, 6–9 |
| axe zero serious/critical in light and dark | Task 9, five routes × two schemes |
| No CSP violations | Task 9 under the production CSP header from `vite preview` |
| Contrast CI on `tokens.css` | Task 2 `tokens.test.ts` |
| Topology table shows every number the map shows | Task 7 `topology.test.ts` |
| Reduced motion / Pause: nothing animates, nothing lost | Task 7 CSS + Task 9 e2e |
| Keyboard paths (topology nodes, chains grid) | Tasks 7, 8 unit tests; Task 9 e2e |
| Side-by-side review with canvas boards | Task 7 Step 7 visual check; repeat for Chains and Dashboard in the final review |
| Blocked request → why → setting → saved → new `config_rev` | **SP6b** (Monitor, Request details, Settings) |
| Live board ≤ 1 s after a replayed honeypot hit | **SP6 final**, once SP5's live channel exists |
