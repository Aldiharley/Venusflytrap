// Capture the README screenshots from a running `npm run preview` (port 4173).
// Usage: npm run build && npm run preview   (in another terminal), then
//        node scripts/screenshots.mjs [outDir]   (default ../docs/images)
// Uses the system Microsoft Edge (or PW_CHANNEL=chrome); ?static freezes the fixture feed.
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { chromium } from '@playwright/test';

const base = process.env.BASE_URL ?? 'http://localhost:4173';
const out = resolve(process.argv[2] ?? '../docs/images');
mkdirSync(out, { recursive: true });

const SHOTS = [
  { name: 'console-dashboard-light', path: '/?static', scheme: 'light', ready: 'button:has-text("Show as table")' },
  { name: 'console-topology-light', path: '/topology?static&view=map', scheme: 'light', ready: '.scene' },
  { name: 'console-topology-dark', path: '/topology?static&view=map', scheme: 'dark', ready: '.scene' },
  { name: 'console-chains-dark', path: '/chains?static', scheme: 'dark', ready: '[role="grid"]' },
  // Scoped exceptions: the list with a row open, a touched request, and its Create exception form (both themes).
  ...['light', 'dark'].flatMap((scheme) => [
    { name: `console-exceptions-${scheme}`, path: '/exceptions?static&id=hook-signature', scheme, ready: '#exc-detail' },
    { name: `console-request-exceptions-${scheme}`, path: '/monitor?static&q=path%3A%2Fapi%2Fsearch', scheme, ready: '[role="grid"]', act: openTouched, after: 'section[aria-labelledby="touched-h"]', fullPage: true },
    { name: `console-create-exception-${scheme}`, path: '/monitor?static&q=path%3A%2Fapi%2Fsearch', scheme, ready: '[role="grid"]', act: createForm, after: 'section[aria-labelledby="ce-h"] pre', fullPage: true },
  ]),
];

// Opens the first Monitor detection an exception touched (found by its marker, not by id; an Allow whose
// evidence was ignored would leave the Create exception form nothing to pre-fill).
async function openTouched(page) {
  await page.locator('tbody tr').filter({ has: page.getByLabel('Exception applied') })
    .filter({ hasNot: page.locator('td.c-verdict', { hasText: 'Allow' }) }).first().locator('td[data-c="0"] a').click();
}

// Opens a touched request, then the Create exception panel, filled so the YAML shows.
async function createForm(page) {
  await openTouched(page);
  await page.getByRole('button', { name: 'Create exception' }).click();
  await page.getByLabel('Owner').fill('platform-team');
  await page.getByLabel('Reason').fill('UTM tags carry markup from the campaign tool');
}

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL ?? 'msedge' });
try {
  for (const s of SHOTS) {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: s.scheme, reducedMotion: 'reduce' });
    await page.goto(base + s.path);
    await page.locator(s.ready).first().waitFor();
    if (s.act) {
      await s.act(page);
      await page.locator(s.after).first().waitFor();
    }
    await page.waitForLoadState('networkidle');
    const file = resolve(out, `${s.name}.png`);
    await page.screenshot({ path: file, fullPage: s.fullPage ?? false });
    console.log(file);
    await page.close();
  }
} finally {
  await browser.close();
}
