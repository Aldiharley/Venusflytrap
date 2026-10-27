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
];

const browser = await chromium.launch({ channel: process.env.PW_CHANNEL ?? 'msedge' });
try {
  for (const s of SHOTS) {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: s.scheme, reducedMotion: 'reduce' });
    await page.goto(base + s.path);
    await page.locator(s.ready).first().waitFor();
    await page.waitForLoadState('networkidle');
    const file = resolve(out, `${s.name}.png`);
    await page.screenshot({ path: file });
    console.log(file);
    await page.close();
  }
} finally {
  await browser.close();
}
