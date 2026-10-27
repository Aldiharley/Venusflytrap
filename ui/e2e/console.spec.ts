import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';

// @axe-core/playwright resolves playwright-core 1.64.1 while @playwright/test brings 1.64.0, so their Page types differ nominally.
type AxePage = ConstructorParameters<typeof AxeBuilder>[0]['page'];

const ROUTES = ['/', '/topology', '/topology?view=table', '/chains', '/monitor'] as const;

// Something only the mounted screen has, so axe never runs against the bare loading shell.
const MOUNTED: Record<(typeof ROUTES)[number], (page: Page) => Locator> = {
  '/': (page) => page.getByRole('region', { name: 'Requests over time' }).getByRole('button', { name: 'Show as table' }),
  '/topology': (page) => page.locator('.scene'),
  '/topology?view=table': (page) => page.getByRole('table').first(),
  '/chains': (page) => page.getByRole('grid'),
  '/monitor': (page) => page.getByText('arrives with console plan SP6b'),
};

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
      await expect(MOUNTED[route](page)).toBeVisible();
      await page.waitForLoadState('networkidle');
      expect(await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches)).toBe(scheme === 'dark');
      await expect(page.locator('html')).not.toHaveAttribute('data-theme');
      const results = await new AxeBuilder({ page: page as unknown as AxePage }).analyze();
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
  await expect(page.locator('.scene')).toBeVisible();
  expect(await page.locator('path.packet').count()).toBeGreaterThan(0);
  await expect(page.locator('path.packet:visible')).toHaveCount(0);
});

test('control: without reduced motion the topology map shows packets', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('/topology?static&view=map');
  await expect(page.locator('.scene')).toBeVisible();
  expect(await page.locator('path.packet').count()).toBeGreaterThan(0);
  await expect(page.locator('path.packet').first()).toBeVisible();
});

test('theme toggle persists across reloads', async ({ page }) => {
  await page.goto('/?static');
  await page.getByLabel('Dark').check();
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});
