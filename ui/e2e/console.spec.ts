import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';

// @axe-core/playwright resolves playwright-core 1.64.1 while @playwright/test brings 1.64.0, so their Page types differ nominally.
type AxePage = ConstructorParameters<typeof AxeBuilder>[0]['page'];

// The Monitor route with a query checks the highlighted query and blocked-row styling under axe.
const ROUTES = ['/', '/topology', '/topology?view=table', '/chains', '/monitor', '/monitor?q=-verdict%3Aallow%20construct%3Asqli.*'] as const;

// Something only the mounted screen has, so axe never runs against the bare loading shell.
const MOUNTED: Record<(typeof ROUTES)[number], (page: Page) => Locator> = {
  '/': (page) => page.getByRole('region', { name: 'Requests over time' }).getByRole('button', { name: 'Show as table' }),
  '/topology': (page) => page.locator('.scene'),
  '/topology?view=table': (page) => page.getByRole('table').first(),
  '/chains': (page) => page.getByRole('grid'),
  '/monitor': (page) => page.getByRole('grid'),
  '/monitor?q=-verdict%3Aallow%20construct%3Asqli.*': (page) => page.getByRole('grid'),
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

test('monitor: / focuses the query, Enter runs it, the grid adds filters and opens a request', async ({ page }) => {
  await page.goto('/monitor?static');
  await expect(page.getByRole('grid')).toBeVisible();
  await page.locator('body').press('/');
  const query = page.getByRole('combobox', { name: 'Query' });
  await expect(query).toBeFocused();
  await query.fill('verdict:block');
  await query.press('Enter');
  await expect(page).toHaveURL(/q=verdict%3Ablock/);
  const first = page.locator('td[data-r="0"][data-c="0"]');
  await first.focus();
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('ArrowRight');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/q=verdict%3Ablock\+src%3A/);
  await page.goto('/monitor?static&q=verdict%3Ablock%20cause%3ADetection');
  await expect(page.getByRole('grid')).toBeVisible();
  await page.locator('td[data-r="1"][data-c="0"]').focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/requests\/R[0-9A-Z]+/);
  // Request details: focus on the h1, then Tab reaches the why sentence's setting link.
  await expect(page.getByRole('heading', { level: 1 })).toBeFocused();
  const why = page.getByRole('region', { name: 'Why this verdict' });
  await expect(why).toContainText('Blocked: score');
  await expect(why.getByRole('link', { name: 'scoring.block_at' }).first()).toHaveAttribute('href', '/settings?highlight=scoring.block_at');
  // Back returns to Monitor with the opened row focused (kept in history state).
  await page.goBack();
  await expect(page.locator('td[data-r="1"][data-c="0"]')).toBeFocused();
});

for (const scheme of ['light', 'dark'] as const) {
  test(`request details in ${scheme}: no serious axe violations, no CSP violations`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    const csp = await collectCsp(page);
    // A blocked request with corroborating evidence (the richest why panel).
    await page.goto('/monitor?static&q=verdict%3Ablock%20cause%3ADetection');
    await page.locator('td[data-c="0"] a').first().click();
    await expect(page.getByRole('region', { name: 'Contributions' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    const results = await new AxeBuilder({ page: page as unknown as AxePage }).analyze();
    const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    expect(bad.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
    expect(await csp()).toEqual([]);
  });
}

// The new ATT&CK/OCSF screens are held to every impact level, not only serious and critical.
async function expectNoAxe(page: Page) {
  const results = await new AxeBuilder({ page: page as unknown as AxePage }).analyze();
  expect(results.violations.map((v) => `${v.impact} ${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
}

// The emulated scheme took effect and no explicit theme override is set.
async function expectScheme(page: Page, scheme: 'light' | 'dark') {
  expect(await page.evaluate(() => matchMedia('(prefers-color-scheme: dark)').matches)).toBe(scheme === 'dark');
  await expect(page.locator('html')).not.toHaveAttribute('data-theme');
}

test('monitor: the Technique and Confidence columns are present, and a blocked row carries an ATT&CK chip', async ({ page }) => {
  await page.goto('/monitor?static&q=verdict%3Ablock%20cause%3ADetection');
  const grid = page.getByRole('grid');
  await expect(grid).toBeVisible();
  await expect(grid.getByRole('columnheader', { name: 'Technique' })).toBeVisible();
  await expect(grid.getByRole('columnheader', { name: 'Confidence' })).toBeVisible();
  await expect(grid.getByText(/^T\d{4}(\.\d{3})?$/).first()).toBeVisible();
});

test('request details: a blocked request shows ATT&CK chips, confidence, IDs, and the OCSF tab', async ({ page }) => {
  await page.goto('/monitor?static&q=verdict%3Ablock%20cause%3ADetection');
  await page.locator('td[data-c="0"] a').first().click();
  const why = page.getByRole('region', { name: 'Why this verdict' });
  await expect(why).toBeVisible();
  await expect(why.getByText(/^T\d{4}(\.\d{3})?$/).first()).toBeVisible();
  await expect(why.getByText(/^Precision on dev: (\d+|not measured)/)).toBeVisible();
  await expect(why.getByText(/^Share of this construct's blocks on the dev split/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copy event ID' })).toBeVisible();

  const tablist = page.getByRole('tablist', { name: 'Request view' });
  await expect(tablist.getByRole('tab', { name: 'Evidence' })).toHaveAttribute('aria-selected', 'true');
  await tablist.getByRole('tab', { name: 'View as OCSF' }).click();
  await expect(tablist.getByRole('tab', { name: 'View as OCSF' })).toHaveAttribute('aria-selected', 'true');
  const ocsf = page.getByRole('region', { name: 'OCSF records' });
  await expect(ocsf).toContainText('"class_uid": 4002');
  await expect(ocsf).toContainText('"class_uid": 2004');
  await expect(why).toHaveCount(0);

  // Arrow keys move between the tabs.
  await tablist.getByRole('tab', { name: 'View as OCSF' }).focus();
  await page.keyboard.press('ArrowLeft');
  await expect(tablist.getByRole('tab', { name: 'Evidence' })).toBeFocused();
  await expect(page.getByRole('region', { name: 'Why this verdict' })).toBeVisible();
});

for (const scheme of ['light', 'dark'] as const) {
  test(`monitor with the Technique and Confidence columns in ${scheme}: no axe violations`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto('/monitor?static');
    await expect(page.getByRole('grid').getByRole('columnheader', { name: 'Technique' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expectScheme(page, scheme);
    await expectNoAxe(page);
  });

  test(`monitor rows with technique chips in ${scheme}: no axe violations`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto('/monitor?static&q=verdict%3Ablock%20cause%3ADetection');
    await expect(page.getByRole('grid').getByText(/^T\d{4}(\.\d{3})?$/).first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expectScheme(page, scheme);
    await expectNoAxe(page);
  });

  test(`request details in ${scheme}: the Evidence tab and the OCSF tab have no axe violations`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto('/monitor?static&q=verdict%3Ablock%20cause%3ADetection');
    await page.locator('td[data-c="0"] a').first().click();
    await expect(page.getByRole('region', { name: 'Why this verdict' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expectScheme(page, scheme);
    await expectNoAxe(page);
    await page.getByRole('tab', { name: 'View as OCSF' }).click();
    await expect(page.getByRole('region', { name: 'OCSF records' })).toBeVisible();
    await expectNoAxe(page);
  });
}
