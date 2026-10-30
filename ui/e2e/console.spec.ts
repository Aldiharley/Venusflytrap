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

// --- exceptions (sub-project C) ---

// A Monitor row an exception touched, found by its marker rather than by a hard-coded id.
const TOUCHED_QUERY = '/monitor?static&q=path%3A%2Fapi%2Fsearch';
const touchedRow = (page: Page) => page.locator('tbody tr').filter({ has: page.getByLabel('Exception applied') }).first();

// A touched detection (not an Allow, whose ignored evidence leaves no construct to pre-fill): which touched
// rows the fixture window holds depends on the wall clock.
const touchedDetection = (page: Page) => page.locator('tbody tr').filter({ has: page.getByLabel('Exception applied') })
  .filter({ hasNot: page.locator('td.c-verdict', { hasText: 'Allow' }) }).first();

async function openTouched(page: Page) {
  await page.goto(TOUCHED_QUERY);
  await expect(page.getByRole('grid')).toBeVisible();
  await touchedDetection(page).locator('td[data-c="0"] a').click();
  await expect(page.getByRole('region', { name: 'Exceptions' })).toBeVisible();
  await page.waitForLoadState('networkidle');
}

test('exceptions: the tabs switch, a row opens its details and Copy YAML copies the entry', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/exceptions?static');
  await expect(page.getByRole('heading', { level: 1, name: 'Exceptions' })).toBeVisible();
  const active = page.getByRole('tab', { name: /^Active/ });
  const expired = page.getByRole('tab', { name: /^Expired/ });
  await expect(active).toHaveAttribute('aria-selected', 'true');
  await expect(active).toContainText('3');
  await expect(expired).toContainText('1');
  const panel = page.getByRole('tabpanel');
  await expect(panel.getByRole('button', { name: 'referer-sql' })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'legacy-search' })).toHaveCount(0);

  await expired.click();
  await expect(expired).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tabpanel').getByRole('button', { name: 'legacy-search' })).toBeVisible();
  await active.click();

  const row = page.getByRole('button', { name: 'hook-signature' });
  await expect(row).toHaveAttribute('aria-expanded', 'false');
  await expect(page.getByText('Skips inspection').first()).toBeVisible();
  await row.click();
  await expect(row).toHaveAttribute('aria-expanded', 'true');
  const detail = page.getByRole('region', { name: /^Exception hook-signature/ });
  await expect(detail).toBeVisible();
  await detail.getByRole('button', { name: 'Copy YAML' }).click();
  await expect(page.getByText('Copied YAML.')).toBeVisible();
  const yaml = await page.evaluate(() => navigator.clipboard.readText());
  expect(yaml).toContain('id: hook-signature');
  expect(yaml).toContain('action: skip-inspection');
});

test('exceptions: ?id opens that row', async ({ page }) => {
  await page.goto('/exceptions?static&id=hook-signature');
  await expect(page.getByRole('button', { name: 'hook-signature' })).toHaveAttribute('aria-expanded', 'true');
  await expect(page.getByRole('region', { name: /^Exception hook-signature/ })).toBeVisible();
});

test('monitor: a row an exception touched carries the marker after its verdict chip', async ({ page }) => {
  await page.goto(TOUCHED_QUERY);
  await expect(page.getByRole('grid')).toBeVisible();
  const marker = page.getByLabel('Exception applied');
  await expect(marker.first()).toBeVisible();
  expect(await marker.count()).toBeLessThan(await page.locator('tbody tr').count());
  await expect(touchedRow(page).locator('td.c-verdict .chip + [aria-label="Exception applied"]')).toHaveCount(1);
});

test('request details: a touched request lists its exceptions and the Create exception form yields YAML', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await openTouched(page);
  const section = page.getByRole('region', { name: 'Exceptions' });
  const link = section.getByRole('link').first();
  await expect(link).toHaveAttribute('href', /^\/exceptions\?id=/);

  await page.getByRole('button', { name: 'Create exception' }).click();
  const form = page.getByRole('region', { name: 'Create exception' });
  await expect(form).toBeVisible();
  await expect(form.locator('pre')).toHaveCount(0);
  await expect(form.getByRole('button', { name: 'Copy YAML' })).toHaveCount(0);
  await form.getByLabel('Owner').fill('platform-team');
  await form.getByLabel('Reason').fill('UTM tags carry markup from the campaign tool');
  await expect(form.locator('pre')).toContainText('owner: "platform-team"');
  await expect(form.locator('pre')).toContainText('reason: "UTM tags carry markup from the campaign tool"');
  await expect(form).toContainText('Paste this under exceptions: in your exceptions file. It takes effect after a restart with --exceptions.');
  await form.getByRole('button', { name: 'Copy YAML' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('owner: "platform-team"');

  // Following an exception link lands on that row, open.
  const id = await link.textContent();
  await link.click();
  await expect(page).toHaveURL(/\/exceptions\?.*id=/);
  await expect(page.getByRole('button', { name: id!.trim() })).toHaveAttribute('aria-expanded', 'true');
});

for (const scheme of ['light', 'dark'] as const) {
  test(`exceptions screen in ${scheme}: no axe violations, list and open row`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto('/exceptions?static');
    await expect(page.getByRole('table')).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expectScheme(page, scheme);
    await expectNoAxe(page);
    await page.getByRole('button', { name: 'hook-signature' }).click();
    await expect(page.getByRole('region', { name: /^Exception hook-signature/ })).toBeVisible();
    await expectNoAxe(page);
    await page.getByRole('tab', { name: /^Expired/ }).click();
    await expect(page.getByRole('button', { name: 'legacy-search' })).toBeVisible();
    await expectNoAxe(page);
  });

  test(`touched request details in ${scheme}: no axe violations, with the create form closed, empty and filled`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await openTouched(page);
    await expectScheme(page, scheme);
    await expectNoAxe(page);
    await page.getByRole('button', { name: 'Create exception' }).click();
    const form = page.getByRole('region', { name: 'Create exception' });
    await expect(form).toBeVisible();
    await expectNoAxe(page); // with the required-field issues showing
    await form.getByLabel('Owner').fill('platform-team');
    await form.getByLabel('Reason').fill('UTM tags carry markup from the campaign tool');
    await expect(form.locator('pre')).toBeVisible();
    await expectNoAxe(page);
  });

  test(`monitor with an exception marker in ${scheme}: no axe violations`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(TOUCHED_QUERY);
    await expect(page.getByLabel('Exception applied').first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    await expectScheme(page, scheme);
    await expectNoAxe(page);
  });
}
