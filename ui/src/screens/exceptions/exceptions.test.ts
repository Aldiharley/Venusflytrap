import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { afterEach, beforeAll, beforeEach, expect, test, vi } from 'vitest';
import { SourceError } from '../../lib/api/errors';
import { FixtureSource } from '../../lib/api/source';
import type { ExceptionEntry } from '../../lib/api/types';
import { toasts } from '../../lib/components/toasts.svelte';
import { liveAt, scopeLabel, toYaml } from '../../lib/exceptions';
import { app } from '../../lib/state/app.svelte';
import { router } from '../../lib/state/router.svelte';
import Exceptions from '../Exceptions.svelte';

const call = () => ({ signal: new AbortController().signal });
let entries: ExceptionEntry[] = [];

beforeAll(async () => {
  const src = new FixtureSource({ live: false });
  await app.start(src);
  entries = await src.exceptions(call());
});
beforeEach(() => router.navigate('/exceptions', true));
afterEach(() => vi.restoreAllMocks());

const byId = (id: string) => entries.find((e) => e.id === id)!;
async function mount(url = '/exceptions') {
  router.navigate(url, true);
  render(Exceptions, { props: { title: 'Exceptions' } });
  return screen.findByRole('tablist', { name: 'Exceptions status' });
}
const rowIds = () => within(screen.getByRole('table')).getAllByRole('row').slice(1).map((r) => r.querySelector('.id')!.textContent);
const rowOf = (id: string) => within(screen.getByRole('table')).getByRole('button', { name: id }).closest('tr')!;
const panelOf = (id: string) => screen.findByRole('region', { name: `Exception ${id}` });

test('the heading, the restart note, and Active / Expired tabs with counts; Active is selected first', async () => {
  const tabs = await mount();
  expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Exceptions');
  expect(screen.getByText('Exceptions are read from the file passed with --exceptions. Changes take effect after a restart.')).toBeTruthy();
  const [active, expired] = within(tabs).getAllByRole('tab');
  const live = entries.filter((e) => liveAt(e, Date.now())).length;
  expect(live).toBe(3);
  expect(active.textContent).toMatch(new RegExp(`^Active\\s*${live}$`));
  expect(expired.textContent).toMatch(new RegExp(`^Expired\\s*${entries.length - live}$`));
  expect(active.getAttribute('aria-selected')).toBe('true');
  expect(active.tabIndex).toBe(0);
  expect(expired.tabIndex).toBe(-1);
  expect(screen.getByRole('tabpanel', { name: /^Active/ })).toBeTruthy();
});

test('the tabs filter by liveAt: Active lists the live entries soonest-expiring first, Expired the rest', async () => {
  const tabs = await mount();
  expect(rowIds()).toEqual(['referer-sql', 'utm-xss', 'hook-signature']);
  await fireEvent.click(within(tabs).getByRole('tab', { name: /^Expired/ }));
  expect(rowIds()).toEqual(['legacy-search']);
  expect(screen.getByRole('tabpanel', { name: /^Expired/ })).toBeTruthy();
});

test('the table has the seven columns, scope label, constructs as written, and the relative expiry with the date in its title', async () => {
  await mount();
  const table = screen.getByRole('table');
  expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(
    ['ID', 'Action', 'Scope', 'Constructs', 'Owner', 'Reason', 'Expires']);
  const e = byId('referer-sql');
  const cells = within(rowOf(e.id)).getAllByRole('cell');
  expect(cells[0].textContent).toBe(e.id);
  expect(cells[0].querySelector('.mono')).toBeTruthy();
  expect(cells[1].textContent).toContain('ignore');
  expect(cells[2].textContent).toBe(scopeLabel(e));
  expect(cells[3].textContent).toBe('sqli.*');
  expect(cells[4].textContent).toBe(e.owner);
  expect(cells[5].textContent).toBe(e.reason);
  expect(cells[6].textContent).toBe('in 21 days');
  expect(cells[6].querySelector('[title]')!.getAttribute('title')).toBe(e.expires);
  expect(within(rowOf('utm-xss')).getAllByRole('cell')[3].textContent).toBe('xss.*');
});

test('an expired entry reads "expired 3 days ago" with its date in the title', async () => {
  const tabs = await mount();
  await fireEvent.click(within(tabs).getByRole('tab', { name: /^Expired/ }));
  const cell = within(rowOf('legacy-search')).getAllByRole('cell')[6];
  expect(cell.textContent).toBe('expired 3 days ago');
  expect(cell.querySelector('[title]')!.getAttribute('title')).toBe(byId('legacy-search').expires);
});

test('only skip-inspection rows carry the "Skips inspection" warning badge', async () => {
  await mount();
  expect(within(rowOf('hook-signature')).getByText('Skips inspection')).toBeTruthy();
  expect(within(rowOf('referer-sql')).queryByText('Skips inspection')).toBeNull();
  expect(within(rowOf('utm-xss')).queryByText('Skips inspection')).toBeNull();
  expect(screen.getAllByText('Skips inspection')).toHaveLength(1);
});

test('the tabs follow the arrow, Home and End keys', async () => {
  const tabs = await mount();
  const [active, expired] = within(tabs).getAllByRole('tab');
  active.focus();
  await fireEvent.keyDown(active, { key: 'ArrowRight' });
  expect(document.activeElement).toBe(expired);
  expect(expired.getAttribute('aria-selected')).toBe('true');
  expect(expired.tabIndex).toBe(0);
  expect(active.tabIndex).toBe(-1);
  expect(rowIds()).toEqual(['legacy-search']);
  await fireEvent.keyDown(expired, { key: 'ArrowRight' });
  expect(document.activeElement).toBe(active);
  await fireEvent.keyDown(active, { key: 'End' });
  expect(document.activeElement).toBe(expired);
  await fireEvent.keyDown(expired, { key: 'Home' });
  expect(document.activeElement).toBe(active);
  expect(rowIds()).toEqual(['referer-sql', 'utm-xss', 'hook-signature']);
});

test('Enter on a row opens its details panel with every field; Close hides it and returns focus to the row', async () => {
  await mount();
  expect(screen.queryByRole('region', { name: /^Exception / })).toBeNull();
  const e = byId('referer-sql');
  const btn = within(rowOf(e.id)).getByRole('button', { name: e.id });
  expect(btn.getAttribute('aria-expanded')).toBe('false');
  btn.focus();
  await fireEvent.keyDown(btn, { key: 'Enter' });
  const panel = await panelOf(e.id);
  expect(btn.getAttribute('aria-expanded')).toBe('true');
  const terms = Object.fromEntries(within(panel).getAllByRole('term').map((t) => [t.textContent, t.nextElementSibling?.textContent?.replace(/\s+/g, ' ').trim()]));
  expect(terms).toEqual({
    ID: e.id, Action: 'ignore', Constructs: 'sqli.*', Methods: 'GET', 'Path prefix': '/api/search', Field: 'header referer',
    Owner: e.owner, Reason: e.reason, Created: e.created, Modified: e.modified, Expires: `${e.expires} (in 21 days)`,
  });
  expect(router.search.get('id')).toBe(e.id);
  await fireEvent.click(within(panel).getByRole('button', { name: 'Close' }));
  expect(screen.queryByRole('region', { name: /^Exception / })).toBeNull();
  expect(router.search.get('id')).toBeNull();
  expect(document.activeElement).toBe(btn);
});

test('clicking a row opens its panel too; a skip-inspection entry carries the badge, an unscoped method list reads "Any method"', async () => {
  await mount();
  await fireEvent.click(rowOf('hook-signature'));
  const panel = await panelOf('hook-signature');
  expect(within(panel).getByText('Skips inspection')).toBeTruthy();
  expect(panel.textContent).toContain('POST');
  await fireEvent.click(rowOf('utm-xss'));
  const next = await panelOf('utm-xss');
  expect(next.textContent).toContain('Any method');
  expect(screen.getAllByRole('region', { name: /^Exception / })).toHaveLength(1);
});

test('?id= switches to the tab holding the entry and opens its panel', async () => {
  await mount('/exceptions?id=legacy-search');
  await panelOf('legacy-search');
  expect(screen.getByRole('tab', { name: /^Expired/ }).getAttribute('aria-selected')).toBe('true');
  expect(rowIds()).toEqual(['legacy-search']);
  expect(rowOf('legacy-search').querySelector('button')!.getAttribute('aria-expanded')).toBe('true');
});

test('an unknown ?id= opens nothing; switching to a tab without the open entry closes its panel', async () => {
  const tabs = await mount('/exceptions?id=nope');
  expect(screen.queryByRole('region', { name: /^Exception / })).toBeNull();
  await fireEvent.click(rowOf('utm-xss'));
  await panelOf('utm-xss');
  await fireEvent.click(within(tabs).getByRole('tab', { name: /^Expired/ }));
  expect(screen.queryByRole('region', { name: /^Exception / })).toBeNull();
  expect(router.search.get('id')).toBeNull();
});

test('Copy YAML writes toYaml(entry) to the clipboard and announces it', async () => {
  const write = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: write }, configurable: true });
  await mount('/exceptions?id=utm-xss');
  const panel = await panelOf('utm-xss');
  await fireEvent.click(within(panel).getByRole('button', { name: 'Copy YAML' }));
  expect(write.mock.calls).toEqual([[toYaml(byId('utm-xss'))]]);
  await waitFor(() => expect(toasts.items.map((t) => t.text)).toContain('Copied YAML.'));
});

test('a failed copy says so', async () => {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) }, configurable: true });
  await mount('/exceptions?id=utm-xss');
  const panel = await panelOf('utm-xss');
  await fireEvent.click(within(panel).getByRole('button', { name: 'Copy YAML' }));
  await waitFor(() => expect(toasts.items.map((t) => t.text)).toContain('Could not copy the YAML.'));
});

test('a load error shows the error card with Retry, which reloads the table', async () => {
  vi.spyOn(app.src!, 'exceptions').mockRejectedValueOnce(SourceError.fromStatus(500, 'boom'));
  render(Exceptions, { props: { title: 'Exceptions' } });
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('HTTP 500');
  expect(screen.queryByRole('table')).toBeNull();
  await fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
  await screen.findByRole('table');
  expect(screen.queryByRole('alert')).toBeNull();
  expect(rowIds()).toHaveLength(3);
});

test('an empty tab says so with an empty state', async () => {
  vi.spyOn(app.src!, 'exceptions').mockResolvedValue([]);
  const tabs = await mount();
  expect(await screen.findByText('No active exceptions')).toBeTruthy();
  expect(screen.queryByRole('table')).toBeNull();
  expect(within(tabs).getAllByRole('tab').map((t) => t.textContent!.replace(/\s+/g, ' ').trim())).toEqual(['Active 0', 'Expired 0']);
  await fireEvent.click(within(tabs).getByRole('tab', { name: /^Expired/ }));
  expect(screen.getByText('No expired exceptions')).toBeTruthy();
});
