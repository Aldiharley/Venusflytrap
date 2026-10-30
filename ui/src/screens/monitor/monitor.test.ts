import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import { afterEach, beforeAll, expect, test, vi } from 'vitest';
import { FixtureSource } from '../../lib/api/source';
import { app } from '../../lib/state/app.svelte';
import { router } from '../../lib/state/router.svelte';
import Monitor from '../Monitor.svelte';

// Each test renders a 100-row, 15-column grid in jsdom; give slow machines room.
vi.setConfig({ testTimeout: 20_000 });

beforeAll(async () => {
  await app.start(new FixtureSource({ live: false }));
});
afterEach(() => vi.useRealTimers());

const q = () => router.search.get('q') ?? '';
async function mount(url: string) {
  router.navigate(url);
  const r = render(Monitor, { props: { title: 'Monitor' } });
  const grid = await screen.findByRole('grid');
  return { ...r, grid };
}
const cell = (grid: HTMLElement, r: number, c: number) => grid.querySelector<HTMLElement>(`td[data-r="${r}"][data-c="${c}"]`)!;

test('a query filters the results and the grid has one tab stop', async () => {
  const { grid } = await mount('/monitor?q=verdict%3Ablock');
  const rows = grid.querySelectorAll('tbody tr');
  expect(rows.length).toBeGreaterThan(0);
  for (const tr of rows) {
    expect(tr.textContent).toContain('Block');
    expect(tr.classList.contains('blocked')).toBe(true);
  }
  expect(grid.querySelectorAll('[tabindex="0"]')).toHaveLength(1);
  expect(screen.getByText(/\d+ results?/)).toBeTruthy();
});

test('arrows move between cells; Enter adds field:value, Shift+Enter excludes it', async () => {
  const { grid } = await mount('/monitor?q=verdict%3Ablock');
  const key = cell(grid, 0, 3).querySelector('.mono')!.textContent!;
  cell(grid, 0, 0).focus();
  await fireEvent.keyDown(grid, { key: 'ArrowRight' });
  await fireEvent.keyDown(grid, { key: 'ArrowRight' });
  await fireEvent.keyDown(grid, { key: 'ArrowRight' });
  expect(document.activeElement).toBe(cell(grid, 0, 3));
  await fireEvent.keyDown(grid, { key: 'Enter' });
  expect(q()).toBe(`verdict:block src:${key}`);
  const g2 = await screen.findByRole('grid');
  await waitFor(() => expect(cell(g2, 0, 7)).toBeTruthy());
  const construct = cell(g2, 0, 7).textContent!.trim();
  cell(g2, 0, 7).focus();
  await fireEvent.keyDown(g2, { key: 'Enter', shiftKey: true });
  expect(q()).toBe(`verdict:block src:${key} -construct:${construct}`);
});

test('clicking a value filters by it; clicking the time opens the request and remembers the row', async () => {
  const { grid } = await mount('/monitor');
  await fireEvent.click(cell(grid, 0, 4).querySelector('.mono')!); // method
  expect(q()).toMatch(/^method:(GET|POST)$/);
  const g2 = await screen.findByRole('grid');
  await waitFor(() => expect(g2.querySelector('td[data-c="0"] a')).toBeTruthy());
  const link = cell(g2, 0, 0).querySelector('a')!;
  const id = decodeURIComponent(link.getAttribute('href')!.split('/').pop()!);
  await fireEvent.click(link);
  expect(router.route).toEqual({ name: 'request', param: id });
  history.back();
  await waitFor(() => expect(router.route.name).toBe('monitor'));
  expect((history.state as { monitorFocus?: { id: string } }).monitorFocus?.id).toBe(id);
});

test('Back to Monitor refocuses the row that was opened', async () => {
  router.navigate('/monitor?q=verdict%3Ablock');
  const { unmount } = render(Monitor, { props: { title: 'Monitor' } });
  const grid = await screen.findByRole('grid');
  const target = cell(grid, 2, 0);
  const id = decodeURIComponent(target.querySelector('a')!.getAttribute('href')!.split('/').pop()!);
  target.focus();
  await fireEvent.keyDown(grid, { key: 'Enter' });
  expect(router.route.name).toBe('request');
  unmount();
  history.back();
  await waitFor(() => expect(router.route.name).toBe('monitor'));
  render(Monitor, { props: { title: 'Monitor' } });
  const again = await screen.findByRole('grid');
  await waitFor(() => expect(document.activeElement).toBe(cell(again, 2, 0)));
  expect(cell(again, 2, 0).querySelector('a')!.getAttribute('href')).toBe(`/requests/${encodeURIComponent(id)}`);
});

test('group-by shows counts; a group drills into an ungrouped query', async () => {
  await mount('/monitor');
  await fireEvent.click(within(screen.getByRole('group', { name: 'Group by' })).getByRole('button', { name: 'verdict' }));
  expect(router.search.get('group_by')).toBe('verdict');
  const grid = await screen.findByRole('grid', { name: 'Requests grouped by verdict' });
  expect(within(grid).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Verdict', 'Requests']);
  const value = cell(grid, 0, 0).textContent!.trim();
  cell(grid, 0, 0).focus();
  await fireEvent.keyDown(grid, { key: 'Enter' });
  expect(q()).toBe(`verdict:${value.toLowerCase()}`);
  expect(router.search.get('group_by')).toBeNull();
});

test('a syntax error shows inline under the query bar', async () => {
  await mount('/monitor');
  const input = screen.getByRole('combobox', { name: 'Query' });
  await fireEvent.input(input, { target: { value: 'verdict:block colour:red' } });
  await fireEvent.keyDown(input, { key: 'Enter' });
  await waitFor(() => expect(input.getAttribute('aria-invalid')).toBe('true'));
  const msg = document.getElementById(input.getAttribute('aria-describedby')!)!;
  expect(msg.textContent?.replace(/\s+/g, ' ').trim()).toBe('Unknown field "colour". (at character 15)');
});

test('suggestions list counted values; Enter accepts one', async () => {
  await mount('/monitor');
  const input = screen.getByRole<HTMLInputElement>('combobox', { name: 'Query' });
  input.focus();
  await fireEvent.input(input, { target: { value: 'construct:sqli' } });
  input.setSelectionRange(14, 14);
  await fireEvent.keyDown(input, { key: 'ArrowDown' });
  const list = await screen.findByRole('listbox', { name: 'Query suggestions' });
  await waitFor(() => expect(within(list).getAllByRole('option').length).toBeGreaterThan(0));
  const first = within(list).getAllByRole('option')[0];
  expect(first.textContent).toMatch(/^sqli\.[a-z-]+\s*\d+$/);
  expect(input.getAttribute('aria-expanded')).toBe('true');
  expect(input.getAttribute('aria-activedescendant')).toBe(first.id);
  await fireEvent.keyDown(input, { key: 'Enter' });
  expect(input.value).toMatch(/^construct:sqli\.[a-z-]+ $/);
  expect(input.getAttribute('aria-expanded')).toBe('false');
});

test('field names are suggested before the colon', async () => {
  await mount('/monitor');
  const input = screen.getByRole<HTMLInputElement>('combobox', { name: 'Query' });
  input.focus();
  await fireEvent.input(input, { target: { value: 'ver' } });
  input.setSelectionRange(3, 3);
  await fireEvent.keyDown(input, { key: 'ArrowDown' });
  const list = await screen.findByRole('listbox', { name: 'Query suggestions' });
  expect(within(list).getByRole('option', { selected: true }).textContent).toContain('verdict:');
});

test('Load more appends the next page', async () => {
  const { grid } = await mount('/monitor');
  expect(grid.querySelectorAll('tbody tr')).toHaveLength(100);
  await fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
  await waitFor(() => expect(grid.querySelectorAll('tbody tr').length).toBeGreaterThan(100));
});

test('an empty result says why and offers to widen the range', async () => {
  router.navigate('/monitor?q=src%3A10.0.0.1');
  render(Monitor, { props: { title: 'Monitor' } });
  expect(await screen.findByText('No requests match “src:10.0.0.1” in this range.')).toBeTruthy();
  await fireEvent.click(screen.getByRole('button', { name: 'Widen range' }));
  expect(router.search.get('range')).toBe('24h');
});

test('auto-refresh pauses while focus is in the grid and offers the new results instead', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] });
  const { grid } = await mount('/monitor?refresh=10s');
  const firstId = cell(grid, 0, 0).querySelector('a')!.getAttribute('href');
  cell(grid, 0, 0).focus();
  await tick();
  vi.advanceTimersByTime(30_000);
  const status = await screen.findByText(/new results? —/);
  expect(status.closest('[role="status"]')).toBeTruthy();
  expect(cell(grid, 0, 0).querySelector('a')!.getAttribute('href')).toBe(firstId); // rows did not move
  await fireEvent.click(screen.getByRole('button', { name: 'Show' }));
  await waitFor(() => expect(cell(screen.getByRole('grid'), 0, 0).querySelector('a')!.getAttribute('href')).not.toBe(firstId));
});

test('the grid has Technique and Confidence columns right after Construct', async () => {
  const { grid } = await mount('/monitor?q=construct%3Acmd.chained-command');
  const heads = within(grid).getAllByRole('columnheader');
  expect(heads.slice(7, 10).map((h) => h.textContent)).toEqual(['Construct', 'Technique', 'Conf.Confidence']);
  // The Confidence header shows "Conf."; its accessible name and tooltip keep the full word.
  const conf = within(grid).getByRole('columnheader', { name: 'Confidence' });
  expect(conf).toBe(heads[9]);
  expect(conf.getAttribute('title')).toBe('Precision on dev of the deciding construct');
  expect(conf.querySelector('[aria-hidden="true"]')!.textContent).toBe('Conf.');
  const row = grid.querySelector('tbody tr')!;
  const tech = row.querySelector('td[data-c="8"]')!;
  // Only the primary technique (row.technique); the construct's other tag (T1059) is in Request details.
  expect(tech.querySelectorAll('.chip').length).toBe(1);
  expect(tech.textContent).toContain('T1190');
  expect(tech.textContent).not.toContain('T1059');
  expect(tech.querySelector('[title="Initial Access · Exploit Public-Facing Application"]')).toBeTruthy();
  expect(tech.querySelector('.sr-only')!.textContent).toBe('Initial Access · Exploit Public-Facing Application');
  expect(row.querySelector('td[data-c="9"]')!.textContent!.trim()).toBe('70');
});

test('a row with no technique or confidence shows a dash', async () => {
  const { grid } = await mount('/monitor?q=cause%3ABan');
  const row = grid.querySelector('tbody tr')!;
  expect(row.querySelector('td[data-c="8"]')!.textContent!.trim()).toBe('—no technique');
  expect(row.querySelector('td[data-c="9"]')!.textContent!.trim()).toBe('—not measured');
});

test('ArrowRight walks Construct, Technique, Confidence, Stage in order', async () => {
  const { grid } = await mount('/monitor?q=verdict%3Ablock');
  cell(grid, 0, 7).focus();
  for (const c of [8, 9, 10]) {
    await fireEvent.keyDown(grid, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(cell(grid, 0, c));
  }
  expect(grid.querySelector('th.c-stage')!.textContent).toBe('Stage');
});

test('the Time link carries the full stamp as its title', async () => {
  const { grid } = await mount('/monitor');
  expect(cell(grid, 0, 0).querySelector('a')!.getAttribute('title')).toMatch(/^\d{1,2} [A-Z][a-z]{2} \d{2}:\d{2}:\d{2}$/);
});
