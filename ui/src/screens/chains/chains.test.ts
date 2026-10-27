import { fireEvent, render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import { beforeAll, expect, test } from 'vitest';
import type { SourceView } from '../../lib/api/types';
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

const keyOf = (el: Element | null) => el?.closest('tr')?.querySelector('td[data-c="0"] .mono')?.textContent;

test('Apply re-sorts and returns focus to the same source, even after focus moves onto the bar', async () => {
  router.navigate('/chains');
  const original = app.board;
  render(Chains, { props: { title: 'Attack chains' } });
  const grid = screen.getByRole('grid');
  const first = grid.querySelector<HTMLElement>('[tabindex="0"]')!;
  const focusedKey = keyOf(first);
  first.focus();
  // Bump the last-listed source to the top while the grid is frozen.
  const last = grid.querySelectorAll('tbody tr')[grid.querySelectorAll('tbody tr').length - 1];
  const bumpKey = keyOf(last.querySelector('td'))!;
  app.board = original.map((s: SourceView) =>
    s.key === bumpKey ? { ...s, stage: 'Exfiltration' as const, last_seen_ms: Date.now() + 3_600_000 } : s);
  await tick();
  expect(keyOf(grid.querySelector('td[data-r="0"]'))).toBe(focusedKey); // order held
  const apply = await screen.findByRole('button', { name: /Apply/ });
  apply.focus(); // focus leaves the table for the bar: the order must stay frozen
  await tick();
  expect(screen.queryByRole('button', { name: /Apply/ })).not.toBeNull();
  await fireEvent.click(apply);
  await tick();
  await tick();
  expect(keyOf(grid.querySelector('td[data-r="0"]'))).toBe(bumpKey);
  expect(keyOf(document.activeElement)).toBe(focusedKey);
  expect(document.activeElement?.getAttribute('data-r')).not.toBe('0');
  app.board = original;
});

test('exactly one tab stop survives the row count shrinking', async () => {
  router.navigate('/chains');
  render(Chains, { props: { title: 'Attack chains' } });
  const grid = screen.getByRole('grid');
  grid.querySelector<HTMLElement>('[tabindex="0"]')!.focus();
  await fireEvent.keyDown(grid, { key: 'PageDown' });
  expect(Number(document.activeElement?.getAttribute('data-r'))).toBeGreaterThanOrEqual(5);
  (document.activeElement as HTMLElement).blur();
  await tick();
  await fireEvent.input(screen.getByPlaceholderText('Key or IP'), { target: { value: '198.51.100.23' } });
  await tick();
  expect(screen.getByRole('grid').querySelectorAll('tbody tr')).toHaveLength(1);
  expect(screen.getByRole('grid').querySelectorAll('[tabindex="0"]')).toHaveLength(1);
});

test('current stage is announced in the cell name', async () => {
  router.navigate('/chains');
  render(Chains, { props: { title: 'Attack chains' } });
  const grid = screen.getByRole('grid');
  expect(grid.querySelectorAll('td[aria-label$=", current stage"]').length).toBeGreaterThan(0);
  expect(grid.querySelector('td[aria-label^="Recon: reached"]')).not.toBeNull();
});
