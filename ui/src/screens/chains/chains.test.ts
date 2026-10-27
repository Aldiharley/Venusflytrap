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
