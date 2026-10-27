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
