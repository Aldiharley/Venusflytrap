import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import { beforeAll, expect, test } from 'vitest';
import { SourceError } from '../../lib/api/errors';
import { FixtureSource, type Call } from '../../lib/api/source';
import type { Dashboard as DashboardData } from '../../lib/api/types';
import { app } from '../../lib/state/app.svelte';
import Dashboard from '../Dashboard.svelte';

beforeAll(async () => {
  await app.start(new FixtureSource({ live: false }));
});

test('a failed load shows an inline error card with the status and Retry; Retry recovers', async () => {
  let fail = true;
  await app.start(new FixtureSource({
    live: false,
    fault: (m) => (m === 'dashboard' && fail ? SourceError.fromStatus(503, 'history store unavailable') : null),
  }));
  render(Dashboard, { props: { title: 'Dashboard' } });
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('503');
  fail = false;
  await fireEvent.click(within(alert).getByRole('button', { name: 'Retry' }));
  expect(await screen.findByText('sqli.union-select')).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
  await app.start(new FixtureSource({ live: false }));
});

test('a superseded dashboard response never lands', async () => {
  const gates: ((d: DashboardData) => void)[] = [];
  class Gated extends FixtureSource {
    override dashboard(from: number, to: number, call: Call): Promise<DashboardData> {
      const real = super.dashboard(from, to, call);
      return new Promise((resolve) => gates.push((d) => resolve(d))).then(() => real);
    }
  }
  await app.start(new Gated({ live: false }));
  render(Dashboard, { props: { title: 'Dashboard' } });
  await tick();
  await fireEvent.click(screen.getByRole('button', { name: '6 h' }));
  await tick();
  expect(gates.length).toBe(2);
  gates[1]({} as DashboardData); // the 6 h answer lands first
  await waitFor(() => expect(screen.getByText('sqli.union-select')).toBeTruthy());
  const sixHour = screen.getByRole('region', { name: 'Top constructs' }).textContent;
  gates[0]({} as DashboardData); // then the stale 1 h answer arrives and must be dropped
  await tick();
  await tick();
  expect(screen.getByRole('region', { name: 'Top constructs' }).textContent).toBe(sixHour);
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
