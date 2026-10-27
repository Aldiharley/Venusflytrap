import { render, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import { expect, test } from 'vitest';
import { makeFixtures } from '../../lib/api/fixtures';
import { buildModel, clusterRates } from './model';
import Scene from './Scene.svelte';
import TableView from './TableView.svelte';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);

function model() {
  const f = makeFixtures(NOW);
  const later = f.board.map((s) => (s.stage === 'Exploitation' ? { ...s, requests: s.requests + 10, blocked: s.blocked + 8 } : s));
  return {
    f,
    m: buildModel({ counters: f.counters, board: later, rates: clusterRates(f.board, later, 1000), dashboard: f.dashboard(NOW - 3_600_000, NOW), status: f.status, now: NOW }),
  };
}

test('the table view carries every number the map shows', () => {
  const { f, m } = model();
  const map = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: false, now: NOW } });
  const mapText = map.container.textContent ?? '';
  const names = [...map.container.querySelectorAll('button.node')].map((b) => b.getAttribute('aria-label') ?? '');
  const table = render(TableView, { props: { nodes: m.nodes, flows: m.flows } });
  const tableText = table.container.textContent ?? '';
  for (const n of m.nodes) {
    expect(names.some((x) => x.includes(n.countText))).toBe(true);
    expect(tableText).toContain(n.countText);
    expect(tableText).toContain(n.rateText);
  }
  for (const f of m.flows.filter((x) => x.step > 0)) {
    expect(mapText).toContain(f.rateText);
    expect(tableText).toContain(f.rateText);
  }
});

test('nodes form one roving tab stop and arrows move along the order', async () => {
  const { f, m } = model();
  const { container } = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: false, now: NOW } });
  const buttons = [...container.querySelectorAll<HTMLButtonElement>('button.node')];
  expect(buttons.filter((b) => b.tabIndex === 0)).toHaveLength(1);
  buttons[0].focus();
  buttons[0].dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
  await tick();
  expect(document.activeElement).toBe(buttons[1]);
  expect(within(container).getByRole('group', { name: /Recon cluster details/ })).toBeTruthy();
});

test('stale scenes stop packets and say so', () => {
  const { f, m } = model();
  const { container } = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: true, now: NOW } });
  expect(container.textContent).toContain('Live paused');
  expect(container.querySelector('.scene.stale')).toBeTruthy();
});
