import { render, within } from '@testing-library/svelte';
import { tick } from 'svelte';
import { expect, test } from 'vitest';
import { SourceError } from '../../lib/api/errors';
import { makeFixtures } from '../../lib/api/fixtures';
import { FixtureSource } from '../../lib/api/source';
import { app } from '../../lib/state/app.svelte';
import { motion } from '../../lib/state/theme.svelte';
import Topology from '../Topology.svelte';
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

function scene() {
  const { f, m } = model();
  const r = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: false, now: NOW } });
  const buttons = [...r.container.querySelectorAll<HTMLButtonElement>('button.node')];
  return { ...r, buttons };
}

const key = (el: Element, k: string) => el.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true }));

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

test('derived rates say "approx." on the map and in the table; counter rates do not', () => {
  const { f, m } = model();
  const map = render(Scene, { props: { nodes: m.nodes, flows: m.flows, board: f.board, rps: f.counters.rps_by_verdict, stale: false, now: NOW } });
  const chips = [...map.container.querySelectorAll('.rate')].map((c) => c.textContent ?? '');
  const approx = m.flows.filter((x) => x.step > 0 && x.approx);
  const exact = m.flows.filter((x) => x.step > 0 && !x.approx);
  expect(approx.length).toBeGreaterThan(0);
  expect(exact.length).toBeGreaterThan(0);
  for (const x of approx) expect(chips).toContain(`${x.rateText} approx.`);
  for (const x of exact) expect(chips).toContain(x.rateText);
  const table = render(TableView, { props: { nodes: m.nodes, flows: m.flows } });
  const rows = [...table.container.querySelectorAll('tbody tr')].map((r) => r.textContent ?? '');
  for (const x of m.flows) {
    const row = rows.find((r) => r.startsWith(`${x.from}${x.to}`) && r.includes(x.verdict) && r.includes(x.rateText));
    expect(row, `${x.id} row`).toBeTruthy();
    expect(row!.includes('(approx.)')).toBe(x.approx);
  }
  // The shield stub's Challenge line is a counter; only its Block remainder is derived.
  const stub = m.flows.filter((x) => x.to === 'Stopped at shield');
  expect(stub.find((x) => x.verdict === 'Challenge')?.approx).toBe(false);
  expect(stub.find((x) => x.verdict === 'Block')?.approx).toBe(true);
});

test('flows carry stable node ids, including the last pod whose label has a suffix', () => {
  const { m } = model();
  expect(m.flows.some((x) => x.toId === 'hp3')).toBe(true);
  expect(m.flows.some((x) => x.fromId === 'tower' && x.toId === 'quarantine')).toBe(true);
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

test('Enter moves focus into the card and Escape closes it, returning focus to that node', async () => {
  const { container, buttons } = scene();
  buttons[3].focus();
  await tick();
  key(buttons[3], 'Enter');
  await tick();
  await tick();
  const card = container.querySelector('#node-card')!;
  expect(card).toBeTruthy();
  expect(card.contains(document.activeElement)).toBe(true);
  key(document.activeElement!, 'Escape');
  await tick();
  expect(container.querySelector('#node-card')).toBeNull();
  expect(document.activeElement).toBe(buttons[3]);
});

test('Escape on the node itself still closes its card', async () => {
  const { container, buttons } = scene();
  buttons[1].focus();
  await tick();
  expect(container.querySelector('#node-card')).toBeTruthy();
  key(buttons[1], 'Escape');
  await tick();
  expect(container.querySelector('#node-card')).toBeNull();
  expect(document.activeElement).toBe(buttons[1]);
});

test('an unpinned card closes when focus leaves the scene, even from inside the card', async () => {
  const { container, buttons } = scene();
  const outside = document.createElement('button');
  document.body.append(outside);
  buttons[3].focus();
  await tick();
  const link = container.querySelector<HTMLElement>('#node-card a')!;
  link.focus();
  await tick();
  expect(container.querySelector('#node-card')).toBeTruthy(); // moving from node to card keeps it open
  outside.focus();
  await tick();
  expect(container.querySelector('#node-card')).toBeNull();
  outside.remove();
});

test('Pause only hides packets: the map stays the default view', () => {
  motion.set(true);
  try {
    const { container } = render(Topology, { props: { title: 'Traffic topology' } });
    expect(container.querySelector('.scene')).toBeTruthy();
    expect(container.querySelector('table')).toBeNull();
    expect(document.documentElement.dataset.motion).toBe('off');
  } finally {
    motion.set(false);
  }
});

test('a failed dashboard load shows an inline error card and keeps the map', async () => {
  await app.start(new FixtureSource({ live: false, fault: (m) => (m === 'dashboard' ? SourceError.fromStatus(502, 'bad gateway') : null) }));
  const r = render(Topology, { props: { title: 'Traffic topology' } });
  const alert = await within(r.container).findByRole('alert');
  expect(alert.textContent).toContain('HTTP 502');
  expect(within(alert).getByRole('button', { name: 'Retry' })).toBeTruthy();
  expect(r.container.querySelector('.scene')).toBeTruthy();
  app.stop();
});
