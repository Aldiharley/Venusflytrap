import { expect, test } from 'vitest';
import { makeFixtures } from '../../lib/api/fixtures';
import { buildModel, clusterRates, volumeStep, type ModelInput } from './model';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);

function input(): ModelInput {
  const f = makeFixtures(NOW);
  const later = f.board.map((s) => (s.stage === 'Exploitation' && !s.ban ? { ...s, requests: s.requests + 10, blocked: s.blocked + 8 } : s));
  return {
    counters: f.counters,
    board: later,
    rates: clusterRates(f.board, later, 1000),
    dashboard: f.dashboard(NOW - 3_600_000, NOW),
    status: f.status,
    now: NOW,
  };
}

test('volume steps are fixed and never interpolated', () => {
  expect([0, 0.5, 1, 9.9, 10, 99, 100, 500].map(volumeStep)).toEqual([0, 1, 2, 2, 3, 3, 4, 4]);
});

test('cluster rates come from board deltas', () => {
  const r = input().rates;
  expect(r.exploit.passed + r.exploit.blocked).toBeCloseTo(20, 5); // two unbanned Exploitation sources x 10 req/s
  expect(r.exploit.blocked).toBeCloseTo(16, 5);
});

test('nodes follow the roving order and name their numbers', () => {
  const m = buildModel(input());
  expect(m.nodes.map((n) => n.id)).toEqual(['clean', 'recon', 'exploit', 'tower', 'route0', 'route1', 'route2', 'route3', 'route4', 'hp0', 'hp1', 'hp2', 'hp3', 'quarantine']);
  const exploit = m.nodes.find((n) => n.id === 'exploit')!;
  expect(exploit.name).toMatch(/^Exploitation cluster, \d+ sources, /);
  expect(m.nodes.find((n) => n.id === 'quarantine')!.countText).toBe('3');
});

test('more than four decoys put "+N more" on the last pod', () => {
  const m = buildModel(input());
  expect(m.nodes.find((n) => n.id === 'hp3')!.label).toContain('+1 more');
});

test('flows carry verdict, rate text and a path', () => {
  const m = buildModel(input());
  expect(m.flows.length).toBeGreaterThan(10);
  for (const f of m.flows) {
    expect(f.d).toMatch(/^M[\d.-]+,[\d.-]+ L[\d.-]+,[\d.-]+$/);
    expect(f.rateText.endsWith('/s')).toBe(true);
  }
});
