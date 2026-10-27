import { expect, test } from 'vitest';
import { makeFixtures } from '../../lib/api/fixtures';
import { moveCell, reconcile, sortKeys, stageCellText } from './grid';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);
const board = makeFixtures(NOW).board;

test('rows sort by stage, then recency', () => {
  const keys = sortKeys(board);
  expect(keys[0]).toBe('198.51.100.23'); // the only Exfiltration source
  const ranks = keys.map((k) => board.find((s) => s.key === k)!.stage);
  expect(ranks.indexOf('Recon')).toBeGreaterThan(ranks.lastIndexOf('Exploitation'));
});

test('a frozen grid keeps its order and counts pending changes', () => {
  const order = sortKeys(board);
  const bumped = board.map((s) => (s.key === '198.51.100.9' ? { ...s, stage: 'Exfiltration' as const, last_seen_ms: NOW } : s));
  const frozen = reconcile(order, bumped, true);
  expect(frozen.order).toEqual(order);
  expect(frozen.pending).toBeGreaterThan(0);
  const applied = reconcile(order, bumped, false);
  expect(applied.order[0]).toBe('198.51.100.9');
  expect(applied.pending).toBe(0);
});

test('new sources wait while frozen; removed ones stay in place', () => {
  const order = sortKeys(board);
  const next = [...board.slice(1), { ...board[0], key: '203.0.113.250', ip: '203.0.113.250' }];
  const r = reconcile(order, next, true);
  expect(r.order).toEqual(order);
  expect(r.order).toContain(board[0].key);
  expect(r.pending).toBeGreaterThanOrEqual(1);
});

test('grid keyboard model', () => {
  const dims = { rows: 11, cols: 9 };
  expect(moveCell({ r: 0, c: 0 }, 'ArrowRight', { ctrl: false }, dims)).toEqual({ r: 0, c: 1 });
  expect(moveCell({ r: 0, c: 8 }, 'ArrowRight', { ctrl: false }, dims)).toEqual({ r: 0, c: 8 });
  expect(moveCell({ r: 3, c: 4 }, 'Home', { ctrl: false }, dims)).toEqual({ r: 3, c: 0 });
  expect(moveCell({ r: 3, c: 4 }, 'Home', { ctrl: true }, dims)).toEqual({ r: 0, c: 0 });
  expect(moveCell({ r: 3, c: 4 }, 'PageDown', { ctrl: false }, dims)).toEqual({ r: 10, c: 4 });
  expect(moveCell({ r: 3, c: 4 }, 'x', { ctrl: false }, dims)).toBeNull();
});

test('stage cells read first-reached time and count', () => {
  const s = board.find((x) => x.key === '203.0.113.7')!;
  expect(stageCellText(s, 'Exploitation')).toMatch(/^\d\d:\d\d · 9$/);
  expect(stageCellText(s, 'Exfiltration')).toBe('—');
});
