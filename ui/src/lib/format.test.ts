import { expect, test } from 'vitest';
import { banText, fmtAgo, fmtCount, fmtRps } from './format';

test('rates', () => {
  expect(fmtRps(0)).toBe('0/s');
  expect(fmtRps(0.003)).toBe('< 0.1/s');
  expect(fmtRps(0.049)).toBe('< 0.1/s');
  expect(fmtRps(0.05)).toBe('0.1/s');
  expect(fmtRps(0.42)).toBe('0.4/s');
  expect(fmtRps(4.06)).toBe('4.1/s');
  expect(fmtRps(38.2)).toBe('38/s');
  expect(fmtRps(412.3)).toBe('412/s');
});

test('counts and ages', () => {
  expect(fmtCount(182400)).toBe('182,400');
  expect(fmtAgo(12_000)).toBe('12 s ago');
  expect(fmtAgo(4 * 60_000)).toBe('4 min ago');
  expect(fmtAgo(2 * 3_600_000)).toBe('2 h ago');
});

test('ban text changes once a minute', () => {
  const now = 1_000_000;
  expect(banText({ until_ms: null }, now)).toBe('Banned · Permanent');
  expect(banText({ until_ms: now + 42 * 60_000 + 30_000 }, now)).toBe('Banned · 42 min left');
  expect(banText({ until_ms: now + 125 * 60_000 }, now)).toBe('Banned · 2 h 5 min left');
  expect(banText({ until_ms: now + 20_000 }, now)).toBe('Banned · < 1 min left');
  expect(banText({ until_ms: now - 1 }, now)).toBe('Ban expired');
});
