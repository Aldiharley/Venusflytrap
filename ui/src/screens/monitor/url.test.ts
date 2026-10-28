import { expect, test } from 'vitest';
import { readState, timeWindow, widen, writeState } from './url';

const read = (qs: string) => readState(new URLSearchParams(qs));

test('defaults: last hour, refresh every minute, ungrouped', () => {
  expect(read('')).toEqual({ q: '', range: '1h', from: null, to: null, group: null, refresh: '1m' });
  expect(writeState(read(''))).toBe('/monitor');
});

test('state round-trips through the URL and invalid values fall back', () => {
  const s = read('q=verdict%3Ablock&range=24h&group_by=construct&refresh=10s');
  expect(s).toMatchObject({ q: 'verdict:block', range: '24h', group: 'construct', refresh: '10s' });
  expect(read(writeState(s).split('?')[1])).toEqual(s);
  expect(read('range=1y&group_by=colour&refresh=1s')).toMatchObject({ range: '1h', group: null, refresh: '1m' });
});

test('an absolute from/to window wins over a preset and does not slide', () => {
  const s = read('from=1000&to=5000&range=7d');
  expect(s).toMatchObject({ range: null, from: 1000, to: 5000 });
  expect(timeWindow(s, 999_999)).toEqual({ from: 1000, to: 5000 });
  expect(writeState(s)).toBe('/monitor?from=1000&to=5000');
  expect(timeWindow(read('range=15m'), 1_000_000)).toEqual({ from: 100_000, to: 1_000_000 });
});

test('widen steps to the next larger preset', () => {
  expect(widen(read(''))).toBe('24h');
  expect(widen(read('range=7d'))).toBeNull();
  expect(widen(read('from=0&to=1'))).toBe('24h'); // an invalid absolute window falls back to 1 h
});
