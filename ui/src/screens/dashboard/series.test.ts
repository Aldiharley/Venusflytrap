import { expect, test } from 'vitest';
import { stackedPaths } from './series';

test('stacked paths cover the cumulative maximum', () => {
  const p = stackedPaths([[1, 2], [3, 4]], 100, 50);
  expect(p).toHaveLength(2);
  expect(p[1].max).toBe(6);
  expect(p[0].d.startsWith('M0,')).toBe(true);
  expect(p[1].d.endsWith('Z')).toBe(true);
});

test('all-zero series do not divide by zero', () => {
  const p = stackedPaths([[0, 0], [0, 0]], 100, 50);
  expect(p[0].d).not.toContain('NaN');
});
