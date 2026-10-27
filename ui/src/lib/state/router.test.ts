import { expect, test } from 'vitest';
import { match, router } from './router.svelte';

test('routes match, including parameters', () => {
  expect(match('/')).toEqual({ name: 'dashboard', param: null });
  expect(match('/topology')).toEqual({ name: 'topology', param: null });
  expect(match('/requests/r_42')).toEqual({ name: 'request', param: 'r_42' });
  expect(match('/sources/2001%3Adb8%3A4f%3A%3A%2F64')).toEqual({ name: 'source', param: '2001:db8:4f::/64' });
  expect(match('/nope')).toEqual({ name: 'notfound', param: null });
});

test('a malformed percent-escape is not found instead of throwing', () => {
  expect(match('/requests/%')).toEqual({ name: 'notfound', param: null });
  expect(match('/sources/%E0%A4%A')).toEqual({ name: 'notfound', param: null });
});

test('navigate updates path, search and history', () => {
  router.navigate('/chains?stage=Exploitation');
  expect(router.route.name).toBe('chains');
  expect(router.search.get('stage')).toBe('Exploitation');
  expect(location.pathname).toBe('/chains');
});
