import { beforeEach, expect, test } from 'vitest';
import { motion, theme } from './theme.svelte';

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
  delete document.documentElement.dataset.motion;
});

test('light and dark set data-theme and persist only the preference', () => {
  theme.set('dark');
  expect(document.documentElement.dataset.theme).toBe('dark');
  expect(localStorage.getItem('vft-theme')).toBe('dark');
  theme.set('light');
  expect(document.documentElement.dataset.theme).toBe('light');
  expect(localStorage.length).toBe(1);
});

test('system removes data-theme so prefers-color-scheme decides', () => {
  theme.set('dark');
  theme.set('system');
  expect(document.documentElement.dataset.theme).toBeUndefined();
  expect(localStorage.getItem('vft-theme')).toBe('system');
});

test('pause sets data-motion off and resume clears it', () => {
  motion.set(true);
  expect(document.documentElement.dataset.motion).toBe('off');
  motion.set(false);
  expect(document.documentElement.dataset.motion).toBeUndefined();
});
