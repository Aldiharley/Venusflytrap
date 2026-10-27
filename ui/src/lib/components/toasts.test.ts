import { render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import ToastStack from './ToastStack.svelte';
import { toasts } from './toasts.svelte';

beforeEach(() => {
  vi.useFakeTimers();
  for (const t of [...toasts.items]) toasts.dismiss(t.id);
});
afterEach(() => vi.useRealTimers());

test('only the three newest toasts are kept', () => {
  for (const n of [1, 2, 3, 4]) toasts.push({ tone: 'error', text: `t${n}` });
  expect(toasts.items.map((t) => t.text)).toEqual(['t2', 't3', 't4']);
});

test('info toasts auto-dismiss after 6 s; error toasts stay', async () => {
  toasts.push({ tone: 'info', text: 'saved' });
  toasts.push({ tone: 'error', text: 'boom' });
  vi.advanceTimersByTime(5_999);
  expect(toasts.items).toHaveLength(2);
  vi.advanceTimersByTime(1);
  expect(toasts.items.map((t) => t.text)).toEqual(['boom']);
  vi.advanceTimersByTime(600_000);
  expect(toasts.items.map((t) => t.text)).toEqual(['boom']);
});

test('error toasts announce as alert, others as status; each can be dismissed', async () => {
  render(ToastStack);
  toasts.push({ tone: 'info', text: 'FYI' });
  toasts.push({ tone: 'error', text: 'Failure' });
  await tick();
  expect(screen.getByText('FYI').closest('div')?.getAttribute('role')).toBe('status');
  expect(screen.getByRole('alert').textContent).toContain('Failure');
  screen.getAllByRole('button', { name: 'Dismiss notification' })[1].click();
  await tick();
  expect(screen.queryByRole('alert')).toBeNull();
});
