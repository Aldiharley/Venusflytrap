import { fireEvent, render, screen } from '@testing-library/svelte';
import { expect, test, vi } from 'vitest';
import App from './App.svelte';
import { app } from './lib/state/app.svelte';

test('the app renders a level-1 heading', async () => {
  render(App);
  expect(await screen.findByRole('heading', { level: 1 })).toBeTruthy();
});

test('a failed start shows an error with Retry, and Retry loads the screen', async () => {
  const spy = vi.spyOn(app, 'start').mockRejectedValueOnce(new Error('offline'));
  render(App);
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('could not load');
  await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  expect(await screen.findByText(/arrives with console plan SP6b/)).toBeTruthy();
  expect(screen.queryByRole('alert')).toBeNull();
  expect(spy).toHaveBeenCalledTimes(2);
  spy.mockRestore();
});
