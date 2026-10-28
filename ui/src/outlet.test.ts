import { fireEvent, render, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import { expect, test, vi } from 'vitest';
import App from './App.svelte';
import { router } from './lib/state/router.svelte';

// The Keys route's chunk fails to load (as a stale deploy or a dropped connection would).
vi.mock('./screens/Placeholder.svelte', () => {
  throw new Error('Failed to fetch dynamically imported module');
});

test('a screen chunk that fails to load shows an error with Retry, and focus stays on the h1', async () => {
  router.navigate('/');
  render(App);
  await screen.findByRole('region', { name: 'Requests over time' });
  router.navigate('/keys');
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('could not be loaded');
  const h1 = screen.getByRole('heading', { level: 1 });
  expect(h1.textContent).toBe('Keys');
  await tick();
  expect(document.activeElement).toBe(h1);
  await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  expect(await screen.findByRole('alert')).toBeTruthy();
  await tick();
  expect(document.activeElement).toBe(screen.getByRole('heading', { level: 1 }));
});
