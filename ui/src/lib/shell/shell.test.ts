import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { beforeEach, expect, test } from 'vitest';
import App from '../../App.svelte';
import { app } from '../state/app.svelte';
import { router } from '../state/router.svelte';
import NavRail from './NavRail.svelte';

beforeEach(() => router.navigate('/', true));

test('nav marks the current route and detail routes mark their parent', async () => {
  router.navigate('/topology');
  render(App);
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  const current = (name: RegExp) => within(nav).getByRole('link', { name }).getAttribute('aria-current');
  expect(current(/Traffic topology/)).toBe('page');
  for (const other of [/Dashboard/, /Monitor/, /Attack chains/, /Honeypot/, /Settings/]) {
    expect(current(other)).toBeNull();
  }
  router.navigate('/sources/203.0.113.7');
  await screen.findByRole('heading', { level: 1, name: 'Source' });
  expect(current(/Attack chains/)).toBe('page');
  expect(current(/Traffic topology/)).toBeNull();
  expect(current(/Monitor/)).toBeNull();
});

test('the theme radio group switches data-theme', async () => {
  render(App);
  await fireEvent.click(await screen.findByLabelText('Dark'));
  expect(document.documentElement.dataset.theme).toBe('dark');
  await fireEvent.click(screen.getByLabelText('System'));
  expect(document.documentElement.dataset.theme).toBeUndefined();
});

test('the skip link targets main', async () => {
  render(App);
  expect((await screen.findByRole('link', { name: 'Skip to content' })).getAttribute('href')).toBe('#main');
});

test('the Keys item is shown to Admin only', async () => {
  const session = { key_id: 'k_test', expires_ms: 0 };
  render(NavRail);
  app.session = { ...session, perm: 'Admin' };
  expect(await screen.findByRole('link', { name: /Keys/ })).toBeTruthy();
  app.session = { ...session, perm: 'Operator' };
  await waitFor(() => expect(screen.queryByRole('link', { name: /Keys/ })).toBeNull());
  app.session = { ...session, perm: 'Viewer' };
  expect(screen.queryByRole('link', { name: /Keys/ })).toBeNull();
  app.session = null;
});

test('after navigation, focus moves to the new screen\'s heading once it has rendered', async () => {
  render(App);
  const first = await screen.findByRole('heading', { level: 1, name: 'Dashboard' });
  expect(document.activeElement).not.toBe(first); // the initial load does not steal focus
  router.navigate('/topology');
  await waitFor(() => {
    const h1 = screen.getByRole('heading', { level: 1, name: 'Traffic topology' });
    expect(document.activeElement).toBe(h1);
  });
});
