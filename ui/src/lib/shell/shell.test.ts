import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import App from '../../App.svelte';
import { router } from '../state/router.svelte';

test('nav marks the current route and detail routes mark their parent', async () => {
  router.navigate('/topology');
  render(App);
  const nav = await screen.findByRole('navigation', { name: 'Main' });
  expect(within(nav).getByRole('link', { name: /Traffic topology/ }).getAttribute('aria-current')).toBe('page');
  router.navigate('/sources/203.0.113.7');
  await screen.findByRole('heading', { level: 1, name: 'Source' });
  expect(within(nav).getByRole('link', { name: /Attack chains/ }).getAttribute('aria-current')).toBe('page');
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
