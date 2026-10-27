import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import App from './App.svelte';

test('the app renders a level-1 heading', async () => {
  render(App);
  expect(await screen.findByRole('heading', { level: 1 })).toBeTruthy();
});
