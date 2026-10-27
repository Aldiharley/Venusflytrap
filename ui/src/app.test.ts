import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import App from './App.svelte';

test('the app renders a level-1 heading', () => {
  render(App);
  expect(screen.getByRole('heading', { level: 1 })).toBeTruthy();
});
