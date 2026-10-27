import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import EmptyState from './EmptyState.svelte';
import KpiTile from './KpiTile.svelte';
import StageChip from './StageChip.svelte';
import VerdictChip from './VerdictChip.svelte';

test.each(['Allow', 'Monitor', 'Challenge', 'Block'] as const)('verdict %s has glyph and word', (v) => {
  const { container } = render(VerdictChip, { props: { verdict: v } });
  expect(container.textContent).toContain(v);
  expect(container.querySelector('svg')).toBeTruthy();
});

test('stage chips show number, label and pips; null is Clean', () => {
  const { container } = render(StageChip, { props: { stage: 'Exploitation' } });
  expect(container.textContent).toContain('3');
  expect(container.textContent).toContain('Exploitation');
  expect(container.querySelectorAll('.pip.on')).toHaveLength(3);
  const clean = render(StageChip, { props: { stage: null } });
  expect(clean.container.textContent).toContain('Clean');
});

test('KPI tile is a definition list entry', () => {
  const { container } = render(KpiTile, { props: { label: 'Block', value: '38', unit: '/s', tone: 'block' } });
  expect(screen.getByText('Block').tagName).toBe('DT');
  expect(container.querySelector('dd')?.textContent).toBe('38/s');
});

test('empty state shows one sentence and an action', () => {
  render(EmptyState, { props: { message: 'No traffic yet.', action: { label: 'Open dashboard', href: '/' } } });
  expect(screen.getByText('No traffic yet.')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Open dashboard' })).toBeTruthy();
});
