import { render, screen } from '@testing-library/svelte';
import { expect, test } from 'vitest';
import EmptyState from './EmptyState.svelte';
import KpiTile from './KpiTile.svelte';
import TechniqueCell from './TechniqueCell.svelte';
import StageChip from './StageChip.svelte';
import VerdictChip from './VerdictChip.svelte';

test.each(['Allow', 'Monitor', 'Challenge', 'Block'] as const)('verdict %s has glyph and word', (v) => {
  const { container } = render(VerdictChip, { props: { verdict: v } });
  expect(container.textContent).toContain(v);
  expect(container.querySelector('svg')).toBeTruthy();
  expect(container.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
});

test('each verdict has a distinct glyph', () => {
  const markup = (['Allow', 'Monitor', 'Challenge', 'Block'] as const).map((v) => {
    const { container, unmount } = render(VerdictChip, { props: { verdict: v } });
    const svg = container.querySelector('svg')?.innerHTML ?? '';
    unmount();
    return svg;
  });
  expect(markup.every((m) => m.length > 0)).toBe(true);
  expect(new Set(markup).size).toBe(4);
});

test('stage chip exposes an accessible name', () => {
  render(StageChip, { props: { stage: 'Exploitation' } });
  expect(screen.getByRole('img', { name: 'Stage 3 of 4: Exploitation' })).toBeTruthy();
  render(StageChip, { props: { stage: null } });
  expect(screen.getByRole('img', { name: 'Clean' })).toBeTruthy();
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

test('a technique shows from the row even when the fixture table does not know the construct', () => {
  const { container } = render(TechniqueCell, { props: { technique: 'T1190', construct: 'made-up.construct' } });
  expect(container.textContent).toContain('T1190');
  const chip = container.querySelector('[title]')!;
  expect(chip.getAttribute('title')).toBe('T1190');
  expect(container.querySelector('.sr-only')!.textContent).toBe('T1190');
});

test('the cell shows only the row technique, even when the construct has more tags', () => {
  const { container } = render(TechniqueCell, { props: { technique: 'T1190', construct: 'cmd.chained-command' } });
  expect(container.querySelectorAll('.chip').length).toBe(1);
  expect(container.textContent).toContain('T1190');
  expect(container.textContent).not.toContain('T1059');
});

test('a known construct enriches its technique with tactic and name; no technique is a dash', () => {
  const known = render(TechniqueCell, { props: { technique: 'T1595.003', construct: 'honeypot.decoy-hit' } });
  expect(known.container.querySelector('.sr-only')!.textContent).toBe('Reconnaissance · Active Scanning: Wordlist Scanning');
  known.unmount();
  const none = render(TechniqueCell, { props: { technique: null, construct: 'sqli.union-select' } });
  expect(none.container.textContent).toContain('—');
  expect(none.container.textContent).not.toContain('T1190');
});
