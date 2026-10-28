import { expect, test } from 'vitest';
import { makeFixtures } from './fixtures';
import { BANDS, PERIOD_MS, makeHistory, rowId } from './history';
import type { Judgment, Verdict } from './types';

const NOW = Date.UTC(2026, 9, 28, 14, 5, 0);
const f = makeFixtures(NOW);
const h = makeHistory(f, () => NOW);
const K = Math.floor(NOW / PERIOD_MS);
const HOUR = Array.from({ length: 360 }, (_, i) => h.detail(rowId(K - i))!);

const band = (score: number): Verdict =>
  score >= BANDS.block_at ? 'Block' : score >= BANDS.challenge_at ? 'Challenge' : score >= BANDS.monitor_at ? 'Monitor' : 'Allow';
const sum = (j: Judgment) => j.contributions.filter((c) => !c.shadow).reduce((a, c) => a + c.points, 0);

test('rows are deterministic and ids round-trip', () => {
  const again = makeHistory(makeFixtures(NOW), () => NOW);
  expect(again.detail(rowId(K))).toEqual(h.detail(rowId(K)));
  expect(h.row(K).id).toBe(rowId(K));
  expect(h.row(K).ts_ms).toBe(K * PERIOD_MS);
});

test('unknown or malformed ids have no detail', () => {
  expect(h.detail('nope')).toBeNull();
  expect(h.detail('R')).toBeNull();
  expect(h.detail('R-1')).toBeNull();
});

test('non-shadow points sum to the score; shadow contributions score nothing', () => {
  for (const d of HOUR) {
    expect(Math.abs(sum(d.judgment) - d.judgment.score)).toBeLessThanOrEqual(0.05);
    for (const c of d.judgment.contributions.filter((c) => c.shadow)) expect(c.points).toBe(0);
  }
  expect(HOUR.some((d) => d.judgment.contributions.some((c) => c.shadow))).toBe(true);
});

test('decided_by follows the engine rules (shield.rs cause_for / ban_cause)', () => {
  const kinds = new Set(HOUR.map((d) => d.judgment.decided_by.kind));
  for (const k of ['NoEvidence', 'Detection', 'Honeypot', 'Ban'] as const) expect(kinds.has(k)).toBe(true);
  for (const { judgment: j, row } of HOUR) {
    const c = j.decided_by;
    expect(row.verdict).toBe(j.verdict);
    expect(row.score).toBe(j.score);
    expect(row.decided_option).toBe(c.option_key);
    expect(row.cause).toBe(c.kind);
    if (c.kind === 'Detection') {
      expect(j.verdict).toBe(band(j.score));
      expect(c.option_key).toBe(`scoring.${j.verdict.toLowerCase()}_at`);
      const top = [...j.contributions].filter((x) => !x.shadow).sort((a, b) => b.points - a.points)[0];
      expect(c.construct).toBe(top.construct);
      expect(c.field).toEqual(top.field);
      expect(c.msg).toMatch(/^score \d+ >= scoring\.\w+_at \d+: /);
    } else if (c.kind === 'NoEvidence') {
      expect(j.verdict).toBe('Allow');
      expect(c.option_key).toBe('scoring.monitor_at');
    } else if (c.kind === 'Honeypot') {
      expect(c.option_key).toBe('honeypot.decoy_paths');
      expect(j.verdict).toBe('Block');
      expect(f.decoys).toContain(row.path);
    } else if (c.kind === 'Ban') {
      expect(c.option_key).toMatch(/^chain\.ban_policy\./);
      expect(j.score).toBe(100);
      expect(f.board.find((s) => s.key === row.src_key)?.ban).not.toBeNull();
    }
  }
});

test('only Allows are sampled, and every Allow is', () => {
  for (const { row } of HOUR) expect(row.sampled).toBe(row.verdict === 'Allow');
});

test('a detail carries the deciding bands, its timeline and snippets', () => {
  const d = HOUR.find((x) => x.judgment.decided_by.kind === 'Detection')!;
  expect(d.bands).toEqual(BANDS);
  expect(d.row.config_rev).toBe(d.setting.rev);
  expect(d.setting.key).toBe(d.judgment.decided_by.option_key);
  expect(d.timeline.length).toBeGreaterThan(0);
  for (const t of d.timeline) expect(t.src_key).toBe(d.row.src_key);
  expect(d.timeline.every((t, i, a) => i === 0 || a[i - 1].ts_ms > t.ts_ms)).toBe(true);
  expect(d.fields?.[0]?.field).toEqual(d.judgment.decided_by.field);
});
