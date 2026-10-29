import { expect, test } from 'vitest';
import { makeFixtures } from './fixtures';
import { BANDS, PERIOD_MS, makeHistory, rowId } from './history';
import { parse } from '../query';
import { techniquesFor } from './attack';
import { confidenceOf } from './confidence';
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

const HOUR_Q = { from: NOW - 3_600_000, to: NOW };

test('a query filters the range newest first and pages with a cursor', () => {
  const all = h.query({ ...HOUR_Q, q: '' }, []);
  expect(all.total).toBe(360);
  expect(all.rows).toHaveLength(100);
  expect(all.rows.every((r, i, a) => i === 0 || a[i - 1].ts_ms > r.ts_ms)).toBe(true);
  const page2 = h.query({ ...HOUR_Q, q: '', cursor: all.next }, []);
  expect(page2.rows[0].ts_ms).toBeLessThan(all.rows[99].ts_ms);
  expect(new Set([...all.rows, ...page2.rows].map((r) => r.id)).size).toBe(200);
  const blocks = h.query({ ...HOUR_Q, q: 'verdict:block', limit: 1000 }, parse('verdict:block').terms);
  expect(blocks.rows.length).toBe(blocks.total);
  expect(blocks.next).toBeNull();
  expect(blocks.rows.every((r) => r.verdict === 'Block')).toBe(true);
});

test('group_by counts every match in the range, largest first', () => {
  const g = h.query({ ...HOUR_Q, q: '', group_by: 'verdict' }, []);
  expect(g.rows).toEqual([]);
  expect(g.groups!.reduce((a, x) => a + x.count, 0)).toBe(g.total);
  expect(g.groups!.every((x, i, a) => i === 0 || a[i - 1].count >= x.count)).toBe(true);
  const c = h.query({ ...HOUR_Q, q: '', group_by: 'construct' }, []);
  expect(c.groups!.some((x) => x.value === 'sqli.union-select')).toBe(true);
});

test('the range is clipped to now and retention', () => {
  expect(h.query({ from: NOW + 1, to: NOW + 3_600_000, q: '' }, []).total).toBe(0);
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

test('rows and judgments carry ATT&CK, confidence and group from the deciding construct only', () => {
  const rows = Array.from({ length: 200 }, (_, i) => h.row(K - i));
  expect(rows.some((r) => r.technique !== null)).toBe(true);
  expect(rows.some((r) => r.confidence !== null)).toBe(true);
  for (const r of rows) {
    expect(r.technique).toBe(techniquesFor(r.construct)[0]?.id ?? null);
    expect(r.confidence).toBe(confidenceOf(r.construct));
  }
  for (const d of Array.from({ length: 200 }, (_, i) => h.detail(rowId(K - i))!)) {
    const j = d.judgment;
    expect(j.attack).toEqual(techniquesFor(j.decided_by.construct));
    expect(j.confidence).toBe(confidenceOf(j.decided_by.construct));
    expect(d.row.technique).toBe(j.attack[0]?.id ?? null);
    expect(d.row.confidence).toBe(j.confidence);
    if (j.chain) {
      expect(j.chain.episode_start_ms).not.toBeNull();
      expect(j.chain.episode_start_ms!).toBeLessThanOrEqual(d.row.ts_ms);
      expect(d.row.group_id).toBe(`${d.ip}@${j.chain.episode_start_ms}`);
    } else {
      expect(d.row.group_id).toBeNull();
    }
  }
});

test('a fast-tracked banned judgment has no tags and no confidence', () => {
  const banned = HOUR.filter((d) => d.judgment.decided_by.kind === 'Ban');
  expect(banned.length).toBeGreaterThan(0);
  for (const d of banned) {
    expect(d.judgment.attack).toEqual([]);
    expect(d.judgment.confidence).toBeNull();
    expect(d.row.technique).toBeNull();
    expect(d.row.confidence).toBeNull();
  }
});
