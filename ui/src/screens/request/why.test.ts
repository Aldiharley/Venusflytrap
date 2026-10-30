import { expect, test } from 'vitest';
import type { Cause, Contribution, RequestDetail } from '../../lib/api/types';
import { arc, contributionRows, excludedNote, gaugeSentence, pointAt, whyParts } from './why';

const BANDS = { monitor_at: 40, challenge_at: 70, block_at: 90 };
function detail(cause: Partial<Cause>, over: Partial<RequestDetail> = {}, verdict: RequestDetail['row']['verdict'] = 'Block', score = 94): RequestDetail {
  const decided_by: Cause = { kind: 'Detection', option_key: 'scoring.block_at', construct: 'sqli.union-select', field: { loc: 'Query', name: 'id' }, msg: 'm', ...cause };
  return {
    row: { id: 'R1', ts_ms: 0, verdict, score, src_key: '203.0.113.7', method: 'GET', host: 'h', path: '/api/items', construct: decided_by.construct, technique: null, confidence: null, group_id: null, stage: null, cause: decided_by.kind, decided_option: decided_by.option_key, config_rev: 12, latency_us: 1, upstream_status: null, sampled: false, excepted: false },
    ip: '203.0.113.7', query: '', bands: BANDS, ban: null, timeline: [], fields: null,
    setting: { key: decided_by.option_key, value: '90', source: 'override', rev: 12 },
    judgment: { verdict, score, contributions: [], decided_by, chain: null, normalized_layers: 0, attack: [], confidence: null, exceptions: [], skipped: [] },
    ...over,
  };
}
const text = (d: RequestDetail) => whyParts(d).map((p) => p.text).join('');

test('a detection names the score, the deciding setting and the top evidence', () => {
  const d = detail({});
  expect(text(d)).toBe('Blocked: score 94 reached scoring.block_at = 90 (override). Top evidence: sqli.union-select in query:id.');
  const parts = whyParts(d);
  expect(parts.find((p) => p.text === 'scoring.block_at')?.href).toBe('/settings?highlight=scoring.block_at');
  expect(parts.find((p) => p.text === 'sqli.union-select')?.code).toBe(true);
});

test('a challenge and a flag use their own verbs', () => {
  expect(text(detail({ option_key: 'scoring.challenge_at' }, { setting: { key: 'scoring.challenge_at', value: '70', source: 'default', rev: 12 } }, 'Challenge', 75)))
    .toMatch(/^Challenged: score 75 reached scoring\.challenge_at = 70 \(default\)\./);
  expect(text(detail({ option_key: 'scoring.monitor_at' }, { setting: { key: 'scoring.monitor_at', value: '40', source: 'default', rev: 12 } }, 'Monitor', 45)))
    .toMatch(/^Flagged: score 45/);
});

test('each other kind reads as its UX sentence', () => {
  expect(text(detail({ kind: 'Honeypot', option_key: 'honeypot.decoy_paths', construct: 'honeypot.decoy-hit' }, {}, 'Block', 100)))
    .toBe('Request hit decoy /api/items.');
  const until = new Date(2026, 9, 28, 15, 4).getTime();
  expect(text(detail({ kind: 'Ban', option_key: 'chain.ban_policy.on_honeypot' }, { ban: { until_ms: until, reason: 'Honeypot', offences: 1, manual: false } }, 'Block', 100)))
    .toBe('Source banned until 15:04.');
  expect(text(detail({ kind: 'Ban' }, { ban: { until_ms: null, reason: 'Manual', offences: 1, manual: true } }, 'Block', 100))).toBe('Source banned permanently.');
  expect(text(detail({ kind: 'IntelDeny', option_key: 'intel.deny_ips' }))).toBe('Source on intel deny list.');
  expect(text(detail({ kind: 'Limit', option_key: 'shield.max_inspect_bytes' }))).toBe('Fail-closed: limit.payload-truncated (shield.max_inspect_bytes).');
  expect(text(detail({ kind: 'Allowlisted', option_key: 'intel.allow_ips' }, {}, 'Allow', 0))).toBe('Source allow-listed.');
  expect(text(detail({ kind: 'NoEvidence', option_key: 'scoring.monitor_at', construct: null, field: null }, {}, 'Allow', 6))).toBe('No evidence; allowed.');
});

const c = (points: number, over: Partial<Contribution> = {}): Contribution => ({
  engine: 'graph-taint', field: null, construct: null, family: null, value: 'Dangerous', weight: 1, points, shadow: false, exception: null, ...over,
});

test('contributions sort by points, shadow rows last, and the scored points sum to the score', () => {
  const rows = contributionRows([c(4.2), c(0, { shadow: true, construct: 'sqli.inline-comment' }), c(85.8), c(4)], 94);
  expect(rows.items.map((r) => r.c.points)).toEqual([85.8, 4.2, 4, 0]);
  expect(rows.items.map((r) => r.top)).toEqual([true, false, false, false]);
  expect(rows.items[3].c.shadow).toBe(true);
  expect(rows.sum).toBeCloseTo(94, 5);
  expect(rows.exact).toBe(true);
  expect(contributionRows([c(93.6)], 94).exact).toBe(false); // the engine sums to the unrounded score
});

test('the gauge maps 0..100 onto a left-to-right semicircle', () => {
  const [x0, y0] = pointAt(0, 50);
  const [x50, y50] = pointAt(50, 50);
  const [x100, y100] = pointAt(100, 50);
  expect([Math.round(x0), Math.round(y0)]).toEqual([50, 108]);
  expect([Math.round(x50), Math.round(y50)]).toEqual([100, 58]);
  expect([Math.round(x100), Math.round(y100)]).toEqual([150, 108]);
  expect(arc(0, 100, 50)).toMatch(/^M 50\.00 108\.00 A 50 50 0 0 1 150\.00 108\.00$/);
});

test('the gauge has a sentence alternative', () => {
  expect(gaugeSentence(94, BANDS, 12)).toBe('Score 94 of 100. Bands at rev 12: Monitor ≥ 40, Challenge ≥ 70, Block ≥ 90.');
});

test('a log-only contribution is excluded from the sum, sorts with the shadow ones and is named in the footer note', () => {
  const cs = [c(0, { shadow: true, exception: 'utm-xss' }), c(90), c(4)];
  const rows = contributionRows(cs, 94);
  expect(rows.items.map((r) => r.c.points)).toEqual([90, 4, 0]);
  expect(rows.sum).toBe(94);
  expect(excludedNote(cs)).toBe(' (suppressed rows excluded)');
  expect(excludedNote([...cs, c(0, { shadow: true })])).toBe(' (shadow and suppressed rows excluded)');
  expect(excludedNote([c(0, { shadow: true })])).toBe(' (shadow rows excluded)');
  expect(excludedNote([c(4)])).toBe('');
});
