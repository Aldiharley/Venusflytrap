import { expect, test } from 'vitest';
import sample from '../../../crates/vft-proxy/tests/fixtures/ocsf-sample.json';
import { encodeOcsf, PRODUCT_VERSION } from './ocsf';
import type { FieldRef, RequestDetail, Verdict } from './api/types';
import type { AttackTag } from '../gen/AttackTag';

// The Rust test (crates/vft-proxy/src/ocsf.rs `shared_sample_matches`) reads the same file and applies every case.
interface Input {
  method: string; path: string; src_ip: string | null; verdict: string; enforced: boolean;
  construct: string | null; construct_summary: string | null; msg: string; score: number; ts_ms: number;
  event_id: string; group_id: string | null; confidence: number | null; attack: AttackTag[];
  exceptions?: string[]; skipped_fields?: string[];
}
interface Case { name: string; input: Input; expected: Record<string, unknown>[] }
const cases = sample.cases as unknown as Case[];
// The richest case (an enforced Block with a source, a group, a construct and a confidence) drives the unit tests.
const input = cases[0].input;

// A `loc:name` label (lowercase location, as the encoder prints it) back to the judgment's FieldRef.
const skippedRef = (label: string): FieldRef => {
  const [loc, ...name] = label.split(':');
  return { loc: (loc[0].toUpperCase() + loc.slice(1)) as FieldRef['loc'], name: name.join(':') };
};

function detailFrom(i: Input, over: { verdict?: Verdict; src_ip?: string; confidence?: number | null } = {}): RequestDetail {
  const verdict = over.verdict ?? (i.verdict as Verdict);
  const confidence = over.confidence === undefined ? i.confidence : over.confidence;
  return {
    row: {
      id: i.event_id, ts_ms: i.ts_ms, verdict, score: i.score, src_key: i.src_ip ?? '', method: i.method, host: 'h', path: i.path,
      construct: i.construct, technique: i.attack[0]?.id ?? null, confidence, group_id: i.group_id, stage: null, cause: 'Detection',
      decided_option: 'scoring.block_at', config_rev: 1, latency_us: 1, upstream_status: null, sampled: false,
      excepted: (i.exceptions?.length ?? 0) + (i.skipped_fields?.length ?? 0) > 0,
    },
    // The console's "unknown source address" is the empty string.
    ip: over.src_ip ?? i.src_ip ?? '',
    query: '',
    judgment: {
      verdict, score: i.score, contributions: [],
      decided_by: { kind: 'Detection', option_key: 'scoring.block_at', field: null, construct: i.construct, msg: i.msg },
      chain: null, normalized_layers: 0, attack: i.attack, confidence,
      exceptions: i.exceptions ?? [], skipped: (i.skipped_fields ?? []).map(skippedRef),
    },
    bands: { monitor_at: 40, challenge_at: 70, block_at: 90 },
    setting: { key: 'scoring.block_at', value: '90', source: 'Override', rev: 1 },
    ban: null, timeline: [], fields: null,
  } as unknown as RequestDetail;
}

const withoutVersion = (recs: Record<string, unknown>[]) =>
  recs.map((r) => {
    const c = structuredClone(r) as { metadata: { product: Record<string, unknown> } };
    delete c.metadata.product.version;
    return c;
  });

test('the shared sample has the Block, the Allow without a source, the monitor-only Block and the ban case', () => {
  expect(cases.length).toBeGreaterThanOrEqual(4);
  expect(cases.some((c) => c.input.verdict === 'Allow' && c.input.src_ip === null)).toBe(true);
  expect(cases.some((c) => c.input.verdict === 'Block' && !c.input.enforced)).toBe(true);
  expect(cases.some((c) => c.input.construct === 'chain.ban' && c.input.construct_summary === null)).toBe(true);
});

for (const c of cases) {
  test(`shared sample "${c.name}" encodes to exactly the Rust encoder's records`, () => {
    const got = encodeOcsf(detailFrom(c.input), c.input.event_id, { summary: c.input.construct_summary, enforced: c.input.enforced });
    expect(got).toHaveLength(c.expected.length);
    for (const r of got) expect((r.metadata as { product: { version: string } }).product.version).toBe(PRODUCT_VERSION);
    expect(withoutVersion(got)).toEqual(withoutVersion(c.expected));
  });
}

test('the product version is a parameter', () => {
  const got = encodeOcsf(detailFrom(input), input.event_id, { version: '9.9.9' });
  expect((got[0].metadata as { product: { version: string } }).product.version).toBe('9.9.9');
});

test('Allow and Monitor give one HTTP Activity; Challenge and Block add a Detection Finding', () => {
  for (const v of ['Allow', 'Monitor'] as const) {
    const recs = encodeOcsf(detailFrom(input, { verdict: v }), input.event_id);
    expect(recs.map((r) => r.class_uid)).toEqual([4002]);
  }
  for (const v of ['Challenge', 'Block'] as const) {
    for (const enforced of [true, false]) {
      const recs = encodeOcsf(detailFrom(input, { verdict: v }), input.event_id, { enforced });
      expect(recs.map((r) => r.class_uid)).toEqual([4002, 2004]);
    }
  }
});

test('verdicts map to action, disposition and severity as in Rust; enforcement defaults to on', () => {
  const at = (v: Verdict, enforced?: boolean) => encodeOcsf(detailFrom(input, { verdict: v }), 'e', { enforced })[0];
  const triple = (r: Record<string, unknown>) => [r.action_id, r.disposition_id, r.severity_id];
  expect(triple(at('Allow'))).toEqual([1, 1, 1]);
  expect(triple(at('Monitor'))).toEqual([1, 17, 2]);
  expect(triple(at('Challenge'))).toEqual([2, 2, 3]);
  expect(triple(at('Block', true))).toEqual([2, 2, 4]);
  // Unenforced (monitor-only), Challenge and Block take Monitor's Allowed/Logged; Allow and Monitor do not change.
  expect((['Allow', 'Monitor', 'Challenge', 'Block'] as const).map((v) => triple(at(v, false)))).toEqual([[1, 1, 1], [1, 17, 2], [1, 17, 3], [1, 17, 4]]);
  for (const v of ['Allow', 'Monitor'] as const) expect(at(v, false)).toEqual(at(v, true));
});

test('only the HTTP Activity has metadata.uid; the finding links to it through finding_info.uid', () => {
  const [h, f] = encodeOcsf(detailFrom(input), 'e');
  expect((h.metadata as Record<string, unknown>).uid).toBe('e');
  expect(f.metadata as Record<string, unknown>).not.toHaveProperty('uid');
  expect((f.finding_info as Record<string, unknown>).uid).toBe('e');
});

test('a sub-technique goes in sub_technique, its parent in technique; JSONL-style ids stay whole elsewhere', () => {
  const d = detailFrom(input);
  d.judgment.attack = [{ tactic_id: 'TA0043', tactic: 'Reconnaissance', id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning' }];
  const f = encodeOcsf(d, 'e')[1];
  const want = {
    tactic: { uid: 'TA0043', name: 'Reconnaissance' },
    technique: { uid: 'T1595', name: 'Active Scanning' },
    sub_technique: { uid: 'T1595.002', name: 'Vulnerability Scanning' },
  };
  expect(f.attacks).toEqual([want]);
  expect((f.finding_info as { attacks: unknown }).attacks).toEqual([want]);
  // The judgment itself keeps the combined form.
  expect(d.judgment.attack[0].id).toBe('T1595.002');
});

test('the finding has no top-level src_endpoint and no confidence when it is null', () => {
  const [, f] = encodeOcsf(detailFrom(input, { confidence: null }), 'e');
  expect(f.src_endpoint).toBeUndefined();
  expect(f.confidence_score).toBeUndefined();
  expect(f.confidence_id).toBeUndefined();
});

test('confidence_id buckets: 70 and over high, 40 and over medium, else low', () => {
  const id = (c: number) => encodeOcsf(detailFrom(input, { confidence: c }), 'e')[1].confidence_id;
  expect([id(100), id(70), id(69), id(40), id(39), id(1)]).toEqual([3, 3, 2, 2, 1, 1]);
});

test('an unknown source address drops src_endpoint and the evidence', () => {
  const [h, f] = encodeOcsf(detailFrom(input, { src_ip: '' }), 'e');
  expect(h.src_endpoint).toBeUndefined();
  expect(f.evidences).toBeUndefined();
});

test('unknown methods are activity 99; without a summary the rule has no name, as in Rust', () => {
  const d = detailFrom(input);
  d.row.method = 'get';
  const [h] = encodeOcsf(d, 'e');
  expect([h.activity_id, h.type_uid]).toEqual([99, 400299]);
  expect(h.firewall_rule).toEqual({ uid: 'sqli.union-select' });
  expect(encodeOcsf(d, 'e', { summary: null })[0].firewall_rule).toEqual({ uid: 'sqli.union-select' });
  expect(encodeOcsf(d, 'e', { summary: 'UNION followed by SELECT' })[0].firewall_rule).toEqual({ uid: 'sqli.union-select', name: 'UNION followed by SELECT' });
  // An empty summary is still a summary, as Rust emits a registered construct's summary as is.
  expect(encodeOcsf(d, 'e', { summary: '' })[0].firewall_rule).toEqual({ uid: 'sqli.union-select', name: '' });
});

test('a judgment without a construct has no firewall_rule; without a group no correlation_uid', () => {
  const d = detailFrom(input);
  d.row.group_id = null;
  d.judgment.decided_by.construct = null;
  const [h] = encodeOcsf(d, 'e');
  expect(h.firewall_rule).toBeUndefined();
  expect((h.metadata as Record<string, unknown>).correlation_uid).toBeUndefined();
});

test('a method named like an inherited property is still an unknown method: activity 99', () => {
  for (const m of ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty']) {
    const d = detailFrom(input);
    d.row.method = m;
    const [h] = encodeOcsf(d, 'e');
    expect([m, h.activity_id, h.type_uid]).toEqual([m, 99, 400299]);
  }
});

test('unmapped.vft is on the 4002 only, when either list is non-empty, with lowercase loc:name labels', () => {
  expect(encodeOcsf(detailFrom(input), 'e')[0]).not.toHaveProperty('unmapped');
  const d = detailFrom(input);
  d.judgment.skipped = [{ loc: 'Header', name: 'x-signature' }, { loc: 'Query', name: 'utm_source' }];
  const [h, f] = encodeOcsf(d, 'e');
  expect(h.unmapped).toEqual({ vft: { exceptions: [], skipped_fields: ['header:x-signature', 'query:utm_source'] } });
  expect(f).not.toHaveProperty('unmapped');
  d.judgment.skipped = [];
  d.judgment.exceptions = ['referer-sql'];
  expect(encodeOcsf(d, 'e')[0].unmapped).toEqual({ vft: { exceptions: ['referer-sql'], skipped_fields: [] } });
});
