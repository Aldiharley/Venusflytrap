import { expect, test } from 'vitest';
import sample from '../../../crates/vft-proxy/tests/fixtures/ocsf-sample.json';
import { encodeOcsf, PRODUCT_VERSION } from './ocsf';
import type { RequestDetail, Verdict } from './api/types';

// The Rust test (crates/vft-proxy/src/ocsf.rs `shared_sample_matches`) reads the same file.
const input = sample.input;

function detailFrom(i: typeof input, over: { verdict?: Verdict; src_ip?: string; confidence?: number | null } = {}): RequestDetail {
  const verdict = over.verdict ?? (i.verdict as Verdict);
  const confidence = over.confidence === undefined ? i.confidence : over.confidence;
  return {
    row: {
      id: i.event_id, ts_ms: i.ts_ms, verdict, score: i.score, src_key: i.src_ip, method: i.method, host: 'h', path: i.path,
      construct: i.construct, technique: i.attack[0]?.id ?? null, confidence, group_id: i.group_id, stage: null, cause: 'Detection',
      decided_option: 'scoring.block_at', config_rev: 1, latency_us: 1, upstream_status: null, sampled: false,
    },
    ip: over.src_ip ?? i.src_ip,
    query: '',
    judgment: {
      verdict, score: i.score, contributions: [],
      decided_by: { kind: 'Detection', option_key: 'scoring.block_at', field: null, construct: i.construct, msg: i.msg },
      chain: null, normalized_layers: 0, attack: i.attack, confidence,
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

test("the shared sample encodes to exactly the Rust encoder's records", () => {
  const got = encodeOcsf(detailFrom(input), input.event_id, { summary: input.construct_summary });
  expect(got).toHaveLength(2);
  for (const r of got) expect((r.metadata as { product: { version: string } }).product.version).toBe(PRODUCT_VERSION);
  expect(withoutVersion(got)).toEqual(withoutVersion(sample.expected as Record<string, unknown>[]));
});

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
    const recs = encodeOcsf(detailFrom(input, { verdict: v }), input.event_id);
    expect(recs.map((r) => r.class_uid)).toEqual([4002, 2004]);
  }
});

test('verdicts map to action, disposition and severity as in Rust', () => {
  const at = (v: Verdict) => encodeOcsf(detailFrom(input, { verdict: v }), 'e')[0];
  expect([at('Allow').action_id, at('Allow').disposition_id, at('Allow').severity_id]).toEqual([1, 1, 1]);
  expect([at('Monitor').action_id, at('Monitor').disposition_id, at('Monitor').severity_id]).toEqual([1, 17, 2]);
  expect([at('Challenge').action_id, at('Challenge').disposition_id, at('Challenge').severity_id]).toEqual([2, 2, 3]);
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

test('unknown methods are activity 99; the rule name falls back to the construct id', () => {
  const d = detailFrom(input);
  d.row.method = 'get';
  const [h] = encodeOcsf(d, 'e');
  expect([h.activity_id, h.type_uid]).toEqual([99, 400299]);
  expect(h.firewall_rule).toEqual({ uid: 'sqli.union-select', name: 'sqli.union-select' });
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
