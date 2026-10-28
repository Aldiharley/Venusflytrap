import { expect, expectTypeOf, test } from 'vitest';
import type { BanRecord as GenBanRecord } from '../../gen/BanRecord';
import type { Cause as GenCause } from '../../gen/Cause';
import type { Contribution as GenContribution } from '../../gen/Contribution';
import type { Judgment as GenJudgment } from '../../gen/Judgment';
import type { Stage as GenStage } from '../../gen/Stage';
import type { Verdict as GenVerdict } from '../../gen/Verdict';
import type { BanRecord, Cause, Contribution, Judgment, Stage, Verdict } from './types';
import { banEntry, banView, PERMANENT_UNTIL_MS } from './views';

test('the wire types are the generated ones', () => {
  expectTypeOf<Contribution>().toEqualTypeOf<GenContribution>();
  expectTypeOf<Cause>().toEqualTypeOf<GenCause>();
  expectTypeOf<Judgment>().toEqualTypeOf<GenJudgment>();
  expectTypeOf<BanRecord>().toEqualTypeOf<GenBanRecord>();
  expectTypeOf<Verdict>().toEqualTypeOf<GenVerdict>();
  expectTypeOf<Stage>().toEqualTypeOf<GenStage>();
});

const rec = (over: Partial<BanRecord> = {}): BanRecord => ({
  since_ms: 1_000, until_ms: 3_601_000, cause: 'Honeypot', offences: 1, ...over,
});

test('banView reads an automatic ban from its BanRecord', () => {
  expect(banView(rec())).toEqual({ until_ms: 3_601_000, reason: 'Honeypot', offences: 1, manual: false });
});

test('a manual ban is marked manual', () => {
  expect(banView(rec({ cause: 'Manual' })).manual).toBe(true);
});

test('an until_ms past the safe-integer range reads as permanent', () => {
  // u64::MAX arrives as a JS number above MAX_SAFE_INTEGER.
  expect(banView(rec({ until_ms: 2 ** 64 })).until_ms).toBeNull();
  expect(banView(rec({ until_ms: PERMANENT_UNTIL_MS })).until_ms).toBeNull();
  expect(banView(rec({ until_ms: PERMANENT_UNTIL_MS - 1 })).until_ms).toBe(PERMANENT_UNTIL_MS - 1);
});

test('banEntry adds the key and keeps since_ms', () => {
  expect(banEntry('203.0.113.7', rec({ offences: 2 }))).toEqual({
    key: '203.0.113.7', since_ms: 1_000, until_ms: 3_601_000, reason: 'Honeypot', offences: 2, manual: false,
  });
});
