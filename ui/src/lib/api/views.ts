import type { BanEntry, BanRecord, BanView } from './types';

/**
 * `BanRecord.until_ms` is a u64 with no "permanent" value of its own; SP5 is expected to send
 * u64::MAX (which arrives above this bound) for a ban that never expires.
 */
export const PERMANENT_UNTIL_MS = Number.MAX_SAFE_INTEGER;

export function banView(r: BanRecord): BanView {
  return {
    until_ms: r.until_ms >= PERMANENT_UNTIL_MS ? null : r.until_ms,
    reason: r.cause,
    offences: r.offences,
    manual: r.cause === 'Manual',
  };
}

export function banEntry(key: string, r: BanRecord): BanEntry {
  return { key, since_ms: r.since_ms, ...banView(r) };
}
