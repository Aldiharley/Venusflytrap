import { GROUP_BYS, type GroupBy } from '../../lib/api/types';

// Monitor keeps everything in the URL (UX §5): ?q&range|from&to&group_by&refresh.
// `range` is a sliding preset (it follows "now" on each refresh); `from&to` is an absolute window.
const MIN = 60_000;
export const RANGES = [
  { key: '15m', label: '15 m', ms: 15 * MIN },
  { key: '1h', label: '1 h', ms: 60 * MIN },
  { key: '24h', label: '24 h', ms: 24 * 60 * MIN },
  { key: '7d', label: '7 d', ms: 7 * 24 * 60 * MIN },
] as const;
export type RangeKey = (typeof RANGES)[number]['key'];
export const REFRESH = [
  { key: '10s', label: '10 s', ms: 10_000 },
  { key: '1m', label: '1 min', ms: 60_000 },
  { key: 'off', label: 'Off', ms: 0 },
] as const;
export type RefreshKey = (typeof REFRESH)[number]['key'];

export interface MonitorState {
  q: string;
  /** Null when an absolute from/to window is in use. */
  range: RangeKey | null;
  from: number | null;
  to: number | null;
  group: GroupBy | null;
  refresh: RefreshKey;
}

const DEFAULT_RANGE: RangeKey = '1h';
const DEFAULT_REFRESH: RefreshKey = '1m';

export function readState(p: URLSearchParams): MonitorState {
  const from = Number(p.get('from'));
  const to = Number(p.get('to'));
  const absolute = Number.isFinite(from) && Number.isFinite(to) && from > 0 && to > from;
  const range = RANGES.find((r) => r.key === p.get('range'))?.key ?? DEFAULT_RANGE;
  const g = p.get('group_by');
  return {
    q: p.get('q') ?? '',
    range: absolute ? null : range,
    from: absolute ? from : null,
    to: absolute ? to : null,
    group: (GROUP_BYS as readonly string[]).includes(g ?? '') ? (g as GroupBy) : null,
    refresh: REFRESH.find((r) => r.key === p.get('refresh'))?.key ?? DEFAULT_REFRESH,
  };
}

/** The Monitor URL for a state, leaving defaults out. */
export function writeState(s: MonitorState): string {
  const p = new URLSearchParams();
  if (s.q) p.set('q', s.q);
  if (s.from !== null && s.to !== null) { p.set('from', String(s.from)); p.set('to', String(s.to)); }
  else if (s.range && s.range !== DEFAULT_RANGE) p.set('range', s.range);
  if (s.group) p.set('group_by', s.group);
  if (s.refresh !== DEFAULT_REFRESH) p.set('refresh', s.refresh);
  const qs = p.toString();
  return qs ? `/monitor?${qs}` : '/monitor';
}

export function timeWindow(s: MonitorState, now: number): { from: number; to: number } {
  if (s.from !== null && s.to !== null) return { from: s.from, to: s.to };
  const ms = RANGES.find((r) => r.key === s.range)?.ms ?? RANGES[1].ms;
  return { from: now - ms, to: now };
}

export function spanMs(s: MonitorState): number {
  return s.from !== null && s.to !== null ? s.to - s.from : (RANGES.find((r) => r.key === s.range)?.ms ?? RANGES[1].ms);
}

/** The next wider preset, or null at the widest. */
export function widen(s: MonitorState): RangeKey | null {
  const span = spanMs(s);
  return RANGES.find((r) => r.ms > span)?.key ?? null;
}
