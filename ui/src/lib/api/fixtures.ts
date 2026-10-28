import { mulberry32 } from './rng';
import type {
  BanCause, BanEntry, BanRecord, Counters, Dashboard, Family, Session, SourceView, Stage, StatusRecord,
} from './types';
import { STAGES } from './types';
import { banEntry, banView } from './views';

const MIN = 60_000;
const HOUR = 60 * MIN;

/** Decoy paths: the engine's default `honeypot.decoy_paths`. */
export const DECOYS = ['/.git/config', '/admin/backup.zip', '/wp-admin/secret', '/phpmyadmin/', '/_internal/debug'];

type Row = [
  key: string, ip: string, stage: Stage,
  path: [Stage, number][], counts: [number, number, number, number],
  requests: number, blocked: number, honeypot: number, constructs: string[], lastAgo: number,
  /** Minutes left (null = permanent); the TTL is 1 h doubling per offence (chain.ban_policy.ttl_secs). */
  ban: null | { inMs: number | null; cause: BanCause; offences: number },
];

/** u64::MAX as it arrives in JSON: the wire form of a ban that never expires. */
const FOREVER = 2 ** 64;

const ROWS: Row[] = [
  ['203.0.113.7', '203.0.113.7', 'Exploitation', [['Recon', 7 * MIN], ['Exploitation', 3 * MIN]], [4, 0, 9, 0], 240, 188, 0, ['sqli.union-select', 'sqli.boolean-tautology'], 2_000, null],
  ['198.51.100.23', '198.51.100.23', 'Exfiltration', [['Recon', 22 * MIN], ['Exploitation', 12 * MIN], ['Exfiltration', 9 * MIN]], [3, 0, 14, 2], 512, 470, 0, ['sqli.union-select', 'sqli.fn-load-file'], 5_000, null],
  ['192.0.2.144', '192.0.2.144', 'Exploitation', [['Exploitation', 4 * MIN]], [0, 0, 6, 0], 131, 97, 0, ['xss.event-handler'], 9_000, null],
  ['203.0.113.51', '203.0.113.51', 'Exploitation', [['Recon', 30 * MIN], ['Exploitation', 18 * MIN]], [2, 0, 5, 0], 88, 61, 1, ['cmd.chained-command'], 40_000, { inMs: 59 * MIN, cause: 'Honeypot', offences: 1 }],
  ['198.51.100.9', '198.51.100.9', 'Recon', [['Recon', 6 * MIN]], [5, 0, 0, 0], 46, 3, 0, ['recon.sensitive-path-probe'], 3_000, null],
  ['192.0.2.77', '192.0.2.77', 'Enumeration', [['Recon', 15 * MIN], ['Enumeration', 11 * MIN]], [2, 6, 0, 0], 310, 22, 0, ['intel.scanner-ua'], 1_000, null],
  ['2001:db8:4f::/64', '2001:db8:4f::17', 'Recon', [['Recon', 2 * MIN]], [3, 0, 0, 0], 19, 0, 0, ['recon.sensitive-path-probe'], 12_000, null],
  ['203.0.113.200', '203.0.113.200', 'Exploitation', [['Exploitation', 50 * MIN]], [0, 0, 3, 0], 64, 64, 2, ['path.directory-traversal'], 8 * MIN, { inMs: 42 * MIN, cause: 'RepeatedExploitation', offences: 2 }],
  ['198.51.100.140', '198.51.100.140', 'Recon', [['Recon', 40 * MIN]], [1, 0, 0, 0], 7, 1, 0, ['recon.sensitive-path-probe'], 25 * MIN, null],
  ['192.0.2.12', '192.0.2.12', 'Exploitation', [['Recon', 55 * MIN], ['Exploitation', 44 * MIN]], [1, 0, 2, 0], 40, 40, 0, ['sqli.stacked-query'], 30 * MIN, { inMs: null, cause: 'Manual', offences: 1 }],
  ['203.0.113.99', '203.0.113.99', 'Recon', [['Recon', 9 * MIN]], [2, 0, 0, 0], 12, 2, 0, ['recon.sensitive-path-probe'], 50_000, null],
];

const TOP_CONSTRUCTS: { id: string; family: Family; count: number }[] = [
  { id: 'sqli.union-select', family: 'Sqli', count: 412 },
  { id: 'xss.event-handler', family: 'Xss', count: 233 },
  { id: 'cmd.chained-command', family: 'CommandInjection', count: 118 },
  { id: 'path.directory-traversal', family: 'PathTraversal', count: 97 },
  { id: 'recon.sensitive-path-probe', family: 'Recon', count: 88 },
  { id: 'sqli.boolean-tautology', family: 'Sqli', count: 61 },
  { id: 'xss.script-tag', family: 'Xss', count: 44 },
  { id: 'honeypot.decoy-hit', family: 'Honeypot', count: 19 },
  { id: 'intel.scanner-ua', family: 'Intel', count: 17 },
  { id: 'limit.payload-truncated', family: 'Limit', count: 3 },
];

/** Per hour. */
const TOP_PATHS: Dashboard['top_paths'] = [
  { prefix: '/api/search', count: 182_400, by_verdict: [171_000, 6_200, 1_400, 3_800] },
  { prefix: '/login', count: 96_300, by_verdict: [90_100, 3_900, 600, 1_700] },
  { prefix: '/api/items', count: 64_800, by_verdict: [62_900, 1_100, 300, 500] },
  { prefix: '/static', count: 51_200, by_verdict: [51_150, 40, 0, 10] },
  { prefix: '/account', count: 23_900, by_verdict: [22_800, 600, 120, 380] },
];

/** Per hour, aligned with DECOYS. */
const DECOY_HITS: [number, number | null, string | null][] = [
  [9, 4 * MIN, '203.0.113.51'], [6, 11 * MIN, '203.0.113.200'], [3, 26 * MIN, '203.0.113.200'], [1, 48 * MIN, '192.0.2.144'], [0, null, null],
];

export const BASE_RPS: Counters['rps_by_verdict'] = [412.3, 18.6, 4.1, 38.2];

export interface Fixtures {
  /** The engine's ban records, keyed by source. */
  banRecords: Map<string, BanRecord>;
  session: Session;
  status: StatusRecord;
  counters: Counters;
  board: SourceView[];
  bans: BanEntry[];
  decoys: string[];
  dashboard(from: number, to: number): Dashboard;
}

export function makeFixtures(now: number): Fixtures {
  const banRecords = new Map<string, BanRecord>();
  for (const [key, , , , , , , , , , ban] of ROWS) {
    if (!ban) continue;
    const ttl = HOUR * 2 ** (ban.offences - 1);
    const until_ms = ban.inMs === null ? FOREVER : now + ban.inMs;
    const since_ms = ban.inMs === null ? now - 30 * MIN : until_ms - ttl;
    banRecords.set(key, { since_ms, until_ms, cause: ban.cause, offences: ban.offences });
  }
  const board: SourceView[] = ROWS.map(([key, ip, stage, path, counts, requests, blocked, honeypot, constructs, lastAgo]) => {
    const rec = banRecords.get(key);
    return {
      key, ip, stage,
      stage_path: path.map(([s, ago]) => ({ stage: s, first_ts_ms: now - ago })),
      stage_counts: counts,
      requests, blocked, honeypot_hits: honeypot, top_constructs: constructs,
      first_seen_ms: now - Math.max(...path.map(([, ago]) => ago)) - MIN,
      last_seen_ms: now - lastAgo,
      ban: rec ? banView(rec) : null,
    };
  });
  const bans: BanEntry[] = [...banRecords].map(([key, rec]) => banEntry(key, rec));

  const dashboard = (from: number, to: number): Dashboard => {
    const buckets = 60;
    const bucket_ms = Math.max(1, Math.floor((to - from) / buckets));
    const perBucket = bucket_ms / MIN;
    const rnd = mulberry32(7);
    const series = BASE_RPS.map((rps, v) =>
      Array.from({ length: buckets }, (_, i) => {
        const wave = 1 + 0.08 * Math.sin(i / 7 + v) + 0.04 * (rnd() - 0.5);
        const burst = v === 3 && i > 44 && i < 52 ? 2.4 : 1;
        return Math.round(rps * 60 * perBucket * wave * burst);
      }),
    ) as Dashboard['requests_by_verdict'];
    const scale = (to - from) / HOUR;
    const byStage = Object.fromEntries(STAGES.map((s) => [s, board.filter((b) => b.stage === s).length]));
    return {
      from_ms: from,
      to_ms: to,
      bucket_ms,
      requests_by_verdict: series,
      sources_by_stage: { Clean: 1832, ...byStage } as Dashboard['sources_by_stage'],
      top_constructs: TOP_CONSTRUCTS.map((c) => ({ ...c, count: Math.round(c.count * scale) })),
      top_paths: TOP_PATHS.map((p) => ({
        prefix: p.prefix,
        count: Math.round(p.count * scale),
        by_verdict: p.by_verdict.map((n) => Math.round(n * scale)) as [number, number, number, number],
      })),
      honeypot_hits: DECOYS.map((path, i) => ({
        path,
        count: Math.round(DECOY_HITS[i][0] * scale),
        last_ts_ms: DECOY_HITS[i][1] === null ? null : now - (DECOY_HITS[i][1] as number),
        last_src: DECOY_HITS[i][2],
      })),
      active_bans: bans.length,
      dropped: 0,
    };
  };

  return {
    banRecords,
    session: { perm: 'Admin', key_id: 'k_7f3a', expires_ms: now + 7 * 24 * HOUR },
    status: {
      worst: 'Ok',
      components: ['proxy', 'history', 'live', 'intel'].map((name) => ({ name, state: 'Ok' as const, msg: '' })),
      drops: { history: 0, live: 0, jsonl: 0 },
      config_rev: 12,
      version: '0.1.0',
      restart_required: false,
    },
    counters: { rps_by_verdict: [...BASE_RPS] as Counters['rps_by_verdict'], dropped_total: 0 },
    board,
    bans,
    decoys: DECOYS,
    dashboard,
  };
}
