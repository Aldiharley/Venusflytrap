// Deterministic request history for the fixture source: one stored request every PERIOD_MS,
// generated from its index alone, so any time range can be queried and any id reopened.
// Judgments follow vft-core's rules (shield.rs `cause_for`, `ban_cause`, `banned_judgment`;
// score.rs: non-shadow points sum to the score, shadow contributions score 0).
import { matches, type Term } from '../query';
import type { Fixtures } from './fixtures';
import { DECOYS } from './fixtures';
import { mulberry32 } from './rng';
import { banView } from './views';
import type {
  Bands, BanRecord, Cause, Contribution, Family, FieldRef, GroupBy, HistoryPage, HistoryQuery, HistoryRow, Judgment,
  RequestDetail, SourceView, Verdict,
} from './types';

export const PERIOD_MS = 10_000;
/** `history.retention_days` (SP4) at its expected default. */
export const RETENTION_MS = 30 * 86_400_000;
export const CONFIG_REV = 12;
/** The engine defaults (config.rs ScoringConfig). */
export const BANDS: Bands = { monitor_at: 40, challenge_at: 70, block_at: 90 };
const HOST = 'shop.example';

export const rowId = (k: number) => `R${k.toString(36).toUpperCase()}`;
export function rowIndex(id: string): number | null {
  if (!/^R[0-9A-Z]+$/.test(id)) return null;
  const k = parseInt(id.slice(1), 36);
  return Number.isSafeInteger(k) ? k : null;
}

interface Attack {
  family: Family; engine: string; method: string; path: string; field: FieldRef;
  raw: string; decoded: string; layers: string[];
}
const q = (name: string): FieldRef => ({ loc: 'Query', name });
const PATH: FieldRef = { loc: 'Path', name: '<path>' };
const ATTACKS: Record<string, Attack> = {
  'sqli.union-select': { family: 'Sqli', engine: 'graph-taint', method: 'GET', path: '/api/items', field: q('id'), raw: '1%20union%20select%20password%20from%20users', decoded: '1 union select password from users', layers: ['url'] },
  'sqli.boolean-tautology': { family: 'Sqli', engine: 'graph-taint', method: 'GET', path: '/api/search', field: q('q'), raw: 'x%27%20or%20%271%27%3D%271', decoded: "x' or '1'='1", layers: ['url'] },
  'sqli.fn-load-file': { family: 'Sqli', engine: 'signature', method: 'GET', path: '/api/items', field: q('id'), raw: '1%20and%20load_file(%27%2Fetc%2Fpasswd%27)', decoded: "1 and load_file('/etc/passwd')", layers: ['url'] },
  'sqli.stacked-query': { family: 'Sqli', engine: 'graph-taint', method: 'POST', path: '/api/search', field: { loc: 'Body', name: 'q' }, raw: 'a%27%3B%20drop%20table%20orders--', decoded: "a'; drop table orders--", layers: ['url'] },
  'xss.event-handler': { family: 'Xss', engine: 'graph-taint', method: 'GET', path: '/api/search', field: q('q'), raw: '%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E', decoded: '<img src=x onerror=alert(1)>', layers: ['url', 'url'] },
  'cmd.chained-command': { family: 'CommandInjection', engine: 'graph-taint', method: 'POST', path: '/account', field: { loc: 'Body', name: 'host' }, raw: 'example.com%3B%20cat%20%2Fetc%2Fpasswd', decoded: 'example.com; cat /etc/passwd', layers: ['url'] },
  'recon.sensitive-path-probe': { family: 'Recon', engine: 'intent', method: 'GET', path: '/.env', field: PATH, raw: '/.env', decoded: '/.env', layers: [] },
  'intel.scanner-ua': { family: 'Intel', engine: 'signature', method: 'GET', path: '/login', field: { loc: 'Header', name: 'user-agent' }, raw: 'sqlmap/1.8.2', decoded: 'sqlmap/1.8.2', layers: [] },
  'path.directory-traversal': { family: 'PathTraversal', engine: 'graph-taint', method: 'GET', path: '/static', field: q('file'), raw: '..%2F..%2F..%2Fetc%2Fpasswd', decoded: '../../../etc/passwd', layers: ['url'] },
};
/** Constructs an operator is trialling in `shield.shadow`: they fire, but never score. */
const SHADOW: Partial<Record<Family, string>> = { Sqli: 'sqli.inline-comment', Xss: 'xss.svg-onload', PathTraversal: 'path.double-dot-encoded' };

const BENIGN: [method: string, path: string, query: string][] = [
  ['GET', '/api/search', 'q=garden%20hose'], ['GET', '/login', ''], ['POST', '/login', ''],
  ['GET', '/api/items', 'id=1042'], ['GET', '/static/app.js', ''], ['GET', '/account', ''],
];
const BENIGN_SRC: [key: string, ip: string][] = [
  ['198.51.100.31', '198.51.100.31'], ['198.51.100.47', '198.51.100.47'], ['192.0.2.201', '192.0.2.201'],
  ['192.0.2.88', '192.0.2.88'], ['203.0.113.140', '203.0.113.140'], ['2001:db8:9a::/64', '2001:db8:9a::5'],
];

const BAN_OPTION: Record<BanRecord['cause'], string> = {
  Honeypot: 'chain.ban_policy.on_honeypot',
  Exfiltration: 'chain.ban_policy.on_exfiltration_block',
  RepeatedExploitation: 'chain.ban_policy.exploitation_blocks',
  Manual: 'chain.ban_policy.ttl_secs',
};
const SETTING_VALUE: Record<string, string> = {
  'scoring.monitor_at': String(BANDS.monitor_at),
  'scoring.challenge_at': String(BANDS.challenge_at),
  'scoring.block_at': String(BANDS.block_at),
  'honeypot.decoy_paths': `${DECOYS.length} paths`,
  'chain.ban_policy.on_honeypot': 'true',
  'chain.ban_policy.on_exfiltration_block': 'true',
  'chain.ban_policy.exploitation_blocks': '3',
  'chain.ban_policy.ttl_secs': '3600',
};

const label = (f: FieldRef) => `${f.loc.toLowerCase()}:${f.name}`;
const tenth = (n: number) => Math.round(n * 10) / 10;
const pick = <T>(rnd: () => number, xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)];
const between = (rnd: () => number, lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo + 1));

/** Splits `score` into points: the top item keeps most, the rest corroborate; exact to 0.1. */
function split(score: number, n: number, rnd: () => number): number[] {
  const total = score * 10;
  if (n === 1) return [score];
  const top = Math.round(total * (0.8 + 0.12 * rnd()));
  const rest = total - top;
  const second = n === 2 ? rest : Math.round(rest * 0.6);
  return [top, second, ...(n === 3 ? [rest - second] : [])].map((t) => t / 10);
}

interface Gen { row: HistoryRow; detail: Omit<RequestDetail, 'timeline' | 'ban'> }

function bandOf(score: number): Verdict {
  if (score >= BANDS.block_at) return 'Block';
  if (score >= BANDS.challenge_at) return 'Challenge';
  if (score >= BANDS.monitor_at) return 'Monitor';
  return 'Allow';
}

function detection(score: number, a: Attack, construct: string, rnd: () => number): { contributions: Contribution[]; decided_by: Cause } {
  const verdict = bandOf(score);
  const n = 1 + Math.floor(rnd() * 3);
  const pts = split(score, n, rnd);
  const value = verdict === 'Monitor' ? 'Suspicious' : 'Dangerous';
  const contributions: Contribution[] = [
    { engine: a.engine, field: a.field, construct, family: a.family, value, weight: tenth(0.6 + 0.4 * rnd()), points: pts[0], shadow: false },
  ];
  if (n >= 2) contributions.push({ engine: 'ai', field: a.field, construct: null, family: null, value: 'Suspicious', weight: 0.6, points: pts[1], shadow: false });
  if (n >= 3) contributions.push({ engine: 'api-safety', field: a.field, construct: 'api.type-violation', family: a.family, value: 'Dangerous', weight: 0.7, points: pts[2], shadow: false });
  const shadow = SHADOW[a.family];
  if (shadow && rnd() < 0.45) {
    contributions.push({ engine: 'graph-taint', field: a.field, construct: shadow, family: a.family, value: 'Suspicious', weight: 0.5, points: 0, shadow: true });
  }
  const key = `scoring.${verdict.toLowerCase()}_at`;
  const threshold = BANDS[`${verdict.toLowerCase()}_at` as keyof Bands];
  return {
    contributions,
    decided_by: { kind: 'Detection', option_key: key, construct, field: a.field, msg: `score ${score} >= ${key} ${threshold}: ${construct} in ${label(a.field)}` },
  };
}

export interface History {
  /** The stored request at index `k` (its time is k × PERIOD_MS). */
  row(k: number): HistoryRow;
  /** The full detail for an id, or null if it is malformed, in the future or past retention. */
  detail(id: string): RequestDetail | null;
  /** Runs an already-parsed query over the range, clipped to now and retention. */
  query(hq: HistoryQuery, terms: Term[]): HistoryPage;
}

function groupValue(r: HistoryRow, g: GroupBy): string | null {
  switch (g) {
    case 'src': return r.src_key;
    case 'path': return r.path;
    case 'construct': return r.construct;
    case 'stage': return r.stage ?? 'Clean';
    case 'verdict': return r.verdict;
  }
}

export function makeHistory(f: Fixtures, now: () => number): History {
  const attackers = f.board.filter((s) => s.stage !== null);

  function gen(k: number): Gen {
    const rnd = mulberry32(Math.imul(k, 2654435761) ^ 0x5bd1e995);
    const ts_ms = k * PERIOD_MS;
    const base = { id: rowId(k), ts_ms, host: HOST, config_rev: CONFIG_REV, latency_us: between(rnd, 80, 420) };
    let src: { key: string; ip: string; stage: SourceView['stage'] };
    let method: string, path: string, query = '';
    let judgment: Judgment;
    let fields: RequestDetail['fields'] = [];

    if (rnd() < 0.55) {
      const [key, ip] = pick(rnd, BENIGN_SRC);
      src = { key, ip, stage: null };
      [method, path, query] = pick(rnd, BENIGN);
      const noisy = rnd() < 0.35;
      const score = noisy ? between(rnd, 3, 12) : 0;
      const field = query ? q(query.split('=')[0]) : PATH;
      judgment = {
        verdict: 'Allow', score,
        contributions: noisy ? [{ engine: 'ai', field, construct: null, family: null, value: 'Suspicious', weight: 0.3, points: score, shadow: false }] : [],
        decided_by: { kind: 'NoEvidence', option_key: 'scoring.monitor_at', construct: null, field: null, msg: `score ${score} < scoring.monitor_at ${BANDS.monitor_at}` },
        chain: null, normalized_layers: query.includes('%') ? 1 : 0,
      };
      if (query) fields = [{ field, raw: query.split('=')[1], decoded: decodeURIComponent(query.split('=')[1]), layers: query.includes('%') ? ['url'] : [] }];
    } else {
      const s = pick(rnd, attackers);
      src = s;
      const ban = f.banRecords.get(s.key);
      const chain = { stage_before: s.stage, stage_after: s.stage, advanced: false, new_ban: null };
      if (ban && ban.since_ms <= ts_ms && ts_ms < ban.until_ms && rnd() < 0.6) {
        const construct = pick(rnd, s.top_constructs);
        ({ method, path } = ATTACKS[construct] ?? ATTACKS['sqli.union-select']);
        judgment = {
          verdict: 'Block', score: 100,
          contributions: [{ engine: 'chain', field: null, construct: 'chain.ban', family: null, value: 'Dangerous', weight: 1, points: 100, shadow: false }],
          decided_by: { kind: 'Ban', option_key: BAN_OPTION[ban.cause], construct: 'chain.ban', field: null, msg: `source banned (${ban.cause}) until t=${ban.until_ms} ms` },
          chain: null, normalized_layers: 0,
        };
        fields = [];
      } else if (rnd() < 0.08) {
        method = 'GET';
        path = pick(rnd, DECOYS);
        judgment = {
          verdict: 'Block', score: 100,
          contributions: [{ engine: 'honeypot', field: PATH, construct: 'honeypot.decoy-hit', family: 'Honeypot', value: 'Dangerous', weight: 1, points: 100, shadow: false }],
          decided_by: { kind: 'Honeypot', option_key: 'honeypot.decoy_paths', construct: 'honeypot.decoy-hit', field: PATH, msg: 'hard-block: request hit a honeypot decoy path' },
          chain, normalized_layers: 0,
        };
        fields = [{ field: PATH, raw: path, decoded: path, layers: [] }];
      } else {
        const construct = pick(rnd, s.top_constructs);
        const a = ATTACKS[construct] ?? ATTACKS['sqli.union-select'];
        ({ method, path } = a);
        if (a.field.loc === 'Query') query = `${a.field.name}=${a.raw}`;
        const hot = s.stage === 'Exploitation' || s.stage === 'Exfiltration';
        const r = rnd();
        const score = hot
          ? (r < 0.7 ? between(rnd, 90, 100) : between(rnd, 70, 89))
          : (r < 0.7 ? between(rnd, 40, 69) : between(rnd, 70, 89));
        const { contributions, decided_by } = detection(score, a, construct, rnd);
        judgment = { verdict: bandOf(score), score, contributions, decided_by, chain, normalized_layers: a.layers.length };
        fields = [{ field: a.field, raw: a.raw, decoded: a.decoded, layers: a.layers }];
      }
    }

    const c = judgment.decided_by;
    const forwarded = judgment.verdict === 'Allow' || judgment.verdict === 'Monitor';
    const row: HistoryRow = {
      ...base, verdict: judgment.verdict, score: judgment.score, src_key: src.key, method, path,
      construct: c.construct, stage: src.stage, cause: c.kind, decided_option: c.option_key,
      upstream_status: forwarded ? (method === 'POST' && path === '/login' ? 302 : 200) : null,
      sampled: judgment.verdict === 'Allow',
    };
    return {
      row,
      detail: {
        row, ip: src.ip, query, judgment, bands: BANDS,
        setting: { key: c.option_key, value: SETTING_VALUE[c.option_key] ?? '—', source: c.option_key === 'scoring.block_at' ? 'override' : 'default', rev: CONFIG_REV },
        fields,
      },
    };
  }

  const inRange = (k: number) => {
    const ts = k * PERIOD_MS;
    return k >= 0 && ts <= now() && ts >= now() - RETENTION_MS;
  };

  return {
    row: (k) => gen(k).row,
    detail(id) {
      const k = rowIndex(id);
      if (k === null || !inRange(k)) return null;
      const { row, detail } = gen(k);
      const timeline: HistoryRow[] = [];
      for (let j = k; j > k - 4000 && timeline.length < 8 && inRange(j); j--) {
        const r = j === k ? row : gen(j).row;
        if (r.src_key === row.src_key) timeline.push(r);
      }
      const rec = f.banRecords.get(row.src_key);
      return { ...detail, ban: rec ? banView(rec) : null, timeline };
    },
    query(hq, terms) {
      const lo = Math.max(0, Math.ceil(hq.from / PERIOD_MS), Math.ceil((now() - RETENTION_MS) / PERIOD_MS));
      const hi = Math.min(Math.floor((hq.to - 1) / PERIOD_MS), Math.floor(now() / PERIOD_MS));
      const limit = Math.max(1, Math.min(1000, hq.limit ?? 100));
      if (hq.group_by) {
        const counts = new Map<string, number>();
        let total = 0;
        for (let k = hi; k >= lo; k--) {
          const r = gen(k).row;
          if (!matches(r, terms)) continue;
          const v = groupValue(r, hq.group_by);
          if (v === null) continue;
          counts.set(v, (counts.get(v) ?? 0) + 1);
          total++;
        }
        const groups = [...counts].map(([value, count]) => ({ value, count }))
          .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
        return { rows: [], groups, total, next: null };
      }
      const start = hq.cursor ? Math.min(hi, Number(hq.cursor)) : hi;
      const rows: HistoryRow[] = [];
      let total = 0;
      let next: string | null = null;
      for (let k = hi; k >= lo; k--) {
        const r = gen(k).row;
        if (!matches(r, terms)) continue;
        total++;
        if (k > start) continue;
        if (rows.length < limit) rows.push(r);
        else next ??= String(k);
      }
      return { rows, groups: null, total, next };
    },
  };
}
