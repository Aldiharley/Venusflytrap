import type { Counters, Dashboard, SourceView, StatusRecord, Verdict } from '../../lib/api/types';
import type { PropName } from '../../lib/assets';
import { fmtCount, fmtRps } from '../../lib/format';
import { ANCHOR, BOX, type Box, type NodeId } from './geometry';

export type Step = 0 | 1 | 2 | 3 | 4;
export const volumeStep = (rps: number): Step => (rps <= 0 ? 0 : rps < 1 ? 1 : rps < 10 ? 2 : rps < 100 ? 3 : 4);

export interface Rates { recon: { passed: number; blocked: number }; exploit: { passed: number; blocked: number }; quarantine: number }

const isRecon = (s: SourceView) => !s.ban && (s.stage === 'Recon' || s.stage === 'Enumeration');
const isExploit = (s: SourceView) => !s.ban && (s.stage === 'Exploitation' || s.stage === 'Exfiltration');

/** Per-second rates derived from two board snapshots (G9: approximate). */
export function clusterRates(prev: SourceView[], next: SourceView[], dtMs: number): Rates {
  const before = new Map(prev.map((s) => [s.key, s]));
  const sec = Math.max(dtMs, 1) / 1000;
  const r: Rates = { recon: { passed: 0, blocked: 0 }, exploit: { passed: 0, blocked: 0 }, quarantine: 0 };
  for (const s of next) {
    const p = before.get(s.key);
    if (!p) continue;
    const req = Math.max(0, s.requests - p.requests) / sec;
    const blk = Math.max(0, s.blocked - p.blocked) / sec;
    if (s.ban) r.quarantine += req;
    else if (isRecon(s)) { r.recon.passed += req - blk; r.recon.blocked += blk; }
    else if (isExploit(s)) { r.exploit.passed += req - blk; r.exploit.blocked += blk; }
  }
  return r;
}

export interface ModelInput {
  counters: Counters;
  board: SourceView[];
  rates: Rates;
  dashboard: Dashboard | null;
  status: StatusRecord | null;
  now: number;
}

export interface TopoNode {
  id: NodeId;
  kind: 'cluster' | 'tower' | 'route' | 'honeypot' | 'quarantine';
  label: string;
  countText: string;
  rateText: string;
  /** Accessible name: label, count and rate (UX §4). */
  name: string;
  prop: PropName;
  box: Box;
  approx: boolean;
  /** Present only for nodes with data behind them. */
  ref: string | null;
}

export interface TopoFlow {
  id: string;
  from: string;
  to: string;
  verdict: Verdict;
  rps: number;
  rateText: string;
  step: Step;
  d: string;
  mid: [number, number];
  approx: boolean;
}

const MAX_PODS = 4;

function seg(a: [number, number], b: [number, number], offset: number): { d: string; mid: [number, number] } {
  const [dx, dy] = [b[0] - a[0], b[1] - a[1]];
  const len = Math.hypot(dx, dy) || 1;
  const [nx, ny] = [(-dy / len) * offset, (dx / len) * offset];
  const p = (q: [number, number]) => `${(q[0] + nx).toFixed(1)},${(q[1] + ny).toFixed(1)}`;
  return { d: `M${p(a)} L${p(b)}`, mid: [(a[0] + b[0]) / 2 + nx, (a[1] + b[1]) / 2 + ny] };
}

export function buildModel(i: ModelInput): { nodes: TopoNode[]; flows: TopoFlow[] } {
  const [allow, monitor, challenge, block] = i.counters.rps_by_verdict;
  const total = allow + monitor + challenge + block;
  const rangeSec = i.dashboard ? Math.max(1, (i.dashboard.to_ms - i.dashboard.from_ms) / 1000) : 3600;
  const recon = i.board.filter(isRecon);
  const exploit = i.board.filter(isExploit);
  const banned = i.board.filter((s) => s.ban);
  const paths = (i.dashboard?.top_paths ?? []).slice(0, 5);
  const hits = i.dashboard?.honeypot_hits ?? [];
  const extra = Math.max(0, hits.length - MAX_PODS);
  const hpRates = hits.slice(0, MAX_PODS).map((h) => h.count / rangeSec);

  const node = (id: NodeId, kind: TopoNode['kind'], label: string, countText: string, unit: string, rps: number, approx: boolean, ref: string | null): TopoNode => {
    const rateText = fmtRps(rps);
    return {
      id, kind, label, countText, rateText, approx, ref, prop: BOX[id].prop, box: BOX[id],
      name: `${label}, ${countText} ${unit}, ${rateText.replace('/s', ' requests per second')}${approx ? ' (approx.)' : ''}`,
    };
  };

  const nodes: TopoNode[] = [
    node('clean', 'cluster', 'Clean sources', fmtCount(allow + monitor), 'requests per second forwarded', allow + monitor, false, null),
    node('recon', 'cluster', 'Recon cluster', String(recon.length), 'sources', i.rates.recon.passed + i.rates.recon.blocked, true, 'Recon'),
    node('exploit', 'cluster', 'Exploitation cluster', String(exploit.length), 'sources', i.rates.exploit.passed + i.rates.exploit.blocked, true, 'Exploitation'),
    node('tower', 'tower', 'Venusflytrap', `rev ${i.status?.config_rev ?? '—'}`, 'config', total, false, null),
    ...([0, 1, 2, 3, 4] as const).map((k) => {
      const p = paths[k];
      return node(`route${k}`, 'route', p ? p.prefix : `Route ${k + 1}`, p ? fmtCount(p.count) : '0', 'requests in range', p ? (p.by_verdict[0] + p.by_verdict[1]) / rangeSec : 0, false, p?.prefix ?? null);
    }),
    ...([0, 1, 2, 3] as const).map((k) => {
      const h = hits[k];
      const more = k === MAX_PODS - 1 && extra > 0 ? ` (+${extra} more)` : '';
      return node(`hp${k}`, 'honeypot', h ? `${h.path}${more}` : `Decoy ${k + 1}`, h ? fmtCount(h.count) : '0', 'hits in range', hpRates[k] ?? 0, false, h?.path ?? null);
    }),
    node('quarantine', 'quarantine', 'Quarantine', String(banned.length), 'banned sources', i.rates.quarantine, true, null),
  ];

  const flows: TopoFlow[] = [];
  const add = (from: string, to: string, a: [number, number], b: [number, number], lines: [Verdict, number][], approx: boolean) => {
    const shown = lines.filter(([, r]) => r > 0);
    const list = shown.length ? shown : lines.slice(0, 1);
    list.forEach(([verdict, rps], k) => {
      const { d, mid } = seg(a, b, (k - (list.length - 1) / 2) * 4);
      flows.push({ id: `${from}-${to}-${verdict}`, from, to, verdict, rps, rateText: fmtRps(rps), step: volumeStep(rps), d, mid, approx });
    });
  };
  const A = ANCHOR;
  add('Internet', 'Clean sources', A.edge, A.clean, [['Allow', allow], ['Monitor', monitor]], false);
  add('Internet', 'Recon cluster', A.edge, A.recon, [['Allow', i.rates.recon.passed], ['Block', i.rates.recon.blocked]], true);
  add('Internet', 'Exploitation cluster', A.edge, A.exploit, [['Allow', i.rates.exploit.passed], ['Block', i.rates.exploit.blocked]], true);
  add('Clean sources', 'Junction', A.clean, A.jA, [['Allow', allow], ['Monitor', monitor]], false);
  add('Recon cluster', 'Junction', A.recon, A.jA, [['Allow', i.rates.recon.passed], ['Block', i.rates.recon.blocked]], true);
  add('Exploitation cluster', 'Junction', A.exploit, A.jA, [['Allow', i.rates.exploit.passed], ['Block', i.rates.exploit.blocked]], true);
  add('Junction', 'Venusflytrap', A.jA, A.tower, [['Allow', allow], ['Monitor', monitor], ['Challenge', challenge], ['Block', block]], false);
  add('Venusflytrap', 'Upstream', A.tower, A.jB, [['Allow', allow], ['Monitor', monitor]], false);
  paths.forEach((p, k) => {
    add('Upstream', p.prefix, A.jB, A[`route${k}` as NodeId], [['Allow', p.by_verdict[0] / rangeSec], ['Monitor', p.by_verdict[1] / rangeSec]], false);
  });
  hits.slice(0, MAX_PODS).forEach((h, k) => {
    add('Venusflytrap', h.path, A.tower, A[`hp${k}` as NodeId], [['Block', hpRates[k]]], false);
  });
  add('Venusflytrap', 'Quarantine', A.tower, A.quarantine, [['Block', i.rates.quarantine]], true);
  const detected = Math.max(0, block - hpRates.reduce((a, b) => a + b, 0) - i.rates.quarantine);
  add('Venusflytrap', 'Stopped at shield', A.tower, A.stub, [['Challenge', challenge], ['Block', detected]], true);
  return { nodes, flows };
}
