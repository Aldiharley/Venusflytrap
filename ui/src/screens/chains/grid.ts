import { STAGES, type SourceView, type Stage } from '../../lib/api/types';

const MAX_ROWS = 500;
const rank = (s: SourceView) => (s.stage === null ? -1 : STAGES.indexOf(s.stage));

export function sortKeys(rows: SourceView[]): string[] {
  return [...rows]
    .sort((a, b) => rank(b) - rank(a) || b.last_seen_ms - a.last_seen_ms)
    .slice(0, MAX_ROWS)
    .map((s) => s.key);
}

/**
 * While frozen (focus inside the grid) the displayed order never changes: values update in
 * place, removed sources keep their row, and new sources wait. `pending` counts the rows
 * whose position would change on apply, plus the waiting ones.
 */
export function reconcile(order: string[], rows: SourceView[], frozen: boolean): { order: string[]; pending: number } {
  const target = sortKeys(rows);
  if (!frozen) return { order: target, pending: 0 };
  const present = new Set(target);
  const kept = order.filter((k) => present.has(k));
  const targetKept = target.filter((k) => order.includes(k));
  const moved = kept.reduce((n, k, i) => n + (targetKept[i] === k ? 0 : 1), 0);
  const added = target.filter((k) => !order.includes(k)).length;
  const removed = order.length - kept.length;
  return { order, pending: moved + added + removed };
}

export { moveCell, type Cell } from '../../lib/grid';

const CLOCK = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });

export function stageCellText(s: SourceView, stage: Stage): string {
  const reached = s.stage_path.find((p) => p.stage === stage);
  if (!reached) return '—';
  const t = CLOCK.format(reached.first_ts_ms);
  return `${t} · ${s.stage_counts[STAGES.indexOf(stage)]}`;
}
