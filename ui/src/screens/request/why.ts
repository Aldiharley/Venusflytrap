// The "why" panel of Request details (UX §6), as pure functions so the sentence, the
// contributions order and the gauge geometry are testable without rendering.
import type { Bands, Contribution, ExceptionEntry, FieldRef, RequestDetail, Verdict } from '../../lib/api/types';

/** One run of the why sentence: plain text, inline code, or a link. */
export interface Part { text: string; code?: boolean; href?: string }

export const fieldLabel = (f: FieldRef) => `${f.loc.toLowerCase()}:${f.name}`;
export const settingHref = (key: string) => `/settings?highlight=${encodeURIComponent(key)}`;
/** `chain.*` ids record chain decisions; they are not constructs that can be disabled. */
export const constructHref = (id: string) =>
  id.startsWith('chain.') ? null : `/settings?highlight=shield.disabled&construct=${encodeURIComponent(id)}`;

const VERB: Record<Verdict, string> = { Block: 'Blocked', Challenge: 'Challenged', Monitor: 'Flagged', Allow: 'Allowed' };
const HHMM = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });

export function whyParts(d: RequestDetail): Part[] {
  const c = d.judgment.decided_by;
  const code = (text: string, href?: string): Part => ({ text, code: true, href });
  switch (c.kind) {
    case 'Detection':
    case 'ChainEscalation': {
      const parts: Part[] = [
        { text: `${VERB[d.judgment.verdict]}: score ${d.judgment.score} reached ` },
        code(c.option_key, settingHref(c.option_key)),
        { text: ` = ${d.setting.value} (${d.setting.source}).` },
      ];
      if (c.kind === 'ChainEscalation') parts.push({ text: ' A kill-chain stage advance added the bonus that crossed the band.' });
      if (c.construct) {
        parts.push({ text: ' Top evidence: ' }, code(c.construct));
        if (c.field) parts.push({ text: ' in ' }, code(fieldLabel(c.field)));
        parts.push({ text: '.' });
      }
      return parts;
    }
    case 'Honeypot': return [{ text: 'Request hit decoy ' }, code(d.row.path), { text: '.' }];
    case 'Ban':
      return d.ban?.until_ms === null
        ? [{ text: 'Source banned permanently.' }]
        : [{ text: `Source banned until ${d.ban ? HHMM.format(d.ban.until_ms) : 'its ban expires'}.` }];
    case 'IntelDeny': return [{ text: 'Source on intel deny list.' }];
    case 'Limit': return [{ text: 'Fail-closed: ' }, code('limit.payload-truncated'), { text: ' (' }, code(c.option_key, settingHref(c.option_key)), { text: ').' }];
    case 'Allowlisted': return [{ text: 'Source allow-listed.' }];
    case 'NoEvidence': return [{ text: 'No evidence; allowed.' }];
  }
}

/**
 * The skip-inspection exceptions of a request that name this skipped field: entries in `ids` (the request's
 * exceptions) whose `scope.field` is the field's location and name (skip-inspection names are exact; ASCII
 * case-insensitive). Empty while the exceptions file is not loaded: no id is guessed.
 */
export function skippingIds(f: FieldRef, ids: string[], entries: ExceptionEntry[] | null): string[] {
  return ids.filter((id) => {
    const e = entries?.find((x) => x.id === id);
    const m = e?.scope.field;
    return e?.action === 'skip-inspection' && !!m && m.loc === f.loc.toLowerCase() && m.name.toLowerCase() === f.name.toLowerCase();
  });
}

export interface ContributionRow { c: Contribution; top: boolean }

/** Scored contributions by points (largest first), then shadow ones; `sum` covers scored points only. */
export function contributionRows(cs: Contribution[], score: number): { items: ContributionRow[]; sum: number; exact: boolean } {
  const scored = cs.filter((c) => !c.shadow).sort((a, b) => b.points - a.points);
  const shadow = cs.filter((c) => c.shadow);
  const sum = scored.reduce((a, c) => a + c.points, 0);
  return {
    items: [...scored.map((c, i) => ({ c, top: i === 0 && c.points > 0 })), ...shadow.map((c) => ({ c, top: false }))],
    sum,
    exact: Math.abs(sum - score) < 0.05,
  };
}

/**
 * What the Σ points footer says was left out. A log-only exception turns a contribution into a shadow
 * one (`exception` names it), so the two kinds are told apart here and `contributionRows` needs no change.
 */
export function excludedNote(cs: Contribution[]): string {
  const shadow = cs.some((c) => c.shadow && c.exception === null);
  const suppressed = cs.some((c) => c.exception !== null);
  return shadow && suppressed ? ' (shadow and suppressed rows excluded)' : shadow ? ' (shadow rows excluded)' : suppressed ? ' (suppressed rows excluded)' : '';
}

// Gauge: a 180° arc in a 200 × 120 viewBox, score 0 at the left, 100 at the right.
export const GAUGE = { w: 200, h: 120, cx: 100, cy: 108, track: 72, band: 86, label: 100 };

export function pointAt(score: number, r: number): [number, number] {
  const t = Math.PI * (1 - Math.max(0, Math.min(100, score)) / 100);
  return [GAUGE.cx + r * Math.cos(t), GAUGE.cy - r * Math.sin(t)];
}

export function arc(from: number, to: number, r: number): string {
  const [x1, y1] = pointAt(from, r);
  const [x2, y2] = pointAt(to, r);
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

export function bandOf(score: number, b: Bands): Verdict {
  return score >= b.block_at ? 'Block' : score >= b.challenge_at ? 'Challenge' : score >= b.monitor_at ? 'Monitor' : 'Allow';
}

export function gaugeSentence(score: number, b: Bands, rev: number): string {
  return `Score ${score} of 100. Bands at rev ${rev}: Monitor ≥ ${b.monitor_at}, Challenge ≥ ${b.challenge_at}, Block ≥ ${b.block_at}.`;
}
