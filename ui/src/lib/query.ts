// The Monitor query language as the console reads it (UX §5): space-separated `field:value`
// terms, ANDed. `-` negates, a trailing `*` matches a prefix, "quotes" allow spaces, and the
// numeric fields take `>=`, `<=`, `>`, `<`. The server's parser stays authoritative (a 400
// with a position); this one drives highlighting, suggestions and the fixture source.
import type { HistoryRow } from './api/types';
import { STAGES, VERDICTS } from './api/types';

export const FIELDS = ['src', 'path', 'construct', 'stage', 'verdict', 'method', 'host', 'cause', 'config_rev', 'score', 'id'] as const;
export type Field = (typeof FIELDS)[number];
const NUMERIC: ReadonlySet<Field> = new Set(['score', 'config_rev']);
export const FIELD_HELP: Record<Field, string> = {
  src: 'source key', path: 'request path', construct: 'construct id', stage: 'kill-chain stage', verdict: 'verdict',
  method: 'HTTP method', host: 'host', cause: 'decided_by kind', config_rev: 'config revision', score: 'score', id: 'request id',
};

export type Op = '=' | '>=' | '<=' | '>' | '<';
export interface Term { field: Field; value: string; neg: boolean; op: Op; prefix: boolean }
export type TokKind = 'field' | 'operator' | 'value' | 'string' | 'number' | 'error' | 'space';
export interface Tok { text: string; kind: TokKind; start: number }
export interface ParseError { pos: number; len: number; msg: string }
export interface Parsed { terms: Term[]; toks: Tok[]; error: ParseError | null }

const isField = (s: string): s is Field => (FIELDS as readonly string[]).includes(s);
const lower = (xs: readonly string[]) => xs.map((x) => x.toLowerCase());

export function parse(q: string): Parsed {
  const toks: Tok[] = [];
  const terms: Term[] = [];
  let error: ParseError | null = null;
  const fail = (pos: number, len: number, msg: string) => { error ??= { pos, len, msg }; };
  const push = (start: number, end: number, kind: TokKind) => { if (end > start) toks.push({ text: q.slice(start, end), kind, start }); };
  let i = 0;
  while (i < q.length) {
    if (/\s/.test(q[i])) {
      const s = i;
      while (i < q.length && /\s/.test(q[i])) i++;
      push(s, i, 'space');
      continue;
    }
    // One term: [-]field:[op]value
    const termStart = i;
    const chunkEnd = () => { let j = i; while (j < q.length && !/\s/.test(q[j])) j++; return j; };
    if (q.startsWith('AND', i) && (i + 3 === q.length || /\s/.test(q[i + 3]))) {
      push(i, i + 3, 'operator');
      i += 3;
      continue;
    }
    const neg = q[i] === '-';
    if (neg) { push(i, i + 1, 'operator'); i++; }
    const nameStart = i;
    while (i < q.length && /[a-z_]/i.test(q[i])) i++;
    const name = q.slice(nameStart, i);
    if (q[i] !== ':' || !name) {
      const end = chunkEnd();
      fail(termStart, end - termStart, 'Use field:value, for example path:/login.');
      push(nameStart, end, 'error');
      i = end;
      continue;
    }
    if (!isField(name)) {
      const end = chunkEnd();
      fail(nameStart, name.length, `Unknown field "${name}".`);
      push(nameStart, end, 'error');
      i = end;
      continue;
    }
    push(nameStart, i, 'field');
    push(i, i + 1, 'operator');
    i++;
    let op: Op = '=';
    if (NUMERIC.has(name)) {
      const m = /^(>=|<=|>|<)/.exec(q.slice(i));
      if (m) { op = m[1] as Op; push(i, i + m[1].length, 'operator'); i += m[1].length; }
    }
    const valStart = i;
    let value: string;
    let prefix = false;
    if (q[i] === '"') {
      i++;
      let v = '';
      while (i < q.length && q[i] !== '"') { if (q[i] === '\\' && i + 1 < q.length) i++; v += q[i]; i++; }
      if (q[i] !== '"') { fail(valStart, i - valStart, 'Unclosed quote.'); push(valStart, i, 'error'); continue; }
      i++;
      push(valStart, i, 'string');
      value = v;
    } else {
      i = chunkEnd();
      value = q.slice(valStart, i);
      if (value.endsWith('*')) { prefix = true; value = value.slice(0, -1); }
      if (!value && !prefix) { fail(termStart, i - termStart, `Missing value after "${name}:".`); continue; }
      const bad =
        (NUMERIC.has(name) && !/^\d+$/.test(value)) ||
        (name === 'verdict' && !lower(VERDICTS).includes(value.toLowerCase())) ||
        (name === 'stage' && ![...lower(STAGES), 'clean'].includes(value.toLowerCase()));
      if (bad) {
        const what = NUMERIC.has(name) ? 'a whole number' : name === 'verdict' ? 'allow, monitor, challenge or block' : 'clean, recon, enumeration, exploitation or exfiltration';
        fail(valStart, i - valStart, `${name} takes ${what}.`);
        push(valStart, i, 'error');
        continue;
      }
      push(valStart, i, /^\d+$/.test(value) ? 'number' : 'value');
    }
    terms.push({ field: name, value, neg, op, prefix });
  }
  return { terms, toks, error };
}

function fieldValue(r: HistoryRow, f: Field): string | number {
  switch (f) {
    case 'src': return r.src_key;
    case 'path': return r.path;
    case 'construct': return r.construct ?? '';
    case 'stage': return r.stage ?? 'clean';
    case 'verdict': return r.verdict;
    case 'method': return r.method;
    case 'host': return r.host;
    case 'cause': return r.cause;
    case 'config_rev': return r.config_rev;
    case 'score': return r.score;
    case 'id': return r.id;
  }
}

export function matches(r: HistoryRow, terms: Term[]): boolean {
  return terms.every((t) => {
    const v = fieldValue(r, t.field);
    let ok: boolean;
    if (typeof v === 'number') {
      const n = Number(t.value);
      ok = t.op === '>=' ? v >= n : t.op === '<=' ? v <= n : t.op === '>' ? v > n : t.op === '<' ? v < n : v === n;
    } else {
      const a = v.toLowerCase();
      const b = t.value.toLowerCase();
      ok = t.prefix ? a.startsWith(b) : a === b;
    }
    return ok !== t.neg;
  });
}

export const quote = (v: string) => (/[\s"]/.test(v) || v === '' ? `"${v.replace(/["\\]/g, '\\$&')}"` : v);
export const termText = (t: Term) => `${t.neg ? '-' : ''}${t.field}:${t.op === '=' ? '' : t.op}${quote(t.value)}${t.prefix ? '*' : ''}`;

/** Adds `field:value` (or its negation), replacing a term for the same value. A query with an error is appended to as typed. */
export function addTerm(q: string, field: Field, value: string, neg: boolean): string {
  const add: Term = { field, value, neg, op: '=', prefix: false };
  const p = parse(q);
  if (p.error) return `${q.trimEnd()} ${termText(add)}`.trim();
  const kept = p.terms.filter((t) => !(t.field === field && t.op === '=' && !t.prefix && t.value.toLowerCase() === value.toLowerCase()));
  return [...kept, add].map(termText).join(' ');
}

/** The whitespace-delimited term around the caret, for suggestions. */
export function tokenAt(q: string, caret: number): { start: number; end: number; neg: boolean; field: string | null; partial: string } {
  let start = caret;
  while (start > 0 && !/\s/.test(q[start - 1])) start--;
  let end = caret;
  while (end < q.length && !/\s/.test(q[end])) end++;
  const text = q.slice(start, caret);
  const neg = text.startsWith('-');
  const body = neg ? text.slice(1) : text;
  const colon = body.indexOf(':');
  return colon < 0
    ? { start, end, neg, field: null, partial: body }
    : { start, end, neg, field: body.slice(0, colon), partial: body.slice(colon + 1).replace(/^"/, '') };
}
