// A TS port of the scoped-exception rules in crates/vft-core/src/exceptions.rs: dates, family wildcards,
// per-entry validation and the YAML form. Pinned to the Rust code by the shared cases
// (crates/vft-core/tests/fixtures/exception-cases.json) and the construct registry JSON (blessed from
// `sinks::constructs()`), which both test suites read. The file's authority stays in the engine: the
// console validates to give feedback before a save, and the engine validates again when it loads.
import registry from '../../../crates/vft-core/tests/fixtures/construct-registry.json';
import type { ExceptionEntry } from './api/types';

const DAY_MS = 86_400_000;
const MAX_LIFETIME_DAYS = 365;

// --- dates (UTC, proleptic Gregorian) ---

/** Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm, as the Rust port). */
function daysFromCivil(y: number, m: number, d: number): number {
  if (m <= 2) y -= 1;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const mp = (m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146_097 + doe - 719_468;
}

function civilFromDays(z: number): [y: number, m: number, d: number] {
  z += 719_468;
  const era = Math.floor(z / 146_097);
  const doe = z - era * 146_097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36_524) - Math.floor(doe / 146_096)) / 365);
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  return [yoe + era * 400 + (m <= 2 ? 1 : 0), m, d];
}

/** `YYYY-MM-DD` (1970 and later) as ms at 00:00 UTC; null if malformed or not a real date. */
export function parseDate(s: string): number | null {
  // `\d` is ASCII-only in JS, as the Rust digit check is.
  const t = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!t) return null;
  const [y, m, d] = [Number(t[1]), Number(t[2]), Number(t[3])];
  if (y < 1970 || m < 1 || m > 12 || d === 0) return null;
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
  if (d > dim) return null;
  return daysFromCivil(y, m, d) * DAY_MS;
}

/** The UTC date of `ms` as `YYYY-MM-DD`. */
export function formatDate(ms: number): string {
  const [y, m, d] = civilFromDays(Math.floor(ms / DAY_MS));
  const p = (n: number, w: number) => String(n).padStart(w, '0');
  return `${p(y, 4)}-${p(m, 2)}-${p(d, 2)}`;
}

// --- constructs ---

type Kind = 'Sink' | 'Latent' | 'Signature' | 'Decoder' | 'Limit' | 'Gate';
interface Registered { id: string; family: string | null; kind: Kind }
const CONSTRUCTS = registry as Registered[];
const BY_ID = new Map(CONSTRUCTS.map((c) => [c.id, c]));

/** `<family>.*` wildcards and the Rust `Family` variant each one names. */
const FAMILY_WILDCARDS = new Map<string, string>([
  ['sqli', 'Sqli'], ['xss', 'Xss'], ['cmd', 'CommandInjection'], ['path', 'PathTraversal'],
  ['recon', 'Recon'], ['honeypot', 'Honeypot'], ['intel', 'Intel'], ['anomaly', 'Anomaly'],
]);
const DENY_LISTED = 'intel.deny-listed';
/** Judged and attributed against exceptions with no `field` only (`REQUEST_LEVEL` in the Rust module). */
export const REQUEST_LEVEL: readonly string[] = ['recon.sensitive-path-probe', 'honeypot.decoy-hit', 'intel.scanner-ua'];

export interface Issue { code: string; msg: string }

/** What a wildcard may expand to: a detection that scores, and never the deny list. */
const eligible = (c: Registered) => (c.kind === 'Sink' || c.kind === 'Latent' || c.kind === 'Signature') && c.id !== DENY_LISTED;

function expand(names: string[]): { ids: string[]; issues: Issue[] } {
  const ids: string[] = [];
  const issues: Issue[] = [];
  const bad = (code: string, msg: string) => issues.push({ code, msg });
  for (const n of names) {
    if (n.endsWith('.*')) {
      const fam = FAMILY_WILDCARDS.get(n.slice(0, -2));
      if (fam === undefined) { bad('unknown-construct', `unknown family wildcard ${JSON.stringify(n)}`); continue; }
      const hit = CONSTRUCTS.filter((c) => c.family === fam && eligible(c)).map((c) => c.id);
      if (hit.length === 0) bad('empty-wildcard', `${JSON.stringify(n)} names no exceptable construct`);
      ids.push(...hit);
      continue;
    }
    if (n.startsWith('chain.') || n === DENY_LISTED) { bad('forbidden-target', `${n} can never be excepted`); continue; }
    const c = BY_ID.get(n);
    if (c === undefined) bad('unknown-construct', `unknown construct id ${JSON.stringify(n)}`);
    else if (c.kind === 'Limit') bad('forbidden-target', `${n} is a limit and can never be excepted`);
    else if (c.kind === 'Decoder' || c.kind === 'Gate') bad('not-a-detection', `${n} is a ${c.kind}, not a detection`);
    else ids.push(c.id);
  }
  return { ids: [...new Set(ids)].sort(), issues };
}

/**
 * Construct ids and family wildcards as the engine expands them: the registered, exceptable construct ids
 * (sorted, unique), and the code of every name that could not be expanded. A file with any code is rejected
 * by the engine, so `ids` is only the preview of what the valid names would cover.
 */
export function expandConstructs(names: string[]): { ids: string[]; codes: string[] } {
  const { ids, issues } = expand(names);
  return { ids, codes: issues.map((i) => i.code) };
}

// --- validation ---

/** Every problem with one entry at `asOfMs`, with the codes and messages of `validate_entry`. */
export function validateEntry(e: ExceptionEntry, asOfMs: number): Issue[] {
  const v: Issue[] = [];
  const bad = (code: string, msg: string) => v.push({ code, msg });
  if (!/^[a-z0-9-]{1,64}$/.test(e.id)) bad('id-format', 'id must be 1-64 chars of [a-z0-9-]');
  if (e.owner.trim() === '') bad('required', 'owner is required');
  if (e.reason.trim() === '') bad('required', 'reason is required');
  const date = (name: string, s: string) => {
    const d = parseDate(s);
    if (d === null) bad('date', `${name} ${JSON.stringify(s)} is not a YYYY-MM-DD date`);
    return d;
  };
  const [c, m, x] = [date('created', e.created), date('modified', e.modified), date('expires', e.expires)];
  if (c !== null && m !== null && m < c) bad('modified-order', 'modified is before created');
  if (m !== null && x !== null) {
    if (x <= m) bad('expires-order', 'expires must be after modified');
    else if (x - m > MAX_LIFETIME_DAYS * DAY_MS) bad('expires-too-far', `expires is more than ${MAX_LIFETIME_DAYS} days after modified`);
  }
  if (x !== null && x <= asOfMs) bad('expired', `expired on ${e.expires} (as of ${formatDate(asOfMs)})`);
  for (const meth of e.scope.methods) {
    if (!/^[A-Za-z]+$/.test(meth)) bad('method', `bad method ${JSON.stringify(meth)}`);
  }
  if (!e.scope.path_prefix.startsWith('/')) bad('path-prefix', 'path_prefix must start with /');
  const f = e.scope.field;
  if (f !== null && f.name === '') bad('field-name', 'field.name is empty');
  if (e.action === 'skip-inspection') {
    if (e.constructs.length > 0) bad('constructs-on-skip', 'skip-inspection takes no constructs');
    if (f === null) bad('skip-needs-field', 'skip-inspection needs scope.field');
    else if (/[*?]/.test(f.name)) bad('skip-wildcard', 'skip-inspection needs an exact field name');
  } else if (e.constructs.length === 0) {
    bad('constructs-missing', 'constructs is required');
  } else {
    const { ids, issues } = expand(e.constructs);
    v.push(...issues);
    // Request-level constructs are reached only by field-less exceptions.
    if (issues.length === 0 && f !== null && ids.every((c) => REQUEST_LEVEL.includes(c))) {
      bad('field-unreachable', `constructs ${ids.join(', ')} are request-level; remove scope.field so the exception can apply`);
    }
  }
  return v;
}

// --- display ---

/** `GET /search · header referer`: methods (omitted when any), the path prefix, then the field (omitted when none). */
export function scopeLabel(e: ExceptionEntry): string {
  const { methods, path_prefix, field } = e.scope;
  const where = methods.length > 0 ? `${methods.join(',')} ${path_prefix}` : path_prefix;
  return field === null ? where : `${where} · ${field.loc} ${field.name}`;
}

/** Whether the engine would still select the exception at `ms` (`now < expires`); a malformed date is never live. */
export function liveAt(e: ExceptionEntry, ms: number): boolean {
  const x = parseDate(e.expires);
  return x !== null && ms < x;
}

// --- YAML ---

/** A JSON string is a YAML double-quoted scalar, except that YAML 1.1 also breaks lines at U+0085, U+2028 and U+2029. */
const LINE_BREAKS = new RegExp(`[${String.fromCharCode(0x85, 0x2028, 0x2029)}]`, 'g');
const quote = (s: string) => JSON.stringify(s).replace(LINE_BREAKS, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
/** Plain when it cannot be read as anything but a string (no leading indicator, no flow or comment syntax), else quoted. */
const scalar = (s: string) => (/^[A-Za-z0-9_/][A-Za-z0-9_.\-*?/]*$/.test(s) && !/^(true|false|null|yes|no|on|off|y|n|[-+.\d]+)$/i.test(s) ? s : quote(s));
const flow = (xs: string[]) => `[${xs.map(scalar).join(', ')}]`;
/** Dates and ids are bare when well formed; a malformed one is quoted so the text still parses as a string. */
const bare = (s: string, re: RegExp) => (re.test(s) ? s : quote(s));

/**
 * The entry as an item of the file's `exceptions:` list (`  - id: …`). Prefixed with
 * `version: 1\nexceptions:\n`, it parses back to an equal entry. `owner` and `reason` are always quoted.
 */
export function toYaml(e: ExceptionEntry): string {
  const { methods, path_prefix, field } = e.scope;
  const lines = [`  - id: ${bare(e.id, /^[a-z0-9-]+$/)}`, `    action: ${e.action}`];
  if (e.constructs.length > 0) lines.push(`    constructs: ${flow(e.constructs)}`);
  lines.push('    scope:');
  if (methods.length > 0) lines.push(`      methods: ${flow(methods)}`);
  lines.push(`      path_prefix: ${scalar(path_prefix)}`);
  if (field !== null) lines.push(`      field: { loc: ${field.loc}, name: ${scalar(field.name)} }`);
  const date = (s: string) => bare(s, /^\d{4}-\d{2}-\d{2}$/);
  lines.push(
    `    owner: ${quote(e.owner)}`, `    reason: ${quote(e.reason)}`,
    `    created: ${date(e.created)}`, `    modified: ${date(e.modified)}`, `    expires: ${date(e.expires)}`,
  );
  return lines.join('\n') + '\n';
}
