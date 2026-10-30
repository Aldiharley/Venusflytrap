import { expect, test } from 'vitest';
import shared from '../../../crates/vft-core/tests/fixtures/exception-cases.json';
import blessed from './__fixtures__/exceptions-yaml.txt?raw';
import { makeExceptions } from './api/fixtures';
import type { ExceptionEntry } from './api/types';
import { expandConstructs, formatDate, liveAt, parseDate, scopeLabel, toYaml, validateEntry } from './exceptions';

const DAY = 86_400_000;
// The fixture clock every console test uses (history.test.ts, fixtures.test.ts).
const NOW = Date.UTC(2026, 9, 28, 14, 5, 0);

// The Rust test (crates/vft-core/tests/exceptions_shared.rs `shared_cases_give_their_codes`) applies the same cases.
type Json = Record<string, unknown>;
const base = shared.base as unknown as ExceptionEntry;
function apply(patch: Json): ExceptionEntry {
  const out = structuredClone(base) as ExceptionEntry;
  for (const [k, v] of Object.entries(patch)) {
    if (k === 'scope') Object.assign(out.scope, v as Json);
    else (out as unknown as Json)[k] = v;
  }
  return out;
}
const asOf = parseDate(shared.as_of)!;

test("the shared cases give the Rust validator's codes", () => {
  expect(shared.cases.length).toBe(35);
  for (const c of shared.cases) {
    const got = [...new Set(validateEntry(apply(c.patch as Json), asOf).map((i) => i.code))].sort();
    expect(got, `case ${c.name}`).toEqual(c.codes);
  }
});

test('every issue has a message', () => {
  const issues = validateEntry(apply({ expires: '2026-10-30', owner: ' ', constructs: ['sqli.nope', 'chain.ban'] }), asOf);
  expect(issues.map((i) => i.code).sort()).toEqual(['expired', 'expires-order', 'forbidden-target', 'required', 'unknown-construct']);
  for (const i of issues) expect(i.msg.length).toBeGreaterThan(0);
  expect(issues.find((i) => i.code === 'expired')!.msg).toBe('expired on 2026-10-30 (as of 2026-10-30)');
  expect(issues.find((i) => i.code === 'unknown-construct')!.msg).toBe('unknown construct id "sqli.nope"');
});

test('a field-scoped exception of request-level constructs says how to make it apply', () => {
  const issues = validateEntry(apply({ constructs: ['recon.*', 'intel.scanner-ua'] }), asOf);
  expect(issues).toEqual([{ code: 'field-unreachable', msg: 'constructs intel.scanner-ua, recon.sensitive-path-probe are request-level; remove scope.field so the exception can apply' }]);
});

test('dates: bounds, leap years and the 1970 floor', () => {
  expect(parseDate('1970-01-01')).toBe(0);
  expect(parseDate('1970-01-02')).toBe(DAY);
  expect(parseDate('2000-02-29')).not.toBeNull();
  for (const s of ['2026-02-29', '2100-02-29', '2026-13-01', '2026-00-10', '1969-12-31', '2026-1-01', '2026-10-3x', '2026-10-30 ', '', '２０２６-10-30']) {
    expect(parseDate(s), s).toBeNull();
  }
  expect(parseDate('2026-10-30')).toBe(Date.UTC(2026, 9, 30));
  expect(formatDate(Date.UTC(2026, 9, 30, 23, 59, 59))).toBe('2026-10-30');
});

test('dates: every day from 1970 to 2105 round-trips and agrees with Date', () => {
  for (let ms = 0; ms < Date.UTC(2105, 0, 1); ms += DAY) {
    const s = formatDate(ms);
    expect(s).toBe(new Date(ms).toISOString().slice(0, 10));
    expect(parseDate(s)).toBe(ms);
  }
});

test('expandConstructs: ids, family wildcards and the codes of what cannot be expanded', () => {
  const sqli = expandConstructs(['sqli.*']);
  expect(sqli.codes).toEqual([]);
  expect(sqli.ids).toContain('sqli.union-select');
  expect(sqli.ids).toContain('sig.classic-or');
  expect(sqli.ids).toContain('api.type-violation');
  expect(sqli.ids.some((i) => i.startsWith('limit.') || i.startsWith('decode.'))).toBe(false);
  expect([...sqli.ids].sort()).toEqual(sqli.ids);
  expect(expandConstructs(['intel.*'])).toEqual({ ids: ['intel.scanner-ua'], codes: [] });
  expect(expandConstructs(['xss.script-tag', 'xss.script-tag', 'sqli.union-select']).ids).toEqual(['sqli.union-select', 'xss.script-tag']);
  expect(expandConstructs(['ssrf.*', 'nope', 'chain.ban', 'intel.deny-listed', 'limit.payload-truncated', 'decode.entity', 'gate.cmd-position']).codes)
    .toEqual(['unknown-construct', 'unknown-construct', 'forbidden-target', 'forbidden-target', 'forbidden-target', 'not-a-detection', 'not-a-detection']);
});

test('scopeLabel: methods joined with commas, then path, then the field', () => {
  const e = apply({ scope: { methods: ['GET'], path_prefix: '/search', field: { loc: 'header', name: 'referer' } } });
  expect(scopeLabel(e)).toBe('GET /search · header referer');
  expect(scopeLabel(apply({ scope: { methods: ['GET', 'POST'] } }))).toBe('GET,POST / · header referer');
  expect(scopeLabel(apply({ scope: { methods: [], field: null } }))).toBe('/');
  expect(scopeLabel(apply({ scope: { methods: [], path_prefix: '/hooks' } }))).toBe('/hooks · header referer');
});

test('liveAt: until the expiry day starts, as the engine selects (now < expires)', () => {
  const e = apply({ expires: '2026-11-30' });
  expect(liveAt(e, parseDate('2026-11-29')!)).toBe(true);
  expect(liveAt(e, parseDate('2026-11-30')! - 1)).toBe(true);
  expect(liveAt(e, parseDate('2026-11-30')!)).toBe(false);
  expect(liveAt(apply({ expires: 'soon' }), 0)).toBe(false);
});

const DATES = { created: '2026-10-30', modified: '2026-10-30', expires: '2026-11-30' };

test('toYaml: ignore', () => {
  const e: ExceptionEntry = {
    ...DATES, id: 'referer-sql', action: 'ignore', constructs: ['sqli.*'], owner: 'dennis', reason: 'Search referers carry SQL-looking text',
    scope: { methods: ['GET'], path_prefix: '/api', field: { loc: 'header', name: 'Refer*' } },
  };
  expect(toYaml(e)).toBe(
`  - id: referer-sql
    action: ignore
    constructs: [sqli.*]
    scope:
      methods: [GET]
      path_prefix: /api
      field: { loc: header, name: Refer* }
    owner: "dennis"
    reason: "Search referers carry SQL-looking text"
    created: 2026-10-30
    modified: 2026-10-30
    expires: 2026-11-30
`);
});

test('toYaml: log-only with no methods and no field; free text is a JSON string', () => {
  const e: ExceptionEntry = {
    ...DATES, id: 'utm-xss', action: 'log-only', constructs: ['xss.event-handler', 'xss.html-tag'], reason: 'say "hi": # not a comment\\ \n', owner: 'o: p',
    scope: { methods: [], path_prefix: '/', field: null },
  };
  expect(toYaml(e)).toBe(
`  - id: utm-xss
    action: log-only
    constructs: [xss.event-handler, xss.html-tag]
    scope:
      path_prefix: /
    owner: "o: p"
    reason: "say \\"hi\\": # not a comment\\\\ \\n"
    created: 2026-10-30
    modified: 2026-10-30
    expires: 2026-11-30
`);
});

test('toYaml: skip-inspection has no constructs line', () => {
  const e: ExceptionEntry = {
    ...DATES, id: 'hook-signature', action: 'skip-inspection', constructs: [], owner: 'dennis', reason: 'Signed payload',
    scope: { methods: ['POST'], path_prefix: '/hooks', field: { loc: 'header', name: 'x-signature' } },
  };
  expect(toYaml(e)).toBe(
`  - id: hook-signature
    action: skip-inspection
    scope:
      methods: [POST]
      path_prefix: /hooks
      field: { loc: header, name: x-signature }
    owner: "dennis"
    reason: "Signed payload"
    created: 2026-10-30
    modified: 2026-10-30
    expires: 2026-11-30
`);
});

test('toYaml quotes plain scalars that YAML would read as something else, and the line separators', () => {
  const e = apply({ id: 'x', reason: `a${String.fromCharCode(0x2028)}b${String.fromCharCode(0x85)}c`, constructs: ['*.x', 'null'], scope: { path_prefix: '/a b', field: { loc: 'query', name: '*' } } });
  const y = toYaml(e);
  expect(y).toContain('constructs: ["*.x", "null"]');
  expect(y).toContain('path_prefix: "/a b"');
  expect(y).toContain('field: { loc: query, name: "*" }');
  const bs = String.fromCharCode(92);
  expect(y).toContain(`reason: "a${bs}u2028b${bs}u0085c"`);
});

// The file Rust deserializes in crates/vft-core/tests/exceptions_shared.rs (`ui_yaml_deserializes`).
// Regenerate from ui/: VFT_BLESS=1 npx vitest run src/lib/exceptions.test.ts
test('the fixture exceptions render to the committed YAML, which Rust parses back', () => {
  const want = makeExceptions(NOW).map(toYaml).join('');
  // The project has no Node type definitions; the blessing path reaches fs through the runtime instead.
  const g = globalThis as unknown as { process: { env: Record<string, string | undefined>; cwd(): string; getBuiltinModule(id: 'node:fs'): { writeFileSync(path: string, data: string): void } } };
  if (g.process.env.VFT_BLESS) {
    g.process.getBuiltinModule('node:fs').writeFileSync(`${g.process.cwd()}/src/lib/__fixtures__/exceptions-yaml.txt`, want);
    return;
  }
  expect(blessed.replace(/\r\n/g, '\n')).toBe(want);
});

test('the fixture exceptions: three live, one expired, all well-formed otherwise', () => {
  const es = makeExceptions(NOW);
  expect(es.map((e) => e.id)).toEqual(['referer-sql', 'utm-xss', 'hook-signature', 'legacy-search']);
  expect(es.map((e) => e.action)).toEqual(['ignore', 'log-only', 'skip-inspection', 'ignore']);
  expect(es.map((e) => liveAt(e, NOW))).toEqual([true, true, true, false]);
  expect(es.slice(0, 3).flatMap((e) => validateEntry(e, NOW))).toEqual([]);
  expect(validateEntry(es[3], NOW).map((i) => i.code)).toEqual(['expired']);
});
