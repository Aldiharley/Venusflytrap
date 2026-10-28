import { expect, test } from 'vitest';
import type { HistoryRow } from './api/types';
import { addTerm, matches, parse, tokenAt } from './query';

const row: HistoryRow = {
  id: 'R1', ts_ms: 0, verdict: 'Block', score: 94, src_key: '203.0.113.7', method: 'GET', host: 'shop.example',
  path: '/api/items', construct: 'sqli.union-select', stage: 'Exploitation', cause: 'Detection',
  decided_option: 'scoring.block_at', config_rev: 12, latency_us: 200, upstream_status: null, sampled: false,
};
const hit = (q: string) => {
  const p = parse(q);
  expect(p.error).toBeNull();
  return matches(row, p.terms);
};

test('field:value terms AND together, case-insensitively', () => {
  expect(hit('verdict:block')).toBe(true);
  expect(hit('verdict:BLOCK src:203.0.113.7')).toBe(true);
  expect(hit('verdict:block src:198.51.100.9')).toBe(false);
  expect(hit('')).toBe(true);
  expect(hit('verdict:block AND stage:exploitation')).toBe(true);
});

test('negation, prefix wildcards, quotes and comparisons', () => {
  expect(hit('-verdict:allow')).toBe(true);
  expect(hit('-construct:sqli.union-select')).toBe(false);
  expect(hit('construct:sqli.*')).toBe(true);
  expect(hit('path:/api/*')).toBe(true);
  expect(hit('path:/api')).toBe(false);
  expect(hit('path:"/api/items"')).toBe(true);
  expect(hit('score:>=90')).toBe(true);
  expect(hit('score:<90')).toBe(false);
  expect(hit('config_rev:12')).toBe(true);
  expect(hit('stage:clean')).toBe(false);
});

test('syntax errors carry the position and length of the bad token', () => {
  expect(parse('verdict:block colour:red').error).toEqual({ pos: 14, len: 6, msg: 'Unknown field "colour".' });
  expect(parse('src:').error).toMatchObject({ pos: 0, msg: 'Missing value after "src:".' });
  expect(parse('union select').error).toMatchObject({ pos: 0, len: 5 });
  expect(parse('verdict:maybe').error).toMatchObject({ pos: 8, len: 5 });
  expect(parse('score:>=high').error).toMatchObject({ pos: 8, len: 4 });
  expect(parse('path:"/open').error).toMatchObject({ pos: 5, msg: 'Unclosed quote.' });
});

test('tokens cover the input exactly and carry the syntax kinds', () => {
  for (const q of ['-path:"/a b" verdict:block', 'score:>=90  src:1.2.3.4', 'bad stuff:x']) {
    const p = parse(q);
    expect(p.toks.map((t) => t.text).join('')).toBe(q);
  }
  const kinds = parse('-path:"/a" score:>=9').toks.filter((t) => t.kind !== 'space').map((t) => t.kind);
  expect(kinds).toEqual(['operator', 'field', 'operator', 'string', 'field', 'operator', 'operator', 'number']);
  expect(parse('colour:red').toks[0].kind).toBe('error');
});

test('addTerm appends, replaces an existing term for the same value, and quotes when needed', () => {
  expect(addTerm('', 'verdict', 'Block', false)).toBe('verdict:Block');
  expect(addTerm('verdict:Block', 'src', '203.0.113.7', false)).toBe('verdict:Block src:203.0.113.7');
  expect(addTerm('verdict:Block src:1.2.3.4', 'src', '1.2.3.4', true)).toBe('verdict:Block -src:1.2.3.4');
  expect(addTerm('', 'path', '/a b', false)).toBe('path:"/a b"');
  expect(addTerm('oops', 'verdict', 'Block', false)).toBe('oops verdict:Block');
});

test('tokenAt finds the term under the caret for suggestions', () => {
  expect(tokenAt('verdict:block cons', 18)).toEqual({ start: 14, end: 18, neg: false, field: null, partial: 'cons' });
  expect(tokenAt('verdict:block -construct:sq', 27)).toEqual({ start: 14, end: 27, neg: true, field: 'construct', partial: 'sq' });
  expect(tokenAt('src: x', 4)).toMatchObject({ field: 'src', partial: '' });
});
