import { describe, expect, test } from 'vitest';
import css from './tokens.css?raw';

function block(re: RegExp): Map<string, string> {
  const m = css.match(re);
  if (!m) throw new Error(`block not found: ${re}`);
  const out = new Map<string, string>();
  for (const d of m[1].matchAll(/--vf-([a-z0-9-]+):\s*([^;]+);/g)) out.set(d[1], d[2].trim());
  return out;
}

const light = block(/^:root\s*\{([\s\S]*?)\n\}/m);
const dark = block(/\[data-theme="dark"\]\s*\{([\s\S]*?)\n\}/);
const systemDark = block(/:root:not\(\[data-theme="light"\]\)\s*\{([\s\S]*?)\n\s*\}/);

function resolve(t: Map<string, string>, name: string): string {
  let v = t.get(name) ?? light.get(name);
  for (let i = 0; v?.startsWith('var(') && i < 5; i++) {
    const ref = v.slice('var(--vf-'.length, -1);
    v = t.get(ref) ?? light.get(ref);
  }
  if (!v || !/^#[0-9A-Fa-f]{6}$/.test(v)) throw new Error(`${name} is not a solid hex colour: ${v}`);
  return v;
}

function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((c) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// [foreground, background, minimum] — design system §1.1–§1.2 and §5.
const PAIRS: [string, string, number][] = [
  ...['surface-raised', 'surface-base', 'surface-overlay'].flatMap((bg): [string, string, number][] => [
    ['text-primary', bg, 4.5],
    ['text-secondary', bg, 4.5],
  ]),
  ['text-muted', 'surface-raised', 4.5],
  ['text-muted', 'surface-overlay', 4.5],
  ['text-muted', 'surface-sunken', 4.5],
  ['text-on-accent', 'accent', 4.5],
  ['text-on-attention', 'attention-fill', 4.5],
  ['text-on-danger', 'danger', 4.5],
  ['accent', 'surface-raised', 4.5],
  ['attention', 'surface-raised', 4.5],
  ['danger', 'surface-raised', 4.5],
  ...['allow', 'monitor', 'challenge', 'block'].flatMap((v): [string, string, number][] => [
    [`verdict-${v}-fg`, `verdict-${v}-bg`, 4.5],
    [`verdict-${v}-fg`, 'surface-raised', 4.5],
    [`verdict-${v}-line`, 'surface-base', 3],
  ]),
  ...['none', 'recon', 'enumeration', 'exploitation', 'exfiltration'].flatMap((s): [string, string, number][] => [
    [`stage-${s}-fg`, `stage-${s}-bg`, 4.5],
    [`stage-${s}-fg`, 'surface-raised', 4.5],
  ]),
  ['focus-ring', 'surface-base', 3],
  ['focus-ring', 'surface-raised', 3],
  ['focus-ring', 'surface-overlay', 3],
  ['border-strong', 'surface-raised', 3],
  ['border-strong', 'surface-base', 3],
  ['line-idle', 'surface-base', 3],
  ['line-active', 'surface-base', 3],
];

describe.each([
  ['light', light],
  ['dark', dark],
])('%s theme', (_, t) => {
  test.each(PAIRS)('%s on %s >= %d:1', (fg, bg, min) => {
    expect(contrast(resolve(t, fg), resolve(t, bg))).toBeGreaterThanOrEqual(min);
  });
});

test('the System dark block equals the manual dark block', () => {
  expect(Object.fromEntries(systemDark)).toEqual(Object.fromEntries(dark));
});
