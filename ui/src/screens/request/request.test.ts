import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { beforeAll, expect, test, vi } from 'vitest';
import { FixtureSource } from '../../lib/api/source';
import type { RequestDetail } from '../../lib/api/types';
import { toasts } from '../../lib/components/toasts.svelte';
import { app } from '../../lib/state/app.svelte';
import RequestDetails from '../RequestDetails.svelte';

const call = () => ({ signal: new AbortController().signal });
let details: RequestDetail[] = [];

beforeAll(async () => {
  const src = new FixtureSource({ live: false });
  await app.start(src);
  const now = Date.now();
  const page = await src.history({ q: '', from: now - 3_600_000, to: now, limit: 200 }, call());
  details = await Promise.all(page.rows.map((r) => src.request(r.id, call())));
});

const find = (p: (d: RequestDetail) => boolean) => {
  const d = details.find(p);
  if (!d) throw new Error('no fixture request matches');
  return d;
};
const show = async (d: RequestDetail) => {
  render(RequestDetails, { props: { title: 'Request details', param: d.row.id } });
  return screen.findByRole('region', { name: 'Why this verdict' });
};

test('the heading names the verdict and the id; the why panel shows every decided_by field', async () => {
  const d = find((x) => x.judgment.decided_by.kind === 'Detection' && x.row.verdict === 'Block');
  const why = await show(d);
  const h1 = screen.getByRole('heading', { level: 1 });
  expect(h1.textContent).toContain('Block');
  expect(h1.textContent).toContain(d.row.id);
  const c = d.judgment.decided_by;
  expect(why.textContent).toContain(`Blocked: score ${d.judgment.score} reached scoring.block_at = 90 (override).`);
  expect(within(why).getAllByRole('link', { name: 'scoring.block_at' })[0].getAttribute('href')).toBe('/settings?highlight=scoring.block_at');
  const terms = Object.fromEntries(within(why).getAllByRole('term').map((t) => [t.textContent, t.nextElementSibling?.textContent?.replace(/\s+/g, ' ').trim()]));
  expect(terms['Decided by']).toBe('Detection');
  expect(terms['Setting']).toContain('scoring.block_at = 90 (override, rev 12)');
  expect(terms['Field']).toBe(`${c.field!.loc.toLowerCase()}:${c.field!.name}`);
  expect(terms['Construct']).toBe(`Construct ${c.construct}`);
  expect(terms['Engine message']).toBe(c.msg);
  expect(within(why).getByRole('link', { name: `Construct ${c.construct}` }).getAttribute('href'))
    .toBe(`/settings?highlight=shield.disabled&construct=${encodeURIComponent(c.construct!)}`);
});

test('contributions are sorted by points and their scored points sum to the score', async () => {
  const d = find((x) => x.judgment.contributions.filter((c) => !c.shadow).length >= 2);
  await show(d);
  const table = within(screen.getByRole('region', { name: 'Contributions' })).getByRole('table');
  const body = within(table).getAllByRole('row').slice(1, -1);
  const pts = body.filter((r) => !r.textContent!.includes('Shadow')).map((r) => parseFloat(r.lastElementChild!.textContent!));
  expect(pts).toEqual([...pts].sort((a, b) => b - a));
  expect(body[0].lastElementChild!.textContent).toContain('top');
  const foot = within(table).getAllByRole('row').at(-1)!;
  expect(foot.textContent).toContain(`= score ${d.judgment.score}`);
  expect(pts.reduce((a, b) => a + b, 0)).toBeCloseTo(d.judgment.score, 0);
});

test('shadow contributions are shown, marked as not scored, with 0 points, after the scored ones', async () => {
  const d = find((x) => x.judgment.contributions.some((c) => c.shadow));
  await show(d);
  const region = screen.getByRole('region', { name: 'Contributions' });
  const rows = within(within(region).getByRole('table')).getAllByRole('row').slice(1, -1);
  const shadow = rows.filter((r) => r.textContent!.includes('Shadow · not scored'));
  expect(shadow.length).toBe(d.judgment.contributions.filter((c) => c.shadow).length);
  for (const r of shadow) expect(r.lastElementChild!.textContent!.trim()).toBe('0.0');
  expect(rows.indexOf(shadow[0])).toBe(rows.length - shadow.length);
  expect(region.textContent).toContain('(shadow rows excluded)');
  expect(region.textContent).toContain('shield.shadow');
});

test('the gauge is decorative and has its sentence alternative', async () => {
  const d = details[0];
  await show(d);
  const region = screen.getByRole('region', { name: /^Score against rev 12 bands$/ });
  expect(region.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
  expect(region.textContent).toContain(`Score ${d.judgment.score} of 100. Bands at rev 12: Monitor ≥ 40, Challenge ≥ 70, Block ≥ 90.`);
});

test('a honeypot hit, a ban and a no-evidence Allow read as their sentences', async () => {
  const hp = find((x) => x.judgment.decided_by.kind === 'Honeypot');
  expect((await show(hp)).textContent).toContain(`Request hit decoy ${hp.row.path}.`);
  document.body.innerHTML = '';
  const ban = find((x) => x.judgment.decided_by.kind === 'Ban');
  expect((await show(ban)).textContent).toMatch(/Source banned (until \d\d:\d\d|permanently)\./);
  document.body.innerHTML = '';
  const allow = find((x) => x.judgment.decided_by.kind === 'NoEvidence');
  expect((await show(allow)).textContent).toContain('No evidence; allowed.');
  expect(screen.getByRole('note').textContent).toBe('Sampled request (1 % of Allows).');
});

test('mutating actions are shown disabled with the reason as visible text', async () => {
  await show(details[0]);
  const ban = screen.getByRole('button', { name: 'Ban source…' }) as HTMLButtonElement;
  expect(ban.disabled).toBe(true);
  expect(document.getElementById(ban.getAttribute('aria-describedby')!)!.textContent).toContain('arrive with the admin API');
});

test('an unknown id says the row is gone and links back to Monitor', async () => {
  render(RequestDetails, { props: { title: 'Request details', param: 'R0' } });
  expect(await screen.findByText('Request not found. Rows older than history.retention_days are removed.')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Open Monitor' }).getAttribute('href')).toBe('/monitor');
  expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('R0');
});

const CONFIDENCE_TITLE = "Share of this construct's blocks on the dev split that were attacks (lower 95 % bound). It does not change the score.";

test('the why panel shows one chip per ATT&CK tag with its tactic, and the precision on dev with its explanation', async () => {
  const d = find((x) => x.judgment.attack.length >= 2 && x.judgment.confidence !== null);
  const why = await show(d);
  const header = why.querySelector('header')!;
  for (const t of d.judgment.attack) {
    const chip = within(header).getByText(`${t.tactic} · ${t.name}`);
    expect(chip.closest('.chip')!.textContent).toContain(t.id);
  }
  for (const t of d.judgment.attack) expect(within(header).getAllByText(t.tactic).length).toBeGreaterThan(0);
  expect(header.querySelectorAll('.tag-item').length).toBe(d.judgment.attack.length);
  const line = within(header).getByText(`Precision on dev: ${d.judgment.confidence}`);
  expect(line.getAttribute('title')).toBe(CONFIDENCE_TITLE);
});

test('a construct with no measured precision says "not measured"; one with no technique shows none', async () => {
  const d = find((x) => x.judgment.confidence === null && x.judgment.attack.length === 0);
  const why = await show(d);
  const line = within(why).getByText('Precision on dev: not measured');
  expect(line.getAttribute('title')).toBe(CONFIDENCE_TITLE);
  expect(why.querySelectorAll('.tag-item').length).toBe(0);
  expect(why.textContent).toContain('No ATT&CK technique');
});

test('the event ID and the group ID each have a copy button that copies and announces', async () => {
  const d = find((x) => x.row.group_id !== null);
  const write = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: write }, configurable: true });
  await show(d);
  const terms = Object.fromEntries(screen.getAllByRole('term').map((t) => [t.textContent, t.nextElementSibling as HTMLElement]));
  expect(terms['Event ID'].textContent).toContain(d.row.id);
  expect(terms['Group ID'].textContent).toContain(d.row.group_id!);
  await fireEvent.click(screen.getByRole('button', { name: 'Copy event ID' }));
  await fireEvent.click(screen.getByRole('button', { name: 'Copy group ID' }));
  expect(write.mock.calls).toEqual([[d.row.id], [d.row.group_id]]);
  await vi.waitFor(() => expect(toasts.items.map((t) => t.text)).toEqual(expect.arrayContaining(['Copied event ID.', 'Copied group ID.'])));
});

test('a request with no group shows a dash, "no group" to screen readers and no group copy button', async () => {
  const d = find((x) => x.row.group_id === null);
  await show(d);
  const dd = screen.getAllByRole('term').find((t) => t.textContent === 'Group ID')!.nextElementSibling as HTMLElement;
  expect(dd.textContent).toContain('—');
  expect(within(dd).getByText('no group').className).toContain('sr-only');
  expect(screen.queryByRole('button', { name: 'Copy group ID' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Copy event ID' })).toBeTruthy();
});

test('"View as OCSF" is a second tab: the evidence view is selected first, the OCSF records show in a pre', async () => {
  const d = find((x) => x.row.verdict === 'Block' && x.judgment.decided_by.kind === 'Detection');
  await show(d);
  const tabs = screen.getByRole('tablist', { name: 'Request view' });
  const [evidence, ocsf] = within(tabs).getAllByRole('tab');
  expect(evidence.getAttribute('aria-selected')).toBe('true');
  expect(ocsf.textContent).toBe('View as OCSF');
  expect(screen.queryByRole('tabpanel', { name: 'View as OCSF' })).toBeNull();
  await fireEvent.click(ocsf);
  expect(ocsf.getAttribute('aria-selected')).toBe('true');
  const panel = screen.getByRole('tabpanel', { name: 'View as OCSF' });
  const pre = panel.querySelector('pre')!;
  expect(pre.textContent).toContain('"class_uid": 4002');
  expect(pre.textContent).toContain('"class_uid": 2004');
  expect(pre.textContent).toContain(`"uid": "${d.row.id}"`);
  expect(screen.queryByRole('region', { name: 'Contributions' })).toBeNull();
  await fireEvent.click(evidence);
  expect(screen.getByRole('region', { name: 'Contributions' })).toBeTruthy();
});

test('the tabs follow the arrow, Home and End keys', async () => {
  await show(details[0]);
  const [evidence, ocsf] = screen.getAllByRole('tab');
  evidence.focus();
  await fireEvent.keyDown(evidence, { key: 'ArrowRight' });
  expect(document.activeElement).toBe(ocsf);
  expect(ocsf.getAttribute('aria-selected')).toBe('true');
  await fireEvent.keyDown(ocsf, { key: 'ArrowRight' });
  expect(document.activeElement).toBe(evidence);
  await fireEvent.keyDown(evidence, { key: 'End' });
  expect(document.activeElement).toBe(ocsf);
  await fireEvent.keyDown(ocsf, { key: 'Home' });
  expect(document.activeElement).toBe(evidence);
});
