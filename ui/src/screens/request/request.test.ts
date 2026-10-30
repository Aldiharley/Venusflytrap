import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { beforeAll, expect, test, vi } from 'vitest';
import { formatDate, toYaml } from '../../lib/exceptions';
import { FixtureSource } from '../../lib/api/source';
import type { RequestDetail } from '../../lib/api/types';
import { toasts } from '../../lib/components/toasts.svelte';
import { app } from '../../lib/state/app.svelte';
import RequestDetails from '../RequestDetails.svelte';
import { prefillException } from './exception-form';

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
  const d = find((x) => x.judgment.contributions.some((c) => c.shadow && !c.exception));
  await show(d);
  const region = screen.getByRole('region', { name: 'Contributions' });
  const rows = within(within(region).getByRole('table')).getAllByRole('row').slice(1, -1);
  const shadow = rows.filter((r) => r.textContent!.includes('Shadow · not scored'));
  expect(shadow.length).toBe(d.judgment.contributions.filter((c) => c.shadow && !c.exception).length);
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
  // The explanation is visible text too, not only a tooltip.
  const help = within(why).getByText(CONFIDENCE_TITLE, { selector: 'p:not([title])' });
  expect(help.className).toContain('secondary');
  expect(help.className).not.toContain('sr-only');
});

test('a construct with no measured precision says "not measured"; one with no technique shows none', async () => {
  const d = find((x) => x.judgment.confidence === null && x.judgment.attack.length === 0);
  const why = await show(d);
  const line = within(why).getByText('Precision on dev: not measured');
  expect(line.getAttribute('title')).toBe(CONFIDENCE_TITLE);
  expect(within(why).getByText(CONFIDENCE_TITLE, { selector: 'p:not([title])' })).toBeTruthy();
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

// --- exceptions (sub-project C) ---

const logOnly = (x: RequestDetail) => x.judgment.exceptions.includes('utm-xss');
const section = () => screen.queryByRole('region', { name: 'Exceptions' });

test('a touched request lists its exceptions as links to the Exceptions screen', async () => {
  const d = find(logOnly);
  await show(d);
  const sec = section()!;
  expect(sec).toBeTruthy();
  expect(within(sec).getByRole('heading', { name: 'Exceptions' })).toBeTruthy();
  expect(within(sec).getByRole('link', { name: 'utm-xss' }).getAttribute('href')).toBe('/exceptions?id=utm-xss');
});

test('an untouched request has no Exceptions section', async () => {
  const d = find((x) => !x.row.excepted);
  await show(d);
  expect(section()).toBeNull();
});

test('a log-only contribution is greyed with "suppressed by <id>" and stays out of the total', async () => {
  const d = find(logOnly);
  await show(d);
  const region = screen.getByRole('region', { name: 'Contributions' });
  const rows = within(within(region).getByRole('table')).getAllByRole('row').slice(1, -1);
  const sup = rows.filter((r) => r.textContent!.includes('suppressed by utm-xss'));
  expect(sup).toHaveLength(d.judgment.contributions.filter((c) => c.exception === 'utm-xss').length);
  for (const r of sup) {
    expect(r.classList.contains('suppressed')).toBe(true);
    expect(r.textContent).not.toContain('Shadow · not scored');
    expect(r.lastElementChild!.textContent!.trim()).toBe('0.0');
  }
  expect(rows.indexOf(sup[0])).toBe(rows.length - sup.length);
  const foot = within(within(region).getByRole('table')).getAllByRole('row').at(-1)!;
  expect(foot.textContent).toContain(`= score ${d.judgment.score}`);
});

test('a skipped field is listed with a warning and "Not inspected (skip-inspection <id>)"', async () => {
  const d = find((x) => !x.row.excepted);
  const skipped: RequestDetail = {
    ...d, row: { ...d.row, excepted: true },
    judgment: { ...d.judgment, exceptions: ['hook-signature'], skipped: [{ loc: 'Header', name: 'X-Hub-Signature' }] },
  };
  vi.spyOn(app.src!, 'request').mockResolvedValueOnce(skipped);
  await show(skipped);
  const sec = section()!;
  expect(within(sec).getByRole('link', { name: 'hook-signature' }).getAttribute('href')).toBe('/exceptions?id=hook-signature');
  const li = within(sec).getByText('Not inspected (skip-inspection hook-signature)').closest('li')!;
  expect(li.textContent).toContain('header:X-Hub-Signature');
  expect(li.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
});

test('the pre-fill follows the deciding construct, the path and the request', async () => {
  const d = find(logOnly);
  const now = Date.UTC(2026, 9, 30, 12);
  const e = prefillException(d, now);
  expect(d.judgment.decided_by.construct).toBe('xss.event-handler');
  expect(e).toEqual({
    id: 'xss-search', action: 'log-only', constructs: ['xss.event-handler'],
    scope: { methods: ['GET'], path_prefix: '/api/search', field: { loc: 'query', name: d.judgment.decided_by.field!.name } },
    owner: '', reason: '', created: '2026-10-30', modified: '2026-10-30', expires: '2026-11-29',
  });
  const none = prefillException({ ...d, judgment: { ...d.judgment, decided_by: { ...d.judgment.decided_by, construct: null, field: null } } }, now);
  expect(none.id).toBe('exception');
  expect(none.constructs).toEqual([]);
  expect(none.scope.field).toBeNull();
});

const open = async (d: RequestDetail) => {
  await show(d);
  await fireEvent.click(screen.getByRole('button', { name: 'Create exception' }));
  return screen.getByRole('region', { name: 'Create exception' });
};
const input = (name: string) => screen.getByLabelText(name) as HTMLInputElement;

test('Create exception opens an inline panel with every input labelled and pre-filled', async () => {
  const d = find(logOnly);
  const panel = await open(d);
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(input('ID').value).toBe('xss-search');
  expect(input('Constructs').value).toBe('xss.event-handler');
  expect(input('Methods').value).toBe('GET');
  expect(input('Path prefix').value).toBe('/api/search');
  expect((screen.getByLabelText('Field location') as HTMLSelectElement).value).toBe('query');
  expect(input('Field name').value).toBe(d.judgment.decided_by.field!.name);
  expect(input('Owner').value).toBe('');
  expect(input('Reason').value).toBe('');
  expect(input('Expires').value).toBe(formatDate(app.now + 30 * 86_400_000));
  const group = within(panel).getByRole('group', { name: 'Action' });
  const radios = within(group).getAllByRole('radio') as HTMLInputElement[];
  expect(radios.map((r) => r.value)).toEqual(['ignore', 'log-only', 'skip-inspection']);
  expect(radios.map((r) => r.checked)).toEqual([false, true, false]);
  for (const r of radios) expect(document.getElementById(r.getAttribute('aria-describedby')!)!.textContent!.length).toBeGreaterThan(10);
});

test('an empty owner shows its required message and hides the YAML', async () => {
  const panel = await open(find(logOnly));
  const owner = input('Owner');
  const ids = owner.getAttribute('aria-describedby')!.split(' ');
  expect(ids.map((i) => document.getElementById(i)?.textContent).join(' ')).toContain('owner is required');
  expect(owner.getAttribute('aria-invalid')).toBe('true');
  expect(screen.queryByRole('button', { name: 'Copy YAML' })).toBeNull();
  expect(panel.querySelector('pre')).toBeNull();
});

test('a valid form shows the YAML of the entry, the restart note and a Copy YAML button', async () => {
  const d = find(logOnly);
  const panel = await open(d);
  await fireEvent.input(input('Owner'), { target: { value: 'platform-team' } });
  await fireEvent.input(input('Reason'), { target: { value: 'UTM tags carry markup from the campaign tool' } });
  const want = { ...prefillException(d, app.now), owner: 'platform-team', reason: 'UTM tags carry markup from the campaign tool' };
  expect(panel.querySelector('pre')!.textContent).toBe(toYaml(want));
  expect(panel.textContent).toContain('Paste this under exceptions: in your exceptions file. It takes effect after a restart with --exceptions.');
  const write = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: write }, configurable: true });
  await fireEvent.click(screen.getByRole('button', { name: 'Copy YAML' }));
  expect(write).toHaveBeenCalledWith(toYaml(want));
  // Breaking an input hides it again.
  await fireEvent.input(input('Path prefix'), { target: { value: 'api' } });
  expect(panel.querySelector('pre')).toBeNull();
  expect(input('Path prefix').getAttribute('aria-invalid')).toBe('true');
});

test('skip-inspection clears the constructs and warns that nothing is inspected', async () => {
  const panel = await open(find(logOnly));
  expect(within(panel).queryByText('Matching fields will not be inspected at all.')).toBeNull();
  await fireEvent.click(within(panel).getByRole('radio', { name: 'skip-inspection' }));
  expect(within(panel).getByText('Matching fields will not be inspected at all.')).toBeTruthy();
  expect(panel.querySelector<HTMLInputElement>('#ce-constructs')?.value ?? '').toBe('');
  await fireEvent.input(input('Owner'), { target: { value: 'o' } });
  await fireEvent.input(input('Reason'), { target: { value: 'r' } });
  expect(panel.querySelector('pre')!.textContent).toContain('action: skip-inspection');
  expect(panel.querySelector('pre')!.textContent).not.toContain('constructs:');
});
