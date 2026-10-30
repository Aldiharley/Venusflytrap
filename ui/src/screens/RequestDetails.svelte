<script lang="ts">
  import { onMount, tick } from 'svelte';
  import type { SourceError } from '../lib/api/errors';
  import { Latest } from '../lib/api/latest';
  import type { ExceptionEntry, FieldRef, RequestDetail } from '../lib/api/types';
  import AttackChip from '../lib/components/AttackChip.svelte';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import ErrorCard from '../lib/components/ErrorCard.svelte';
  import EvidenceChip from '../lib/components/EvidenceChip.svelte';
  import Link from '../lib/components/Link.svelte';
  import StageChip from '../lib/components/StageChip.svelte';
  import VerdictChip from '../lib/components/VerdictChip.svelte';
  import { toasts } from '../lib/components/toasts.svelte';
  import { fmtClock } from '../lib/format';
  import { Copy, FilePlus, TriangleAlert } from '../lib/icons';
  import { encodeOcsf } from '../lib/ocsf';
  import { app } from '../lib/state/app.svelte';
  import CreateException from './request/CreateException.svelte';
  import ScoreGauge from './request/ScoreGauge.svelte';
  import { constructHref, contributionRows, excludedNote, fieldLabel, settingHref, skippingIds, whyParts } from './request/why';

  let { title, param }: { title: string; param: string | null } = $props();
  const id = $derived(param ?? '');

  let d = $state<RequestDetail | null>(null);
  let error = $state<SourceError | null>(null);
  const latest = new Latest();

  async function load() {
    const src = app.src;
    if (!src) return;
    const want = id;
    const r = await latest.run((call) => src.request(want, call));
    if (!r) return;
    if (r.ok) { d = r.value; error = null; } else { d = null; error = r.error; }
  }
  onMount(() => { load(); return () => latest.abort(); });

  const parts = $derived(d ? whyParts(d) : []);
  const contribs = $derived(d ? contributionRows(d.judgment.contributions, d.judgment.score) : null);
  const cause = $derived(d?.judgment.decided_by);
  const excluded = $derived(d ? excludedNote(d.judgment.contributions) : '');
  const touched = $derived(d ? d.judgment.exceptions.length > 0 || d.judgment.skipped.length > 0 : false);
  const skippedBy = (f: FieldRef) => skippingIds(f, d?.judgment.exceptions ?? [], entries).join(', ');
  const exceptionHref = (eid: string) => `/exceptions?id=${encodeURIComponent(eid)}`;

  // A skipped field does not say which exception skipped it: the exceptions file tells, by the field each
  // skip-inspection entry names. Until it loads (or if it cannot, or nothing matches) no id is named.
  let entries = $state<ExceptionEntry[] | null>(null);
  $effect(() => {
    const src = app.src;
    if (!src || !d || d.judgment.skipped.length === 0) return;
    const ctl = new AbortController();
    src.exceptions({ signal: ctl.signal }).then((r) => { entries = r; }, () => { entries = null; });
    return () => ctl.abort();
  });

  // The inline "Create exception" panel: closing it hands focus back to the button that opened it.
  let creating = $state(false);
  let createBtn: HTMLButtonElement | undefined = $state();
  async function closeCreate() {
    creating = false;
    await tick();
    createBtn?.focus();
  }
  const fmtTime = (ms: number) => `${new Date(ms).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })} ${fmtClock(ms)}`;
  const fmtPoints = (n: number) => n.toFixed(1);
  const sourceHref = (key: string) => `/sources/${encodeURIComponent(key)}`;

  // The event id is the history row's id for now: the fixture ids are not UUIDs.
  const eventId = $derived(d?.row.id ?? '');
  // Enforced unless something says the proxy runs monitor-only: neither the status record nor the
  // fixture rows carry the mode yet, so this is always true for now (the B API will provide it).
  const enforced = true;
  const ocsf = $derived(d ? JSON.stringify(encodeOcsf(d, eventId, { version: app.status?.version, enforced }), null, 2) : '');
  const CONFIDENCE_HELP = "Share of this construct's blocks on the dev split that were attacks (lower 95 % bound). It does not change the score.";

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      toasts.push({ tone: 'success', text: `Copied ${what}.` });
    } catch {
      toasts.push({ tone: 'warn', text: `Could not copy the ${what}.` });
    }
  }

  const TABS = [{ key: 'evidence', label: 'Evidence' }, { key: 'ocsf', label: 'View as OCSF' }] as const;
  type TabKey = (typeof TABS)[number]['key'];
  let tab = $state<TabKey>('evidence');
  let tabEls: HTMLButtonElement[] = [];
  function onTabKey(e: KeyboardEvent, i: number) {
    const to = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i + TABS.length - 1) % TABS.length
      : e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    tab = TABS[to].key;
    tabEls[to]?.focus();
  }
</script>

<nav class="crumbs secondary" aria-label="Breadcrumb">
  <Link href="/monitor">Monitor</Link> <span aria-hidden="true">›</span> <span class="mono">{id}</span>
</nav>

<header class="head">
  <h1 tabindex="-1">
    {#if d}<VerdictChip verdict={d.row.verdict} />{/if}
    <span>{title}</span> <span class="mono id">{id}</span>
  </h1>
  {#if d}
    <p class="mono reqline">{d.row.method} {d.row.path}{d.query ? `?${d.query}` : ''}</p>
    <dl class="meta">
      <div><dt class="label-caps">Time</dt><dd class="num">{fmtTime(d.row.ts_ms)}</dd></div>
      <div><dt class="label-caps">Source</dt><dd><Link href={sourceHref(d.row.src_key)} class="mono">{d.row.src_key}</Link></dd></div>
      <div><dt class="label-caps">IP</dt><dd class="mono">{d.ip}</dd></div>
      <div><dt class="label-caps">Host</dt><dd class="mono">{d.row.host}</dd></div>
      <div><dt class="label-caps">Inspection</dt><dd class="num">{d.row.latency_us} µs</dd></div>
      <div><dt class="label-caps">Upstream</dt><dd class="num">{d.row.upstream_status ?? 'not forwarded'}</dd></div>
      <div><dt class="label-caps">Config</dt><dd class="num">rev {d.row.config_rev}</dd></div>
      <div><dt class="label-caps">Event ID</dt><dd class="idrow"><span class="mono">{eventId}</span>
        <button class="btn btn-ghost btn-sm icon" aria-label="Copy event ID" onclick={() => copy(eventId, 'event ID')}><Copy size={14} aria-hidden="true" /></button>
        <button bind:this={createBtn} class="btn btn-sm" aria-expanded={creating} aria-controls="ce-panel" onclick={() => (creating = true)}><FilePlus size={14} aria-hidden="true" />Create exception</button></dd></div>
      <div><dt class="label-caps">Group ID</dt><dd class="idrow">
        {#if d.row.group_id !== null}
          {@const group = d.row.group_id}
          <span class="mono">{group}</span>
          <button class="btn btn-ghost btn-sm icon" aria-label="Copy group ID" onclick={() => copy(group, 'group ID')}><Copy size={14} aria-hidden="true" /></button>
        {:else}<span aria-hidden="true">—</span><span class="sr-only">no group</span>{/if}
      </dd></div>
    </dl>
  {/if}
</header>

{#if error?.kind === 'not_found'}
  <div class="card">
    <EmptyState scene="quiet" message="Request not found. Rows older than history.retention_days are removed." action={{ label: 'Open Monitor', href: '/monitor' }} />
  </div>
{:else if error}
  <ErrorCard {error} onretry={load} />
{:else if !d}
  <div class="card skeleton" aria-busy="true" aria-label="Loading request"></div>
{:else if cause && contribs}
  {#if d.row.sampled}<p class="banner card" role="note">Sampled request (1 % of Allows).</p>{/if}

  {#if creating}<div id="ce-panel"><CreateException {d} onclose={closeCreate} /></div>{/if}

  <div class="tabs" role="tablist" aria-label="Request view">
    {#each TABS as t, i (t.key)}
      <button bind:this={tabEls[i]} role="tab" id="tab-{t.key}" class="tab" aria-selected={tab === t.key} aria-controls="panel-{t.key}"
        tabindex={tab === t.key ? 0 : -1} onclick={() => (tab = t.key)} onkeydown={(e) => onTabKey(e, i)}>{t.label}</button>
    {/each}
  </div>

  {#if tab === 'ocsf'}
  <div role="tabpanel" id="panel-ocsf" aria-labelledby="tab-ocsf" class="panel">
    <p class="secondary small">The records the proxy emits for this request, as OCSF 1.9.0 JSON: {d.row.verdict === 'Allow' || d.row.verdict === 'Monitor' ? 'an HTTP Activity (4002)' : 'an HTTP Activity (4002) and a Detection Finding (2004)'}.</p>
    <!-- svelte-ignore a11y_no_noninteractive_tabindex: axe requires a keyboard-focusable scroll container -->
    <pre class="mono ocsf" tabindex="0" role="region" aria-label="OCSF records">{ocsf}</pre>
  </div>
  {:else}
  <div role="tabpanel" id="panel-evidence" aria-labelledby="tab-evidence" class="grid">
    <section class="card why" aria-labelledby="why-h">
      <header class="why-head">
        <h2 id="why-h" class="title">Why this verdict</h2>
        <VerdictChip verdict={d.row.verdict} size="sm" />
        {#each d.judgment.attack as tag (tag.id)}
          <span class="tag-item"><AttackChip {tag} /><span class="secondary small" aria-hidden="true">{tag.tactic}</span></span>
        {:else}
          <span class="secondary small">No ATT&amp;CK technique</span>
        {/each}
        <p class="conf small secondary" title={CONFIDENCE_HELP}>Precision on dev: {d.judgment.confidence ?? 'not measured'}</p>
      </header>
      <p class="conf-help small secondary">{CONFIDENCE_HELP}</p>
      <p class="sentence">{#each parts as p, i (i)}{#if p.href}<Link href={p.href} class="mono code">{p.text}</Link>{:else if p.code}<code class="mono code">{p.text}</code>{:else}{p.text}{/if}{/each}</p>
      <dl class="cause">
        <div><dt class="label-caps">Decided by</dt><dd>{cause.kind}</dd></div>
        <div><dt class="label-caps">Setting</dt><dd><Link href={settingHref(cause.option_key)} class="mono">{cause.option_key}</Link> = <span class="mono">{d.setting.value}</span> <span class="secondary">({d.setting.source}, rev {d.setting.rev})</span></dd></div>
        <div><dt class="label-caps">Field</dt><dd class="mono">{cause.field ? fieldLabel(cause.field) : '—'}</dd></div>
        <div><dt class="label-caps">Construct</dt><dd>
          {#if cause.construct && constructHref(cause.construct)}
            <Link href={constructHref(cause.construct)!}>Construct <span class="mono">{cause.construct}</span></Link>
          {:else}<span class="mono">{cause.construct ?? '—'}</span>{/if}
        </dd></div>
        <div><dt class="label-caps">Engine message</dt><dd class="mono msg">{cause.msg}</dd></div>
      </dl>
      <div class="actions">
        <Link href={settingHref(cause.option_key)} class="btn btn-sm btn-primary">Open setting</Link>
        <Link href={sourceHref(d.row.src_key)} class="btn btn-sm">Open source</Link>
        <button class="btn btn-sm" disabled aria-describedby="act-note">Ban source…</button>
        <button class="btn btn-sm" disabled aria-describedby="act-note">Disable construct…</button>
      </div>
      <p id="act-note" class="secondary small">Ban (Operator) and Disable construct (Admin) arrive with the admin API.</p>
    </section>

    <section class="card gauge" aria-labelledby="gauge-h">
      <h2 id="gauge-h" class="title">Score against rev {d.setting.rev} bands</h2>
      <ScoreGauge score={d.judgment.score} bands={d.bands} rev={d.setting.rev} />
    </section>

    <section class="card contribs" aria-labelledby="contrib-h">
      <h2 id="contrib-h" class="title">Contributions</h2>
      <div class="scroll">
        <table class="data-table">
          <thead><tr><th scope="col">Engine</th><th scope="col">Field</th><th scope="col">Construct</th><th scope="col">Evidence</th><th scope="col" class="n">Weight</th><th scope="col" class="n">Points</th></tr></thead>
          <tbody>
            {#each contribs.items as { c, top }, i (i)}
              <tr class:top class:shadow={c.shadow && c.exception === null} class:suppressed={c.exception !== null}>
                <td>{c.engine}</td>
                <td class="mono">{c.field ? fieldLabel(c.field) : '—'}</td>
                <td><span class="mono">{c.construct ?? '—'}</span>{#if c.exception !== null} <span class="tag">suppressed by <Link href={exceptionHref(c.exception)} class="mono">{c.exception}</Link></span>{:else if c.shadow} <span class="tag">Shadow · not scored</span>{/if}</td>
                <td><EvidenceChip value={c.value} /></td>
                <td class="n">{c.weight.toFixed(2)}</td>
                <td class="n">{fmtPoints(c.points)}{#if top} <span class="tag">top</span>{/if}</td>
              </tr>
            {:else}
              <tr><td colspan="6" class="secondary">No evidence was recorded for this request.</td></tr>
            {/each}
          </tbody>
          <tfoot>
            <tr><th scope="row" colspan="5">Σ points{excluded}</th><td class="n num">{`${fmtPoints(contribs.sum)} ${contribs.exact ? '=' : '≈'} score ${d.judgment.score}`}</td></tr>
          </tfoot>
        </table>
      </div>
      {#if d.judgment.contributions.some((c) => c.shadow && c.exception === null)}
        <p class="secondary small">Shadow contributions come from constructs in <code class="mono">shield.shadow</code>: they fired but were judged as disabled, so they add no points and never decide a verdict.</p>
      {/if}
    </section>

    {#if touched}
      <section class="card touched" aria-labelledby="touched-h">
        <h2 id="touched-h" class="title">Exceptions</h2>
        <p class="secondary small">These exceptions changed how this request was judged.</p>
        <ul>
          {#each d.judgment.exceptions as eid (eid)}
            <li><Link href={exceptionHref(eid)} class="mono">{eid}</Link></li>
          {/each}
          {#each d.judgment.skipped as f, i (i)}
            <li class="skipped"><TriangleAlert size={14} strokeWidth={1.5} aria-hidden="true" /><span class="mono">{fieldLabel(f)}</span> <span>Not inspected (skip-inspection {skippedBy(f) || 'exception'})</span></li>
          {/each}
        </ul>
      </section>
    {/if}

    <section class="card chain" aria-labelledby="chain-h">
      <h2 id="chain-h" class="title">Chain outcome</h2>
      {#if d.judgment.chain}
        {@const ch = d.judgment.chain}
        <dl class="kv">
          <div><dt class="label-caps">Stage before</dt><dd><StageChip stage={ch.stage_before} /></dd></div>
          <div><dt class="label-caps">Stage after</dt><dd><StageChip stage={ch.stage_after} /></dd></div>
          <div><dt class="label-caps">Advanced</dt><dd>{ch.advanced ? 'Yes, with this request' : 'No'}</dd></div>
          <div><dt class="label-caps">New ban</dt><dd>{ch.new_ban ? `${ch.new_ban.cause}, offence ${ch.new_ban.offences}` : 'None'}</dd></div>
          <div><dt class="label-caps">Normalized layers</dt><dd class="num">{d.judgment.normalized_layers}</dd></div>
        </dl>
      {:else}
        <p class="secondary">No chain observation for this request{d.judgment.decided_by.kind === 'Ban' ? ': the source was already banned, so it was not inspected' : ''}.</p>
        <p class="secondary small">Normalized layers: <span class="num">{d.judgment.normalized_layers}</span></p>
      {/if}
    </section>

    <section class="card timeline" aria-labelledby="tl-h">
      <h2 id="tl-h" class="title">Source timeline</h2>
      <ol>
        {#each d.timeline as t (t.id)}
          <li>
            <span class="num secondary">{fmtClock(t.ts_ms)}</span>
            <VerdictChip verdict={t.verdict} size="sm" />
            {#if t.id === d.row.id}
              <span class="mono" aria-current="page">{t.path} (this request)</span>
            {:else}
              <Link href={`/requests/${encodeURIComponent(t.id)}`} class="mono">{t.path}</Link>
            {/if}
          </li>
        {/each}
      </ol>
      <Link href={`/monitor?q=${encodeURIComponent(`src:${d.row.src_key}`)}`}>All requests from this source</Link>
    </section>

    <section class="card fields" aria-labelledby="fields-h">
      <h2 id="fields-h" class="title">Field values</h2>
      {#if d.fields === null}
        <p class="secondary">Field values not stored.</p>
      {:else if d.fields.length === 0}
        <p class="secondary">No field carried evidence.</p>
      {:else}
        {#each d.fields as f (fieldLabel(f.field))}
          <dl class="kv">
            <div><dt class="label-caps">Field</dt><dd class="mono">{fieldLabel(f.field)}</dd></div>
            <div><dt class="label-caps">Raw (as received)</dt><dd class="mono value">{f.raw}</dd></div>
            <div><dt class="label-caps">Decoded · {f.layers.length} {f.layers.length === 1 ? 'layer' : 'layers'}{f.layers.length ? ` (${f.layers.join(', ')})` : ''}</dt><dd class="mono value">{f.decoded}</dd></div>
          </dl>
        {/each}
      {/if}
    </section>
  </div>
  {/if}
{/if}

<style>
  .crumbs { font-size: var(--vf-fs-sm); margin-bottom: var(--vf-space-2); }
  .head { display: grid; gap: var(--vf-space-2); margin-bottom: var(--vf-space-4); }
  h1 { display: flex; align-items: center; flex-wrap: wrap; gap: var(--vf-space-3); }
  .id { font-size: var(--vf-fs-title-sm); }
  .reqline { overflow-wrap: anywhere; }
  .meta { display: flex; flex-wrap: wrap; gap: var(--vf-space-2) var(--vf-space-5); }
  .meta div, .cause div, .kv div { display: grid; gap: 2px; }
  dd { margin: 0; }
  .banner { margin-bottom: var(--vf-space-4); background: var(--vf-attention-soft); color: var(--vf-attention); }
  .skeleton { height: 320px; background: var(--vf-surface-sunken); }
  .grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: var(--vf-space-5); }
  .tabs { display: flex; gap: var(--vf-space-1); margin-bottom: var(--vf-space-4); border-bottom: var(--vf-bw-std) solid var(--vf-border-subtle); }
  .tab {
    height: var(--vf-control-sm); padding: 0 var(--vf-space-3); background: transparent; border: 0; cursor: pointer;
    border-bottom: var(--vf-bw-strong) solid transparent; margin-bottom: calc(-1 * var(--vf-bw-std));
    font-size: var(--vf-fs-sm); font-weight: 600; color: var(--vf-text-secondary);
  }
  .tab:hover { color: var(--vf-text-primary); }
  .tab[aria-selected='true'] { color: var(--vf-accent); border-bottom-color: var(--vf-accent); }
  .panel { display: grid; gap: var(--vf-space-3); }
  .ocsf {
    margin: 0; padding: var(--vf-space-4); overflow: auto; max-height: 70vh; white-space: pre;
    background: var(--vf-surface-sunken); border-radius: var(--vf-radius-md); border: var(--vf-bw-hair) solid var(--vf-border-hairline);
  }
  .why-head { display: flex; align-items: center; flex-wrap: wrap; gap: var(--vf-space-2) var(--vf-space-3); }
  .why-head .title { margin-right: var(--vf-space-1); }
  .tag-item { display: inline-flex; align-items: center; gap: var(--vf-space-1); }
  .conf { margin: 0; }
  .conf-help { margin: calc(-1 * var(--vf-space-2)) 0 0; }
  .idrow { display: flex; align-items: center; gap: var(--vf-space-1); }
  .icon { padding: 0 var(--vf-space-2); }
  .why { grid-column: 1 / 8; }
  .gauge { grid-column: 8 / 13; }
  .contribs { grid-column: 1 / 13; }
  .touched { grid-column: 1 / 13; }
  .touched ul { margin: 0; padding: 0; list-style: none; display: grid; gap: var(--vf-space-2); }
  .skipped { display: flex; align-items: center; gap: var(--vf-space-2); color: var(--vf-health-warn-fg); }
  .chain { grid-column: 1 / 7; }
  .timeline { grid-column: 7 / 13; }
  .fields { grid-column: 1 / 13; }
  .card { display: grid; gap: var(--vf-space-3); align-content: start; }
  .title { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); }
  .sentence { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); }
  .code { padding: 0 var(--vf-space-1); border-radius: var(--vf-radius-xs); background: var(--vf-surface-sunken); }
  .cause { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--vf-space-3); }
  .cause div:last-child { grid-column: 1 / -1; }
  .msg, .value { overflow-wrap: anywhere; }
  .actions { display: flex; flex-wrap: wrap; gap: var(--vf-space-2); }
  .btn:disabled { color: var(--vf-text-disabled); box-shadow: none; cursor: not-allowed; background: var(--vf-surface-raised); border-color: color-mix(in srgb, var(--vf-border-strong) 50%, transparent); }
  .small { font-size: var(--vf-fs-xs); }
  .scroll { overflow-x: auto; }
  tr.top td { background: var(--vf-row-selected); }
  tr.suppressed td { color: var(--vf-text-muted); }
  .tag { font-size: var(--vf-fs-xs); color: var(--vf-text-secondary); font-weight: 600; }
  tfoot th { text-align: right; text-transform: none; letter-spacing: 0; font-size: var(--vf-fs-sm); }
  tfoot td { font-weight: 600; }
  .kv { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: var(--vf-space-3); }
  .timeline ol { margin: 0; padding: 0; list-style: none; display: grid; gap: var(--vf-space-2); }
  .timeline li { display: flex; align-items: center; gap: var(--vf-space-2); }
  @media (max-width: 1279px) {
    .why { grid-column: 1 / 13; }
    .gauge { grid-column: 1 / 13; }
  }
</style>
