<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import type { SourceError } from '../lib/api/errors';
  import { Latest } from '../lib/api/latest';
  import { GROUP_BYS, type GroupBy, type HistoryPage, type HistoryRow } from '../lib/api/types';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import ErrorCard from '../lib/components/ErrorCard.svelte';
  import StageChip from '../lib/components/StageChip.svelte';
  import TechniqueCell from '../lib/components/TechniqueCell.svelte';
  import { toasts } from '../lib/components/toasts.svelte';
  import VerdictChip from '../lib/components/VerdictChip.svelte';
  import { fmtClock, fmtCount, fmtStamp } from '../lib/format';
  import { moveCell, type Cell } from '../lib/grid';
  import { Copy, ExternalLink, ShieldOff } from '../lib/icons';
  import { addTerm, type Field } from '../lib/query';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import QueryBar, { type Suggest } from './monitor/QueryBar.svelte';
  import { RANGES, REFRESH, readState, spanMs, timeWindow, widen, writeState, type MonitorState } from './monitor/url';

  let { title }: { title: string } = $props();
  const PAGE = 100;

  /** `short` is the visible header when the full label does not fit; the label stays the accessible name. */
  interface Col { key: string; label: string; short?: string; field: Field | null; n?: boolean }
  const COLS: Col[] = [
    { key: 'ts', label: 'Time', field: null },
    { key: 'verdict', label: 'Verdict', field: 'verdict' },
    { key: 'score', label: 'Score', field: null, n: true },
    { key: 'src', label: 'Source', field: 'src' },
    { key: 'method', label: 'Method', field: 'method' },
    { key: 'host', label: 'Host', field: 'host' },
    { key: 'path', label: 'Path', field: 'path' },
    { key: 'construct', label: 'Construct', field: 'construct' },
    { key: 'technique', label: 'Technique', field: null },
    { key: 'confidence', label: 'Confidence', short: 'Conf.', field: null, n: true },
    { key: 'stage', label: 'Stage', field: 'stage' },
    { key: 'decided', label: 'Decided by', field: null },
    { key: 'rev', label: 'Rev', field: 'config_rev', n: true },
    { key: 'latency', label: 'Latency', field: null, n: true },
    { key: 'upstream', label: 'HTTP', field: null, n: true },
  ];
  const HEAD_TITLE: Record<string, string | undefined> = {
    upstream: 'Upstream status',
    technique: 'MITRE ATT&CK technique of the deciding construct',
    confidence: 'Precision on dev of the deciding construct',
  };
  const GROUP_LABEL: Record<GroupBy, string> = { src: 'Source', path: 'Path', construct: 'Construct', stage: 'Stage', verdict: 'Verdict' };

  const st = $derived(readState(router.search));
  let draft = $state(untrack(() => st.q));
  $effect(() => { draft = st.q; }); // Back/Forward or a cell filter changes the committed query

  let rows = $state<HistoryRow[]>([]);
  let groups = $state<HistoryPage['groups']>(null);
  let total = $state(0);
  let next = $state<string | null>(null);
  let loaded = $state(false);
  let error = $state<SourceError | null>(null);
  let updatedAt = $state(0);
  let newCount = $state(0);
  let focusIn = $state(false);
  let pos = $state<Cell>({ r: 0, c: 0 });
  let table: HTMLTableElement | undefined = $state();
  let queryInput: HTMLInputElement | undefined = $state();

  const main = new Latest();
  const more = new Latest();
  const peek = new Latest();
  const sugg = new Latest();

  const grouped = $derived(groups !== null);
  const nrows = $derived(grouped ? (groups?.length ?? 0) : rows.length);
  const ncols = $derived(grouped ? 2 : COLS.length);
  const active = $derived<Cell>({
    r: Math.max(0, Math.min(pos.r, nrows - 1)),
    c: Math.max(0, Math.min(pos.c, ncols - 1)),
  });
  const withDate = $derived(spanMs(st) > 24 * 3_600_000);
  const queryError = $derived(error?.kind === 'bad_request' ? { ...error.detail, msg: error.message } : null);
  const otherError = $derived(error && error.kind !== 'bad_request' ? error : null);
  const historyDrops = $derived(app.status?.drops.history ?? 0);
  // Auto-refresh pauses while focus is in the grid or the user has paged past page 1 (UX §5).
  const paused = $derived(focusIn || rows.length > PAGE);

  // Back from Request details refocuses the row it opened (kept in history state, UX §12).
  let restore = (history.state as { monitorFocus?: { id: string; c: number } } | null)?.monitorFocus ?? null;

  function setState(patch: Partial<MonitorState>) {
    router.navigate(writeState({ ...st, ...patch }));
  }

  function base(s: MonitorState) {
    return { q: s.q, ...timeWindow(s, Date.now()), group_by: s.group, limit: PAGE };
  }

  async function load() {
    const src = app.src;
    if (!src) return;
    more.abort();
    peek.abort();
    const hadFocus = !!table?.contains(document.activeElement);
    const r = await main.run((call) => src.history(base(st), call));
    if (!r) return;
    if (!r.ok) { error = r.error; loaded = true; return; }
    error = null;
    rows = r.value.rows;
    groups = r.value.groups;
    total = r.value.total;
    next = r.value.next;
    newCount = 0;
    loaded = true;
    updatedAt = Date.now();
    if (restore) {
      const i = rows.findIndex((x) => x.id === restore!.id);
      if (i >= 0) { pos = { r: i, c: restore.c }; await tick(); focusCell(); }
      restore = null;
    } else if (hadFocus) { await tick(); focusCell(); }
  }

  async function loadMore() {
    const src = app.src;
    if (!src || !next) return;
    const cursor = next;
    const r = await more.run((call) => src.history({ ...base(st), cursor }, call));
    if (!r) return;
    if (!r.ok) { error = r.error; return; }
    rows = [...rows, ...r.value.rows];
    next = r.value.next;
  }

  // While paused, count what a refresh would add instead of reordering rows under the user.
  async function refreshTick() {
    const src = app.src;
    if (!src) return;
    if (!paused) { load(); return; }
    if (grouped) return;
    const newest = rows[0]?.ts_ms ?? 0;
    const r = await peek.run((call) => src.history(base(st), call));
    if (r?.ok) newCount = r.value.rows.filter((x) => x.ts_ms > newest).length;
  }

  async function showNew() {
    await load();
    await tick();
    focusCell();
  }

  const loadKey = $derived(JSON.stringify([st.q, st.range, st.from, st.to, st.group]));
  $effect(() => { void loadKey; untrack(() => load()); });
  $effect(() => {
    const ms = REFRESH.find((r) => r.key === st.refresh)?.ms ?? 0;
    if (!ms) return;
    const t = setInterval(() => untrack(() => refreshTick()), ms);
    return () => clearInterval(t);
  });

  onMount(() => {
    // `/` focuses the query bar (UX §2.4), unless the user is already typing somewhere.
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (t?.closest('input, textarea, select, [contenteditable="true"]')) return;
      e.preventDefault();
      queryInput?.focus();
    };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); main.abort(); more.abort(); peek.abort(); sugg.abort(); };
  });

  const suggest: Suggest = async (field, rest) => {
    const src = app.src;
    if (!src) return null;
    const r = await sugg.run((call) => src.history({ ...base(st), q: rest, group_by: field }, call));
    return r?.ok ? (r.value.groups ?? []) : null;
  };

  function filterValue(r: HistoryRow, key: string): string | null {
    switch (key) {
      case 'verdict': return r.verdict;
      case 'src': return r.src_key;
      case 'method': return r.method;
      case 'host': return r.host;
      case 'path': return r.path;
      case 'construct': return r.construct;
      case 'stage': return r.stage ?? 'clean';
      case 'rev': return String(r.config_rev);
      default: return null;
    }
  }

  const requestHref = (r: HistoryRow) => `/requests/${encodeURIComponent(r.id)}`;
  const sourceHref = (key: string) => `/sources/${encodeURIComponent(key)}`;
  const settingHref = (key: string) => `/settings?highlight=${encodeURIComponent(key)}`;

  function openRequest(r: HistoryRow, c = active.c) {
    history.replaceState({ ...(history.state ?? {}), monitorFocus: { id: r.id, c } }, '');
    router.navigate(requestHref(r));
  }

  function activate(cell: Cell, negate: boolean) {
    if (grouped) {
      const g = groups?.[cell.r];
      const field = st.group;
      if (!g || !field) return;
      setState({ q: addTerm(st.q, field, field === 'stage' || field === 'verdict' ? g.value.toLowerCase() : g.value, negate), group: null });
      return;
    }
    const r = rows[cell.r];
    const col = COLS[cell.c];
    if (!r) return;
    if (col.key === 'ts') openRequest(r, cell.c);
    else if (col.key === 'decided') router.navigate(settingHref(r.decided_option));
    else if (col.field) {
      const v = filterValue(r, col.key);
      if (v !== null) setState({ q: addTerm(st.q, col.field, col.key === 'verdict' ? v.toLowerCase() : v, negate) });
    }
  }

  function focusCell() {
    table?.querySelector<HTMLElement>(`[data-r="${active.r}"][data-c="${active.c}"]`)?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') { e.preventDefault(); activate(active, e.shiftKey); return; }
    if ((e.key === 'o' || e.key === 'O') && !e.ctrlKey && !e.metaKey && !e.altKey && !grouped) {
      const r = rows[active.r];
      if (r) router.navigate(sourceHref(r.src_key));
      return;
    }
    const n = moveCell(active, e.key, { ctrl: e.ctrlKey }, { rows: nrows, cols: ncols });
    if (!n) return;
    e.preventDefault();
    pos = n;
    focusCell();
  }

  // A click on a value filters by it (Shift excludes it); links inside cells keep their own behaviour.
  function onclick(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const td = target.closest<HTMLElement>('td[data-r]');
    if (!td || target.closest('a')) return;
    pos = { r: Number(td.dataset.r), c: Number(td.dataset.c) };
    if (td.dataset.act) activate(pos, e.shiftKey);
  }

  function linkClick(e: MouseEvent, go: () => void) {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    go();
  }

  function onfocusin(e: FocusEvent) {
    focusIn = true;
    const td = (e.target as HTMLElement).closest<HTMLElement>('td[data-r]');
    if (td) pos = { r: Number(td.dataset.r), c: Number(td.dataset.c) };
  }
  function onfocusout(e: FocusEvent) {
    if (!table?.contains(e.relatedTarget as Node | null)) focusIn = false;
  }

  async function copyUrl() {
    try {
      await navigator.clipboard.writeText(location.href);
      toasts.push({ tone: 'success', text: 'Query URL copied.' });
    } catch {
      toasts.push({ tone: 'warn', text: 'Could not copy the URL; it is in the address bar.' });
    }
  }

  const acts = (c: Col, r: HistoryRow) => c.key === 'ts' || c.key === 'decided' || (!!c.field && filterValue(r, c.key) !== null);
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
</header>

<div class="bar card">
  <div class="query">
    <QueryBar bind:value={draft} bind:input={queryInput} error={queryError} {suggest} onsubmit={(q) => setState({ q })} />
  </div>
  <div class="seg" role="group" aria-label="Time range">
    {#each RANGES as r (r.key)}
      <button class="btn btn-sm" aria-pressed={st.range === r.key} onclick={() => setState({ range: r.key, from: null, to: null })}>{r.label}</button>
    {/each}
  </div>
  <div class="chips" role="group" aria-label="Group by">
    <span class="label-caps">Group by</span>
    {#each GROUP_BYS as g (g)}
      <button class="btn btn-sm" aria-pressed={st.group === g} onclick={() => setState({ group: st.group === g ? null : g })}>{g}</button>
    {/each}
  </div>
</div>

<div class="results-head">
  <p class="num count">
    {#if !loaded}Loading…{:else if grouped}{fmtCount(groups?.length ?? 0)} groups · {fmtCount(total)} requests{:else}{fmtCount(total)} {total === 1 ? 'result' : 'results'}{#if rows.length < total}{` · showing ${fmtCount(rows.length)}, newest first`}{/if}{/if}
  </p>
  <p class="secondary note">Allows are sampled at 1 %; every other verdict is stored.</p>
  <div class="seg" role="group" aria-label="Auto-refresh">
    <span class="label-caps">Auto-refresh</span>
    {#each REFRESH as r (r.key)}
      <button class="btn btn-sm" aria-pressed={st.refresh === r.key} onclick={() => setState({ refresh: r.key })}>{r.label}</button>
    {/each}
  </div>
  {#if updatedAt}<span class="secondary num updated">Updated {fmtClock(updatedAt)}{#if paused && st.refresh !== 'off'} · paused{/if}</span>{/if}
  <button class="btn btn-sm btn-ghost" onclick={copyUrl}><Copy size={14} aria-hidden="true" />Copy query URL</button>
</div>

<p class="live" role="status">
  {#if newCount > 0}
    {newCount >= PAGE ? `${PAGE}+` : newCount} new {newCount === 1 ? 'result' : 'results'} —
    <button class="btn btn-sm btn-ghost" onclick={showNew}>Show</button>
  {/if}
</p>

{#if historyDrops > 0}
  <p class="notice card" role="status">History writer dropped {fmtCount(historyDrops)} events since start; counts may be low.</p>
{/if}
{#if otherError}<div class="error"><ErrorCard error={otherError} onretry={load} /></div>{/if}

<section class="results card" aria-label="Results" aria-busy={!loaded}>
  {#if !loaded}
    <div class="skeleton" aria-hidden="true">{#each Array.from({ length: 10 }, (_, i) => i) as i (i)}<span></span>{/each}</div>
  {:else if nrows === 0 && !error}
    <EmptyState scene="quiet" message={`No requests match ${st.q ? `“${st.q}”` : 'anything'} in this range.`} />
    {#if widen(st)}
      <p class="widen"><button class="btn btn-sm" onclick={() => setState({ range: widen(st)!, from: null, to: null })}>Widen range</button></p>
    {/if}
  {:else if nrows > 0}
    <p class="secondary hint">
      {#if grouped}Enter or click on a group opens its requests.{:else}Enter or click on a value adds it to the query; Shift excludes it. Enter on the time opens the request; O opens its source.{/if}
    </p>
    <div class="scroll">
      <table
        bind:this={table}
        class="data-table grid"
        class:dated={withDate}
        role="grid"
        aria-label={grouped ? `Requests grouped by ${st.group}` : 'Matching requests'}
        aria-rowcount={nrows + 1}
        {onkeydown}
        {onclick}
        {onfocusin}
        {onfocusout}
      >
        {#if grouped && groups && st.group}
          <thead><tr><th scope="col">{GROUP_LABEL[st.group]}</th><th scope="col" class="n">Requests</th></tr></thead>
          <tbody>
            {#each groups as g, r (g.value)}
              <tr aria-rowindex={r + 2}>
                <td role="gridcell" data-r={r} data-c={0} data-act="1" tabindex={r === active.r && active.c === 0 ? 0 : -1} class="act"><span class="mono">{g.value}</span></td>
                <td role="gridcell" data-r={r} data-c={1} data-act="1" tabindex={r === active.r && active.c === 1 ? 0 : -1} class="n act">{fmtCount(g.count)}</td>
              </tr>
            {/each}
          </tbody>
        {:else}
          <thead><tr>{#each COLS as c (c.key)}<th scope="col" class="c-{c.key}" class:n={c.n} title={HEAD_TITLE[c.key]}>{#if c.short}<span aria-hidden="true">{c.short}</span><span class="sr-only">{c.label}</span>{:else}{c.label}{/if}</th>{/each}</tr></thead>
          <tbody>
            {#each rows as row, r (row.id)}
              <tr class:blocked={row.verdict === 'Block'} aria-rowindex={r + 2}>
                {#each COLS as col, c (col.key)}
                  <td
                    role="gridcell"
                    data-r={r}
                    data-c={c}
                    data-act={acts(col, row) ? '1' : undefined}
                    tabindex={r === active.r && c === active.c ? 0 : -1}
                    class:n={col.n}
                    class:act={!!col.field && acts(col, row)}
                    class="c-{col.key}"
                  >
                    {#if col.key === 'ts'}
                      <a href={requestHref(row)} tabindex="-1" class="mono clip" title={fmtStamp(row.ts_ms, true)} onclick={(e) => linkClick(e, () => openRequest(row, c))}>{fmtStamp(row.ts_ms, withDate)}</a>
                    {:else if col.key === 'verdict'}
                      <VerdictChip verdict={row.verdict} size="sm" />{#if row.excepted}<span class="excepted" role="img" aria-label="Exception applied" title="An exception changed how this request was judged"><ShieldOff size={14} strokeWidth={1.5} aria-hidden="true" /></span>{/if}{#if row.sampled}<span class="tag">sampled</span>{/if}
                    {:else if col.key === 'score'}
                      <span class="num">{row.score}</span>
                    {:else if col.key === 'src'}
                      <span class="srcwrap"><span class="mono clip" title={row.src_key}>{row.src_key}</span><a href={sourceHref(row.src_key)} tabindex="-1" class="open" aria-label={`Open source ${row.src_key}`} onclick={(e) => linkClick(e, () => router.navigate(sourceHref(row.src_key)))}><ExternalLink size={14} aria-hidden="true" /></a></span>
                    {:else if col.key === 'method'}
                      <span class="mono">{row.method}</span>
                    {:else if col.key === 'host'}
                      <span class="mono clip" title={row.host}>{row.host}</span>
                    {:else if col.key === 'path'}
                      <span class="mono clip" title={row.path}>{row.path}</span>
                    {:else if col.key === 'construct'}
                      <span class="mono clip" title={row.construct ?? undefined}>{row.construct ?? '—'}</span>
                    {:else if col.key === 'technique'}
                      <TechniqueCell technique={row.technique} construct={row.construct} />
                    {:else if col.key === 'confidence'}
                      {#if row.confidence === null}<span aria-hidden="true">—</span><span class="sr-only">not measured</span>{:else}<span class="num">{row.confidence}</span>{/if}
                    {:else if col.key === 'stage'}
                      <StageChip stage={row.stage} compact />
                    {:else if col.key === 'decided'}
                      <a href={settingHref(row.decided_option)} tabindex="-1" class="mono clip" title={row.decided_option} onclick={(e) => linkClick(e, () => router.navigate(settingHref(row.decided_option)))}>{row.decided_option}</a>
                    {:else if col.key === 'rev'}
                      <span class="num">{row.config_rev}</span>
                    {:else if col.key === 'latency'}
                      <span class="num">{row.latency_us} µs</span>
                    {:else}
                      {#if row.upstream_status === null}<span aria-hidden="true">—</span><span class="sr-only">not forwarded</span>{:else}<span class="num">{row.upstream_status}</span>{/if}
                    {/if}
                  </td>
                {/each}
              </tr>
            {/each}
          </tbody>
        {/if}
      </table>
    </div>
    {#if !grouped && next}
      <p class="pager"><button class="btn btn-sm" onclick={loadMore}>Load more</button></p>
    {/if}
  {/if}
</section>

<style>
  .head { margin-bottom: var(--vf-space-4); }
  .bar { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: var(--vf-space-3) var(--vf-space-4); align-items: start; margin-bottom: var(--vf-space-3); }
  .query { min-width: 0; }
  .seg { display: inline-flex; align-items: center; gap: var(--vf-space-1); }
  .bar > .seg { margin-top: calc(var(--vf-lh-label) + var(--vf-space-1)); }
  .chips { grid-column: 1 / -1; display: flex; flex-wrap: wrap; align-items: center; gap: var(--vf-space-1); }
  .chips .label-caps, .seg .label-caps { margin-right: var(--vf-space-1); }
  .results-head { display: flex; flex-wrap: wrap; align-items: center; gap: var(--vf-space-2) var(--vf-space-4); margin-bottom: var(--vf-space-2); }
  .count { font-weight: 600; }
  .note, .updated, .hint { font-size: var(--vf-fs-xs); }
  .results-head .seg { margin-left: auto; }
  .live:empty { display: none; }
  .live { display: flex; align-items: center; gap: var(--vf-space-2); margin-bottom: var(--vf-space-2); font-size: var(--vf-fs-sm); }
  .notice { margin-bottom: var(--vf-space-3); background: var(--vf-attention-soft); color: var(--vf-attention); }
  .error { margin-bottom: var(--vf-space-3); }
  .results { padding: var(--vf-space-2) 0 0; }
  .hint { padding: 0 var(--vf-space-3) var(--vf-space-2); }
  .scroll { overflow: auto; max-height: calc(100vh - 360px); }
  /* Fixed layout: the grid always fits its card at 1440; long values are clipped with the full text in title. */
  .grid { font-size: var(--vf-fs-sm); table-layout: fixed; }
  .grid th, .grid td { padding: 0 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .grid th { position: sticky; top: 0; z-index: 1; background: var(--vf-surface-raised); }
  /* Widths (about 1160 px of grid at 1280 and 1440): every header fits its label; Time and the usual
     Decided-by key take one line; Path is readable; Technique fits one chip (T1595.003); Confidence shows "Conf.". */
  .grid th.c-ts { width: 6.5%; }
  .grid th.c-verdict { width: 9%; }
  .grid th.c-score { width: 4.7%; }
  .grid th.c-src { width: 7.5%; }
  .grid th.c-method { width: 5.7%; }
  .grid th.c-host { width: 4.8%; }
  .grid th.c-path { width: 9.7%; }
  .grid th.c-construct { width: 9%; }
  .grid th.c-technique { width: 7.7%; }
  .grid th.c-confidence { width: 4.4%; }
  .grid th.c-stage { width: 6.5%; }
  .grid th.c-decided { width: 11.2%; }
  .grid th.c-rev { width: 3.3%; }
  .grid th.c-latency { width: 6%; }
  .grid th.c-upstream { width: 4%; }
  /* With the date, Time breaks once, between the date and the clock. */
  .grid.dated th.c-ts { width: 8.5%; }
  .grid.dated th.c-src { width: 6.5%; }
  .grid.dated th.c-verdict { width: 8.5%; }
  .grid.dated th.c-path { width: 9.2%; }
  .grid td.c-verdict { white-space: normal; }
  .srcwrap { display: flex; align-items: center; min-width: 0; }
  .grid td:focus-visible { outline-offset: -2px; box-shadow: none; }
  .grid tr:hover td { background: var(--vf-row-hover); }
  .grid tr.blocked td { background: var(--vf-row-blocked); }
  .grid tr.blocked td:first-child { box-shadow: inset 3px 0 0 var(--vf-verdict-block-line); }
  .grid tr.blocked:hover td { background: var(--vf-row-hover); }
  td.act { cursor: pointer; }
  td.act:hover .mono, td.act:hover > .num { text-decoration: underline; }
  .grid .mono { font-size: var(--vf-fs-xs); }
  /* Long mono values wrap at any character, at most two lines, so a 40 px row still fits them. */
  .clip {
    display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; line-clamp: 2;
    max-width: 100%; overflow: hidden; white-space: normal; overflow-wrap: anywhere; line-height: var(--vf-lh-xs);
  }
  .srcwrap .clip { min-width: 0; }
  .excepted { display: inline-flex; vertical-align: middle; margin-left: var(--vf-space-1); color: var(--vf-text-secondary); }
  .tag { margin-left: var(--vf-space-1); font-size: var(--vf-fs-xs); color: var(--vf-text-secondary); }
  .open { display: inline-flex; flex: none; margin-left: var(--vf-space-1); color: var(--vf-accent); }
  .skeleton { display: grid; gap: var(--vf-space-2); padding: var(--vf-space-3); }
  .skeleton span { height: var(--vf-row-h-dense); border-radius: var(--vf-radius-xs); background: var(--vf-surface-sunken); }
  .widen, .pager { display: flex; justify-content: center; padding: var(--vf-space-3); }
</style>
