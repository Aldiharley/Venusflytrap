<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { STAGES, type SourceView, type Stage } from '../lib/api/types';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import StageChip from '../lib/components/StageChip.svelte';
  import { banText, fmtAgo, fmtCount } from '../lib/format';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import { moveCell, reconcile, sortKeys, stageCellText, type Cell } from './chains/grid';

  let { title }: { title: string } = $props();
  const COLS = ['Source', ...STAGES, 'Requests / Blocked', 'Honeypot', 'Ban', 'Last seen'];

  let minStage = $state<Stage | ''>((router.search.get('stage') as Stage) ?? '');
  let bannedOnly = $state(false);
  let search = $state('');
  let frozen = $state(false);
  let order = $state<string[]>([]);
  let pending = $state(0);
  let pos = $state<Cell>({ r: 0, c: 0 });
  let table: HTMLTableElement | undefined = $state();
  let region: HTMLDivElement | undefined = $state();

  const rows = $derived(
    app.board.filter((s) =>
      s.stage !== null &&
      (!minStage || STAGES.indexOf(s.stage) >= STAGES.indexOf(minStage)) &&
      (!bannedOnly || s.ban) &&
      (!search || s.key.includes(search) || s.ip.includes(search)),
    ),
  );
  // The roving tab stop always lands on a cell that exists, even after the row count shrinks.
  const active = $derived<Cell>({
    r: Math.max(0, Math.min(pos.r, order.length - 1)),
    c: Math.max(0, Math.min(pos.c, COLS.length - 1)),
  });
  const byKey = $derived(new Map(app.board.map((s) => [s.key, s])));

  // Depends on rows and frozen only: `order` is read untracked, or writing it would re-run
  // this effect forever.
  $effect(() => {
    const current = untrack(() => order);
    const r = reconcile(current.length ? current : sortKeys(rows), rows, frozen);
    order = r.order;
    pending = r.pending;
  });

  // The frozen region is the table plus the pending bar, so Tab or a click onto Apply keeps the order.
  function onfocusin(e: FocusEvent) {
    frozen = true;
    const td = (e.target as HTMLElement).closest('td');
    if (td) pos = { r: Number(td.dataset.r), c: Number(td.dataset.c) };
  }

  function onfocusout(e: FocusEvent) {
    if (!region?.contains(e.relatedTarget as Node | null)) frozen = false;
  }

  async function apply() {
    const focusedKey = order[active.r];
    const c = active.c;
    order = sortKeys(rows);
    pending = 0;
    const i = order.indexOf(focusedKey);
    pos = { r: i >= 0 ? i : 0, c };
    await tick(); // the bar may unmount and the rows reorder first; then focus returns to the same key
    focusCell();
  }

  function focusCell() {
    table?.querySelector<HTMLElement>(`[data-r="${pos.r}"][data-c="${pos.c}"]`)?.focus();
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      const key = order[active.r];
      if (key) router.navigate(`/sources/${encodeURIComponent(key)}`);
      return;
    }
    if ((e.key === 'r' || e.key === 'R') && !e.ctrlKey && !e.metaKey && !e.altKey) { apply(); return; }
    const next = moveCell(active, e.key, { ctrl: e.ctrlKey }, { rows: order.length, cols: COLS.length });
    if (!next) return;
    e.preventDefault();
    pos = next;
    focusCell();
  }

  // `now` matters only to the Ban and Last-seen columns; the other cells are passed 0 so a clock tick leaves them alone.
  function cell(s: SourceView | undefined, c: number, now: number): string {
    if (!s) return c === 0 ? 'Source left the board' : '';
    if (c >= 1 && c <= 4) return stageCellText(s, STAGES[c - 1]);
    if (c === 5) return `${fmtCount(s.requests)} / ${fmtCount(s.blocked)}`;
    if (c === 6) return fmtCount(s.honeypot_hits);
    if (c === 7) return s.ban ? banText(s.ban, now) : '—';
    if (c === 8) return fmtAgo(now - s.last_seen_ms);
    return s.key;
  }
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
</header>

<div class="toolbar card">
  <label>Minimum stage
    <select bind:value={minStage}>
      <option value="">Any</option>
      {#each STAGES as s (s)}<option value={s}>{s}</option>{/each}
    </select>
  </label>
  <label class="check"><input type="checkbox" bind:checked={bannedOnly} /> Banned only</label>
  <label>Source <input class="mono" bind:value={search} placeholder="Key or IP" /></label>
  <span class="secondary num count">{order.length} of ≤ 500</span>
  <span class="secondary">Live: {app.stale ? 'paused' : app.live} · dropped {app.counters?.dropped_total ?? 0}</span>
</div>

<div class="region" bind:this={region} {onfocusin} {onfocusout}>
{#if order.length === 0}
  <div class="card"><EmptyState scene="quiet" message="No source has reached Recon in the chain window." /></div>
{:else}
  <div class="scroll card">
    <table
      bind:this={table}
      class="data-table grid"
      role="grid"
      aria-label="Sources by kill-chain stage"
      aria-rowcount={order.length + 1}
      {onkeydown}
    >
      <thead>
        <tr>{#each COLS as c (c)}<th scope="col">{c}</th>{/each}</tr>
      </thead>
      <tbody>
        {#each order as key, r (key)}
          {@const s = byKey.get(key)}
          <tr class:banned={s?.ban} aria-rowindex={r + 2}>
            {#each COLS as colName, c (colName)}
              {@const text = cell(s, c, c >= 7 ? app.now : 0)}
              {@const isCurrent = !!s && c >= 1 && c <= 4 && s.stage === STAGES[c - 1]}
              <td
                role="gridcell"
                data-r={r}
                data-c={c}
                tabindex={r === active.r && c === active.c ? 0 : -1}
                class:n={c >= 5 && c <= 6}
                class:stagecell={c >= 1 && c <= 4}
                class:current={isCurrent}
                aria-label={s && c >= 1 && c <= 4 ? `${colName}: ${text === '—' ? 'not reached' : `reached ${text.replace(' · ', ', ')} events`}${isCurrent ? ', current stage' : ''}` : undefined}
              >
                {#if c === 0 && s}
                  <span class="mono">{s.key}</span>{#if s.ip !== s.key}<span class="secondary ip">{s.ip}</span>{/if}
                {:else if isCurrent && s}
                  <StageChip stage={s.stage} compact /> <span class="num">{text}</span>
                {:else if c === 7 && s?.ban}
                  <span class="ban">{text}</span>
                {:else}
                  <span class="num">{text}</span>
                {/if}
              </td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if frozen && pending > 0}
  <div class="pending glass" role="status">
    Order paused while you navigate — {pending} {pending === 1 ? 'update' : 'updates'}.
    <button class="btn btn-sm btn-primary" onclick={apply}>Apply (R)</button>
  </div>
{/if}
</div>

<style>
  .head { margin-bottom: var(--vf-space-4); }
  .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--vf-space-4); margin-bottom: var(--vf-space-4); }
  .toolbar label { display: inline-flex; align-items: center; gap: var(--vf-space-2); font-size: var(--vf-fs-sm); }
  .toolbar select, .toolbar input:not([type]) {
    height: var(--vf-control-sm); padding: 0 var(--vf-space-2); border-radius: var(--vf-radius-sm);
    border: var(--vf-bw-std) solid var(--vf-border-strong); background: var(--vf-surface-input);
  }
  .count { margin-left: auto; }
  .scroll { overflow: auto; max-height: calc(100vh - 260px); padding: 0; }
  .grid td { white-space: nowrap; }
  .grid td:first-child, .grid td.stagecell { white-space: normal; }
  .grid td.stagecell .num { display: inline-block; white-space: nowrap; }
  .grid td:focus-visible { outline-offset: -2px; box-shadow: none; }
  .grid tr:hover td { background: var(--vf-row-hover); }
  td.current { font-weight: 600; }
  .ban { padding: 2px 6px; border-radius: var(--vf-radius-xs); background: var(--vf-verdict-block-bg); color: var(--vf-verdict-block-fg); font-weight: 600; }
  .ip { display: block; font-size: var(--vf-fs-xs); }
  .pending { position: sticky; bottom: var(--vf-space-4); margin-top: var(--vf-space-3); display: flex; align-items: center; justify-content: space-between; gap: var(--vf-space-3); padding: var(--vf-space-2) var(--vf-space-4); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-2); }
</style>
