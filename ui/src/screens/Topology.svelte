<script lang="ts">
  import { onMount } from 'svelte';
  import type { SourceError } from '../lib/api/errors';
  import { Latest } from '../lib/api/latest';
  import type { Dashboard } from '../lib/api/types';
  import ErrorCard from '../lib/components/ErrorCard.svelte';
  import { Pause, Play, Table2 } from '../lib/icons';
  import { fmtCount } from '../lib/format';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import { motion } from '../lib/state/theme.svelte';
  import Legend from './topology/Legend.svelte';
  import { buildModel, clusterRates } from './topology/model';
  import Scene from './topology/Scene.svelte';
  import TableView from './topology/TableView.svelte';

  let { title }: { title: string } = $props();
  let dashboard = $state<Dashboard | null>(null);
  let error = $state<SourceError | null>(null);
  const latest = new Latest();

  // Route groups come from the dashboard aggregate; on failure the last one stays on the map.
  async function load() {
    const src = app.src;
    if (!src) return;
    const to = Date.now();
    const r = await latest.run((call) => src.dashboard(to - 3_600_000, to, call));
    if (!r) return;
    if (r.ok) { dashboard = r.value; error = null; } else error = r.error;
  }
  onMount(() => {
    load();
    const t = setInterval(load, 60_000);
    return () => { clearInterval(t); latest.abort(); };
  });

  const view = $derived(router.search.get('view') ?? (motion.osReduced ? 'table' : 'map'));
  const model = $derived(
    buildModel({
      counters: app.counters ?? { rps_by_verdict: [0, 0, 0, 0], dropped_total: 0 },
      board: app.board,
      rates: clusterRates(app.prevBoard, app.board, app.boardAt - app.prevBoardAt),
      dashboard,
      status: app.status,
      now: app.now,
    }),
  );

  function setView(v: 'map' | 'table') {
    const p = new URLSearchParams(router.search);
    p.set('view', v);
    router.navigate(`/topology?${p}`, true);
  }
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
  <p class="secondary status">Live: {app.liveLabel} · dropped {fmtCount(app.counters?.dropped_total ?? 0)}</p>
</header>

{#if error}<div class="error"><ErrorCard {error} onretry={load} /></div>{/if}

<div class="layout">
  <div class="stage">
    {#if view === 'table'}
      <TableView nodes={model.nodes} flows={model.flows} />
    {:else}
      <Scene nodes={model.nodes} flows={model.flows} board={app.board} rps={app.counters?.rps_by_verdict ?? [0, 0, 0, 0]} stale={app.stale} now={app.now} />
      <Legend />
      {#if model.flows.every((f) => f.step === 0)}<p class="note card">No traffic yet</p>{/if}
    {/if}
  </div>
  <div class="rail glass" role="toolbar" aria-label="View controls" aria-orientation="vertical">
    <button class="btn btn-ghost" aria-pressed={view === 'table'} onclick={() => setView(view === 'table' ? 'map' : 'table')}>
      <Table2 size={18} aria-hidden="true" /><span class="sr-only">Table view</span>
    </button>
    <button class="btn btn-ghost" aria-pressed={motion.paused} onclick={() => motion.set(!motion.paused)}>
      {#if motion.paused}<Play size={18} aria-hidden="true" />{:else}<Pause size={18} aria-hidden="true" />{/if}
      <span class="sr-only">Pause animation</span>
    </button>
  </div>
</div>

<style>
  .head { display: flex; align-items: baseline; gap: var(--vf-space-4); margin-bottom: var(--vf-space-4); }
  .status { font-size: var(--vf-fs-sm); }
  .error { margin-bottom: var(--vf-space-3); }
  .layout { display: grid; grid-template-columns: minmax(0, 1fr) 48px; gap: var(--vf-space-3); }
  .stage { position: relative; }
  .rail { display: grid; align-content: start; gap: var(--vf-space-1); padding: var(--vf-space-1); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-1); }
  .rail .btn { width: 40px; padding: 0; justify-content: center; }
  .note { position: absolute; left: 50%; top: var(--vf-space-4); transform: translateX(-50%); }
</style>
