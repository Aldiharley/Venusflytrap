<script lang="ts">
  import { onMount } from 'svelte';
  import type { SourceError } from '../lib/api/errors';
  import { Latest } from '../lib/api/latest';
  import { STAGES, VERDICTS, type Dashboard } from '../lib/api/types';
  import { propUrl } from '../lib/assets';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import ErrorCard from '../lib/components/ErrorCard.svelte';
  import KpiTile from '../lib/components/KpiTile.svelte';
  import Link from '../lib/components/Link.svelte';
  import Region from '../lib/components/Region.svelte';
  import StageChip from '../lib/components/StageChip.svelte';
  import { fmtCount, fmtRps } from '../lib/format';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';
  import StackedArea from './dashboard/StackedArea.svelte';

  let { title }: { title: string } = $props();
  const RANGES: [string, number][] = [['1 h', 3_600_000], ['6 h', 6 * 3_600_000], ['24 h', 24 * 3_600_000], ['7 d', 7 * 24 * 3_600_000]];

  let data = $state<Dashboard | null>(null);
  let error = $state<SourceError | null>(null);
  let updatedAt = $state(0);
  const latest = new Latest();

  const span = $derived.by(() => {
    const from = Number(router.search.get('from'));
    const to = Number(router.search.get('to'));
    return from && to && to > from ? to - from : RANGES[0][1];
  });

  async function load() {
    const src = app.src;
    if (!src) return;
    const to = Date.now();
    const from = to - span;
    const r = await latest.run((call) => src.dashboard(from, to, call));
    if (!r) return; // superseded by a newer load, or the screen left
    if (r.ok) {
      data = r.value;
      error = null;
      updatedAt = Date.now();
    } else error = r.error;
  }

  onMount(() => {
    const t = setInterval(load, 60_000);
    return () => { clearInterval(t); latest.abort(); };
  });
  $effect(() => { void span; load(); });

  function pick(ms: number) {
    const to = Date.now();
    router.navigate(`/?from=${to - ms}&to=${to}`, true);
  }

  const rps = $derived(app.counters?.rps_by_verdict ?? [0, 0, 0, 0]);
  const maxStage = $derived(data ? Math.max(1, ...STAGES.map((s) => data!.sources_by_stage[s])) : 1);
  const honeypotTotal = $derived(data ? data.honeypot_hits.reduce((a, h) => a + h.count, 0) : 0);
  const tower = propUrl('shield-tower');
</script>

<header class="head">
  <h1 tabindex="-1">{title}</h1>
  <div class="seg" role="group" aria-label="Time range">
    {#each RANGES as [label, ms] (label)}
      <button class="btn btn-sm" aria-pressed={span === ms} onclick={() => pick(ms)}>{label}</button>
    {/each}
  </div>
</header>

{#if error}
  <div class="error"><ErrorCard {error} onretry={load} /></div>
{/if}

{#if app.status && app.status.worst !== 'Ok'}
  <p class="banner card" role="status">Service state: {app.status.worst}. {app.status.components.filter((c) => c.state !== 'Ok').map((c) => c.name).join(', ')}</p>
{/if}

<div class="grid">
  <dl class="kpis" aria-label="Live counters">
    {#each VERDICTS as v, i (v)}
      <KpiTile label={v} value={fmtRps(rps[i]).replace('/s', '')} unit="/s" tone={v.toLowerCase() as 'allow'} stale={app.stale} />
    {/each}
    <KpiTile label="Active bans" value={fmtCount(data?.active_bans ?? 0)} />
    <KpiTile label="Honeypot hits" value={fmtCount(honeypotTotal)} note="in range" />
    <KpiTile label="Dropped" value={fmtCount(app.counters?.dropped_total ?? 0)} note={`history ${fmtCount(app.status?.drops.history ?? 0)}`} />
  </dl>

  <div class="chart">
    <Region title="Requests over time" {updatedAt} busy={!data && !error} stale={!!error}>
      {#if data}
        <StackedArea series={data.requests_by_verdict} from={data.from_ms} bucketMs={data.bucket_ms} />
      {:else}
        <div class="skeleton"></div>
      {/if}
    </Region>
  </div>

  <div class="stages">
    <Region title="Sources by stage" {updatedAt} stale={!!error}>
      {#if data}
        <ul class="bars">
          {#each STAGES as s (s)}
            <li>
              <Link href={`/chains?stage=${s}`} class="bar-row">
                <StageChip stage={s} />
                <span class="track" aria-hidden="true"><span class="fill {s.toLowerCase()}" style:width={`${(data.sources_by_stage[s] / maxStage) * 100}%`}></span></span>
                <span class="num">{fmtCount(data.sources_by_stage[s])}</span>
              </Link>
            </li>
          {/each}
        </ul>
        <p class="secondary small">Clean sources: {fmtCount(data.sources_by_stage.Clean)}</p>
      {/if}
    </Region>
  </div>

  <div class="constructs">
    <Region title="Top constructs" {updatedAt} stale={!!error}>
      {#if data && data.top_constructs.length}
        <table class="data-table">
          <thead><tr><th>Construct</th><th>Family</th><th class="n">Count</th></tr></thead>
          <tbody>
            {#each data.top_constructs as c (c.id)}
              <tr>
                <td><Link href={`/monitor?q=${encodeURIComponent(`construct:${c.id}`)}`} class="mono">{c.id}</Link></td>
                <td>{c.family}</td>
                <td class="n">{fmtCount(c.count)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else if data}
        <EmptyState scene="quiet" message="No requests recorded since start." />
      {/if}
    </Region>
  </div>

  <div class="paths">
    <Region title="Top targeted paths" {updatedAt} stale={!!error}>
      {#if data}
        <table class="data-table">
          <thead><tr><th>Path prefix</th><th class="n">Requests</th><th class="n">Blocked</th></tr></thead>
          <tbody>
            {#each data.top_paths as p (p.prefix)}
              <tr>
                <td><Link href={`/monitor?q=${encodeURIComponent(`path:${p.prefix}*`)}`} class="mono">{p.prefix}</Link></td>
                <td class="n">{fmtCount(p.count)}</td>
                <td class="n">{fmtCount(p.by_verdict[2] + p.by_verdict[3])}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </Region>
  </div>

  <div class="teaser">
    <Region title="Traffic topology">
      <Link href="/topology" class="teaser-link">
        {#if tower}<img src={tower} alt="" width="120" />{/if}
        <span>Open traffic topology</span>
      </Link>
    </Region>
  </div>
</div>

<style>
  .head { display: flex; align-items: center; gap: var(--vf-space-4); margin-bottom: var(--vf-space-5); }
  .seg { margin-left: auto; display: inline-flex; gap: var(--vf-space-1); }
  .error { margin-bottom: var(--vf-space-4); }
  .banner { margin-bottom: var(--vf-space-4); background: var(--vf-attention-soft); color: var(--vf-attention); }
  .grid { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: var(--vf-space-5); }
  .kpis { grid-column: 1 / 4; grid-row: 1 / 4; display: grid; grid-template-columns: 1fr 1fr; gap: var(--vf-space-3); align-content: start; margin: 0; }
  .chart { grid-column: 4 / 13; }
  .stages, .paths { grid-column: 4 / 8; }
  .constructs, .teaser { grid-column: 8 / 13; }
  .skeleton { height: 280px; border-radius: var(--vf-radius-sm); background: var(--vf-surface-sunken); }
  .bars { margin: 0; padding: 0; list-style: none; display: grid; gap: var(--vf-space-2); }
  .bars :global(.bar-row) { display: grid; grid-template-columns: 150px 1fr 48px; align-items: center; gap: var(--vf-space-3); color: inherit; text-decoration: none; }
  .track { height: 8px; border-radius: 4px; background: var(--vf-surface-sunken); box-shadow: var(--vf-shadow-inset); overflow: hidden; }
  .fill { display: block; height: 100%; }
  .fill.recon { background: var(--vf-stage-recon-fg); }
  .fill.enumeration { background: var(--vf-stage-enumeration-fg); }
  .fill.exploitation { background: var(--vf-stage-exploitation-fg); }
  .fill.exfiltration { background: var(--vf-stage-exfiltration-fg); }
  .small { font-size: var(--vf-fs-xs); }
  .teaser :global(.teaser-link) { display: flex; align-items: center; gap: var(--vf-space-4); font-weight: 600; }
  .teaser img { height: auto; filter: var(--vf-prop-filter); }
  @media (max-width: 1439px) {
    .kpis { grid-column: 1 / 13; grid-row: auto; grid-template-columns: repeat(4, 1fr); }
    .chart { grid-column: 1 / 13; }
    .stages, .paths { grid-column: 1 / 7; }
    .constructs, .teaser { grid-column: 7 / 13; }
  }
</style>
