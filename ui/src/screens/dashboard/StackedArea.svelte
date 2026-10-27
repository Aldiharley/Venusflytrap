<script lang="ts">
  import { VERDICTS } from '../../lib/api/types';
  import { fmtClock, fmtCount } from '../../lib/format';
  import { stackedPaths } from './series';

  let { series, from, bucketMs }: { series: number[][]; from: number; bucketMs: number } = $props();
  let asTable = $state(false);
  const W = 800, H = 280;
  const paths = $derived(stackedPaths(series, W, H));
</script>

<div class="wrap">
  <button class="btn btn-sm toggle" aria-pressed={asTable} onclick={() => (asTable = !asTable)}>Show as table</button>
  {#if asTable}
    <!-- A scrolling region must be keyboard-focusable (axe scrollable-region-focusable). -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex: axe requires a keyboard-focusable scroll container -->
    <div class="scroll" tabindex="0" role="region" aria-label="Requests over time, as a table">
      <table class="data-table">
        <thead><tr><th>Time</th>{#each VERDICTS as v (v)}<th class="n">{v}</th>{/each}</tr></thead>
        <tbody>
          {#each series[0] as _, i (i)}
            <tr><td class="num">{fmtClock(from + i * bucketMs)}</td>{#each series as s, k (k)}<td class="n">{fmtCount(s[i])}</td>{/each}</tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <svg viewBox="0 0 {W} {H}" preserveAspectRatio="none" aria-hidden="true">
      {#each [0.25, 0.5, 0.75] as g (g)}<line class="grid" x1="0" x2={W} y1={H * g} y2={H * g} />{/each}
      {#each paths as p, k (k)}<path class="area {VERDICTS[k].toLowerCase()}" d={p.d} />{/each}
    </svg>
    <ul class="legend">
      {#each VERDICTS as v, k (v)}
        <li><span class="sw {v.toLowerCase()}"></span>{v} <span class="num secondary">{fmtCount(series[k].reduce((a, b) => a + b, 0))}</span></li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .wrap { position: relative; display: grid; gap: var(--vf-space-2); }
  .toggle { justify-self: end; }
  svg { width: 100%; height: 280px; display: block; }
  .grid { stroke: var(--vf-chart-grid); stroke-width: 1; }
  .area { stroke-width: 1; }
  .area.allow { fill: color-mix(in srgb, var(--vf-verdict-allow-line) 40%, transparent); stroke: var(--vf-verdict-allow-line); }
  .area.monitor { fill: color-mix(in srgb, var(--vf-verdict-monitor-line) 50%, transparent); stroke: var(--vf-verdict-monitor-line); }
  .area.challenge { fill: color-mix(in srgb, var(--vf-verdict-challenge-line) 60%, transparent); stroke: var(--vf-verdict-challenge-line); }
  .area.block { fill: color-mix(in srgb, var(--vf-verdict-block-line) 70%, transparent); stroke: var(--vf-verdict-block-line); }
  .legend { display: flex; gap: var(--vf-space-4); margin: 0; padding: 0; list-style: none; font-size: var(--vf-fs-xs); }
  .sw { display: inline-block; width: 12px; height: 12px; margin-right: 4px; vertical-align: -2px; border-radius: 2px; }
  .sw.allow { background: var(--vf-verdict-allow-line); }
  .sw.monitor { background: var(--vf-verdict-monitor-line); }
  .sw.challenge { background: var(--vf-verdict-challenge-line); }
  .sw.block { background: var(--vf-verdict-block-line); }
  .scroll { max-height: 320px; overflow: auto; }
</style>
