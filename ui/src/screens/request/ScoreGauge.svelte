<script lang="ts">
  import type { Bands } from '../../lib/api/types';
  import { arc, bandOf, GAUGE, gaugeSentence, pointAt } from './why';

  // Design system §4 "Score gauge": track, band ring in the verdict line colours, value arc, needle.
  // The SVG is decorative; the sentence below carries the same information.
  let { score, bands, rev }: { score: number; bands: Bands; rev: number } = $props();

  const ring = $derived([
    { cls: 'monitor', from: bands.monitor_at, to: bands.challenge_at },
    { cls: 'challenge', from: bands.challenge_at, to: bands.block_at },
    { cls: 'block', from: bands.block_at, to: 100 },
  ]);
  const ticks = $derived([bands.monitor_at, bands.challenge_at, bands.block_at]);
  const tone = $derived(bandOf(score, bands).toLowerCase());
  const needle = $derived(pointAt(score, GAUGE.track - 8));
</script>

<figure class="gauge">
  <svg viewBox="0 0 {GAUGE.w} {GAUGE.h}" width={GAUGE.w} height={GAUGE.h} aria-hidden="true" focusable="false">
    <path class="track" d={arc(0, 100, GAUGE.track)} stroke-width="10" />
    {#each ring as b (b.cls)}<path class="band {b.cls}" d={arc(b.from, b.to, GAUGE.band)} stroke-width="4" />{/each}
    {#if score > 0}<path class="value {tone}" d={arc(0, score, GAUGE.track)} stroke-width="10" stroke-linecap="round" />{/if}
    {#each ticks as t (t)}
      {@const [x1, y1] = pointAt(t, GAUGE.band - 5)}
      {@const [x2, y2] = pointAt(t, GAUGE.band + 5)}
      {@const [lx, ly] = pointAt(t, GAUGE.label)}
      <line class="tick" {x1} {y1} {x2} {y2} stroke-width="2" />
      <text class="lbl num" x={lx} y={ly} text-anchor="middle" dominant-baseline="middle">{t}</text>
    {/each}
    <line class="needle" x1={GAUGE.cx} y1={GAUGE.cy} x2={needle[0]} y2={needle[1]} stroke-width="2" />
    <circle class="hub" cx={GAUGE.cx} cy={GAUGE.cy} r="6" />
  </svg>
  <figcaption>
    <span class="score num" aria-hidden="true">{score}</span>
    <p class="secondary">{gaugeSentence(score, bands, rev)}</p>
  </figcaption>
</figure>

<style>
  .gauge { display: grid; justify-items: center; gap: var(--vf-space-2); margin: 0; }
  svg { overflow: visible; }
  path { fill: none; }
  .track { stroke: var(--vf-surface-sunken); }
  .band.monitor, .value.monitor { stroke: var(--vf-verdict-monitor-line); }
  .band.challenge, .value.challenge { stroke: var(--vf-verdict-challenge-line); }
  .band.block, .value.block { stroke: var(--vf-verdict-block-line); }
  .value.allow { stroke: var(--vf-verdict-allow-line); }
  .tick, .needle { stroke: var(--vf-text-primary); }
  .hub { fill: var(--vf-text-primary); }
  .lbl { fill: var(--vf-text-primary); font-size: var(--vf-fs-xs); }
  figcaption { display: grid; justify-items: center; gap: var(--vf-space-1); text-align: center; }
  .score { font-size: var(--vf-fs-kpi-md); line-height: var(--vf-lh-kpi-md); font-weight: 600; }
  p { font-size: var(--vf-fs-sm); }
</style>
