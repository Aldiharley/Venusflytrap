<script lang="ts">
  let {
    label, value, unit = '', tone = 'neutral', stale = false, note = '',
  }: { label: string; value: string; unit?: string; tone?: 'allow' | 'monitor' | 'challenge' | 'block' | 'neutral'; stale?: boolean; note?: string } = $props();
</script>

<div class="tile card {tone}" class:stale>
  <dt class="label-caps">{label}</dt>
  <dd class="value num">{value}{#if unit}<span class="unit">{unit}</span>{/if}</dd>
  {#if note}<dd class="note secondary">{note}</dd>{/if}
</div>

<style>
  .tile { position: relative; display: grid; gap: var(--vf-space-1); overflow: hidden; }
  .tile::after { content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 2px; background: var(--vf-border-subtle); }
  .allow::after { background: var(--vf-verdict-allow-line); }
  .monitor::after { background: var(--vf-verdict-monitor-line); }
  .challenge::after { background: var(--vf-verdict-challenge-line); }
  .block::after { background: var(--vf-verdict-block-line); }
  .value { font-size: var(--vf-fs-kpi-sm); line-height: var(--vf-lh-kpi-sm); font-weight: 600; margin: 0; }
  .unit { font-size: .5em; color: var(--vf-text-secondary); margin-left: 2px; }
  .note { font-size: var(--vf-fs-xs); margin: 0; }
  .stale { opacity: .7; background-image: var(--vf-hatch); }
</style>
