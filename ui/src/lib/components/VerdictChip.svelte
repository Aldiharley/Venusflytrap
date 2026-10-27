<script lang="ts">
  import type { Verdict } from '../api/types';
  import { CircleCheck, Eye, OctagonX, TriangleAlert } from '../icons';

  let { verdict, size = 'md' }: { verdict: Verdict; size?: 'sm' | 'md' } = $props();
  const GLYPH = { Allow: CircleCheck, Monitor: Eye, Challenge: TriangleAlert, Block: OctagonX };
  const Glyph = $derived(GLYPH[verdict]);
</script>

<span class="chip {verdict.toLowerCase()} {size}">
  <Glyph size={14} strokeWidth={1.5} aria-hidden="true" />{verdict}
</span>

<style>
  .chip {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 24px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); font-size: var(--vf-fs-sm); font-weight: 600; text-transform: uppercase;
    letter-spacing: .04em; border: var(--vf-bw-std) solid; white-space: nowrap;
  }
  .sm { height: 20px; }
  .allow { background: var(--vf-verdict-allow-bg); color: var(--vf-verdict-allow-fg); border-color: color-mix(in srgb, var(--vf-verdict-allow-fg) 35%, transparent); }
  .monitor { background: var(--vf-verdict-monitor-bg); color: var(--vf-verdict-monitor-fg); border-color: color-mix(in srgb, var(--vf-verdict-monitor-fg) 35%, transparent); }
  .challenge { background: var(--vf-verdict-challenge-bg); color: var(--vf-verdict-challenge-fg); border-color: color-mix(in srgb, var(--vf-verdict-challenge-fg) 35%, transparent); }
  .block { background: var(--vf-verdict-block-bg); color: var(--vf-verdict-block-fg); border-color: color-mix(in srgb, var(--vf-verdict-block-fg) 35%, transparent); }
</style>
