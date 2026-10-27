<script lang="ts">
  import { STAGES, type Stage } from '../api/types';

  let { stage, compact = false }: { stage: Stage | null; compact?: boolean } = $props();
  const n = $derived(stage === null ? 0 : STAGES.indexOf(stage) + 1);
  const cls = $derived(stage === null ? 'none' : stage.toLowerCase());
</script>

<span class="chip {cls}" aria-label={stage === null ? 'Clean' : `Stage ${n} of 4: ${stage}`}>
  <span class="badge" aria-hidden="true">{n === 0 ? '–' : n}</span>
  {#if !compact}<span aria-hidden="true">{stage ?? 'Clean'}</span>{/if}
  <span class="pips" aria-hidden="true">
    {#each [1, 2, 3, 4] as i (i)}<span class="pip" class:on={i <= n}></span>{/each}
  </span>
</span>

<style>
  .chip {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 24px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); font-size: var(--vf-fs-sm); font-weight: 600; white-space: nowrap;
  }
  /* The numeral sits upright on top; the shape (circle 1, square 2, diamond 3, hexagon 4,
     hollow circle for Clean) is drawn by ::before so it can rotate or clip independently. */
  .badge {
    position: relative; display: inline-grid; place-items: center; width: 16px; height: 16px;
    font-size: var(--vf-fs-xs); font-weight: 700; line-height: 1;
  }
  .badge::before { content: ''; position: absolute; inset: 0; border: 1.5px solid currentColor; }
  .recon .badge::before, .none .badge::before { border-radius: 50%; }
  .enumeration .badge::before { border-radius: 2px; }
  .exploitation .badge::before { inset: 2px; transform: rotate(45deg); border-radius: 1px; }
  .exfiltration .badge::before {
    border: 0; background: color-mix(in srgb, currentColor 28%, transparent);
    clip-path: polygon(25% 0, 75% 0, 100% 50%, 75% 100%, 25% 100%, 0 50%);
  }
  .pips { display: inline-flex; gap: 2px; margin-left: 2px; }
  .pip { width: 4px; height: 4px; border-radius: 1px; background: color-mix(in srgb, currentColor 25%, transparent); }
  .pip.on { background: currentColor; }
  .none { background: var(--vf-stage-none-bg); color: var(--vf-stage-none-fg); }
  .recon { background: var(--vf-stage-recon-bg); color: var(--vf-stage-recon-fg); }
  .enumeration { background: var(--vf-stage-enumeration-bg); color: var(--vf-stage-enumeration-fg); }
  .exploitation { background: var(--vf-stage-exploitation-bg); color: var(--vf-stage-exploitation-fg); }
  .exfiltration { background: var(--vf-stage-exfiltration-bg); color: var(--vf-stage-exfiltration-fg); }
</style>
