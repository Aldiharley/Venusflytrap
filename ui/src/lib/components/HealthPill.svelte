<script lang="ts">
  import type { Health } from '../api/types';
  import { CircleCheck, CircleGauge, OctagonAlert, TriangleAlert } from '../icons';

  let { health, detail = '' }: { health: Health; detail?: string } = $props();
  const GLYPH = { Ok: CircleCheck, Warn: TriangleAlert, Degraded: CircleGauge, Critical: OctagonAlert };
  const TONE = { Ok: 'ok', Warn: 'warn', Degraded: 'warn', Critical: 'error' };
  const Glyph = $derived(GLYPH[health]);
</script>

<span class="pill {TONE[health]}">
  <Glyph size={14} strokeWidth={1.5} aria-hidden="true" />
  <span>{health === 'Ok' ? 'OK' : health}</span>
  {#if detail}<span class="detail">{detail}</span>{/if}
</span>

<style>
  .pill {
    display: inline-flex; align-items: center; gap: var(--vf-space-1);
    height: 24px; padding: 0 10px; border-radius: var(--vf-radius-pill);
    font-size: var(--vf-fs-sm); font-weight: 600; box-shadow: var(--vf-shadow-1);
  }
  .ok { background: var(--vf-health-ok-bg); color: var(--vf-health-ok-fg); }
  .warn { background: var(--vf-health-warn-bg); color: var(--vf-health-warn-fg); }
  .error { background: var(--vf-health-error-bg); color: var(--vf-health-error-fg); }
  .detail { font-size: var(--vf-fs-xs); font-weight: 400; }
</style>
