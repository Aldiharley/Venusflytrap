<script lang="ts">
  import type { FourValued } from '../api/types';
  import { CircleDashed, ShieldCheck, ShieldQuestionMark, ShieldX } from '../icons';

  // Evidence uses the shield family (design system §1.3), so it never reads as a verdict.
  let { value }: { value: FourValued } = $props();
  const GLYPH = { None: CircleDashed, Safe: ShieldCheck, Suspicious: ShieldQuestionMark, Dangerous: ShieldX };
  const Glyph = $derived(GLYPH[value]);
</script>

<span class="chip {value.toLowerCase()}"><Glyph size={14} strokeWidth={1.5} aria-hidden="true" />{value}</span>

<style>
  .chip {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 20px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); font-size: var(--vf-fs-xs); font-weight: 600; white-space: nowrap; border: var(--vf-bw-std) solid;
  }
  .none { background: var(--vf-evidence-none-bg); color: var(--vf-evidence-none-fg); border-color: color-mix(in srgb, var(--vf-evidence-none-fg) 35%, transparent); }
  .safe { background: var(--vf-evidence-safe-bg); color: var(--vf-evidence-safe-fg); border-color: color-mix(in srgb, var(--vf-evidence-safe-fg) 35%, transparent); }
  .suspicious { background: var(--vf-evidence-suspicious-bg); color: var(--vf-evidence-suspicious-fg); border-color: color-mix(in srgb, var(--vf-evidence-suspicious-fg) 35%, transparent); }
  .dangerous { background: var(--vf-evidence-dangerous-bg); color: var(--vf-evidence-dangerous-fg); border-color: color-mix(in srgb, var(--vf-evidence-dangerous-fg) 35%, transparent); }
</style>
