<script lang="ts">
  import type { AttackTag } from '../../gen/AttackTag';

  // A MITRE ATT&CK technique: the id is the text; the tactic and technique name are the title and
  // the visually hidden text, so the meaning is not carried by colour or by an opaque id alone.
  // Reuses the evidence chip's neutral look (design system §1.3): it is a label, never a verdict.
  let { tag, compact = false }: { tag: AttackTag; compact?: boolean } = $props();
  const full = $derived(`${tag.tactic} · ${tag.name}`);
</script>

<span class="chip" class:compact title={full}><span aria-hidden="true">{tag.id}</span><span class="sr-only">{full}</span></span>

<style>
  .chip {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 20px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); font-size: var(--vf-fs-xs); font-weight: 600; white-space: nowrap; border: var(--vf-bw-std) solid;
    font-family: var(--vf-font-mono);
    background: var(--vf-evidence-none-bg); color: var(--vf-evidence-none-fg);
    border-color: color-mix(in srgb, var(--vf-evidence-none-fg) 35%, transparent);
  }
  .compact { height: 16px; padding: 0 var(--vf-space-1); }
</style>
