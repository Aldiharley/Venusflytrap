<script lang="ts">
  import type { Snippet } from 'svelte';
  import { fmtClock } from '../format';

  let {
    title, updatedAt = 0, stale = false, busy = false, children, actions,
  }: { title: string; updatedAt?: number; stale?: boolean; busy?: boolean; children: Snippet; actions?: Snippet } = $props();
  const id = `r-${Math.random().toString(36).slice(2, 8)}`;
</script>

<section class="card region" class:stale aria-labelledby={id} aria-busy={busy}>
  <header>
    <h2 {id} class="title">{title}</h2>
    {#if actions}<div class="actions">{@render actions()}</div>{/if}
    {#if updatedAt}<span class="updated secondary num">Updated {fmtClock(updatedAt)}</span>{/if}
  </header>
  {@render children()}
</section>

<style>
  .region { display: grid; gap: var(--vf-space-3); align-content: start; }
  header { display: flex; align-items: center; gap: var(--vf-space-3); }
  .title { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); }
  .actions { margin-left: auto; display: flex; gap: var(--vf-space-2); }
  .updated { font-size: var(--vf-fs-xs); margin-left: auto; }
  .actions + .updated { margin-left: 0; }
  .stale { opacity: .7; background-image: var(--vf-hatch); }
</style>
