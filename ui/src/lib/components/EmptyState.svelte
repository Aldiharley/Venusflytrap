<script lang="ts">
  import { sceneUrl, type SceneName } from '../assets';
  import Link from './Link.svelte';

  let { message, scene, action }: { message: string; scene?: SceneName; action?: { label: string; href: string } } = $props();
  const img = $derived(scene ? sceneUrl(scene) : undefined);
</script>

<div class="empty">
  {#if img}<img src={img} alt="" width="200" />{/if}
  <p class="secondary">{message}</p>
  {#if action}<Link href={action.href} class="btn btn-ghost">{action.label}</Link>{/if}
</div>

<style>
  .empty { display: grid; justify-items: center; gap: var(--vf-space-3); padding: var(--vf-space-5); text-align: center; }
  img { height: auto; filter: var(--vf-prop-filter); }
</style>
