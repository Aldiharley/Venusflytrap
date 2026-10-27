<script lang="ts">
  import { sceneUrl } from '../lib/assets';

  let { title }: { title: string } = $props();
  const img = sceneUrl('not-built');
</script>

<h1 tabindex="-1">{title}</h1>
<div class="card empty">
  {#if img}<img src={img} alt="" width="256" />{/if}
  <p class="secondary">This screen is specified in the UX architecture and arrives with console plan SP6b.</p>
</div>

<style>
  h1 { margin-bottom: var(--vf-space-5); }
  .empty { display: grid; justify-items: center; gap: var(--vf-space-4); padding: var(--vf-space-6); text-align: center; }
  img { height: auto; filter: var(--vf-prop-filter); }
</style>
