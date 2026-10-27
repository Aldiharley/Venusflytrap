<script lang="ts">
  import EmptyState from '../lib/components/EmptyState.svelte';

  let { title }: { title: string } = $props();
</script>

<h1 tabindex="-1">{title}</h1>
<div class="card">
  <EmptyState scene="not-built" message="This screen is specified in the UX architecture and arrives with console plan SP6b." action={{ label: 'Open dashboard', href: '/' }} />
</div>

<style>
  h1 { margin-bottom: var(--vf-space-5); }
</style>
