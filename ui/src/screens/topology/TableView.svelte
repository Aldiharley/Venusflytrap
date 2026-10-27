<script lang="ts">
  import type { TopoFlow, TopoNode } from './model';
  import VerdictChip from '../../lib/components/VerdictChip.svelte';

  let { nodes, flows }: { nodes: TopoNode[]; flows: TopoFlow[] } = $props();
</script>

<div class="tables">
  <table class="data-table">
    <caption class="label-caps">Nodes</caption>
    <thead><tr><th>Node</th><th>Kind</th><th class="n">Count</th><th class="n">Rate</th></tr></thead>
    <tbody>
      {#each nodes as n (n.id)}
        <tr><td>{n.label}</td><td>{n.kind}</td><td class="n">{n.countText}</td><td class="n">{n.rateText}{n.approx ? ' (approx.)' : ''}</td></tr>
      {/each}
    </tbody>
  </table>
  <table class="data-table">
    <caption class="label-caps">Flows</caption>
    <thead><tr><th>From</th><th>To</th><th>Verdict</th><th class="n">Rate</th></tr></thead>
    <tbody>
      {#each flows as f (f.id)}
        <tr><td>{f.from}</td><td>{f.to}</td><td><VerdictChip verdict={f.verdict} size="sm" /></td><td class="n">{f.rateText}{f.approx ? ' (approx.)' : ''}</td></tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .tables { display: grid; grid-template-columns: 1fr 1fr; gap: var(--vf-space-5); }
  caption { text-align: left; padding-bottom: var(--vf-space-2); }
  @media (max-width: 1023px) { .tables { grid-template-columns: 1fr; } }
</style>
