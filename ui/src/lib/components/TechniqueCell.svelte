<script lang="ts">
  import { techniquesFor } from '../api/attack';
  import AttackChip from './AttackChip.svelte';

  // A history row's technique. The row's own `technique` id decides whether there is one; the
  // fixture table only enriches it with tactic and name. A construct the table does not know
  // still shows its id, as a bare chip whose accessible name is the id.
  let { technique, construct }: { technique: string | null; construct: string | null } = $props();
  const tags = $derived.by(() => {
    if (technique === null) return [];
    const known = techniquesFor(construct);
    return known.some((t) => t.id === technique) ? known : [{ tactic_id: '', tactic: '', id: technique, name: '' }];
  });
</script>

{#if tags.length === 0}
  <span aria-hidden="true">—</span><span class="sr-only">no technique</span>
{:else}
  <span class="techs">{#each tags as tag (tag.id)}<AttackChip {tag} compact />{/each}</span>
{/if}

<style>
  .techs { display: inline-flex; flex-wrap: wrap; gap: 2px; }
</style>
