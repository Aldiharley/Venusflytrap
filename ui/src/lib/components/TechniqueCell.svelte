<script lang="ts">
  import type { AttackTag } from '../../gen/AttackTag';
  import { techniquesFor } from '../api/attack';
  import AttackChip from './AttackChip.svelte';

  // A history row's technique: one chip, the row's own primary `technique` id. The fixture table
  // only enriches it with tactic and name; the construct's other tags are in Request details. A
  // technique the table does not know still shows its id, as a bare chip whose accessible name is the id.
  let { technique, construct }: { technique: string | null; construct: string | null } = $props();
  const tag = $derived.by((): AttackTag | null => {
    if (technique === null) return null;
    return techniquesFor(construct).find((t) => t.id === technique) ?? { tactic_id: '', tactic: '', id: technique, name: '' };
  });
</script>

{#if tag === null}
  <span aria-hidden="true">—</span><span class="sr-only">no technique</span>
{:else}
  <AttackChip {tag} compact />
{/if}
