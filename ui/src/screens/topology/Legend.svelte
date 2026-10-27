<script lang="ts">
  import { CircleCheck, Eye, OctagonX, TriangleAlert } from '../../lib/icons';
  const ROWS = [
    { v: 'allow', label: 'Allow', Icon: CircleCheck },
    { v: 'monitor', label: 'Monitor', Icon: Eye },
    { v: 'challenge', label: 'Challenge', Icon: TriangleAlert },
    { v: 'block', label: 'Block', Icon: OctagonX },
  ];
  const STEPS = ['0', '< 1/s', '1–10/s', '10–100/s', '> 100/s'];
</script>

<aside class="legend glass" aria-label="Legend">
  <div>
    <h2 class="label-caps">Lines</h2>
    <ul>
      {#each ROWS as r (r.v)}
        <li><svg width="32" height="8" aria-hidden="true"><path d="M2,4 L30,4" class="base v-{r.v} s3" /></svg><r.Icon size={14} aria-hidden="true" />{r.label}</li>
      {/each}
    </ul>
  </div>
  <div>
    <h2 class="label-caps">Volume</h2>
    <ul>
      {#each STEPS as s, k (s)}
        <li><svg width="32" height="8" aria-hidden="true"><path d="M2,4 L30,4" class="base v-allow s{k}" /></svg>{s}</li>
      {/each}
    </ul>
  </div>
</aside>

<style>
  /* Sits below the scene (not over it) so it never covers a prop at any stage width. */
  .legend { margin-top: var(--vf-space-3); padding: var(--vf-space-3); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-1); display: flex; flex-wrap: wrap; gap: var(--vf-space-2) var(--vf-space-6); }
  h2 { margin: 0 0 var(--vf-space-1); }
  ul { margin: 0; padding: 0; list-style: none; display: flex; flex-wrap: wrap; gap: 2px var(--vf-space-4); font-size: var(--vf-fs-xs); }
  li { display: flex; align-items: center; gap: var(--vf-space-2); height: 20px; }
  @media (max-width: 1023px) { .legend { display: none; } }
</style>
