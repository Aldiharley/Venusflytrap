<script lang="ts">
  import type { SourceView } from '../../lib/api/types';
  import Link from '../../lib/components/Link.svelte';
  import StageChip from '../../lib/components/StageChip.svelte';
  import { banText, fmtCount, fmtRps } from '../../lib/format';
  import { pct, SCENE } from './geometry';
  import type { TopoNode } from './model';

  let {
    node, board, rps, pinned, now, onclose,
  }: { node: TopoNode; board: SourceView[]; rps: [number, number, number, number]; pinned: boolean; now: number; onclose: () => void } = $props();

  const right = $derived(node.box.x > SCENE.w * 0.55);
  const members = $derived(
    board
      .filter((s) => !s.ban && (node.ref === 'Recon' ? s.stage === 'Recon' || s.stage === 'Enumeration' : s.stage === 'Exploitation' || s.stage === 'Exfiltration'))
      .sort((a, b) => b.last_seen_ms - a.last_seen_ms)
      .slice(0, 5),
  );
  const soonest = $derived(
    board.filter((s) => s.ban).sort((a, b) => (a.ban!.until_ms ?? Infinity) - (b.ban!.until_ms ?? Infinity)).slice(0, 5),
  );

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') { e.stopPropagation(); onclose(); }
  }
</script>

<!-- Escape closes the card from anywhere inside it (UX §4); the group is a popover, not a widget. -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
  id="node-card"
  class="card detail"
  class:pinned
  role="group"
  aria-label={`${node.label} details`}
  style:left={right ? undefined : pct(node.box.x + node.box.w + 16, SCENE.w)}
  style:right={right ? pct(SCENE.w - node.box.x + 16, SCENE.w) : undefined}
  style:top={pct(node.box.y, SCENE.h)}
  {onkeydown}
>
  <h3>{node.label}</h3>
  <p class="meta secondary">{node.countText} · {node.rateText}{node.approx ? ' (approx.)' : ''}</p>

  {#if node.kind === 'cluster' && node.ref}
    <ul class="rows">
      {#each members as s (s.key)}
        <li><span class="mono">{s.key}</span><StageChip stage={s.stage} compact /><span class="num">{fmtCount(s.requests)} / {fmtCount(s.blocked)}</span><span class="mono secondary">{s.top_constructs[0] ?? ''}</span></li>
      {/each}
    </ul>
    <footer>
      <Link href={`/chains?stage=${node.ref}`} class="btn btn-sm">Show in Attack chains</Link>
      {#if members[0]}<Link href={`/sources/${encodeURIComponent(members[0].key)}`} class="btn btn-sm btn-primary">Open source</Link>{/if}
    </footer>
  {:else if node.kind === 'tower'}
    <dl class="kv">
      {#each ['Allow', 'Monitor', 'Challenge', 'Block'] as v, k (v)}<div><dt class="label-caps">{v}</dt><dd class="num">{fmtRps(rps[k])}</dd></div>{/each}
    </dl>
    <footer><Link href="/" class="btn btn-sm btn-primary">Open dashboard</Link></footer>
  {:else if node.kind === 'route' && node.ref}
    <footer><Link href={`/monitor?q=${encodeURIComponent(`path:${node.ref}*`)}`} class="btn btn-sm btn-primary">Open in Monitor</Link></footer>
  {:else if node.kind === 'honeypot'}
    <footer><Link href="/honeypot" class="btn btn-sm btn-primary">Open Honeypot &amp; bans</Link></footer>
  {:else if node.kind === 'quarantine'}
    <ul class="rows">
      {#each soonest as s (s.key)}<li><span class="mono">{s.key}</span><span>{banText(s.ban!, now)}</span></li>{/each}
    </ul>
    <footer><Link href="/honeypot" class="btn btn-sm btn-primary">Manage bans</Link></footer>
  {/if}
</div>

<style>
  .detail { position: absolute; z-index: 5; width: 320px; display: grid; gap: var(--vf-space-2); background: var(--vf-surface-overlay-glass); box-shadow: var(--vf-shadow-3); }
  .pinned { box-shadow: var(--vf-shadow-3), var(--vf-glow-selected); }
  .meta { font-size: var(--vf-fs-xs); }
  .rows { margin: 0; padding: 0; list-style: none; display: grid; gap: var(--vf-space-1); font-size: var(--vf-fs-xs); }
  .rows li { display: flex; align-items: center; gap: var(--vf-space-2); flex-wrap: wrap; }
  .kv { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--vf-space-2); margin: 0; }
  .kv dd { margin: 0; }
  footer { display: flex; justify-content: flex-end; gap: var(--vf-space-2); }
</style>
