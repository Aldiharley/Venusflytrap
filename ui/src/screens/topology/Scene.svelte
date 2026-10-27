<script lang="ts">
  import { tick } from 'svelte';
  import type { SourceView } from '../../lib/api/types';
  import { propUrl } from '../../lib/assets';
  import { BOX, PLATE, SCENE, pct, type DecorId } from './geometry';
  import type { TopoFlow, TopoNode } from './model';
  import DetailCard from './DetailCard.svelte';

  let {
    nodes, flows, board, rps, stale, now,
  }: { nodes: TopoNode[]; flows: TopoFlow[]; board: SourceView[]; rps: [number, number, number, number]; stale: boolean; now: number } = $props();

  let active = $state(0);
  let open = $state<string | null>(null);
  let pinned = $state(false);
  const buttons: HTMLButtonElement[] = [];
  const DECOR: DecorId[] = ['edge', 'jA', 'jB'];
  const openNode = $derived(nodes.find((n) => n.id === open) ?? null);
  const plate = propUrl(PLATE.prop);

  function focusAt(i: number) {
    active = (i + nodes.length) % nodes.length;
    buttons[active]?.focus();
  }

  async function onkeydown(e: KeyboardEvent, i: number) {
    const k = e.key;
    if (k === 'ArrowRight' || k === 'ArrowDown') { e.preventDefault(); focusAt(i + 1); }
    else if (k === 'ArrowLeft' || k === 'ArrowUp') { e.preventDefault(); focusAt(i - 1); }
    else if (k === 'Home') { e.preventDefault(); focusAt(0); }
    else if (k === 'End') { e.preventDefault(); focusAt(nodes.length - 1); }
    else if (k === 'Enter') {
      e.preventDefault();
      open = nodes[i].id;
      pinned = true;
      await tick();
      document.querySelector<HTMLElement>('#node-card a, #node-card button')?.focus();
    } else if (k === 'Escape') { open = null; pinned = false; }
  }

  function close() {
    pinned = false;
    open = null;
    buttons[active]?.focus();
  }

  function onfocusout(e: FocusEvent) {
    const to = e.relatedTarget as Node | null;
    const card = document.getElementById('node-card');
    if (!pinned && !(to && card?.contains(to))) open = null;
  }
</script>

<div class="scene" class:stale role="group" aria-label="Traffic topology scene">
  {#if plate}<img class="plate" src={plate} alt="" style:left={pct(PLATE.x, SCENE.w)} style:top={pct(PLATE.y, SCENE.h)} style:width={pct(PLATE.w, SCENE.w)} />{/if}

  <svg class="lines" viewBox="0 0 {SCENE.w} {SCENE.h}" aria-hidden="true">
    {#each flows as f (f.id)}
      {#if openNode && (f.from === openNode.label || f.to === openNode.label)}<path class="halo" d={f.d} />{/if}
      <path class="base v-{f.verdict.toLowerCase()} s{f.step}" d={f.d} />
      {#if f.step > 0}<path class="packet f{f.step}" d={f.d} />{/if}
    {/each}
  </svg>

  {#each DECOR as id (id)}
    {@const url = propUrl(BOX[id].prop)}
    {#if url}<img class="prop" src={url} alt="" style:left={pct(BOX[id].x, SCENE.w)} style:top={pct(BOX[id].y, SCENE.h)} style:width={pct(BOX[id].w, SCENE.w)} />{/if}
  {/each}

  {#each flows as f (f.id)}
    {#if f.step > 0}<span class="rate num" aria-hidden="true" style:left={pct(f.mid[0], SCENE.w)} style:top={pct(f.mid[1], SCENE.h)}>{f.rateText}</span>{/if}
  {/each}

  {#each nodes as n, i (n.id)}
    {@const url = propUrl(n.prop)}
    {#if url}<img class="prop" src={url} alt="" style:left={pct(n.box.x, SCENE.w)} style:top={pct(n.box.y, SCENE.h)} style:width={pct(n.box.w, SCENE.w)} />{/if}
    <button
      bind:this={buttons[i]}
      class="node"
      class:open={open === n.id}
      tabindex={i === active ? 0 : -1}
      aria-label={n.name}
      aria-describedby={open === n.id ? 'node-card' : undefined}
      style:left={pct(n.box.x, SCENE.w)}
      style:top={pct(n.box.y, SCENE.h)}
      style:width={pct(n.box.w, SCENE.w)}
      style:height={pct(n.box.w * 0.9, SCENE.h)}
      onfocus={() => { active = i; if (!pinned) open = n.id; }}
      onfocusout={onfocusout}
      onmouseenter={() => { if (!pinned) open = n.id; }}
      onmouseleave={() => { if (!pinned) open = null; }}
      onclick={() => {
        if (pinned && open === n.id) pinned = false;
        else { open = n.id; pinned = true; }
      }}
      onkeydown={(e) => onkeydown(e, i)}
    >
      <span class="chip" aria-hidden="true">{n.label} <span class="num count">{n.countText}</span></span>
    </button>
  {/each}

  {#if openNode}
    <DetailCard node={openNode} {board} {rps} {pinned} {now} onclose={close} />
  {/if}

  {#if stale}<div class="hatch" aria-hidden="true"><span class="paused card">Live paused</span></div>{/if}
</div>

<style>
  .scene { position: relative; width: 100%; aspect-ratio: 960 / 720; max-height: 720px; border-radius: var(--vf-radius-md); overflow: hidden; background: var(--vf-surface-base); }
  .plate { position: absolute; height: auto; filter: var(--vf-plate-shadow); }
  .prop { position: absolute; height: auto; filter: var(--vf-prop-filter); pointer-events: none; }
  .lines { position: absolute; inset: 0; width: 100%; height: 100%; }
  .node { position: absolute; padding: 0; border: 0; background: transparent; cursor: pointer; border-radius: var(--vf-radius-sm); }
  .node:hover .chip, .node.open .chip { box-shadow: var(--vf-shadow-2), var(--vf-glow-hover); }
  .chip {
    position: absolute; left: 50%; top: -12px; transform: translate(-50%, -100%); white-space: nowrap;
    height: 24px; padding: 0 var(--vf-space-2); display: inline-flex; align-items: center; gap: var(--vf-space-1);
    border-radius: var(--vf-radius-sm); background: var(--vf-surface-raised-glass); backdrop-filter: var(--vf-glass-filter);
    border: var(--vf-bw-hair) solid var(--vf-border-hairline); box-shadow: var(--vf-shadow-1);
    font-size: var(--vf-fs-xs); font-weight: 600; color: var(--vf-text-primary);
  }
  .count { font-weight: 400; }
  .rate {
    position: absolute; transform: translate(-50%, -50%); height: 20px; padding: 0 6px; display: inline-flex; align-items: center;
    border-radius: var(--vf-radius-sm); background: var(--vf-surface-raised-glass); font-size: var(--vf-fs-xs);
    color: var(--vf-text-secondary); pointer-events: none;
  }
  .hatch { position: absolute; inset: 0; background-image: var(--vf-hatch); display: grid; place-items: start center; padding-top: 20%; }
  .paused { font-weight: 600; }

  :global(.base) { fill: none; stroke-linecap: butt; }
  :global(.base.v-allow) { stroke: var(--vf-verdict-allow-line); }
  :global(.base.v-monitor) { stroke: var(--vf-verdict-monitor-line); stroke-dasharray: 12 6; }
  :global(.base.v-challenge) { stroke: var(--vf-verdict-challenge-line); stroke-dasharray: 10 4 2 4; }
  :global(.base.v-block) { stroke: var(--vf-verdict-block-line); stroke-dasharray: 0 6; stroke-linecap: round; }
  :global(.base.s0) { stroke: var(--vf-line-idle); stroke-width: 1; }
  :global(.base.s1) { stroke-width: 1.5; }
  :global(.base.s2) { stroke-width: 2; }
  :global(.base.s3) { stroke-width: 3; }
  :global(.base.s4) { stroke-width: 4; }
  :global(.base.v-block.s1) { stroke-width: 2.5; }
  :global(.base.v-block.s2) { stroke-width: 3; }
  :global(.base.v-block.s3) { stroke-width: 4; }
  :global(.base.v-block.s4) { stroke-width: 5; }
  .halo { fill: none; stroke: var(--vf-line-active); stroke-width: 8; opacity: .55; filter: var(--vf-glow-line-active); }
  .packet {
    fill: none; stroke: var(--vf-line-packet); stroke-width: 2; stroke-linecap: round; stroke-dasharray: 2 22;
    animation: flow var(--dur) linear infinite; animation-play-state: var(--vf-motion-play);
  }
  .f1 { --dur: var(--vf-flow-1); } .f2 { --dur: var(--vf-flow-2); } .f3 { --dur: var(--vf-flow-3); } .f4 { --dur: var(--vf-flow-4); }
  @keyframes flow { from { stroke-dashoffset: 24; } to { stroke-dashoffset: 0; } }
  :global([data-motion='off']) .packet { display: none; }
  @media (prefers-reduced-motion: reduce) { .packet { display: none; } }
  .stale :global(.base) { stroke: var(--vf-line-idle); }
  .stale .packet { display: none; }
  @media (max-width: 1023px) { .rate { display: none; } }
</style>
