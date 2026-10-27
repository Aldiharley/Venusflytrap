<script lang="ts">
  import HealthPill from '../components/HealthPill.svelte';
  import { fmtCount } from '../format';
  import { Radio, TriangleAlert } from '../icons';
  import { app } from '../state/app.svelte';
  import { router } from '../state/router.svelte';
  import ThemeToggle from './ThemeToggle.svelte';

  let jump = $state('');

  function onJump(e: SubmitEvent) {
    e.preventDefault();
    const v = jump.trim();
    if (!v) return;
    // A source key is an IP or prefix; anything else is a request id.
    const isSource = /^[0-9a-f:.]+(\/\d+)?$/i.test(v) && /[.:]/.test(v);
    router.navigate(isSource ? `/sources/${encodeURIComponent(v)}` : `/requests/${encodeURIComponent(v)}`);
    jump = '';
  }

  const dropped = $derived(app.counters?.dropped_total ?? 0);
  const liveLabel = $derived(app.liveLabel);
</script>

<header class="bar glass">
  <div class="brand">
    <span class="name">Venusflytrap</span>
    {#if app.status}<span class="ver secondary">v{app.status.version}</span>{/if}
  </div>
  <form class="jump" role="search" onsubmit={onJump}>
    <label class="sr-only" for="quick-jump">Request id or source key</label>
    <input id="quick-jump" class="mono" placeholder="Request id or source key" bind:value={jump} autocomplete="off" />
  </form>
  <ul class="status" aria-label="Service status">
    <li>
      <span class="label-caps">State</span>
      {#if app.status}<HealthPill health={app.status.worst} />{:else}<span>—</span>{/if}
    </li>
    <li>
      <span class="label-caps">Live</span>
      <span class="val" class:warn={liveLabel !== 'Connected'}><Radio size={14} aria-hidden="true" /> {liveLabel}</span>
    </li>
    <li>
      <span class="label-caps">Config</span>
      <span class="val num">rev {app.status?.config_rev ?? '—'}</span>
    </li>
    <li>
      <span class="label-caps">Dropped</span>
      <span class="val num" class:warn={dropped > 0}>
        {#if dropped > 0}<TriangleAlert size={14} aria-hidden="true" />{/if}
        {fmtCount(dropped)}
      </span>
    </li>
  </ul>
  <div class="right">
    <ThemeToggle />
    {#if app.session}<span class="perm label-caps">{app.session.perm}</span>{/if}
  </div>
</header>

<style>
  .bar {
    position: sticky; top: 0; z-index: 10; height: var(--vf-topbar-h);
    display: flex; align-items: center; gap: var(--vf-space-5); padding: 0 var(--vf-space-4);
    box-shadow: var(--vf-shadow-2); border-width: 0 0 var(--vf-bw-hair) 0;
  }
  .brand { display: flex; align-items: baseline; gap: var(--vf-space-2); }
  .name { font-weight: 600; font-size: var(--vf-fs-title-sm); }
  .ver { font-size: var(--vf-fs-xs); }
  .jump input {
    width: 260px; height: var(--vf-control-md); padding: 0 var(--vf-space-3);
    border-radius: var(--vf-radius-sm); border: var(--vf-bw-std) solid var(--vf-border-strong);
    background: var(--vf-surface-input); box-shadow: var(--vf-shadow-inset);
  }
  .status { display: flex; gap: var(--vf-space-5); margin: 0; padding: 0; list-style: none; }
  .status li { display: grid; gap: 2px; padding-left: var(--vf-space-4); border-left: var(--vf-bw-std) solid var(--vf-border-subtle); }
  .status li:first-child { border-left: 0; padding-left: 0; }
  .val { display: inline-flex; align-items: center; gap: var(--vf-space-1); font-size: var(--vf-fs-sm); font-weight: 500; }
  .val.warn { color: var(--vf-health-warn-fg); }
  .right { margin-left: auto; display: flex; align-items: center; gap: var(--vf-space-4); }
  .perm { padding: 2px 8px; border-radius: var(--vf-radius-xs); background: var(--vf-surface-sunken); }
  @media (max-width: 1279px) { .jump input { width: 180px; } .status { gap: var(--vf-space-3); } }
</style>
