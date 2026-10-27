<script lang="ts">
  import Link from '../components/Link.svelte';
  import { KeyRound, LayoutDashboard, ListFilter, Network, Settings, ShieldBan, Workflow } from '../icons';
  import { app } from '../state/app.svelte';
  import { NAV, PARENT, router, type RouteName } from '../state/router.svelte';

  const ICON: Record<string, typeof Network> = {
    dashboard: LayoutDashboard, topology: Network, monitor: ListFilter, chains: Workflow,
    honeypot: ShieldBan, settings: Settings, keys: KeyRound,
  };
  const current = $derived<RouteName>(PARENT[router.route.name] ?? router.route.name);
  const items = $derived(NAV.filter((n) => !n.adminOnly || app.session?.perm === 'Admin'));
</script>

<nav class="rail" aria-label="Main">
  <ul>
    {#each items as n (n.name)}
      {@const Icon = ICON[n.name]}
      <li>
        <Link href={n.href} class="item" current={current === n.name}>
          <Icon size={18} strokeWidth={1.5} aria-hidden="true" />
          <span>{n.label}</span>
        </Link>
      </li>
    {/each}
  </ul>
  <p class="foot secondary">Live: {app.liveLabel}</p>
</nav>

<style>
  .rail { width: var(--vf-nav-w); padding: var(--vf-space-2); background: var(--vf-surface-sunken); display: flex; flex-direction: column; }
  ul { margin: 0; padding: 0; list-style: none; display: grid; gap: 2px; }
  .rail :global(.item) {
    display: flex; align-items: center; gap: var(--vf-space-3); height: 40px; padding: 0 var(--vf-space-3);
    border-radius: var(--vf-radius-sm); color: var(--vf-text-secondary); text-decoration: none; font-weight: 500;
  }
  .rail :global(.item:hover) { background: var(--vf-surface-raised); color: var(--vf-text-primary); box-shadow: var(--vf-shadow-1); }
  .rail :global(.item[aria-current='page']) {
    background: var(--vf-accent-soft); color: var(--vf-text-primary); font-weight: 600;
    box-shadow: inset 2px 0 0 var(--vf-accent);
  }
  .rail :global(.item[aria-current='page'] svg) { color: var(--vf-accent); }
  .foot { margin-top: auto; padding: var(--vf-space-3); font-size: var(--vf-fs-xs); }
  @media (max-width: 1439px) {
    .rail { width: var(--vf-nav-rail-w); }
    .rail :global(.item) { flex-direction: column; justify-content: center; height: 56px; gap: 2px; padding: 0; font-size: 11px; text-align: center; }
    .foot { padding: var(--vf-space-1); text-align: center; }
  }
</style>
