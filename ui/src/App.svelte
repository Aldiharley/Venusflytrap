<script lang="ts">
  import { onMount, tick, type Component } from 'svelte';
  import { FixtureSource } from './lib/api/source';
  import ToastStack from './lib/components/ToastStack.svelte';
  import NavRail from './lib/shell/NavRail.svelte';
  import TopBar from './lib/shell/TopBar.svelte';
  import { app } from './lib/state/app.svelte';
  import { router, type RouteName } from './lib/state/router.svelte';

  type Screen = () => Promise<{ default: Component<any> }>;
  const placeholder: Screen = () => import('./screens/Placeholder.svelte');
  const SCREENS: Record<RouteName, Screen> = {
    dashboard: placeholder,
    topology: placeholder,
    chains: placeholder,
    monitor: placeholder,
    honeypot: placeholder,
    settings: placeholder,
    keys: placeholder,
    request: placeholder,
    source: placeholder,
    notfound: placeholder,
  };
  const TITLES: Record<RouteName, string> = {
    dashboard: 'Dashboard', topology: 'Traffic topology', chains: 'Attack chains', monitor: 'Monitor',
    honeypot: 'Honeypot & bans', settings: 'Settings', keys: 'Keys', request: 'Request details',
    source: 'Source', notfound: 'Page not found',
  };

  let ready = $state(false);
  onMount(() => {
    const live = !new URLSearchParams(location.search).has('static');
    app.start(new FixtureSource({ live })).then(() => (ready = true));
    return () => app.stop();
  });

  // Move focus to the new screen's heading after navigation (UX: focus goes to h1).
  let first = true;
  $effect(() => {
    void router.path;
    if (first) { first = false; return; }
    tick().then(() => document.querySelector<HTMLElement>('main h1')?.focus());
  });
  $effect(() => { document.title = `${TITLES[router.route.name]} · Venusflytrap`; });
</script>

<a class="skip btn" href="#main">Skip to content</a>
<TopBar />
<div class="body">
  <NavRail />
  <main id="main" tabindex="-1">
    {#if ready}
      {#await SCREENS[router.route.name]() then mod}
        <mod.default title={TITLES[router.route.name]} param={router.route.param} />
      {/await}
    {:else}
      <h1 tabindex="-1">{TITLES[router.route.name]}</h1>
    {/if}
  </main>
</div>
<ToastStack />

<style>
  .skip { position: absolute; left: var(--vf-space-2); top: -60px; z-index: 30; }
  .skip:focus { top: var(--vf-space-2); }
  .body { display: flex; min-height: calc(100vh - var(--vf-topbar-h)); }
  main { flex: 1; min-width: 0; padding: var(--vf-space-5); }
  main:focus { outline: none; }
</style>
