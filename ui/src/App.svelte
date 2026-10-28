<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import type { Attachment } from 'svelte/attachments';
  import { toSourceError, type SourceError } from './lib/api/errors';
  import { FixtureSource } from './lib/api/source';
  import ToastStack from './lib/components/ToastStack.svelte';
  import NavRail from './lib/shell/NavRail.svelte';
  import TopBar from './lib/shell/TopBar.svelte';
  import { app } from './lib/state/app.svelte';
  import { router, type RouteName } from './lib/state/router.svelte';

  type Screen = () => Promise<{ default: Component<any> }>;
  const placeholder: Screen = () => import('./screens/Placeholder.svelte');
  const SCREENS: Record<RouteName, Screen> = {
    dashboard: () => import('./screens/Dashboard.svelte'),
    topology: () => import('./screens/Topology.svelte'),
    chains: () => import('./screens/Chains.svelte'),
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
  let failed = $state<SourceError | null>(null);
  let boot = 0;
  function load() {
    const mine = ++boot;
    failed = null;
    ready = false;
    const live = !new URLSearchParams(location.search).has('static');
    app.start(new FixtureSource({ live })).then(
      () => { if (mine === boot) ready = true; },
      (e) => { if (mine === boot) failed = toSourceError(e); },
    );
  }
  onMount(() => {
    load();
    return () => { boot++; app.stop(); };
  });

  // After a navigation, focus goes to the new screen's h1 (UX). The screen is lazy, so the
  // request is parked here and honoured by `focusScreen` once the screen has rendered.
  let first = true;
  let focusPending = false;
  $effect(() => {
    void router.path;
    if (first) { first = false; return; }
    focusPending = true;
  });
  const focusScreen: Attachment<HTMLElement> = (el) => {
    if (!focusPending) return;
    focusPending = false;
    el.querySelector<HTMLElement>('h1')?.focus();
  };

  // A screen chunk that fails to load (dropped connection, stale deploy) gets an error and Retry;
  // Retry re-runs the import and keeps focus on the heading.
  let attempt = $state(0);
  function retryScreen() {
    focusPending = true;
    attempt++;
  }
  $effect(() => { document.title = `${TITLES[router.route.name]} · Venusflytrap`; });
</script>

<a class="skip btn" href="#main">Skip to content</a>
<TopBar />
<div class="body">
  <NavRail />
  <main id="main" tabindex="-1">
    {#if ready}
      {#key `${router.path}#${attempt}`}
        {#await SCREENS[router.route.name]() then mod}
          <div {@attach focusScreen}>
            <mod.default title={TITLES[router.route.name]} param={router.route.param} />
          </div>
        {:catch}
          <div {@attach focusScreen}>
            <h1 tabindex="-1">{TITLES[router.route.name]}</h1>
            <div class="card failed" role="alert">
              <p>This screen could not be loaded. Check the connection, then retry.</p>
              <button class="btn btn-primary" onclick={retryScreen}>Retry</button>
            </div>
          </div>
        {/await}
      {/key}
    {:else if failed}
      <h1 tabindex="-1">{TITLES[router.route.name]}</h1>
      <div class="card failed" role="alert">
        <p>The console could not load its data from the source.</p>
        <p class="secondary">{failed.status ? `HTTP ${failed.status} · ` : ''}{failed.message}</p>
        <button class="btn btn-primary" onclick={load}>Retry</button>
      </div>
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
  h1 { margin-bottom: var(--vf-space-5); }
  .failed { display: grid; justify-items: start; gap: var(--vf-space-3); padding: var(--vf-space-5); }
</style>
