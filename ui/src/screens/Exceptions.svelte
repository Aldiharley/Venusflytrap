<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import type { SourceError } from '../lib/api/errors';
  import { Latest } from '../lib/api/latest';
  import type { ExceptionEntry } from '../lib/api/types';
  import EmptyState from '../lib/components/EmptyState.svelte';
  import ErrorCard from '../lib/components/ErrorCard.svelte';
  import { toasts } from '../lib/components/toasts.svelte';
  import { liveAt, parseDate, scopeLabel, toYaml } from '../lib/exceptions';
  import { fmtExpiry } from '../lib/format';
  import { Copy, TriangleAlert, X } from '../lib/icons';
  import { app } from '../lib/state/app.svelte';
  import { router } from '../lib/state/router.svelte';

  let { title }: { title: string } = $props();

  let entries = $state<ExceptionEntry[] | null>(null);
  let error = $state<SourceError | null>(null);
  const latest = new Latest();

  async function load() {
    const src = app.src;
    if (!src) return;
    const r = await latest.run((call) => src.exceptions(call));
    if (!r) return;
    if (r.ok) { entries = r.value; error = null; } else { entries = null; error = r.error; }
  }
  onMount(() => { load(); return () => latest.abort(); });

  const TABS = [{ key: 'active', label: 'Active' }, { key: 'expired', label: 'Expired' }] as const;
  type TabKey = (typeof TABS)[number]['key'];
  let tab = $state<TabKey>('active');
  let tabEls = $state<HTMLButtonElement[]>([]);

  // Active entries list the soonest expiry first (what needs renewing next); expired ones the latest first.
  const byExpiry = (a: ExceptionEntry, b: ExceptionEntry) => (a.expires < b.expires ? -1 : a.expires > b.expires ? 1 : a.id < b.id ? -1 : 1);
  const lists = $derived.by(() => {
    const all = entries ?? [];
    return {
      active: all.filter((e) => liveAt(e, app.now)).sort(byExpiry),
      expired: all.filter((e) => !liveAt(e, app.now)).sort((a, b) => byExpiry(b, a)),
    };
  });
  const rows = $derived(lists[tab]);

  // `?id=` (Request details links here) names the entry whose panel is open and the tab holding it.
  const idParam = $derived(router.search.get('id'));
  const entry = $derived(entries?.find((e) => e.id === idParam) ?? null);
  const home = $derived<TabKey | null>(entry ? (liveAt(entry, app.now) ? 'active' : 'expired') : null);
  const selected = $derived(home === tab ? entry : null);
  $effect(() => { if (home) untrack(() => { tab = home; }); });

  let rowBtns = $state<Record<string, HTMLButtonElement | undefined>>({});
  let heading: HTMLHeadingElement | undefined = $state();

  async function select(id: string) {
    router.navigate(`/exceptions?id=${encodeURIComponent(id)}`, true);
    await tick();
    heading?.focus();
  }
  async function close() {
    const id = selected?.id;
    router.navigate('/exceptions', true);
    await tick();
    if (id) rowBtns[id]?.focus();
  }
  function onRowKey(e: KeyboardEvent, id: string) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    e.preventDefault();
    select(id);
  }

  function pick(key: TabKey) {
    tab = key;
    if (entry && home !== key) router.navigate('/exceptions', true); // the open entry is on the other tab
  }
  function onTabKey(e: KeyboardEvent, i: number) {
    const to = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i + TABS.length - 1) % TABS.length
      : e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : -1;
    if (to < 0) return;
    e.preventDefault();
    pick(TABS[to].key);
    tabEls[to]?.focus();
  }

  /** The relative expiry for display; a malformed date (the engine would reject the file) shows as written. */
  function relative(e: ExceptionEntry): string | null {
    const ms = parseDate(e.expires);
    return ms === null ? null : fmtExpiry(ms, app.now);
  }

  async function copy(text: string, what: string) {
    try {
      await navigator.clipboard.writeText(text);
      toasts.push({ tone: 'success', text: `Copied ${what}.` });
    } catch {
      toasts.push({ tone: 'warn', text: `Could not copy the ${what}.` });
    }
  }
</script>

<h1 tabindex="-1">{title}</h1>
<p class="secondary note">Exceptions are read from the file passed with --exceptions. Changes take effect after a restart.</p>

{#if error}
  <ErrorCard {error} onretry={load} />
{:else if !entries}
  <div class="card skeleton" aria-busy="true" aria-label="Loading exceptions"></div>
{:else}
  <div class="tabs" role="tablist" aria-label="Exceptions status">
    {#each TABS as t, i (t.key)}
      <button bind:this={tabEls[i]} role="tab" id="tab-{t.key}" class="tab" aria-selected={tab === t.key} aria-controls="exc-panel"
        tabindex={tab === t.key ? 0 : -1} onclick={() => pick(t.key)} onkeydown={(e) => onTabKey(e, i)}>
        {t.label} <span class="count num">{lists[t.key].length}</span>
      </button>
    {/each}
  </div>

  <div role="tabpanel" id="exc-panel" aria-labelledby="tab-{tab}" class="panel">
    {#if rows.length === 0}
      <div class="card">
        <EmptyState scene="quiet" message="No {tab} exceptions" />
      </div>
    {:else}
      <div class="card scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">ID</th><th scope="col">Action</th><th scope="col">Scope</th><th scope="col">Constructs</th>
              <th scope="col">Owner</th><th scope="col">Reason</th><th scope="col">Expires</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as e (e.id)}
              <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions: the ID button is the keyboard path; the row click is a larger target for the mouse -->
              <tr class:sel={selected?.id === e.id} onclick={() => select(e.id)}>
                <td>
                  <button bind:this={rowBtns[e.id]} class="rowbtn" aria-expanded={selected?.id === e.id} aria-controls="exc-detail"
                    onkeydown={(ev) => onRowKey(ev, e.id)}><span class="mono id">{e.id}</span></button>
                </td>
                <td>
                  <span class="mono">{e.action}</span>
                  {#if e.action === 'skip-inspection'}
                    <span class="warn"><TriangleAlert size={12} strokeWidth={1.5} aria-hidden="true" />Skips inspection</span>
                  {/if}
                </td>
                <td class="mono">{scopeLabel(e)}</td>
                <td class="mono">
                  {#if e.constructs.length}{e.constructs.join(', ')}{:else}<span aria-hidden="true">—</span><span class="sr-only">none</span>{/if}
                </td>
                <td>{e.owner}</td>
                <td class="reason">{e.reason}</td>
                <td class="num nowrap"><span title={e.expires}>{relative(e) ?? e.expires}</span></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

    {#if selected}
      {@const s = selected}
      <section id="exc-detail" class="card detail" aria-labelledby="exc-detail-h">
        <header class="detail-head">
          <h2 id="exc-detail-h" class="sub" tabindex="-1" bind:this={heading}>Exception <span class="mono">{s.id}</span></h2>
          {#if s.action === 'skip-inspection'}
            <span class="warn"><TriangleAlert size={12} strokeWidth={1.5} aria-hidden="true" />Skips inspection</span>
          {/if}
          <span class="spacer"></span>
          <button class="btn btn-sm" onclick={() => copy(toYaml(s), 'YAML')}><Copy size={14} aria-hidden="true" />Copy YAML</button>
          <button class="btn btn-sm btn-ghost" onclick={close}><X size={14} aria-hidden="true" />Close</button>
        </header>
        <dl class="kv">
          <div><dt class="label-caps">ID</dt><dd class="mono">{s.id}</dd></div>
          <div><dt class="label-caps">Action</dt><dd class="mono">{s.action}</dd></div>
          <div><dt class="label-caps">Constructs</dt><dd class="mono">{s.constructs.length ? s.constructs.join(', ') : 'None (the field is not inspected)'}</dd></div>
          <div><dt class="label-caps">Methods</dt><dd class="mono">{s.scope.methods.length ? s.scope.methods.join(', ') : 'Any method'}</dd></div>
          <div><dt class="label-caps">Path prefix</dt><dd class="mono">{s.scope.path_prefix}</dd></div>
          <div><dt class="label-caps">Field</dt><dd class="mono">{s.scope.field ? `${s.scope.field.loc} ${s.scope.field.name}` : 'Any field'}</dd></div>
          <div><dt class="label-caps">Owner</dt><dd>{s.owner}</dd></div>
          <div class="wide"><dt class="label-caps">Reason</dt><dd>{s.reason}</dd></div>
          <div><dt class="label-caps">Created</dt><dd class="num">{s.created}</dd></div>
          <div><dt class="label-caps">Modified</dt><dd class="num">{s.modified}</dd></div>
          <div><dt class="label-caps">Expires</dt><dd class="num">{s.expires}{#if relative(s)}{' '}<span class="secondary">({relative(s)})</span>{/if}</dd></div>
        </dl>
      </section>
    {/if}
  </div>
{/if}

<style>
  .note { margin: calc(-1 * var(--vf-space-3)) 0 var(--vf-space-4); }
  .skeleton { height: 240px; background: var(--vf-surface-sunken); }
  .tabs { display: flex; gap: var(--vf-space-1); margin-bottom: var(--vf-space-4); border-bottom: var(--vf-bw-std) solid var(--vf-border-subtle); }
  .tab {
    height: var(--vf-control-sm); padding: 0 var(--vf-space-3); background: transparent; border: 0; cursor: pointer;
    border-bottom: var(--vf-bw-strong) solid transparent; margin-bottom: calc(-1 * var(--vf-bw-std));
    font-size: var(--vf-fs-sm); font-weight: 600; color: var(--vf-text-secondary);
  }
  .tab:hover { color: var(--vf-text-primary); }
  .tab[aria-selected='true'] { color: var(--vf-accent); border-bottom-color: var(--vf-accent); }
  .count { margin-left: var(--vf-space-1); color: var(--vf-text-secondary); font-weight: 500; }
  .panel { display: grid; gap: var(--vf-space-4); }
  .scroll { overflow-x: auto; padding: 0; }
  td { vertical-align: top; padding-block: var(--vf-space-2); }
  .reason { min-width: 18em; max-width: 36em; }
  .nowrap { white-space: nowrap; }
  tbody tr { cursor: pointer; }
  tbody tr:hover td { background: var(--vf-row-hover); }
  tbody tr.sel td { background: var(--vf-row-selected); }
  .rowbtn { padding: 0; background: none; border: 0; cursor: pointer; color: var(--vf-accent); text-align: left; }
  .rowbtn:hover .id { text-decoration: underline; }
  .warn {
    display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 20px; padding: 0 var(--vf-space-2);
    border-radius: var(--vf-radius-xs); border: var(--vf-bw-std) solid color-mix(in srgb, var(--vf-health-warn-fg) 35%, transparent);
    background: var(--vf-health-warn-bg); color: var(--vf-health-warn-fg);
    font-size: var(--vf-fs-xs); font-weight: 600; white-space: nowrap;
  }
  .detail { display: grid; gap: var(--vf-space-3); }
  .detail-head { display: flex; align-items: center; flex-wrap: wrap; gap: var(--vf-space-2) var(--vf-space-3); }
  .sub { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); }
  .spacer { flex: 1; }
  .detail-head .btn { display: inline-flex; align-items: center; gap: var(--vf-space-1); }
  .kv { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: var(--vf-space-3); margin: 0; }
  .kv div { display: grid; gap: 2px; min-width: 0; }
  .kv .wide { grid-column: 1 / -1; }
  dd { margin: 0; overflow-wrap: anywhere; }
</style>
