<script lang="ts" module>
  import type { GroupBy } from '../../lib/api/types';

  /** Counted values for `field` over the current range, given the rest of the query; null when superseded. */
  export type Suggest = (field: GroupBy, rest: string) => Promise<{ value: string; count: number }[] | null>;
</script>

<script lang="ts">
  import { tick } from 'svelte';
  import type { ErrorDetail } from '../../lib/api/errors';
  import { GROUP_BYS } from '../../lib/api/types';
  import { Search, X } from '../../lib/icons';
  import { FIELD_HELP, FIELDS, parse, quote, tokenAt } from '../../lib/query';

  let {
    value = $bindable(''), error = null, onsubmit, suggest, input = $bindable(),
  }: {
    value: string;
    /** A 400 from the last submit: its message and the bad token. */
    error: (ErrorDetail & { msg: string }) | null;
    onsubmit: (q: string) => void;
    suggest: Suggest;
    input?: HTMLInputElement;
  } = $props();

  interface Opt { label: string; insert: string; count: number | null; hint: string; match: [number, number] | null; kind: 'field' | 'value' }

  const parsed = $derived(parse(value));
  let open = $state(false);
  let opts = $state<Opt[]>([]);
  let active = $state(-1);
  let scroll = $state(0);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let gen = 0;

  async function update(openNow = false) {
    clearTimeout(timer);
    const mine = ++gen;
    const caret = input?.selectionStart ?? value.length;
    const t = tokenAt(value, caret);
    let next: Opt[] = [];
    if (t.field === null) {
      if (!t.partial && !openNow) { close(); return; }
      const p = t.partial.toLowerCase();
      next = FIELDS.filter((f) => f.startsWith(p)).map((f) => ({
        label: `${f}:`, insert: `${t.neg ? '-' : ''}${f}:`, count: null, hint: FIELD_HELP[f], match: p ? [0, p.length] : null, kind: 'field',
      }));
    } else if ((GROUP_BYS as readonly string[]).includes(t.field)) {
      const field = t.field as GroupBy;
      const rest = (value.slice(0, t.start) + value.slice(t.end)).trim();
      const got = await suggest(field, parse(rest).error ? '' : rest);
      if (got === null || mine !== gen) return; // superseded by later typing
      const p = t.partial.toLowerCase();
      next = got
        .filter((g) => g.value.toLowerCase().includes(p))
        .slice(0, 8)
        .map((g) => {
          const at = g.value.toLowerCase().indexOf(p);
          return { label: g.value, insert: `${t.neg ? '-' : ''}${field}:${quote(field === 'stage' || field === 'verdict' ? g.value.toLowerCase() : g.value)} `, count: g.count, hint: '', match: p ? [at, at + p.length] : null, kind: 'value' };
        });
    } else { close(); return; }
    opts = next;
    active = openNow && next.length ? 0 : -1;
    open = true;
  }

  function close() {
    clearTimeout(timer);
    gen++;
    open = false;
    active = -1;
  }

  async function accept(i: number) {
    const o = opts[i];
    if (!o || !input) return;
    const t = tokenAt(value, input.selectionStart ?? value.length);
    const after = value.slice(t.end).replace(/^\s+/, '');
    value = value.slice(0, t.start) + o.insert + (after ? (o.insert.endsWith(' ') ? '' : ' ') + after : '');
    const caret = t.start + o.insert.length;
    await tick();
    input.setSelectionRange(caret, caret);
    syncScroll();
    if (o.kind === 'field') update(true);
    else close();
  }

  function onkeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!open) update(true);
      else if (opts.length) active = (active + 1) % opts.length;
    } else if (e.key === 'ArrowUp') {
      if (!open || !opts.length) return;
      e.preventDefault();
      active = (active - 1 + opts.length) % opts.length;
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (open && active >= 0) accept(active);
      else { close(); onsubmit(value.trim()); }
    } else if (e.key === 'Escape') {
      if (open) { e.preventDefault(); e.stopPropagation(); close(); }
    } else if (e.key === 'Tab') close();
  }

  function oninput() {
    syncScroll();
    clearTimeout(timer);
    timer = setTimeout(() => update(), 120);
  }

  // The highlight layer follows the input's own horizontal scroll.
  function syncScroll() { scroll = input?.scrollLeft ?? 0; }

  const describedBy = $derived(error ? 'mq-error' : 'mq-help');
</script>

<div class="qb">
  <label for="mq" class="label-caps">Query</label>
  <div class="field" class:invalid={!!error}>
    <Search size={18} strokeWidth={1.5} aria-hidden="true" />
    <div class="wrap">
      <!-- The visible, highlighted query (design system §1.4). While the input is not focused it is
           the only rendering; while focused the input draws only its caret and selection over it. -->
      <div class="mirror" aria-hidden="true"><span class="line" style:transform={`translateX(${-scroll}px)`}>{#each parsed.toks as t (t.start)}<span class="t-{t.kind}">{t.text}</span>{/each}</span></div>
      <input
        id="mq"
        bind:this={input}
        bind:value
        class:hl={value.length > 0}
        type="text"
        role="combobox"
        aria-autocomplete="list"
        aria-expanded={open}
        aria-controls="mq-list"
        aria-activedescendant={open && active >= 0 ? `mq-opt-${active}` : undefined}
        aria-invalid={error ? 'true' : undefined}
        aria-describedby={describedBy}
        autocomplete="off"
        spellcheck="false"
        placeholder="verdict:block construct:sqli.* -path:/health"
        {onkeydown}
        {oninput}
        onscroll={syncScroll}
        onclick={syncScroll}
        onblur={() => { close(); syncScroll(); }}
      />
    </div>
    {#if value}
      <button class="btn btn-ghost btn-sm clear" aria-label="Clear query" onclick={() => { value = ''; input?.focus(); }}>
        <X size={14} aria-hidden="true" />
      </button>
    {/if}
  </div>
  <ul id="mq-list" class="pop" role="listbox" aria-label="Query suggestions" hidden={!open}>
    {#each opts as o, i (o.label)}
      <li id="mq-opt-{i}" role="option" tabindex="-1" aria-selected={i === active} class:active={i === active}
        onmousedown={(e) => { e.preventDefault(); accept(i); }}>
        <span class="mono label">{#if o.match}{o.label.slice(0, o.match[0])}<strong>{o.label.slice(o.match[0], o.match[1])}</strong>{o.label.slice(o.match[1])}{:else}{o.label}{/if}</span>
        {#if o.count !== null}<span class="count num">{o.count}</span>{:else}<span class="count">{o.hint}</span>{/if}
      </li>
    {:else}
      <li role="option" aria-selected="false" aria-disabled="true" class="none">No matches</li>
    {/each}
  </ul>
  {#if error}
    <p id="mq-error" class="msg err">{error.msg}{#if error.pos !== undefined}{` (at character ${error.pos + 1})`}{/if}</p>
  {:else}
    <p id="mq-help" class="msg secondary">Press Enter to run. Down arrow lists fields and values with counts.</p>
  {/if}
</div>

<style>
  .qb { position: relative; display: grid; gap: var(--vf-space-1); }
  .field {
    display: flex; align-items: center; gap: var(--vf-space-2); height: var(--vf-control-md); padding: 0 var(--vf-space-1) 0 var(--vf-space-3);
    border-radius: var(--vf-radius-sm); border: var(--vf-bw-std) solid var(--vf-border-strong);
    background: var(--vf-surface-input); box-shadow: var(--vf-shadow-inset); color: var(--vf-text-secondary);
  }
  .field:hover { border-color: var(--vf-text-secondary); }
  .field:focus-within { border-color: var(--vf-accent); outline: var(--vf-bw-focus) solid var(--vf-focus-ring); outline-offset: 2px; }
  .field.invalid { border: var(--vf-bw-strong) solid var(--vf-danger); }
  .wrap { position: relative; flex: 1; min-width: 0; height: 100%; }
  .mirror, input {
    font-family: var(--vf-font-mono); font-size: var(--vf-fs-sm); line-height: var(--vf-lh-md); letter-spacing: 0;
  }
  .mirror { position: absolute; inset: 0; display: flex; align-items: center; overflow: hidden; white-space: pre; pointer-events: none; color: var(--vf-syntax-value); }
  .line { display: inline-block; }
  input {
    position: relative; width: 100%; height: 100%; padding: 0; border: 0; background: transparent;
    color: var(--vf-text-primary); outline: none;
  }
  input:focus-visible { outline: none; box-shadow: none; }
  input::placeholder { color: var(--vf-text-muted); }
  /* At rest the highlighted mirror is the rendering; focused, the input shows only caret and selection. */
  input.hl { opacity: 0; }
  input.hl:focus { opacity: 1; color: transparent; caret-color: var(--vf-text-primary); }
  input.hl::selection { color: var(--vf-text-primary); background: var(--vf-accent-soft); }
  .t-field { color: var(--vf-syntax-field); }
  .t-operator { color: var(--vf-syntax-operator); }
  .t-string { color: var(--vf-syntax-string); }
  .t-number { color: var(--vf-syntax-number); }
  .t-error { color: var(--vf-syntax-error); text-decoration: underline wavy var(--vf-syntax-error); text-decoration-thickness: var(--vf-bw-strong); text-underline-offset: 3px; }
  .clear { width: 28px; padding: 0; justify-content: center; }
  .pop {
    position: absolute; z-index: 15; top: calc(var(--vf-lh-label) + var(--vf-control-md) + var(--vf-space-2)); left: 0; right: 0;
    margin: 0; padding: var(--vf-space-1);
    list-style: none; max-height: calc(8 * var(--vf-control-sm) + var(--vf-space-2)); overflow-y: auto;
    background: var(--vf-surface-overlay); border: var(--vf-bw-hair) solid var(--vf-border-hairline);
    border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-3);
  }
  .pop[hidden] { display: none; }
  .pop li {
    display: flex; align-items: center; justify-content: space-between; gap: var(--vf-space-3);
    height: var(--vf-control-sm); padding: 0 var(--vf-space-2); border-radius: var(--vf-radius-sm); cursor: pointer;
  }
  .pop li:hover, .pop li.active { background: var(--vf-accent-soft); }
  .pop li.active { box-shadow: inset 2px 0 0 var(--vf-accent); }
  .pop li.none { color: var(--vf-text-secondary); cursor: default; }
  .label strong { font-weight: 600; }
  .count { color: var(--vf-text-muted); font-size: var(--vf-fs-xs); }
  .msg { font-size: var(--vf-fs-xs); line-height: var(--vf-lh-xs); }
  .err { color: var(--vf-danger); }
  @media (forced-colors: active) {
    .mirror { display: none; }
    input.hl, input.hl:focus { opacity: 1; color: CanvasText; }
  }
</style>
