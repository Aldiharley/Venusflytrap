<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import type { ExceptionAction, ExceptionEntry, FieldLoc, RequestDetail } from '../../lib/api/types';
  import { toasts } from '../../lib/components/toasts.svelte';
  import { toYaml, validateEntry } from '../../lib/exceptions';
  import { Copy, TriangleAlert, X } from '../../lib/icons';
  import { app } from '../../lib/state/app.svelte';
  import { prefillException, slotOf, splitList, type Slot } from './exception-form';

  let { d, onclose }: { d: RequestDetail; onclose: () => void } = $props();

  // Pre-filled once, from the request as it is when the panel opens.
  const start = untrack(() => prefillException(d, app.now));

  let id = $state(start.id);
  let action = $state<ExceptionAction>(start.action);
  let constructs = $state(start.constructs.join(', '));
  let methods = $state(start.scope.methods.join(', '));
  let path = $state(start.scope.path_prefix);
  let loc = $state<FieldLoc | ''>(start.scope.field?.loc ?? '');
  let fieldName = $state(start.scope.field?.name ?? '');
  let owner = $state('');
  let reason = $state('');
  let expires = $state(start.expires);
  // What the construct input held before skip-inspection cleared it, for when the action changes back.
  let kept = start.constructs.join(', ');

  const ACTIONS: { value: ExceptionAction; blurb: string }[] = [
    { value: 'ignore', blurb: 'Drops the matching evidence: it is neither scored nor kept in the log.' },
    { value: 'log-only', blurb: 'Keeps the matching evidence in the log with 0 points: it never scores or decides.' },
    { value: 'skip-inspection', blurb: 'Does not inspect the matching field at all, so no construct can fire on it.' },
  ];

  function pick(a: ExceptionAction) {
    if (a === 'skip-inspection' && action !== 'skip-inspection') { kept = constructs; constructs = ''; }
    else if (a !== 'skip-inspection' && action === 'skip-inspection' && constructs === '') constructs = kept;
    action = a;
  }

  const entry = $derived<ExceptionEntry>({
    id, action,
    constructs: action === 'skip-inspection' ? [] : splitList(constructs),
    scope: {
      methods: splitList(methods).map((m) => m.toUpperCase()),
      path_prefix: path,
      field: loc === '' ? null : { loc, name: fieldName },
    },
    owner, reason, created: start.created, modified: start.modified, expires,
  });
  const issues = $derived(validateEntry(entry, app.now));
  const at = (s: Slot) => issues.filter((i) => slotOf(i) === s);
  const yaml = $derived(issues.length === 0 ? toYaml(entry) : '');

  /** The ids an input is described by: its hint, then its issues, if any. */
  const described = (s: Slot, hint = true) => [hint ? `ce-hint-${s}` : '', at(s).length ? `ce-issue-${s}` : ''].filter(Boolean).join(' ') || undefined;
  const invalid = (s: Slot) => (at(s).length ? 'true' : undefined);

  let heading: HTMLHeadingElement | undefined = $state();
  onMount(() => heading?.focus());

  async function copy() {
    try {
      await navigator.clipboard.writeText(yaml);
      toasts.push({ tone: 'success', text: 'Copied YAML.' });
    } catch {
      toasts.push({ tone: 'warn', text: 'Could not copy the YAML.' });
    }
  }
</script>

{#snippet problems(s: Slot)}
  {#if at(s).length}
    <p id="ce-issue-{s}" class="issue">{#each at(s) as i, k (k)}{k ? ' ' : ''}{i.msg}.{/each}</p>
  {/if}
{/snippet}

<section class="card panel" aria-labelledby="ce-h">
  <header class="head">
    <h2 id="ce-h" class="title" tabindex="-1" bind:this={heading}>Create exception</h2>
    <span class="spacer"></span>
    <button class="btn btn-sm btn-ghost" onclick={onclose}><X size={14} aria-hidden="true" />Close</button>
  </header>
  <p class="secondary small">Starts from this request: its deciding construct, method, path and field. Narrow it before you use it.</p>

  <fieldset class="actions">
    <legend class="label-caps">Action</legend>
    {#each ACTIONS as a (a.value)}
      <div class="opt">
        <input type="radio" id="ce-action-{a.value}" name="ce-action" value={a.value} checked={action === a.value}
          aria-describedby="ce-blurb-{a.value}" onchange={() => pick(a.value)} />
        <label for="ce-action-{a.value}" class="mono">{a.value}</label>
        <span id="ce-blurb-{a.value}" class="secondary small">{a.blurb}</span>
      </div>
    {/each}
  </fieldset>
  {#if action === 'skip-inspection'}
    <p class="warn" role="note"><TriangleAlert size={14} strokeWidth={1.5} aria-hidden="true" />Matching fields will not be inspected at all.</p>
  {/if}

  <div class="fields">
    <div class="f">
      <label for="ce-id">ID</label>
      <input id="ce-id" class="mono" bind:value={id} autocomplete="off" spellcheck="false" aria-invalid={invalid('id')} aria-describedby={described('id')} />
      <span id="ce-hint-id" class="secondary small">Lowercase letters, digits and dashes, up to 64.</span>
      {@render problems('id')}
    </div>
    {#if action !== 'skip-inspection'}
      <div class="f wide">
        <label for="ce-constructs">Constructs</label>
        <input id="ce-constructs" class="mono" bind:value={constructs} autocomplete="off" spellcheck="false" aria-invalid={invalid('constructs')} aria-describedby={described('constructs')} />
        <span id="ce-hint-constructs" class="secondary small">Construct ids or a family wildcard such as <code class="mono">sqli.*</code>, separated by commas.</span>
        {@render problems('constructs')}
      </div>
    {/if}
    <div class="f">
      <label for="ce-methods">Methods</label>
      <input id="ce-methods" class="mono" bind:value={methods} autocomplete="off" spellcheck="false" aria-invalid={invalid('methods')} aria-describedby={described('methods')} />
      <span id="ce-hint-methods" class="secondary small">Empty means any method.</span>
      {@render problems('methods')}
    </div>
    <div class="f">
      <label for="ce-path">Path prefix</label>
      <input id="ce-path" class="mono" bind:value={path} autocomplete="off" spellcheck="false" aria-invalid={invalid('path')} aria-describedby={described('path')} />
      <span id="ce-hint-path" class="secondary small">Matches whole path segments, starting with /.</span>
      {@render problems('path')}
    </div>
    <div class="f">
      <label for="ce-loc">Field location</label>
      <select id="ce-loc" bind:value={loc} aria-describedby={described('field', false)}>
        <option value="">Any field</option>
        {#each ['path', 'query', 'header', 'cookie', 'body'] as l (l)}<option value={l}>{l}</option>{/each}
      </select>
    </div>
    <div class="f">
      <label for="ce-field">Field name</label>
      <input id="ce-field" class="mono" bind:value={fieldName} disabled={loc === ''} autocomplete="off" spellcheck="false" aria-invalid={invalid('field')} aria-describedby={described('field')} />
      <span id="ce-hint-field" class="secondary small">Exact, or a glob with * and ?; skip-inspection needs an exact name.</span>
      {@render problems('field')}
    </div>
    <div class="f">
      <label for="ce-owner">Owner</label>
      <input id="ce-owner" bind:value={owner} autocomplete="off" aria-invalid={invalid('owner')} aria-describedby={described('owner')} />
      <span id="ce-hint-owner" class="secondary small">Who answers for this exception.</span>
      {@render problems('owner')}
    </div>
    <div class="f">
      <label for="ce-expires">Expires</label>
      <input id="ce-expires" class="mono" bind:value={expires} autocomplete="off" spellcheck="false" aria-invalid={invalid('expires')} aria-describedby={described('expires')} />
      <span id="ce-hint-expires" class="secondary small">YYYY-MM-DD, at most 365 days from {start.modified}.</span>
      {@render problems('expires')}
    </div>
    <div class="f wide">
      <label for="ce-reason">Reason</label>
      <textarea id="ce-reason" rows="2" bind:value={reason} aria-invalid={invalid('reason')} aria-describedby={described('reason')}></textarea>
      <span id="ce-hint-reason" class="secondary small">Why this is safe, for whoever reviews it next.</span>
      {@render problems('reason')}
    </div>
  </div>

  {#if at('form').length}<div class="issue" role="group" aria-label="Other issues">{#each at('form') as i, k (k)}<p>{i.msg}.</p>{/each}</div>{/if}

  {#if yaml}
    <div class="out">
      <div class="out-head">
        <h3 class="label-caps">Exception YAML</h3>
        <button class="btn btn-sm" onclick={copy}><Copy size={14} aria-hidden="true" />Copy YAML</button>
      </div>
      <pre class="mono yaml">{yaml}</pre>
      <p class="secondary small">Paste this under exceptions: in your exceptions file. It takes effect after a restart with --exceptions.</p>
    </div>
  {:else}
    <p class="secondary small">Fix the issues above to get the YAML.</p>
  {/if}
</section>

<style>
  .panel { display: grid; gap: var(--vf-space-3); margin-bottom: var(--vf-space-4); }
  .head { display: flex; align-items: center; gap: var(--vf-space-3); }
  .head .btn { display: inline-flex; align-items: center; gap: var(--vf-space-1); }
  .spacer { flex: 1; }
  .title { font-size: var(--vf-fs-title-sm); line-height: var(--vf-lh-title-sm); }
  .small { font-size: var(--vf-fs-xs); }
  .actions { display: grid; gap: var(--vf-space-2); margin: 0; padding: 0; border: 0; min-width: 0; }
  .actions legend { padding: 0; margin-bottom: var(--vf-space-1); }
  .opt { display: grid; grid-template-columns: auto auto minmax(0, 1fr); align-items: baseline; gap: var(--vf-space-2); }
  .opt label { font-weight: 600; }
  .warn {
    display: flex; align-items: center; gap: var(--vf-space-2); margin: 0; padding: var(--vf-space-2) var(--vf-space-3);
    border-radius: var(--vf-radius-xs); border: var(--vf-bw-std) solid color-mix(in srgb, var(--vf-health-warn-fg) 35%, transparent);
    background: var(--vf-health-warn-bg); color: var(--vf-health-warn-fg); font-size: var(--vf-fs-sm); font-weight: 600;
  }
  .fields { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: var(--vf-space-3) var(--vf-space-4); }
  .f { display: grid; gap: var(--vf-space-1); align-content: start; min-width: 0; }
  .f.wide { grid-column: 1 / -1; }
  .f label { font-size: var(--vf-fs-sm); font-weight: 600; }
  input:not([type='radio']), select, textarea {
    height: var(--vf-control-md); padding: 0 var(--vf-space-2); width: 100%; min-width: 0;
    border-radius: var(--vf-radius-sm); border: var(--vf-bw-std) solid var(--vf-border-strong);
    background: var(--vf-surface-input); box-shadow: var(--vf-shadow-inset); color: var(--vf-text-primary);
  }
  textarea { height: auto; padding: var(--vf-space-2); font: inherit; resize: vertical; }
  input:disabled { color: var(--vf-text-disabled); cursor: not-allowed; }
  input:not([type='radio']):hover, select:hover, textarea:hover { border-color: var(--vf-text-secondary); }
  [aria-invalid='true'] { border: var(--vf-bw-strong) solid var(--vf-danger); }
  .issue { margin: 0; color: var(--vf-danger); font-size: var(--vf-fs-xs); font-weight: 600; }
  .out { display: grid; gap: var(--vf-space-2); }
  .out-head { display: flex; align-items: center; justify-content: space-between; gap: var(--vf-space-3); }
  .out-head .btn { display: inline-flex; align-items: center; gap: var(--vf-space-1); }
  .yaml {
    margin: 0; padding: var(--vf-space-3); overflow: auto; white-space: pre;
    background: var(--vf-surface-sunken); border-radius: var(--vf-radius-md); border: var(--vf-bw-hair) solid var(--vf-border-hairline);
  }
</style>
