<script lang="ts">
  import type { SourceError } from '../api/errors';
  import { TriangleAlert } from '../icons';

  // The inline error card of UX §1.1: the HTTP status, a plain message and Retry. Never a full-page error.
  let { error, onretry }: { error: SourceError; onretry?: () => void } = $props();

  const head = $derived(error.status ? `HTTP ${error.status}` : error.kind === 'network' ? 'Network error' : 'Error');
  const text = $derived.by(() => {
    switch (error.kind) {
      case 'unauthorized': return 'Your session has ended. Sign in again to continue.';
      case 'forbidden': return `Requires ${error.detail.need ?? 'a higher permission'}.`;
      case 'network': return 'The console could not reach the service.';
      case 'server': return `The service could not answer: ${error.message}`;
      default: return error.message;
    }
  });
</script>

<div class="err" role="alert">
  <TriangleAlert size={14} strokeWidth={1.5} aria-hidden="true" />
  <p><strong class="num">{head}</strong> · {text}</p>
  {#if onretry}<button class="btn btn-sm" onclick={onretry}>Retry</button>{/if}
</div>

<style>
  .err {
    display: flex; align-items: center; gap: var(--vf-space-2); padding: var(--vf-space-2) var(--vf-space-3);
    border: var(--vf-bw-strong) solid var(--vf-danger); border-radius: var(--vf-radius-sm);
    background: var(--vf-surface-raised); color: var(--vf-text-primary); font-size: var(--vf-fs-sm);
  }
  .err :global(svg) { color: var(--vf-danger); flex: none; }
  p { flex: 1; }
  strong { color: var(--vf-danger); font-weight: 600; }
</style>
