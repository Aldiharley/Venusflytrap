<script lang="ts">
  import { X } from '../icons';
  import { toasts } from './toasts.svelte';
</script>

<section class="stack" aria-label="Notifications">
  {#each toasts.items as t (t.id)}
    <div class="toast glass {t.tone}" role={t.tone === 'error' ? 'alert' : 'status'} aria-live={t.tone === 'error' ? undefined : 'polite'}>
      <span>{t.text}</span>
      <button class="btn btn-ghost btn-sm" aria-label="Dismiss notification" onclick={() => toasts.dismiss(t.id)}>
        <X size={14} aria-hidden="true" />
      </button>
    </div>
  {/each}
</section>

<style>
  .stack { position: fixed; right: var(--vf-space-5); bottom: var(--vf-space-5); display: grid; gap: var(--vf-space-2); z-index: 20; }
  .toast {
    width: 360px; display: flex; align-items: center; justify-content: space-between; gap: var(--vf-space-2);
    padding: var(--vf-space-3) var(--vf-space-4); border-radius: var(--vf-radius-md); box-shadow: var(--vf-shadow-2);
  }
  .info { box-shadow: inset 3px 0 0 var(--vf-accent), var(--vf-shadow-2); }
  .success { box-shadow: inset 3px 0 0 var(--vf-verdict-allow-fg), var(--vf-shadow-2); }
  .warn { box-shadow: inset 3px 0 0 var(--vf-verdict-challenge-fg), var(--vf-shadow-2); }
  .error { box-shadow: inset 3px 0 0 var(--vf-verdict-block-fg), var(--vf-shadow-2); }
</style>
