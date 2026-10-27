<script lang="ts">
  import { MonitorIcon, Moon, Sun } from '../icons';
  import { theme, type ThemePref } from '../state/theme.svelte';

  const OPTIONS: { value: ThemePref; label: string; Icon: typeof Sun }[] = [
    { value: 'light', label: 'Light', Icon: Sun },
    { value: 'dark', label: 'Dark', Icon: Moon },
    { value: 'system', label: 'System', Icon: MonitorIcon },
  ];
</script>

<fieldset class="seg">
  <legend class="sr-only">Theme</legend>
  {#each OPTIONS as o (o.value)}
    <label class:on={theme.pref === o.value}>
      <input type="radio" name="vft-theme" value={o.value} checked={theme.pref === o.value} onchange={() => theme.set(o.value)} />
      <o.Icon size={14} aria-hidden="true" />
      <span>{o.label}</span>
    </label>
  {/each}
</fieldset>

<style>
  .seg { display: inline-flex; gap: 2px; margin: 0; padding: 2px; border: 0; border-radius: var(--vf-radius-pill); background: var(--vf-surface-sunken); box-shadow: var(--vf-shadow-inset); }
  label { position: relative; display: inline-flex; align-items: center; gap: var(--vf-space-1); height: 28px; padding: 0 10px; border-radius: var(--vf-radius-pill); font-size: var(--vf-fs-sm); color: var(--vf-text-secondary); cursor: pointer; }
  label.on { background: var(--vf-surface-raised); color: var(--vf-text-primary); box-shadow: var(--vf-shadow-1); }
  input { position: absolute; opacity: 0; inset: 0; margin: 0; cursor: pointer; }
  label:has(input:focus-visible) { outline: var(--vf-bw-focus) solid var(--vf-focus-ring); outline-offset: 2px; }
</style>
