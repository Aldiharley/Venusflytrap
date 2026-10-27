<script lang="ts">
  import type { Snippet } from 'svelte';
  import { router } from '../state/router.svelte';

  let { href, class: cls = '', current = false, children, ...rest }:
    { href: string; class?: string; current?: boolean; children: Snippet; [k: string]: unknown } = $props();

  function onclick(e: MouseEvent) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    router.navigate(href);
  }
</script>

<a {href} class={cls} aria-current={current ? 'page' : undefined} {onclick} {...rest}>{@render children()}</a>
