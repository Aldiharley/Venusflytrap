/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// The admin listener's policy (parent spec §5.8). `vite preview` serves it so the
// e2e suite sees exactly what production will enforce.
export const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
  "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  build: { target: 'es2022', manifest: true, assetsInlineLimit: 0 },
  preview: {
    headers: {
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    // Vitest blanks CSS modules by default, including ?raw imports; tokens.test.ts parses the real file.
    css: { include: [/tokens\.css/] },
    setupFiles: ['src/test-setup.ts'],
  },
});
