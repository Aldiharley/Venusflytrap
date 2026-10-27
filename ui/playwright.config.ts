import { defineConfig } from '@playwright/test';

// No @types/node in this package; only the env lookup below is needed.
declare const process: { env: Record<string, string | undefined> };

// Uses the system Microsoft Edge (or Chrome via PW_CHANNEL=chrome), so no browser download is needed.
export default defineConfig({
  testDir: 'e2e',
  timeout: 30_000,
  use: { baseURL: 'http://localhost:4173', channel: process.env.PW_CHANNEL ?? 'msedge', viewport: { width: 1440, height: 900 } },
  webServer: { command: 'npm run build && npm run preview', url: 'http://localhost:4173', reuseExistingServer: false, timeout: 120_000 },
});
