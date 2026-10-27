import { afterEach, expect, test, vi } from 'vitest';
import type { DataSource } from '../api/source';
import { FixtureSource } from '../api/source';
import type { LiveFrame } from '../api/types';
import { app } from './app.svelte';

afterEach(() => {
  app.stop();
  vi.useRealTimers();
});

/** A source whose session() resolves only when the test says so. */
function gatedSource(): { src: DataSource; release: () => void; subscribed: () => number; unsubscribed: () => number } {
  const real = new FixtureSource({ live: false });
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let subs = 0;
  let unsubs = 0;
  const src: DataSource = {
    session: async () => { await gate; return real.session(); },
    status: () => real.status(),
    counters: () => real.counters(),
    dashboard: (a, b) => real.dashboard(a, b),
    board: () => real.board(),
    bans: () => real.bans(),
    decoys: () => real.decoys(),
    subscribe: (_cb: (f: LiveFrame) => void) => { subs++; return () => { unsubs++; }; },
  };
  return { src, release, subscribed: () => subs, unsubscribed: () => unsubs };
}

test('stop() during start() leaves no subscription and no timer behind', async () => {
  vi.useFakeTimers();
  const g = gatedSource();
  const started = app.start(g.src);
  app.stop();
  g.release();
  await started;
  expect(g.subscribed()).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
  expect(app.session).toBeNull();
});

test('a second start() supersedes the first', async () => {
  vi.useFakeTimers();
  const first = gatedSource();
  const second = new FixtureSource({ live: false });
  const p1 = app.start(first.src);
  await app.start(second);
  first.release();
  await p1;
  expect(first.subscribed()).toBe(0);
  expect(vi.getTimerCount()).toBe(1); // only the second start's clock
  app.stop();
  expect(vi.getTimerCount()).toBe(0);
});

test('start() registers a subscription and the clock; stop() clears them', async () => {
  vi.useFakeTimers();
  const g = gatedSource();
  g.release();
  await app.start(g.src);
  expect(g.subscribed()).toBe(1);
  expect(vi.getTimerCount()).toBe(1);
  app.stop();
  expect(g.unsubscribed()).toBe(1);
  expect(vi.getTimerCount()).toBe(0);
});
