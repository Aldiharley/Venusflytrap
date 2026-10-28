import { afterEach, expect, test, vi } from 'vitest';
import { SourceError } from '../api/errors';
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
    session: async (c) => { await gate; return real.session(c); },
    status: (c) => real.status(c),
    counters: (c) => real.counters(c),
    dashboard: (a, b, c) => real.dashboard(a, b, c),
    board: (c) => real.board(c),
    bans: (c) => real.bans(c),
    decoys: (c) => real.decoys(c),
    history: (q, c) => real.history(q, c),
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

test('stop() aborts the calls start() has in flight', async () => {
  const seen: AbortSignal[] = [];
  const real = new FixtureSource({ live: false, latencyMs: 1_000 });
  const spy = (c: { signal: AbortSignal }) => { seen.push(c.signal); return c; };
  const src: DataSource = {
    session: (c) => real.session(spy(c)), status: (c) => real.status(spy(c)), counters: (c) => real.counters(spy(c)),
    dashboard: (a, b, c) => real.dashboard(a, b, c), board: (c) => real.board(spy(c)),
    bans: (c) => real.bans(c), decoys: (c) => real.decoys(c), history: (q, c) => real.history(q, c), subscribe: () => () => {},
  };
  const started = app.start(src);
  app.stop();
  await expect(started).resolves.toBeUndefined(); // quietly, not as an error
  expect(seen).toHaveLength(4);
  expect(seen.every((s) => s.aborted)).toBe(true);
});

test('a failed start rejects with a typed SourceError', async () => {
  const src = new FixtureSource({ live: false, fault: (m) => (m === 'status' ? SourceError.fromStatus(401, 'session expired') : null) });
  await expect(app.start(src)).rejects.toMatchObject({ kind: 'unauthorized', status: 401 });
});

test('liveLabel: Connected when fresh, Stale when connected but silent, real state otherwise', () => {
  app.live = 'Connected';
  app.now = 1_000_000;
  app.lastFrameAt = app.now - 1_000;
  expect(app.liveLabel).toBe('Connected');
  app.lastFrameAt = app.now - 21_000;
  expect(app.liveLabel).toBe('Stale');
  app.live = 'Reconnecting';
  expect(app.liveLabel).toBe('Reconnecting');
  app.live = 'Offline';
  expect(app.liveLabel).toBe('Offline');
});
