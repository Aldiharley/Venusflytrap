import { expect, test } from 'vitest';
import { SourceError, toSourceError } from './errors';
import { Latest } from './latest';
import { FixtureSource } from './source';

const NOW = Date.UTC(2026, 9, 28, 14, 5, 0);
const call = () => ({ signal: new AbortController().signal });

function deferred<T>() {
  let resolve!: (v: T) => void;
  const p = new Promise<T>((r) => (resolve = r));
  return { p, resolve };
}

test('SourceError maps HTTP statuses to kinds', () => {
  const kinds = [400, 401, 403, 404, 409, 422, 500, 503].map((s) => SourceError.fromStatus(s, 'x').kind);
  expect(kinds).toEqual(['bad_request', 'unauthorized', 'forbidden', 'not_found', 'conflict', 'invalid', 'server', 'server']);
  expect(SourceError.fromStatus(503, 'x').retryable).toBe(true);
  expect(SourceError.fromStatus(404, 'x').retryable).toBe(false);
});

test('toSourceError normalises aborts, network failures and unknowns', () => {
  expect(toSourceError(new DOMException('stop', 'AbortError')).kind).toBe('aborted');
  expect(toSourceError(new TypeError('Failed to fetch')).kind).toBe('network');
  const e = SourceError.fromStatus(403, 'no', { need: 'Admin' });
  expect(toSourceError(e)).toBe(e);
  expect(toSourceError('weird').kind).toBe('network');
});

test('a FixtureSource call rejects as aborted when its signal is already aborted', async () => {
  const src = new FixtureSource({ now: () => NOW, live: false });
  const ctl = new AbortController();
  ctl.abort();
  await expect(src.board({ signal: ctl.signal })).rejects.toMatchObject({ kind: 'aborted' });
});

test('a FixtureSource call rejects as aborted when aborted during its latency', async () => {
  const src = new FixtureSource({ now: () => NOW, live: false, latencyMs: 50 });
  const ctl = new AbortController();
  const p = src.dashboard(NOW - 3_600_000, NOW, { signal: ctl.signal });
  ctl.abort();
  await expect(p).rejects.toMatchObject({ kind: 'aborted' });
});

test('a FixtureSource can inject a typed fault per method', async () => {
  const src = new FixtureSource({
    now: () => NOW, live: false,
    fault: (m) => (m === 'dashboard' ? SourceError.fromStatus(503, 'history store unavailable') : null),
  });
  await expect(src.dashboard(NOW - 1, NOW, call())).rejects.toMatchObject({ kind: 'server', status: 503 });
  await expect(src.board(call())).resolves.toBeInstanceOf(Array);
});

test('Latest drops a superseded response and aborts its signal', async () => {
  const latest = new Latest();
  const slow = deferred<string>();
  let firstSignal: AbortSignal | undefined;
  const first = latest.run(({ signal }) => { firstSignal = signal; return slow.p; });
  const second = latest.run(async () => 'fresh');
  expect(firstSignal?.aborted).toBe(true);
  slow.resolve('stale');
  expect(await first).toBeNull();
  expect(await second).toEqual({ ok: true, value: 'fresh' });
});

test('Latest reports a typed error, and nothing after abort()', async () => {
  const latest = new Latest();
  expect(await latest.run(async () => { throw SourceError.fromStatus(500, 'boom'); }))
    .toMatchObject({ ok: false, error: { kind: 'server', status: 500 } });
  const gate = deferred<number>();
  const p = latest.run(() => gate.p);
  latest.abort();
  gate.resolve(1);
  expect(await p).toBeNull();
});

test('Latest treats an aborted rejection as superseded, not as an error', async () => {
  const latest = new Latest();
  expect(await latest.run(async () => { throw SourceError.aborted(); })).toBeNull();
});
