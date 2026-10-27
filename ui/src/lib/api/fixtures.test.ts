import { expect, test } from 'vitest';
import { makeFixtures } from './fixtures';
import { FixtureSource } from './source';
import { STAGES } from './types';

const NOW = Date.UTC(2026, 9, 27, 14, 5, 0);

test('fixtures are deterministic', () => {
  const [a, b] = [makeFixtures(NOW), makeFixtures(NOW)];
  expect(a.board).toEqual(b.board);
  expect(a.dashboard(NOW - 3_600_000, NOW)).toEqual(b.dashboard(NOW - 3_600_000, NOW));
});

test('board is consistent with its own stage paths', () => {
  for (const s of makeFixtures(NOW).board) {
    if (s.stage === null) continue;
    expect(s.stage_path.at(-1)?.stage).toBe(s.stage);
    expect(s.blocked).toBeLessThanOrEqual(s.requests);
    expect(s.stage_counts[STAGES.indexOf(s.stage)]).toBeGreaterThan(0);
  }
});

test('dashboard aggregates agree with the board', () => {
  const f = makeFixtures(NOW);
  const d = f.dashboard(NOW - 3_600_000, NOW);
  expect(d.active_bans).toBe(f.board.filter((s) => s.ban).length);
  for (const stage of STAGES) {
    expect(d.sources_by_stage[stage]).toBe(f.board.filter((s) => s.stage === stage).length);
  }
  const lens = d.requests_by_verdict.map((a) => a.length);
  expect(new Set(lens).size).toBe(1);
  expect(d.top_paths).toHaveLength(5);
});

test('a static FixtureSource emits no frames', async () => {
  const src = new FixtureSource({ now: () => NOW, live: false });
  let frames = 0;
  const stop = src.subscribe(() => frames++);
  await new Promise((r) => setTimeout(r, 30));
  stop();
  expect(frames).toBe(0);
  expect((await src.board()).length).toBeGreaterThan(8);
});

test('a live FixtureSource emits counters and board frames', async () => {
  const src = new FixtureSource({ now: () => NOW, live: true, tickMs: 5 });
  const kinds = new Set<string>();
  const stop = src.subscribe((f) => kinds.add(f.kind));
  await new Promise((r) => setTimeout(r, 40));
  stop();
  expect(kinds.has('counters') && kinds.has('board')).toBe(true);
});
