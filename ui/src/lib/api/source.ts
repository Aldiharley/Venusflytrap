import { BASE_RPS, makeFixtures, type Fixtures } from './fixtures';
import { mulberry32 } from './rng';
import type { BanEntry, Counters, Dashboard, LiveFrame, Session, SourceView, StatusRecord } from './types';

/** Everything the console reads. SP5 adds an HTTP + SSE implementation. */
export interface DataSource {
  session(): Promise<Session>;
  status(): Promise<StatusRecord>;
  counters(): Promise<Counters>;
  dashboard(from: number, to: number): Promise<Dashboard>;
  board(): Promise<SourceView[]>;
  bans(): Promise<BanEntry[]>;
  decoys(): Promise<string[]>;
  /** Live frames until the returned function is called. */
  subscribe(onFrame: (f: LiveFrame) => void): () => void;
}

export interface FixtureOptions {
  now?: () => number;
  /** Simulate the live feed (counters jitter, board activity). */
  live?: boolean;
  tickMs?: number;
}

export class FixtureSource implements DataSource {
  private readonly now: () => number;
  private readonly live: boolean;
  private readonly tickMs: number;
  private readonly f: Fixtures;
  private board_: SourceView[];

  constructor(opts: FixtureOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.live = opts.live ?? true;
    this.tickMs = opts.tickMs ?? 1000;
    this.f = makeFixtures(this.now());
    this.board_ = this.f.board;
  }

  async session() { return this.f.session; }
  async status() { return this.f.status; }
  async counters() { return this.f.counters; }
  async dashboard(from: number, to: number) { return this.f.dashboard(from, to); }
  async board() { return this.board_; }
  async bans() { return this.f.bans; }
  async decoys() { return this.f.decoys; }

  subscribe(onFrame: (f: LiveFrame) => void): () => void {
    if (!this.live) return () => {};
    const rnd = mulberry32(11);
    const timer = setInterval(() => {
      const rps = BASE_RPS.map((r) => Math.max(0, r * (1 + 0.1 * (rnd() - 0.5)))) as Counters['rps_by_verdict'];
      onFrame({ kind: 'counters', counters: { rps_by_verdict: rps, dropped_total: 0 } });
      const now = this.now();
      this.board_ = this.board_.map((s) => {
        if (s.stage === null || s.last_seen_ms < now - 5 * 60_000) return s;
        const hot = s.stage === 'Exploitation' || s.stage === 'Exfiltration';
        const add = Math.round((hot ? 6 : 1.5) * rnd() * (this.tickMs / 1000));
        if (add === 0) return s;
        const blocked = s.ban ? add : Math.round(add * (hot ? 0.8 : 0.1));
        return { ...s, requests: s.requests + add, blocked: s.blocked + blocked, last_seen_ms: now };
      });
      onFrame({ kind: 'board', board: this.board_ });
    }, this.tickMs);
    return () => clearInterval(timer);
  }
}
