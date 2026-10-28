import { parse } from '../query';
import { SourceError } from './errors';
import { BASE_RPS, makeFixtures, type Fixtures } from './fixtures';
import { makeHistory, type History } from './history';
import { mulberry32 } from './rng';
import type {
  BanEntry, Counters, Dashboard, HistoryPage, HistoryQuery, LiveFrame, RequestDetail, Session, SourceView, StatusRecord,
} from './types';

/** Every call carries the caller's AbortSignal; aborting rejects it with a SourceError of kind 'aborted'. */
export interface Call { signal: AbortSignal }

/**
 * Everything the console reads. SP5 adds an HTTP + SSE implementation.
 * Contract: every call takes a `Call`; every failure rejects with a `SourceError`.
 */
export interface DataSource {
  session(call: Call): Promise<Session>;
  status(call: Call): Promise<StatusRecord>;
  counters(call: Call): Promise<Counters>;
  dashboard(from: number, to: number, call: Call): Promise<Dashboard>;
  board(call: Call): Promise<SourceView[]>;
  bans(call: Call): Promise<BanEntry[]>;
  decoys(call: Call): Promise<string[]>;
  /** A history query; a syntax error rejects as `bad_request` with the token's `pos`/`len`. */
  history(q: HistoryQuery, call: Call): Promise<HistoryPage>;
  /** One stored request with its full judgment; an unknown or expired id rejects as `not_found`. */
  request(id: string, call: Call): Promise<RequestDetail>;
  /** Live frames until the returned function is called. */
  subscribe(onFrame: (f: LiveFrame) => void): () => void;
}

export type Method = Exclude<keyof DataSource, 'subscribe'>;

export interface FixtureOptions {
  now?: () => number;
  /** Simulate the live feed (counters jitter, board activity). */
  live?: boolean;
  tickMs?: number;
  /** Simulated latency per call, so aborts and stale responses can be exercised. */
  latencyMs?: number;
  /** Test hook: a SourceError to fail a call with, or null to answer it. */
  fault?: (method: Method) => SourceError | null;
}

function wait(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(SourceError.aborted()); };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export class FixtureSource implements DataSource {
  protected readonly now: () => number;
  private readonly live: boolean;
  private readonly tickMs: number;
  private readonly latencyMs: number;
  private readonly fault: FixtureOptions['fault'];
  protected readonly f: Fixtures;
  protected readonly h: History;
  private board_: SourceView[];

  constructor(opts: FixtureOptions = {}) {
    this.now = opts.now ?? (() => Date.now());
    this.live = opts.live ?? true;
    this.tickMs = opts.tickMs ?? 1000;
    this.latencyMs = opts.latencyMs ?? 0;
    this.fault = opts.fault;
    this.f = makeFixtures(this.now());
    this.h = makeHistory(this.f, this.now);
    this.board_ = this.f.board;
  }

  /** The common path of every call: honour the signal, simulate latency, inject faults. */
  protected async reply<T>(method: Method, call: Call, make: () => T): Promise<T> {
    if (call.signal.aborted) throw SourceError.aborted();
    if (this.latencyMs > 0) await wait(this.latencyMs, call.signal);
    const err = this.fault?.(method);
    if (err) throw err;
    return make();
  }

  session(call: Call) { return this.reply('session', call, () => this.f.session); }
  status(call: Call) { return this.reply('status', call, () => this.f.status); }
  counters(call: Call) { return this.reply('counters', call, () => this.f.counters); }
  dashboard(from: number, to: number, call: Call) { return this.reply('dashboard', call, () => this.f.dashboard(from, to)); }
  board(call: Call) { return this.reply('board', call, () => this.board_); }
  bans(call: Call) { return this.reply('bans', call, () => this.f.bans); }
  decoys(call: Call) { return this.reply('decoys', call, () => this.f.decoys); }
  request(id: string, call: Call) {
    return this.reply('request', call, () => {
      const d = this.h.detail(id);
      if (!d) throw SourceError.fromStatus(404, 'Request not found.');
      return d;
    });
  }
  history(hq: HistoryQuery, call: Call) {
    return this.reply('history', call, () => {
      if (!(hq.to > hq.from)) throw SourceError.fromStatus(400, 'The time range is empty.');
      const p = parse(hq.q);
      if (p.error) throw SourceError.fromStatus(400, p.error.msg, { pos: p.error.pos, len: p.error.len });
      return this.h.query(hq, p.terms);
    });
  }

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
