import type { DataSource } from '../api/source';
import type { Counters, LiveFrame, LiveState, Session, SourceView, StatusRecord } from '../api/types';

/** Live data is stale after 20 s without a frame (15 s heartbeat + 5 s grace, UX §1). */
const STALE_MS = 20_000;

class AppState {
  src: DataSource | null = null;
  session = $state<Session | null>(null);
  status = $state<StatusRecord | null>(null);
  counters = $state<Counters | null>(null);
  board = $state<SourceView[]>([]);
  prevBoard: SourceView[] = [];
  boardAt = 0;
  prevBoardAt = 0;
  live = $state<LiveState>('Offline');
  lastFrameAt = $state(0);
  now = $state(Date.now());
  stale = $derived(this.live !== 'Connected' || this.now - this.lastFrameAt > STALE_MS);
  /** The one live label every screen shows: the real LiveState, or 'Stale' when connected but silent for 20 s. */
  liveLabel = $derived<LiveState | 'Stale'>(
    this.live === 'Connected' && this.now - this.lastFrameAt > STALE_MS ? 'Stale' : this.live,
  );
  private stops: (() => void)[] = [];
  /** Bumped by stop(); a start() that finds it changed after its await was stopped or superseded. */
  private gen = 0;

  async start(src: DataSource) {
    this.stop(); // a second start supersedes the first
    const gen = this.gen;
    this.src = src;
    const [session, status, counters, board] = await Promise.all([
      src.session(), src.status(), src.counters(), src.board(),
    ]);
    if (gen !== this.gen) return; // stopped or superseded while loading: register nothing
    this.session = session;
    this.status = status;
    this.counters = counters;
    this.board = board;
    this.boardAt = Date.now();
    this.live = 'Connected';
    this.lastFrameAt = Date.now();
    this.stops.push(src.subscribe((f) => this.onFrame(f)));
    const clock = setInterval(() => (this.now = Date.now()), 1000);
    this.stops.push(() => clearInterval(clock));
  }

  stop() {
    this.gen++;
    for (const s of this.stops.splice(0)) s();
  }

  private onFrame(f: LiveFrame) {
    this.lastFrameAt = Date.now();
    if (f.kind === 'counters') this.counters = f.counters;
    else if (f.kind === 'board') {
      this.prevBoard = this.board;
      this.prevBoardAt = this.boardAt;
      this.board = f.board;
      this.boardAt = Date.now();
    } else this.live = f.live;
  }
}

export const app = new AppState();
