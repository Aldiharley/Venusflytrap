import { toSourceError, type SourceError } from './errors';
import type { Call } from './source';

export type Outcome<T> = { ok: true; value: T } | { ok: false; error: SourceError };

/**
 * Keeps only the newest of a screen's calls. Each `run` aborts the previous call's signal;
 * a call that was superseded, or stopped by `abort()`, resolves to null, so a slow stale
 * response can never overwrite a fresh one. Aborts are never reported as errors.
 */
export class Latest {
  private ctl: AbortController | null = null;

  async run<T>(fn: (call: Call) => Promise<T>): Promise<Outcome<T> | null> {
    this.ctl?.abort();
    const ctl = new AbortController();
    this.ctl = ctl;
    const current = () => this.ctl === ctl && !ctl.signal.aborted;
    try {
      const value = await fn({ signal: ctl.signal });
      return current() ? { ok: true, value } : null;
    } catch (e) {
      const error = toSourceError(e);
      return current() && error.kind !== 'aborted' ? { ok: false, error } : null;
    }
  }

  /** Stops the call in flight (on destroy, or before navigating away). */
  abort() {
    this.ctl?.abort();
    this.ctl = null;
  }
}
