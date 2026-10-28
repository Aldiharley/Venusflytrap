import type { Perm } from './types';

/** Every way a DataSource call can fail. Screens branch on `kind`, never on message text. */
export type ErrorKind =
  | 'aborted'        // the caller's signal fired; not an error to show
  | 'network'        // no answer (offline, DNS, reset)
  | 'unauthorized'   // 401: the session ended
  | 'forbidden'      // 403: the key lacks the permission
  | 'not_found'      // 404
  | 'bad_request'    // 400: e.g. a query syntax error, with its position
  | 'conflict'       // 409: e.g. config changed since it was loaded
  | 'invalid'        // 422: per-key validation issues
  | 'server';        // 5xx

export interface ErrorDetail {
  /** 400 on a query: the offset and length of the bad token in `q`. */
  pos?: number;
  len?: number;
  /** 403: the permission the call needs. */
  need?: Perm;
}

export class SourceError extends Error {
  override readonly name = 'SourceError';

  constructor(
    readonly kind: ErrorKind,
    message: string,
    readonly status: number | null = null,
    readonly detail: ErrorDetail = {},
  ) {
    super(message);
  }

  /** Worth retrying unchanged: the failure was transient. */
  get retryable(): boolean {
    return this.kind === 'network' || this.kind === 'server';
  }

  static aborted(): SourceError {
    return new SourceError('aborted', 'The request was cancelled.');
  }

  static fromStatus(status: number, message: string, detail: ErrorDetail = {}): SourceError {
    const kind: ErrorKind =
      status === 400 ? 'bad_request'
      : status === 401 ? 'unauthorized'
      : status === 403 ? 'forbidden'
      : status === 404 ? 'not_found'
      : status === 409 ? 'conflict'
      : status === 422 ? 'invalid'
      : 'server';
    return new SourceError(kind, message, status, detail);
  }
}

/** Normalises anything a call can throw (fetch TypeError, DOM AbortError, …) into a SourceError. */
export function toSourceError(e: unknown): SourceError {
  if (e instanceof SourceError) return e;
  if (e instanceof DOMException && e.name === 'AbortError') return SourceError.aborted();
  const msg = e instanceof Error ? e.message : String(e);
  return new SourceError('network', msg || 'The service could not be reached.');
}
