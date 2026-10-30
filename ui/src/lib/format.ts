const nf = new Intl.NumberFormat('en-US');

export function fmtRps(n: number): string {
  if (n <= 0) return '0/s';
  if (n < 0.05) return '< 0.1/s'; // live but tiny must not read as zero
  if (n < 10) return `${n.toFixed(1)}/s`;
  return `${Math.round(n)}/s`;
}

export function fmtCount(n: number): string {
  return nf.format(Math.round(n));
}

export function fmtClock(ms: number): string {
  return new Date(ms).toLocaleTimeString('en-GB', { hour12: false });
}

const DAY = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short' });

/** A row timestamp: the clock time, with the day when the range spans more than a day. */
export function fmtStamp(ms: number, withDate: boolean): string {
  return withDate ? `${DAY.format(ms)} ${fmtClock(ms)}` : fmtClock(ms);
}

export function fmtAgo(ms: number): string {
  if (ms < 60_000) return `${Math.max(0, Math.floor(ms / 1000))} s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)} min ago`;
  return `${Math.floor(ms / 3_600_000)} h ago`;
}

/** Ban badge text. Minute granularity, so screen readers hear it change at most once a minute. */
export function banText(ban: { until_ms: number | null }, now: number): string {
  if (ban.until_ms === null) return 'Banned · Permanent';
  const left = ban.until_ms - now;
  if (left <= 0) return 'Ban expired';
  const min = Math.floor(left / 60_000);
  if (min < 1) return 'Banned · < 1 min left';
  if (min < 60) return `Banned · ${min} min left`;
  return `Banned · ${Math.floor(min / 60)} h ${min % 60} min left`;
}

const DAY_MS = 86_400_000;

/**
 * An exception's expiry as whole days from `now`: "in 12 days" while live (a started day counts, so it
 * never reads "in 0 days"), "expired 3 days ago" after. The engine stops selecting at now >= expires.
 */
export function fmtExpiry(expiresMs: number, now: number): string {
  const plural = (n: number) => `${n} ${n === 1 ? 'day' : 'days'}`;
  if (expiresMs > now) return `in ${plural(Math.ceil((expiresMs - now) / DAY_MS))}`;
  const ago = Math.floor((now - expiresMs) / DAY_MS);
  return ago === 0 ? 'expired today' : `expired ${plural(ago)} ago`;
}
