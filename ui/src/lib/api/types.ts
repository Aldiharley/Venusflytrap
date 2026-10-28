// Wire types: generated from vft-core by ts-rs (cargo test -p vft-core --features ts --test ts_bindings).
// Never hand-edit ui/src/gen; this file only re-exports it and adds view types.
export type { Apply } from '../../gen/Apply';
export type { BanCause } from '../../gen/BanCause';
export type { BanRecord } from '../../gen/BanRecord';
export type { Cause } from '../../gen/Cause';
export type { CauseKind } from '../../gen/CauseKind';
export type { ChainOutcome } from '../../gen/ChainOutcome';
export type { Contribution } from '../../gen/Contribution';
export type { Expertise } from '../../gen/Expertise';
export type { Family } from '../../gen/Family';
export type { FieldRef } from '../../gen/FieldRef';
export type { FourValued } from '../../gen/FourValued';
export type { Judgment } from '../../gen/Judgment';
export type { Location } from '../../gen/Location';
export type { OptionDescriptor } from '../../gen/OptionDescriptor';
export type { OptionKind } from '../../gen/OptionKind';
export type { Source as OptionSource } from '../../gen/Source';
export type { Stage } from '../../gen/Stage';
export type { Verdict } from '../../gen/Verdict';

import type { BanCause } from '../../gen/BanCause';
import type { CauseKind } from '../../gen/CauseKind';
import type { Family } from '../../gen/Family';
import type { FieldRef } from '../../gen/FieldRef';
import type { Judgment } from '../../gen/Judgment';
import type { Source as OptionSource } from '../../gen/Source';
import type { Stage } from '../../gen/Stage';
import type { Verdict } from '../../gen/Verdict';

// View types for SP3-SP5 (UX architecture §14, gaps G1-G10). Provisional: the admin API
// that will serve them does not exist yet, so nothing in ui/src/gen covers them.
export type Perm = 'Viewer' | 'Operator' | 'Admin';
export type Health = 'Ok' | 'Warn' | 'Degraded' | 'Critical';
export type LiveState = 'Connected' | 'Reconnecting' | 'Offline';

export interface Session { perm: Perm; key_id: string; expires_ms: number } // G1
export interface StatusRecord {                                              // G3
  worst: Health;
  components: { name: string; state: Health; msg: string }[];
  drops: Record<string, number>;
  config_rev: number;
  version: string;
  restart_required: boolean;
}
/** Requests per second by verdict, in VERDICTS order. */
export interface Counters { rps_by_verdict: [number, number, number, number]; dropped_total: number }
export interface Dashboard {                                                 // G2
  from_ms: number;
  to_ms: number;
  bucket_ms: number;
  /** One count array per verdict, in VERDICTS order; all the same length. */
  requests_by_verdict: [number[], number[], number[], number[]];
  sources_by_stage: { Clean: number } & Record<Stage, number>;
  top_constructs: { id: string; family: Family; count: number }[];
  top_paths: { prefix: string; count: number; by_verdict: [number, number, number, number] }[];
  honeypot_hits: { path: string; count: number; last_ts_ms: number | null; last_src: string | null }[];
  active_bans: number;
  dropped: number;
}
/**
 * A ban as the screens show it (G8), built from the generated `BanRecord` by `banView()`.
 * `until_ms` is null for a permanent ban; `manual` is a `Manual` cause.
 */
export interface BanView { until_ms: number | null; reason: BanCause; offences: number; manual: boolean }
export interface BanEntry extends BanView { key: string; since_ms: number }
export interface SourceView {                                                // G5
  key: string;
  ip: string;
  stage: Stage | null;
  stage_path: { stage: Stage; first_ts_ms: number }[];
  /** Events per stage, in STAGES order. */
  stage_counts: [number, number, number, number];
  requests: number;
  blocked: number;
  honeypot_hits: number;
  top_constructs: string[];
  first_seen_ms: number;
  last_seen_ms: number;
  ban: BanView | null;
}
export type LiveFrame =
  | { kind: 'counters'; counters: Counters }
  | { kind: 'board'; board: SourceView[] }
  | { kind: 'state'; live: LiveState };

/** Score bands of the config revision that decided a request (G4). */
export interface Bands { monitor_at: number; challenge_at: number; block_at: number }

/** One row of `POST /api/v1/history/query` (UX §5). SP4 owns the real shape. */
export interface HistoryRow {
  id: string;
  ts_ms: number;
  verdict: Verdict;
  score: number;
  src_key: string;
  method: string;
  host: string;
  /** Path without the query string. */
  path: string;
  construct: string | null;
  stage: Stage | null;
  /** `decided_by.kind`, the G6 `cause:` field. */
  cause: CauseKind;
  /** `decided_by.option_key`. */
  decided_option: string;
  config_rev: number;
  latency_us: number;
  /** Null when the request was not forwarded. */
  upstream_status: number | null;
  /** A 1 % sample of Allows; every non-Allow is stored. */
  sampled: boolean;
}

/** The group-by chips of UX §5. */
export type GroupBy = 'src' | 'path' | 'construct' | 'stage' | 'verdict';
export const GROUP_BYS: readonly GroupBy[] = ['src', 'path', 'construct', 'stage', 'verdict'];

/** `POST /api/v1/history/query`. `from` is inclusive, `to` exclusive; both are required. */
export interface HistoryQuery {
  q: string;
  from: number;
  to: number;
  group_by?: GroupBy | null;
  /** Page size: default 100, at most 1000. */
  limit?: number;
  /** `next` from the previous page. */
  cursor?: string | null;
}
export interface HistoryPage {
  /** Newest first; empty when grouped. */
  rows: HistoryRow[];
  /** Group value and count, largest first; null when not grouped. */
  groups: { value: string; count: number }[] | null;
  /** Matches in the whole range (rows, or the sum of the groups). */
  total: number;
  /** Cursor for the next page, or null on the last one. */
  next: string | null;
}

/** `GET /api/v1/requests/{id}` (UX §6). */
export interface RequestDetail {
  row: HistoryRow;
  ip: string;
  /** Raw query string, without the leading `?`; empty when there was none. */
  query: string;
  judgment: Judgment;
  bands: Bands;
  /** The deciding option's value and where it came from, at the deciding revision. */
  setting: { key: string; value: string; source: OptionSource; rev: number };
  /** The source's ban now, if any (for "Source banned until hh:mm"). */
  ban: BanView | null;
  /** The source's most recent requests, newest first (this one included). */
  timeline: HistoryRow[];
  /** Raw and decoded field values; null when `history.store_snippets` is off. */
  fields: { field: FieldRef; raw: string; decoded: string; layers: string[] }[] | null;
}

export const VERDICTS: readonly Verdict[] = ['Allow', 'Monitor', 'Challenge', 'Block'];
export const STAGES: readonly Stage[] = ['Recon', 'Enumeration', 'Exploitation', 'Exfiltration'];
