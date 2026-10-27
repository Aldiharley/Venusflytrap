// Wire types mirrored from the SP2 plan (vft-core). Replace with re-exports from
// ui/src/gen once SP2 Task 9 lands.
export type Verdict = 'Allow' | 'Monitor' | 'Challenge' | 'Block';
export type Stage = 'Recon' | 'Enumeration' | 'Exploitation' | 'Exfiltration';
export type FourValued = 'None' | 'Safe' | 'Suspicious' | 'Dangerous';
export type Location = 'Path' | 'Query' | 'Header' | 'Cookie' | 'Body';
export type Family =
  | 'Sqli' | 'Xss' | 'CommandInjection' | 'PathTraversal' | 'Recon' | 'Ssrf'
  | 'Honeypot' | 'Intel' | 'Limit' | 'Anomaly';
export type CauseKind =
  | 'NoEvidence' | 'Detection' | 'Honeypot' | 'IntelDeny' | 'Ban'
  | 'ChainEscalation' | 'Limit' | 'Allowlisted';
export type BanCause = 'Honeypot' | 'Exfiltration' | 'RepeatedExploitation' | 'Manual';

export interface FieldRef { loc: Location; name: string }
export interface Contribution {
  engine: string; field: FieldRef | null; construct: string | null; family: Family | null;
  value: FourValued; weight: number; points: number;
}
export interface Cause {
  kind: CauseKind; option_key: string; construct: string | null; field: FieldRef | null; msg: string;
}

// View types for SP3-SP5 (UX architecture §14, gaps G1-G10). Provisional.
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
export interface BanView { until_ms: number | null; reason: BanCause; offences: number; manual: boolean } // G8
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

export const VERDICTS: readonly Verdict[] = ['Allow', 'Monitor', 'Challenge', 'Block'];
export const STAGES: readonly Stage[] = ['Recon', 'Enumeration', 'Exploitation', 'Exfiltration'];
