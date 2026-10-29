// A TS port of crates/vft-proxy/src/ocsf.rs `encode` (OCSF 1.9.0): one HTTP Activity (4002) per
// judgment, plus a Detection Finding (2004) for Challenge and Block. Pinned to the Rust encoder by
// the shared sample (crates/vft-proxy/tests/fixtures/ocsf-sample.json), which both test suites apply.
// The "View as OCSF" view prints these records as they are.
import type { RequestDetail, Verdict } from './api/types';

export const OCSF_VERSION = '1.9.0';
/** The Cargo workspace version (Cargo.toml `workspace.package.version`), for when the status has none. */
export const PRODUCT_VERSION = '0.1.0';

// Enum values confirmed against the committed 1.9.0 schema fixtures (see ocsf.rs).
const ACTION_ALLOWED = 1;
const ACTION_DENIED = 2;
const DISPOSITION_ALLOWED = 1;
const DISPOSITION_BLOCKED = 2;
const DISPOSITION_LOGGED = 17;

/** HTTP Activity `activity_id`. Methods are case-sensitive (RFC 9110 section 9.1), so only the uppercase tokens match. */
// A Map, not an object literal: the method comes from untrusted traffic, and `ACTIVITY['constructor']`
// would find an inherited property instead of falling back to 99 as the Rust `match` does.
const ACTIVITY = new Map<string, number>([
  ['CONNECT', 1], ['DELETE', 2], ['GET', 3], ['HEAD', 4], ['OPTIONS', 5], ['POST', 6], ['PUT', 7], ['TRACE', 8], ['PATCH', 9],
]);
const activityId = (method: string) => ACTIVITY.get(method) ?? 99;

const SEVERITY = new Map<Verdict, number>([['Allow', 1], ['Monitor', 2], ['Challenge', 3], ['Block', 4]]);

const confidenceId = (c: number) => (c >= 70 ? 3 : c >= 40 ? 2 : 1);

export interface OcsfOptions {
  /** `metadata.product.version`; defaults to `PRODUCT_VERSION`. */
  version?: string;
  /** The deciding construct's one-line summary (`firewall_rule.name`). The console has no construct registry; without it the name is the construct id. */
  summary?: string | null;
}

type Rec = Record<string, unknown>;

/** The OCSF records for one request: a 4002, plus a 2004 for Challenge and Block. */
export function encodeOcsf(detail: RequestDetail, eventId: string, opts: OcsfOptions = {}): Rec[] {
  const { row, judgment: j } = detail;
  const metadata: Rec = {
    version: OCSF_VERSION,
    uid: eventId,
    profiles: ['security_control'],
    product: { name: 'Venusflytrap', vendor_name: 'Venusflytrap', version: opts.version ?? PRODUCT_VERSION },
  };
  // The row's group id exists exactly when the chain observed the request (`ip@episode_start_ms`).
  if (row.group_id !== null) metadata.correlation_uid = row.group_id;
  const msg = j.decided_by.msg;
  const base = (): Rec => ({ time: row.ts_ms, metadata: structuredClone(metadata), message: msg });

  const severity = SEVERITY.get(j.verdict);
  const stopped = j.verdict === 'Challenge' || j.verdict === 'Block';
  const activity = activityId(row.method);
  const srcEndpoint = detail.ip ? { ip: detail.ip } : null;
  const httpRequest = { http_method: row.method, url: { path: row.path } };

  const http: Rec = {
    class_uid: 4002, category_uid: 4, activity_id: activity, type_uid: 400200 + activity, severity_id: severity,
    ...base(),
  };
  if (srcEndpoint) http.src_endpoint = srcEndpoint;
  http.http_request = httpRequest;
  http.action_id = stopped ? ACTION_DENIED : ACTION_ALLOWED;
  http.disposition_id = j.verdict === 'Allow' ? DISPOSITION_ALLOWED : j.verdict === 'Monitor' ? DISPOSITION_LOGGED : DISPOSITION_BLOCKED;
  const construct = j.decided_by.construct;
  if (construct !== null) http.firewall_rule = { uid: construct, name: opts.summary ?? construct };
  const out: Rec[] = [http];

  if (stopped) {
    const attacks = j.attack.map((a) => ({
      tactic: { uid: a.tactic_id, name: a.tactic },
      technique: { uid: a.id, name: a.name },
    }));
    const f: Rec = {
      class_uid: 2004, category_uid: 2, activity_id: 1, type_uid: 200401, severity_id: severity,
      ...base(),
      is_alert: true,
      finding_info: { uid: eventId, title: msg, attacks },
      attacks,
    };
    // Detection Finding has no top-level src_endpoint; the source goes in an evidence.
    // Without one the evidence would fail its at_least_one constraint.
    if (srcEndpoint) f.evidences = [{ src_endpoint: srcEndpoint, http_request: httpRequest }];
    if (j.confidence !== null) {
      f.confidence_score = j.confidence;
      f.confidence_id = confidenceId(j.confidence);
    }
    out.push(f);
  }
  return out;
}
