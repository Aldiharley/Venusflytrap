// A TS port of crates/vft-proxy/src/ocsf.rs `encode` (OCSF 1.9.0): one HTTP Activity (4002) per
// judgment, plus a Detection Finding (2004) for Challenge and Block. Pinned to the Rust encoder by
// the shared sample (crates/vft-proxy/tests/fixtures/ocsf-sample.json), which both test suites apply.
// The "View as OCSF" view prints these records as they are.
import type { AttackTag } from '../gen/AttackTag';
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
  /** The deciding construct's one-line summary (`firewall_rule.name`). The console has no construct registry; without it the rule has no name, as Rust omits it for an unregistered construct such as `chain.ban`. */
  summary?: string | null;
  /** Whether Challenge and Block were enforced; false under `serve --monitor-only`, where every request is forwarded. Defaults to true. */
  enforced?: boolean;
}

/**
 * The 4002 action and disposition. Enforcement only changes Challenge and Block: unenforced they are
 * forwarded, so they take Monitor's Allowed/Logged. Allow and Monitor are the same in both modes.
 */
function actionDisposition(v: Verdict, enforced: boolean): [number, number] {
  if (v === 'Allow') return [ACTION_ALLOWED, DISPOSITION_ALLOWED];
  if (v === 'Monitor' || !enforced) return [ACTION_ALLOWED, DISPOSITION_LOGGED];
  return [ACTION_DENIED, DISPOSITION_BLOCKED];
}

/** One OCSF `attack` object: a sub-technique id (`T1595.002`) goes in `sub_technique`, its parent in `technique`; the combined name is split on `": "`. */
function attackObject(a: AttackTag): Rec {
  const tactic = { uid: a.tactic_id, name: a.tactic };
  const dot = a.id.indexOf('.');
  if (dot < 0) return { tactic, technique: { uid: a.id, name: a.name } };
  const sep = a.name.indexOf(': ');
  const [technique, sub] = sep < 0 ? [a.name, a.name] : [a.name.slice(0, sep), a.name.slice(sep + 2)];
  return { tactic, technique: { uid: a.id.slice(0, dot), name: technique }, sub_technique: { uid: a.id, name: sub } };
}

type Rec = Record<string, unknown>;

/**
 * The OCSF records for one request: a 4002, plus a 2004 for Challenge and Block. Only the 4002 has
 * `metadata.uid`; the 2004 links to it through `finding_info.uid`. Unenforced, the 2004 is still
 * written for Challenge and Block (the detection happened).
 */
export function encodeOcsf(detail: RequestDetail, eventId: string, opts: OcsfOptions = {}): Rec[] {
  const { row, judgment: j } = detail;
  const metadata = (uid: string | null): Rec => {
    const m: Rec = { version: OCSF_VERSION };
    if (uid !== null) m.uid = uid;
    m.profiles = ['security_control'];
    m.product = { name: 'Venusflytrap', vendor_name: 'Venusflytrap', version: opts.version ?? PRODUCT_VERSION };
    // The row's group id exists exactly when the chain observed the request (`key@episode_start_ms`).
    if (row.group_id !== null) m.correlation_uid = row.group_id;
    return m;
  };
  const msg = j.decided_by.msg;
  const base = (uid: string | null): Rec => ({ time: row.ts_ms, metadata: metadata(uid), message: msg });

  const severity = SEVERITY.get(j.verdict);
  const detected = j.verdict === 'Challenge' || j.verdict === 'Block';
  const activity = activityId(row.method);
  const srcEndpoint = detail.ip ? { ip: detail.ip } : null;
  const httpRequest = { http_method: row.method, url: { path: row.path } };

  const http: Rec = {
    class_uid: 4002, category_uid: 4, activity_id: activity, type_uid: 400200 + activity, severity_id: severity,
    ...base(eventId),
  };
  if (srcEndpoint) http.src_endpoint = srcEndpoint;
  http.http_request = httpRequest;
  [http.action_id, http.disposition_id] = actionDisposition(j.verdict, opts.enforced ?? true);
  const construct = j.decided_by.construct;
  // As in Rust: a known summary is the name, even an empty one; no summary, no name.
  const summary = opts.summary ?? null;
  if (construct !== null) http.firewall_rule = summary !== null ? { uid: construct, name: summary } : { uid: construct };
  const out: Rec[] = [http];

  if (detected) {
    const attacks = j.attack.map(attackObject);
    const f: Rec = {
      class_uid: 2004, category_uid: 2, activity_id: 1, type_uid: 200401, severity_id: severity,
      ...base(null),
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
