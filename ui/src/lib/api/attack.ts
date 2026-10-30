// MITRE ATT&CK tags for constructs: a TS copy of crates/vft-core/src/attack.rs, pinned by attack.test.ts.
// The engine is the source of truth; on the wire the tags arrive on `Judgment.attack`. The fixture
// source has no engine, so it derives them here: a construct id goes to its family, and a family
// goes to its techniques, with the two id overrides of the Rust table.
import type { AttackTag } from '../../gen/AttackTag';
import type { Family } from '../../gen/Family';

const T1190: AttackTag = { tactic_id: 'TA0001', tactic: 'Initial Access', id: 'T1190', name: 'Exploit Public-Facing Application' };
const T1059: AttackTag = { tactic_id: 'TA0002', tactic: 'Execution', id: 'T1059', name: 'Command and Scripting Interpreter' };
const T1083: AttackTag = { tactic_id: 'TA0007', tactic: 'Discovery', id: 'T1083', name: 'File and Directory Discovery' };
const T1595_002: AttackTag = { tactic_id: 'TA0043', tactic: 'Reconnaissance', id: 'T1595.002', name: 'Active Scanning: Vulnerability Scanning' };
const T1595_003: AttackTag = { tactic_id: 'TA0043', tactic: 'Reconnaissance', id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' };

const BY_FAMILY: Record<Family, readonly AttackTag[]> = {
  Sqli: [T1190],
  Xss: [T1190],
  Ssrf: [T1190],
  CommandInjection: [T1190, T1059],
  PathTraversal: [T1190, T1083],
  Recon: [T1595_002],
  Honeypot: [T1595_003],
  Intel: [],
  Limit: [],
  Anomaly: [],
};

// Maps, not object literals: a construct id such as 'constructor' must not find an inherited property.

/** The overrides that beat the family (attack.rs `techniques_for`). */
const OVERRIDE = new Map<string, readonly AttackTag[]>([
  ['intel.scanner-ua', [T1595_002]],
  ['intel.deny-listed', []],
]);

/** Construct id to family: the engine registry ids the fixtures emit and the Rust tests pin. Anything else has no tags. */
const FAMILY = new Map<string, Family>(Object.entries({
  'sqli.union-select': 'Sqli',
  'sqli.boolean-tautology': 'Sqli',
  'sqli.fn-load-file': 'Sqli',
  'sqli.stacked-query': 'Sqli',
  'sqli.quote-breakout': 'Sqli',
  'sig.classic-or': 'Sqli',
  'xss.event-handler': 'Xss',
  'xss.script-tag': 'Xss',
  'xss.dangerous-proto': 'Xss',
  'cmd.chained-command': 'CommandInjection',
  'cmd.shell-meta': 'CommandInjection',
  'path.directory-traversal': 'PathTraversal',
  'sig.etc-passwd': 'PathTraversal',
  'recon.sensitive-path-probe': 'Recon',
  'honeypot.decoy-hit': 'Honeypot',
  'intel.scanner-ua': 'Intel',
  'intel.deny-listed': 'Intel',
  'limit.payload-truncated': 'Limit',
  'ai.anomaly-score': 'Anomaly',
  'api.oversized-header': 'Anomaly',
  'api.type-violation': 'Sqli', // the engine files it under Sqli (sinks/mod.rs)
} satisfies Record<string, Family>));

/** The techniques of a construct id; empty for null and for unregistered ids (such as `chain.ban`). */
export function techniquesFor(construct: string | null): AttackTag[] {
  if (construct === null) return [];
  const o = OVERRIDE.get(construct);
  if (o) return [...o];
  const fam = FAMILY.get(construct);
  return fam ? [...BY_FAMILY[fam]] : [];
}
