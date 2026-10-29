import { expect, test } from 'vitest';
import { techniquesFor } from './attack';

// Pins the same expectations as crates/vft-core/src/attack.rs.
const ids = (c: string | null) => techniquesFor(c).map((t) => t.id);

test('injection sinks map to Exploit Public-Facing Application', () => {
  for (const c of ['sqli.union-select', 'xss.script-tag', 'sig.classic-or', 'api.type-violation']) expect(ids(c), c).toEqual(['T1190']);
  expect(ids('cmd.chained-command')).toEqual(['T1190', 'T1059']);
  expect(ids('path.directory-traversal')).toEqual(['T1190', 'T1083']);
  expect(ids('sig.etc-passwd')).toEqual(['T1190', 'T1083']);
  expect(ids('cmd.shell-meta')).toEqual(['T1190', 'T1059']);
});

test('recon and deception map to Active Scanning', () => {
  expect(ids('recon.sensitive-path-probe')).toEqual(['T1595.002']);
  expect(ids('intel.scanner-ua')).toEqual(['T1595.002']);
  expect(techniquesFor('honeypot.decoy-hit')[0].id).toBe('T1595.003');
});

test('limits, anomaly, deny-list, unregistered ids and null have no tags', () => {
  for (const c of ['limit.payload-truncated', 'ai.anomaly-score', 'api.oversized-header', 'intel.deny-listed', 'chain.ban', 'nope.nope', 'sqli.inline-comment', 'xss.svg-onload', 'path.double-dot-encoded', null]) {
    expect(ids(c), String(c)).toEqual([]);
  }
});

test('a tag carries its tactic and the full technique name', () => {
  expect(techniquesFor('honeypot.decoy-hit')[0]).toEqual({ tactic_id: 'TA0043', tactic: 'Reconnaissance', id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' });
  expect(techniquesFor('cmd.chained-command')[1]).toEqual({ tactic_id: 'TA0002', tactic: 'Execution', id: 'T1059', name: 'Command and Scripting Interpreter' });
});
