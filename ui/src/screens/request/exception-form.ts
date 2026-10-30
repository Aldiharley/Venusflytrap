// The "Create exception" form of Request details as pure functions: the pre-fill from one request, the
// text-to-entry parsing, and which input each validation issue belongs to.
import type { ExceptionEntry, FieldLoc, RequestDetail } from '../../lib/api/types';
import { REQUEST_LEVEL, formatDate, type Issue } from '../../lib/exceptions';

const DAY_MS = 86_400_000;
export const DEFAULT_LIFETIME_DAYS = 30;

/** `<family>-<last path segment>`, lowercased, anything outside `[a-z0-9-]` replaced by `-`, at most 64 chars. */
export function suggestId(construct: string | null, path: string): string {
  if (construct === null) return 'exception';
  const segment = path.split('/').filter((s) => s !== '').at(-1);
  const raw = segment === undefined ? construct.split('.')[0] : `${construct.split('.')[0]}-${segment}`;
  return raw.toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 64);
}

/**
 * A log-only exception for what decided this request, scoped to its method, path and field, expiring in 30 days.
 * A request-level construct (recon, honeypot, scanner user agent) gets no field: only field-less exceptions reach it.
 */
export function prefillException(d: RequestDetail, nowMs: number): ExceptionEntry {
  const { construct } = d.judgment.decided_by;
  const field = construct !== null && REQUEST_LEVEL.includes(construct) ? null : d.judgment.decided_by.field;
  const today = formatDate(nowMs);
  return {
    id: suggestId(construct, d.row.path),
    action: 'log-only',
    constructs: construct === null ? [] : [construct],
    scope: {
      methods: [d.row.method],
      path_prefix: d.row.path,
      field: field === null ? null : { loc: field.loc.toLowerCase() as FieldLoc, name: field.name },
    },
    owner: '',
    reason: '',
    created: today,
    modified: today,
    expires: formatDate(nowMs + DEFAULT_LIFETIME_DAYS * DAY_MS),
  };
}

/** Comma- or space-separated text as a list, empties dropped. */
export const splitList = (s: string): string[] => s.split(/[\s,]+/).filter((x) => x !== '');

/** The inputs an issue can sit next to; anything else shows above the output. */
export type Slot = 'id' | 'constructs' | 'methods' | 'path' | 'field' | 'owner' | 'reason' | 'expires' | 'form';

export function slotOf(i: Issue): Slot {
  switch (i.code) {
    case 'id-format': return 'id';
    case 'required': return i.msg.startsWith('owner') ? 'owner' : 'reason';
    case 'expires-order': case 'expires-too-far': case 'expired': return 'expires';
    case 'date': return i.msg.startsWith('expires') ? 'expires' : 'form';
    case 'method': return 'methods';
    case 'path-prefix': return 'path';
    case 'field-name': case 'skip-needs-field': case 'skip-wildcard': case 'field-unreachable': return 'field';
    case 'constructs-missing': case 'constructs-on-skip': case 'unknown-construct': case 'forbidden-target':
    case 'not-a-detection': case 'empty-wildcard': return 'constructs';
    default: return 'form';
  }
}
