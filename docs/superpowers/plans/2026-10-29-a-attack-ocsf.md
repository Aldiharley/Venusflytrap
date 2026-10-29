# A — ATT&CK tags, measured confidence, IDs, native OCSF: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every judgment carries ATT&CK tags, a confidence measured on dev, an event ID and an episode group ID; the proxy can write OCSF 1.9.0; the console shows all of it. No detection changes.

**Architecture:** Tags and confidence are static metadata in `vft-core`, looked up from the construct in `decided_by` and filled in one place. The chain tracker records each source's episode start. The proxy mints UUIDv7 event IDs, adds the fields to its JSONL audit and, with `serve --ocsf <path>`, writes OCSF records through a second sink. The console gets the new wire types, fixtures and screen changes.

**Tech Stack:** Rust (vft-core, vft-proxy, vft-cli, serde, ts-rs behind the `ts` feature), Python 3 (eval scripts, unittest), Svelte 5 + Vite + Vitest + Playwright (ui/).

**Spec:** `docs/superpowers/specs/2026-10-29-attack-ocsf-design.md`.

## Global Constraints

- No detection change: score, verdict, contributions and every eval number stay identical; the dev A/B must show ΔTP = ΔFP = 0 and zero changed verdicts.
- `#![forbid(unsafe_code)]` stays in every crate; `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` stay green.
- No new Rust crate dependencies (UUIDv7 and randomness are built from std).
- No outside product names in code, UI or docs beyond the public standards MITRE ATT&CK and OCSF.
- OCSF target version string: `"1.9.0"`.
- Confidence = ⌊100 × Wilson 95 % lower bound (z = 1.96) of TP / (TP + FP)⌋ over dev Challenge/Block rows decided by that construct; fewer than 5 such rows → no entry. Confidence never affects score or verdict.
- Group ID string: `"{key}@{episode_start_ms}"`, where `{key}` is the chain source key's address (`SourceKey::ip`: IPv4-mapped folded to IPv4, IPv6 masked to `chain.ipv6_prefix`), not the raw client IP; a new episode starts when the source was idle for more than the chain window (`chain.window_secs`, 3,600 s by default) or never seen.
- Console: existing tokens, fonts and components only; both themes; axe clean; initial JS ≤ 150 KB gz; `ui/vitest.junction.config.ts` style local configs are never committed.
- Tune on dev only; held-out is not touched by this sub-project.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Environment (all tasks)

- Worktree: `M:\Projects\venusflytrap\.claude\worktrees\sp-a`, branch `a-attack-ocsf`. Run every command from there.
- Corpus: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\C--Users-Dennis-Liu--claude-spares-spare-LkQ6gu\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\ext\blazehttp\testcases`
- Split manifest: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\split\manifest.tsv`
- Main baseline binary: `C:\Users\DENNIS~1\AppData\Local\Temp\claude\M--Projects-venusflytrap\da1b01dd-cef6-4b76-bba8-0e55e99fd9e4\scratchpad\dq5\bin\fix12b.exe` (identical detection to main `ed2a953`).
- Python: `py -I -X utf8`.
- UI: `ui/node_modules` may need `npm install` in `ui/` (do not bypass the npm-install hook).

## File map

| File | Responsibility |
|---|---|
| `crates/vft-core/src/attack.rs` (new) | `Technique`, `AttackTag`, the family/id → techniques mapping |
| `crates/vft-core/src/confidence.rs` (new, generated) | sorted `(construct, confidence)` table + lookup |
| `eval/confidence.py`, `eval/test_confidence.py`, `eval/fixtures/confidence_sample.csv` (new) | generator and its tests |
| `crates/vft-core/src/judgment.rs` | `attack`, `confidence` fields, `Judgment::annotate` |
| `crates/vft-core/src/shield.rs` | call `annotate` where judgments are built |
| `crates/vft-core/src/chain.rs` | `episode_start_ms`, `group_id()` |
| `crates/vft-core/tests/ts_bindings.rs`, `ui/src/gen/*` | wire types |
| `crates/vft-proxy/src/ids.rs` (new) | UUIDv7 event IDs |
| `crates/vft-proxy/src/audit.rs` | JSONL additions; format-generic sink |
| `crates/vft-proxy/src/ocsf.rs` (new) + `tests/fixtures/ocsf-1.9.0-*.json` | OCSF encoder and schema fixtures |
| `crates/vft-proxy/src/lib.rs`, `crates/vft-cli/src/main.rs` | wiring, `--ocsf` flag |
| `ui/src/lib/api/*`, `ui/src/screens/Monitor.svelte`, `ui/src/screens/RequestDetails.svelte`, `ui/src/lib/ocsf.ts` (new), `ui/src/lib/components/AttackChip.svelte` (new) | console |
| `eval/RESULTS-A-attack-ocsf.md`, `docs/BENCHMARK.md` | results note and status line |

---

### Task 1: ATT&CK mapping in the core

**Files:**
- Create: `crates/vft-core/src/attack.rs`
- Modify: `crates/vft-core/src/lib.rs` (add `pub mod attack;` and re-export `AttackTag`)

**Interfaces:**
- Produces: `pub struct Technique { pub tactic_id: &'static str, pub tactic: &'static str, pub id: &'static str, pub name: &'static str }`; `pub struct AttackTag { pub tactic_id: String, pub tactic: String, pub id: String, pub name: String }` (Serialize, Deserialize, Clone, Debug, PartialEq, `#[cfg_attr(feature = "ts", derive(ts_rs::TS))]`); `pub fn techniques_for(construct_id: &str) -> &'static [Technique]`; `pub fn tags_for(construct_id: &str) -> Vec<AttackTag>`.

- [ ] **Step 1: Write the failing tests** at the bottom of `attack.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::sinks::{constructs, ConstructKind};

    fn ids(c: &str) -> Vec<&'static str> {
        techniques_for(c).iter().map(|t| t.id).collect()
    }

    #[test]
    fn injection_sinks_map_to_exploit_public_facing_application() {
        for c in ["sqli.union-select", "xss.script-tag", "sig.classic-or", "api.type-violation"] {
            assert_eq!(ids(c), vec!["T1190"], "{c}");
        }
        assert_eq!(ids("cmd.chained-command"), vec!["T1190", "T1059"]);
        assert_eq!(ids("path.directory-traversal"), vec!["T1190", "T1083"]);
        assert_eq!(ids("sig.etc-passwd"), vec!["T1190", "T1083"]);
        // Latents carry their family's tags.
        assert_eq!(ids("cmd.shell-meta"), vec!["T1190", "T1059"]);
    }

    #[test]
    fn recon_and_deception_map_to_active_scanning() {
        assert_eq!(ids("recon.sensitive-path-probe"), vec!["T1595.002"]);
        assert_eq!(ids("intel.scanner-ua"), vec!["T1595.002"]);
        assert_eq!(ids("honeypot.decoy-hit"), vec!["T1595.003"]);
    }

    #[test]
    fn limits_anomaly_and_unregistered_ids_have_no_tags() {
        for c in ["limit.payload-truncated", "ai.anomaly-score", "api.oversized-header", "intel.deny-listed", "chain.ban", "nope.nope"] {
            assert!(ids(c).is_empty(), "{c}");
        }
    }

    #[test]
    fn every_evidence_construct_is_mapped_on_purpose() {
        // Decoders and gates emit no evidence; every other construct goes through
        // the exhaustive family match in `techniques_for`, so a new family cannot
        // compile untagged. This pins the families that must have tags.
        for c in constructs() {
            if matches!(c.kind, ConstructKind::Decoder | ConstructKind::Gate) {
                continue;
            }
            let fam = c.family.expect("evidence constructs have a family");
            let tagged = !techniques_for(c.id).is_empty();
            let must = matches!(fam, crate::Family::Sqli | crate::Family::Xss | crate::Family::CommandInjection | crate::Family::PathTraversal | crate::Family::Recon | crate::Family::Honeypot);
            if must {
                assert!(tagged, "{} has no ATT&CK tag", c.id);
            }
        }
    }

    #[test]
    fn tags_are_owned_copies() {
        let t = tags_for("honeypot.decoy-hit");
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].tactic_id.as_str(), t[0].id.as_str()), ("TA0043", "T1595.003"));
    }
}
```

- [ ] **Step 2: Run** `cargo test -p vft-core attack::` — expected: FAIL (module does not exist).

- [ ] **Step 3: Implement** `attack.rs`:

```rust
//! MITRE ATT&CK tags for constructs (sub-project A). Static and reviewed in code:
//! a family maps to its techniques through an exhaustive match, so a new family
//! does not compile until it is tagged; a few ids override their family.

use serde::{Deserialize, Serialize};

use crate::graph::sinks::lookup;
use crate::judgment::Family;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Technique {
    pub tactic_id: &'static str,
    pub tactic: &'static str,
    pub id: &'static str,
    pub name: &'static str,
}

/// A technique as carried on a judgment and in audit and OCSF records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct AttackTag {
    pub tactic_id: String,
    pub tactic: String,
    pub id: String,
    pub name: String,
}

const T1190: Technique = Technique { tactic_id: "TA0001", tactic: "Initial Access", id: "T1190", name: "Exploit Public-Facing Application" };
const T1059: Technique = Technique { tactic_id: "TA0002", tactic: "Execution", id: "T1059", name: "Command and Scripting Interpreter" };
const T1083: Technique = Technique { tactic_id: "TA0007", tactic: "Discovery", id: "T1083", name: "File and Directory Discovery" };
const T1595_002: Technique = Technique { tactic_id: "TA0043", tactic: "Reconnaissance", id: "T1595.002", name: "Active Scanning: Vulnerability Scanning" };
const T1595_003: Technique = Technique { tactic_id: "TA0043", tactic: "Reconnaissance", id: "T1595.003", name: "Active Scanning: Wordlist Scanning" };

static INJECTION: &[Technique] = &[T1190];
static COMMAND: &[Technique] = &[T1190, T1059];
static PATH: &[Technique] = &[T1190, T1083];
static SCANNING: &[Technique] = &[T1595_002];
static WORDLIST: &[Technique] = &[T1595_003];
static NONE: &[Technique] = &[];

/// The techniques of a construct id; empty for unregistered ids (such as
/// `chain.ban`), decoders, gates, limits and anomaly signals.
pub fn techniques_for(construct_id: &str) -> &'static [Technique] {
    match construct_id {
        "intel.scanner-ua" => return SCANNING,
        "intel.deny-listed" => return NONE,
        _ => {}
    }
    let Some(fam) = lookup(construct_id).and_then(|c| c.family) else {
        return NONE;
    };
    match fam {
        Family::Sqli | Family::Xss | Family::Ssrf => INJECTION,
        Family::CommandInjection => COMMAND,
        Family::PathTraversal => PATH,
        Family::Recon => SCANNING,
        Family::Honeypot => WORDLIST,
        Family::Intel | Family::Limit | Family::Anomaly => NONE,
    }
}

pub fn tags_for(construct_id: &str) -> Vec<AttackTag> {
    techniques_for(construct_id)
        .iter()
        .map(|t| AttackTag { tactic_id: t.tactic_id.into(), tactic: t.tactic.into(), id: t.id.into(), name: t.name.into() })
        .collect()
}
```

Check `api.oversized-header` has family `Anomaly` (it does in `sinks/mod.rs`), so it maps to none; `api.type-violation` is `Sqli`, so it maps to T1190.

- [ ] **Step 4: Run** `cargo test -p vft-core attack::` — expected: PASS (5 tests).
- [ ] **Step 5: Commit** `feat(core): ATT&CK tags for constructs`.

---

### Task 2: Measured confidence table and its generator

**Files:**
- Create: `eval/confidence.py`, `eval/test_confidence.py`, `eval/fixtures/confidence_sample.csv`
- Create (generated): `crates/vft-core/src/confidence.rs`, `ui/src/lib/api/confidence.ts`
- Modify: `crates/vft-core/src/lib.rs` (`pub mod confidence;`)

**Interfaces:**
- Produces: `vft_core::confidence::confidence(construct_id: &str) -> Option<u8>`; `vft_core::confidence::TABLE: &[(&str, u8)]` (sorted by id); TS `export const CONFIDENCE: Record<string, number>` and `export function confidenceOf(id: string | null): number | null` in `ui/src/lib/api/confidence.ts`.
- Script CLI: `py -I -X utf8 eval/confidence.py <dev library CSV> --manifest <manifest.tsv> --rust <out.rs> --ts <out.ts>`.

- [ ] **Step 1: Fixture** `eval/fixtures/confidence_sample.csv` (eval CSV header, only the columns the script reads must be correct; keep the full header):

```
rel,label,lib_verdict,serve_verdict,score,banned,constructs,cause,field,top,shadow,top_field
a.black,1,Block,,100,false,,Detection:scoring.block_at,,sqli.union-select,,query:id
b.black,1,Block,,100,false,,Detection:scoring.block_at,,sqli.union-select,,query:id
c.black,1,Block,,100,false,,Detection:scoring.block_at,,sqli.union-select,,query:id
d.black,1,Challenge,,75,false,,Detection:scoring.challenge_at,,sqli.union-select,,query:id
e.white,0,Block,,100,false,,Detection:scoring.block_at,,sqli.union-select,,header:referer
f.black,1,Block,,100,false,,Detection:scoring.block_at,,xss.script-tag,,query:q
g.black,1,Allow,,0,false,,NoEvidence:scoring.monitor_at,,,,
h.white,0,Monitor,,45,false,,Detection:scoring.monitor_at,,cmd.shell-meta,,header:user-agent
```

- [ ] **Step 2: Failing test** `eval/test_confidence.py`:

```python
import os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(__file__))
import confidence as c

HERE = os.path.dirname(__file__)

class T(unittest.TestCase):
    def test_wilson_lower_bound(self):
        self.assertEqual(c.wilson_lower(0, 0), 0.0)
        self.assertAlmostEqual(c.wilson_lower(4, 5), 0.3755, places=3)
        self.assertAlmostEqual(c.wilson_lower(100, 100), 0.963, places=3)

    def test_counts_only_challenge_and_block_rows(self):
        rows = c.read_rows(os.path.join(HERE, 'fixtures', 'confidence_sample.csv'))
        counts = c.count(rows)
        self.assertEqual(counts, {'sqli.union-select': (4, 1), 'xss.script-tag': (1, 0)})

    def test_table_drops_constructs_below_five_rows(self):
        table = c.table({'sqli.union-select': (4, 1), 'xss.script-tag': (1, 0)}, min_rows=5)
        self.assertEqual(table, [('sqli.union-select', 37)])

    def test_rust_and_ts_outputs(self):
        rs = c.render_rust([('a.b', 9), ('c.d', 80)], 'src.csv', 'abc123', '2026-10-29')
        self.assertIn('("a.b", 9),', rs)
        self.assertIn('pub static TABLE', rs)
        ts = c.render_ts([('a.b', 9)], 'src.csv', 'abc123', '2026-10-29')
        self.assertIn("'a.b': 9,", ts)

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 3: Run** `py -I -X utf8 -m unittest eval/test_confidence.py` from `eval/` — expected: FAIL (no module).

- [ ] **Step 4: Implement** `eval/confidence.py`:

```python
"""Measured confidence per deciding construct (sub-project A).

For every construct in the `top` column of Challenge/Block rows of a dev library
CSV: confidence = floor(100 * Wilson 95 % lower bound of TP / (TP + FP)).
Constructs that decide fewer than --min-rows rows get no entry.
Writes a Rust table (vft-core) and a TS table (console fixtures).

Usage: py -I -X utf8 eval/confidence.py <dev.csv> --manifest <manifest.tsv>
       --rust crates/vft-core/src/confidence.rs --ts ui/src/lib/api/confidence.ts
"""
import argparse, csv, datetime, hashlib, math, os

Z = 1.96

def wilson_lower(k, n):
    if n == 0:
        return 0.0
    p = k / n
    den = 1 + Z * Z / n
    centre = p + Z * Z / (2 * n)
    margin = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
    return max(0.0, (centre - margin) / den)

def read_rows(path):
    with open(path, encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def count(rows):
    out = {}
    for r in rows:
        if r['lib_verdict'] not in ('Challenge', 'Block') or not r['top']:
            continue
        tp, fp = out.get(r['top'], (0, 0))
        out[r['top']] = (tp + 1, fp) if r['label'] == '1' else (tp, fp + 1)
    return out

def table(counts, min_rows=5):
    rows = []
    for k in sorted(counts):
        tp, fp = counts[k]
        if tp + fp >= min_rows:
            rows.append((k, max(1, math.floor(100 * wilson_lower(tp, tp + fp)))))
    return rows

def _header(src, manifest_sha, date):
    return f"Generated by eval/confidence.py from {src} (manifest sha256 {manifest_sha[:16]}, {date}). Do not edit."

def render_rust(rows, src, manifest_sha, date):
    body = ''.join(f'    ("{k}", {v}),\n' for k, v in rows)
    return (f"//! Measured confidence per deciding construct: floor(100 x Wilson 95 % lower bound\n"
            f"//! of dev precision). {_header(src, manifest_sha, date)}\n\n"
            f"/// Sorted by construct id.\npub static TABLE: &[(&str, u8)] = &[\n{body}];\n\n"
            "/// The measured confidence of a construct, if it decided enough dev rows.\n"
            "pub fn confidence(construct_id: &str) -> Option<u8> {\n"
            "    TABLE.binary_search_by(|(k, _)| (*k).cmp(construct_id)).ok().map(|i| TABLE[i].1)\n}\n")

def render_ts(rows, src, manifest_sha, date):
    body = ''.join(f"  '{k}': {v},\n" for k, v in rows)
    return (f"// {_header(src, manifest_sha, date)}\n"
            f"export const CONFIDENCE: Record<string, number> = {{\n{body}}};\n\n"
            "export function confidenceOf(id: string | null): number | null {\n"
            "  return id !== null && id in CONFIDENCE ? CONFIDENCE[id] : null;\n}\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv'); ap.add_argument('--manifest', required=True)
    ap.add_argument('--rust', required=True); ap.add_argument('--ts', required=True)
    ap.add_argument('--min-rows', type=int, default=5)
    a = ap.parse_args()
    sha = hashlib.sha256(open(a.manifest, 'rb').read()).hexdigest()
    rows = table(count(read_rows(a.csv)), a.min_rows)
    date = datetime.date.today().isoformat()
    src = os.path.basename(a.csv)
    for path, text in ((a.rust, render_rust(rows, src, sha, date)), (a.ts, render_ts(rows, src, sha, date))):
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
    print(f'{len(rows)} constructs')

if __name__ == '__main__':
    main()
```

- [ ] **Step 5: Run** the unit test again — expected: PASS (4 tests).
- [ ] **Step 6: Generate the real table.** Build `cargo build --release -p vft-cli`, run a dev library eval with the branch binary, then the script:

```bash
target/release/venusflytrap.exe eval --corpus "$CORPUS" --mode library --manifest "$MANIFEST" --side dev --out "$SCRATCH/a-dev.csv" > "$SCRATCH/a-dev.json"
py -I -X utf8 eval/confidence.py "$SCRATCH/a-dev.csv" --manifest "$MANIFEST" --rust crates/vft-core/src/confidence.rs --ts ui/src/lib/api/confidence.ts
```

(`$SCRATCH` = the session scratchpad `...\scratchpad\a`.) Record the TP/FP totals from the JSON in the task report.

- [ ] **Step 7: Rust test** appended to the generated file is not allowed (it is regenerated). Instead add to `crates/vft-core/src/attack.rs`'s test module neighbour — create `crates/vft-core/tests/confidence_table.rs`:

```rust
use vft_core::confidence::{confidence, TABLE};
use vft_core::graph::sinks::lookup;

#[test]
fn table_is_sorted_unique_in_range_and_registered() {
    for w in TABLE.windows(2) {
        assert!(w[0].0 < w[1].0, "not sorted/unique at {}", w[1].0);
    }
    for (id, v) in TABLE {
        assert!((1..=100).contains(v), "{id}: {v}");
        assert!(lookup(id).is_some(), "{id} is not a registered construct");
        assert_eq!(confidence(id), Some(*v));
    }
    assert_eq!(confidence("nope.nope"), None);
}
```

(If `graph::sinks` is not public from the crate root, use the existing public path the other integration tests use; check `crates/vft-core/tests/points.rs` imports.)

- [ ] **Step 8: Run** `cargo test -p vft-core --test confidence_table` — PASS.
- [ ] **Step 9: Commit** `feat(core): confidence measured on dev, with its generator`.

---

### Task 3: Judgment carries tags and confidence

**Files:**
- Modify: `crates/vft-core/src/judgment.rs` (fields + `annotate`), `crates/vft-core/src/shield.rs` (call sites at the end of `inspect`'s judgment build ~L326, `finalize` ~L387, `banned_judgment` ~L434), `crates/vft-core/src/chain.rs` test helper `judgment()` ~L315 if it builds a `Judgment` literal, `crates/vft-core/tests/ts_bindings.rs` (add `check::<AttackTag>`), `ui/src/gen/*` (blessed).

**Interfaces:**
- Consumes: `attack::tags_for`, `confidence::confidence`.
- Produces: `Judgment { …, pub attack: Vec<AttackTag>, pub confidence: Option<u8> }` and `pub fn annotate(mut self) -> Self` (fills both from `decided_by.construct`, clears them when it is `None`).

- [ ] **Step 1: Failing test** in `judgment.rs` tests:

```rust
#[test]
fn annotate_follows_the_deciding_construct() {
    let mut j = Judgment::allow();
    j.decided_by.construct = Some("honeypot.decoy-hit".into());
    let j = j.annotate();
    assert_eq!(j.attack.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), vec!["T1595.003"]);
    assert_eq!(j.confidence, crate::confidence::confidence("honeypot.decoy-hit"));
    let mut k = j.clone();
    k.decided_by.construct = None;
    let k = k.annotate();
    assert!(k.attack.is_empty() && k.confidence.is_none());
}
```

And in `shield.rs` tests:

```rust
#[test]
fn judgments_are_annotated_and_scores_unchanged() {
    let s = Shield::default();
    let j = s.inspect(&Request::get("/search?q=1%20union%20select%20a%20from%20b"));
    assert_eq!(j.decided_by.construct.as_deref(), Some("sqli.union-select"));
    assert_eq!(j.attack.first().map(|t| t.id.as_str()), Some("T1190"));
    let plain = s.inspect(&Request::get("/"));
    assert!(plain.attack.is_empty() && plain.confidence.is_none());
}
```

(Adapt `Shield::default()` / `Request::get` to the constructors the existing shield tests use.)

- [ ] **Step 2: Run** — FAIL (no fields).
- [ ] **Step 3: Implement.** Add the two fields after `normalized_layers` with doc comments ("ATT&CK techniques of the deciding construct (sub-project A)", "Measured precision on dev of the deciding construct, 1–100; never affects score or verdict"). `allow()` sets `attack: Vec::new(), confidence: None`. Add:

```rust
/// Fill `attack` and `confidence` from `decided_by.construct`.
pub fn annotate(mut self) -> Self {
    match self.decided_by.construct.as_deref() {
        Some(c) => {
            self.attack = crate::attack::tags_for(c);
            self.confidence = crate::confidence::confidence(c);
        }
        None => {
            self.attack.clear();
            self.confidence = None;
        }
    }
    self
}
```

In `shield.rs`, every `Judgment { … }` literal gets `attack: Vec::new(), confidence: None` and is followed by `.annotate()` where it is returned or stored; `finalize` ends with `j.annotate()` (it may change `decided_by`). Fix any other `Judgment {` literal the compiler reports (tests included).

- [ ] **Step 4: Bless types:** `VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings`, then run it again without the variable — PASS. Add `check::<AttackTag>(&cfg, &mut stale);` before blessing.
- [ ] **Step 5: Run** `cargo test --workspace` — PASS; `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- [ ] **Step 6: Commit** `feat(core): judgments carry ATT&CK tags and measured confidence`.

---

### Task 4: Episode start and group ID in the chain

**Files:**
- Modify: `crates/vft-core/src/chain.rs`

**Interfaces:**
- Produces: `ChainOutcome { …, pub episode_start_ms: Option<u64> }` (still `Copy + Default`); `pub fn group_id(ip: std::net::IpAddr, o: &ChainOutcome) -> Option<String>` returning `Some(format!("{ip}@{start}"))` when `episode_start_ms` is set.

- [ ] **Step 1: Failing tests** in `chain.rs` tests (use the module's existing tracker/key helpers):

```rust
#[test]
fn events_within_the_window_share_an_episode() {
    let mut t = tracker();            // existing helper, default config
    let k = key("203.0.113.9");       // existing helper
    let a = t.observe(k, Event::Benign, 1_000, true);
    let b = t.observe(k, Event::Benign, 1_000 + 3_599_000, true);
    assert_eq!(a.episode_start_ms, Some(1_000));
    assert_eq!(b.episode_start_ms, Some(1_000));
}

#[test]
fn an_idle_window_starts_a_new_episode() {
    let mut t = tracker();
    let k = key("203.0.113.9");
    t.observe(k, Event::Benign, 1_000, true);
    let c = t.observe(k, Event::Benign, 1_000 + 3_600_001, true);
    assert_eq!(c.episode_start_ms, Some(1_000 + 3_600_001));
}

#[test]
fn group_id_names_the_source_and_episode() {
    let o = ChainOutcome { episode_start_ms: Some(42), ..Default::default() };
    assert_eq!(group_id("198.51.100.7".parse().unwrap(), &o).as_deref(), Some("198.51.100.7@42"));
    assert_eq!(group_id("198.51.100.7".parse().unwrap(), &ChainOutcome::default()), None);
}
```

If the test module has no `tracker()`/`key()` helpers, build them the way the existing chain tests build a `ChainTracker` and `SourceKey`.

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement.** Add `episode_start: u64` to `SourceState`. In `observe`, before `st.last_seen = now_ms;`:

```rust
let st = self.sources.entry(key).or_insert_with(|| SourceState {
    events: VecDeque::new(), last_seen: now_ms, tally: VecDeque::new(), episode_start: now_ms,
});
if now_ms.saturating_sub(st.last_seen) > window_ms {
    st.episode_start = now_ms;
}
st.last_seen = now_ms;
```

and set `episode_start_ms: Some(st.episode_start)` in the returned `ChainOutcome`. Note the idle test uses the gap since `last_seen`, not since the first event. Check the source-eviction code (sources idle past the window may be removed): an evicted then re-seen source also starts a new episode, which is the same rule.

- [ ] **Step 4: Bless TS** (ChainOutcome changed) and run `cargo test --workspace` — PASS.
- [ ] **Step 5: Commit** `feat(core): chain episodes and group IDs`.

---

### Task 5: Event IDs and JSONL audit additions

**Files:**
- Create: `crates/vft-proxy/src/ids.rs`
- Modify: `crates/vft-proxy/src/audit.rs`, `crates/vft-proxy/src/lib.rs`

**Interfaces:**
- Produces: `pub struct EventIds` with `pub fn new() -> Self` and `pub fn next(&self, ts_ms: u64) -> String` (UUIDv7 text, lowercase, 36 chars); `ProxyState.ids: EventIds`; `AuditSink::record(&self, req: &Request, j: &Judgment, ts_ms: u64, request_id: u64, event_id: &str)`; JSONL gains `event_id`, `group_id` (`Option<String>`), `confidence` (`Option<u8>`), `attack` (`[{tactic_id, id}]`).

- [ ] **Step 1: Failing tests.** In `ids.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uuid_v7_shape_time_prefix_and_uniqueness() {
        let ids = EventIds::new();
        let a = ids.next(0x0190_0000_0000);
        let b = ids.next(0x0190_0000_0000);
        assert_eq!(a.len(), 36);
        assert_ne!(a, b);
        let hex: String = a.chars().filter(|c| *c != '-').collect();
        assert_eq!(&hex[..12], "019000000000");
        assert_eq!(&hex[12..13], "7");                    // version
        assert!(matches!(&hex[16..17], "8" | "9" | "a" | "b")); // RFC 9562 variant
    }
}
```

In `audit.rs` tests, extend the existing round-trip test (the one that records with `1_700_000_000_000, 7`) to pass an `event_id` and assert the parsed line has `event_id`, `confidence`, `attack` and `group_id` keys (group_id `null` when the judgment has no chain).

- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** `ids.rs`:

```rust
//! UUIDv7 event IDs (RFC 9562): 48-bit Unix ms, version 7, then a per-process
//! random value mixed with a counter, so IDs are unique within a process and
//! sortable by time. Built from std only.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct EventIds {
    seed: u64,
    counter: AtomicU64,
}

impl EventIds {
    pub fn new() -> Self {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x5646_5401);
        EventIds { seed: h.finish(), counter: AtomicU64::new(0) }
    }

    pub fn next(&self, ts_ms: u64) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let rand_a = (n & 0x0fff) as u16;
        let rand_b = self.seed ^ n.rotate_left(17);
        let hi: u64 = ((ts_ms & 0xffff_ffff_ffff) << 16) | (0x7 << 12) | u64::from(rand_a);
        let lo: u64 = (rand_b & 0x3fff_ffff_ffff_ffff) | 0x8000_0000_0000_0000;
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            hi >> 32, (hi >> 16) & 0xffff, hi & 0xffff, lo >> 48, lo & 0xffff_ffff_ffff
        )
    }
}

impl Default for EventIds {
    fn default() -> Self {
        Self::new()
    }
}
```

In `audit.rs`: add to `AuditLine` `event_id: &'a str, group_id: Option<String>, confidence: Option<u8>, attack: Vec<AttackLine<'a>>` with `#[derive(Serialize)] struct AttackLine<'a> { tactic_id: &'a str, id: &'a str }`; `group_id` = `req.src_ip.zip(j.chain.as_ref()).and_then(|(ip, o)| vft_core::chain::group_id(ip, o))`. Add the `event_id: &str` parameter to `record`. In `lib.rs`, add `pub ids: ids::EventIds` to `ProxyState` (initialised in `new`), `pub mod ids;`, and at both record call sites compute `let ts = now_ms(); let eid = state.ids.next(ts);` and pass `ts` and `&eid`. Update every `record(` call in tests.

- [ ] **Step 4: Run** `cargo test -p vft-proxy` — PASS; workspace tests and clippy — green.
- [ ] **Step 5: Commit** `feat(proxy): UUIDv7 event IDs; audit lines carry IDs, confidence and ATT&CK`.

---

### Task 6: OCSF 1.9.0 encoder and `serve --ocsf`

**Files:**
- Create: `crates/vft-proxy/src/ocsf.rs`, `crates/vft-proxy/tests/fixtures/ocsf-1.9.0-http_activity.json`, `crates/vft-proxy/tests/fixtures/ocsf-1.9.0-detection_finding.json`, `crates/vft-proxy/tests/fixtures/ocsf-sample.json`
- Modify: `crates/vft-proxy/src/audit.rs` (format-generic sink), `crates/vft-proxy/src/lib.rs` (`ProxyState.ocsf`), `crates/vft-cli/src/main.rs` (`--ocsf <PATH>`), every `ProxyState::new` caller (`crates/vft-proxy/src/lib.rs` tests, `crates/vft-cli/src/eval.rs`).

**Interfaces:**
- Consumes: `EventIds`, `chain::group_id`, `Judgment.attack/confidence`.
- Produces: `pub fn encode(req: &Request, j: &Judgment, ts_ms: u64, event_id: &str) -> Vec<serde_json::Value>` (one 4002 record, plus one 2004 record for Challenge/Block); `pub enum Format { Jsonl, Ocsf }`; `AuditSink::with_format(path: Option<PathBuf>, max_bytes: u64, format: Format) -> Self` (`new` keeps meaning `Jsonl`); `ProxyState::new(shield, upstream, audit, ocsf: AuditSink, enforce)`.

- [ ] **Step 1: Fetch schema fixtures** (read-only public API) and commit them:

```bash
curl -fsS "https://schema.ocsf.io/api/1.9.0/classes/http_activity?profiles=security_control" -o crates/vft-proxy/tests/fixtures/ocsf-1.9.0-http_activity.json
curl -fsS "https://schema.ocsf.io/api/1.9.0/classes/detection_finding?profiles=security_control" -o crates/vft-proxy/tests/fixtures/ocsf-1.9.0-detection_finding.json
```

Open both and confirm the structure (expected: an `attributes` map whose entries carry `requirement` and, for enums, an `enum` map of value → `{caption}`). Look up the numeric values whose captions are `Allowed`, `Denied` (`action_id`), `Allowed`, `Blocked`, `Logged` (`disposition_id`), and the `confidence_id` captions `Low`/`Medium`/`High`. Use those numbers below; if a caption is missing, stop and report it.

- [ ] **Step 2: Failing tests** in `ocsf.rs` (`#[cfg(test)]`), loading fixtures with `include_str!("../tests/fixtures/…")`:

```rust
fn required(schema: &serde_json::Value) -> Vec<String> {
    schema["attributes"].as_object().unwrap().iter()
        .filter(|(_, a)| a["requirement"] == "required")
        .map(|(k, _)| k.clone()).collect()
}
fn enum_ok(schema: &serde_json::Value, attr: &str, v: &serde_json::Value) -> bool {
    schema["attributes"][attr]["enum"].as_object().is_none_or(|e| e.contains_key(&v.to_string()))
}

#[test]
fn http_activity_has_required_fields_and_allowed_enums() { /* encode a Block on POST /x from 192.0.2.1;
   recs[0] has every required() key of the 4002 fixture; class_uid 4002, category_uid 4, activity_id 6,
   type_uid 400206, metadata.version "1.9.0", metadata.uid == event_id; enum_ok for activity_id,
   severity_id, action_id, disposition_id */ }

#[test]
fn detection_finding_only_for_challenge_and_block() { /* Allow and Monitor -> 1 record; Challenge and
   Block -> 2; recs[1] has every required() key of the 2004 fixture, class_uid 2004, type_uid 200401,
   finding_info.uid == event_id, finding_info.attacks[0].technique.uid == "T1190" for a union-select
   judgment, confidence_score == j.confidence when Some, absent when None */ }

#[test]
fn shared_sample_matches() { /* load tests/fixtures/ocsf-sample.json: {input:{method,path,src_ip,
   verdict,construct,score,ts_ms,event_id,group_id,confidence,attack}, expected:[...]} ; build the
   judgment from input, encode, compare with expected (the console's TS encoder reads the same file) */ }
```

Write the three tests out in full (the comments above list exactly what each asserts). For `ocsf-sample.json` write one Block sample by hand from the mapping rules below and make the Rust test pass against it; Task 9 makes the TS encoder pass against the same file.

- [ ] **Step 3: Run** — FAIL.
- [ ] **Step 4: Implement `encode`.** Mapping (use the fixture-confirmed numbers for action/disposition/confidence ids):
  - method → activity_id: CONNECT 1, DELETE 2, GET 3, HEAD 4, OPTIONS 5, POST 6, PUT 7, TRACE 8, PATCH 9, else 99; `type_uid = 400200 + activity_id`.
  - verdict → severity_id: Allow 1, Monitor 2, Challenge 3, Block 4.
  - common: `time` = ts_ms; `metadata = {version: "1.9.0", uid: event_id, profiles: ["security_control"], product: {name: "Venusflytrap", vendor_name: "Venusflytrap", version: env!("CARGO_PKG_VERSION")}}` plus `correlation_uid: group_id` when present; `src_endpoint: {ip}` when known; `message: decided_by.msg`.
  - 4002: `class_uid 4002`, `category_uid 4`, `http_request: {http_method, url: {path}}`, `action_id` (Allowed for Allow/Monitor, Denied for Challenge/Block), `disposition_id` (Allowed / Logged for Monitor / Blocked), `firewall_rule: {uid: construct, name: construct summary from the registry}` when a construct decided.
  - 2004 (Challenge/Block only): `class_uid 2004`, `category_uid 2`, `activity_id 1`, `type_uid 200401`, `is_alert: true`, `severity_id`, `finding_info: {uid: event_id, title: decided_by.msg, attacks: [{tactic: {uid, name}, technique: {uid, name}}]}`, the same `attacks` at top level, and when `confidence` is `Some(c)`: `confidence_score: c` and `confidence_id` (1–39 Low, 40–69 Medium, 70–100 High).
- [ ] **Step 5: Format-generic sink.** In `audit.rs` add `pub enum Format { Jsonl, Ocsf }`, store it on `AuditSink`, add `with_format`, keep `new` = `with_format(.., Format::Jsonl)`. In `record`, `Format::Ocsf` sends one line per `ocsf::encode` record (each through `try_send`, each drop counted). Test: an Ocsf sink writing a Block produces two lines whose `class_uid`s are 4002 and 2004.
- [ ] **Step 6: Wire.** `ProxyState` gains `pub ocsf: audit::AuditSink`; both record call sites also call `state.ocsf.record(…, &eid)` with the same `ts`/`eid`. CLI: `Serve { …, /// Also write OCSF 1.9.0 JSONL to this file. #[arg(long)] ocsf: Option<String> }`; build `AuditSink::with_format(Some(path), max, Format::Ocsf)` or `AuditSink::off()`. Update every `ProxyState::new` caller to pass `AuditSink::off()` for `ocsf`.
- [ ] **Step 7: Run** `cargo test --workspace` and clippy — green.
- [ ] **Step 8: Commit** `feat(proxy): native OCSF 1.9.0 output (serve --ocsf)`.

---

### Task 7: Verify no detection change; results note

**Files:**
- Create: `eval/RESULTS-A-attack-ocsf.md`
- Modify: `docs/BENCHMARK.md` (one status line after the DQ5 line)

- [ ] **Step 1: Dev A/B** (branch build vs the main baseline binary):

```bash
export VFT_CORPUS=… VFT_MANIFEST=… VFT_RUNS="$SCRATCH/runs"
bash eval/ab_dev.sh a-fields "" "" "$MAIN_BIN" target/release/venusflytrap.exe
```

Required: `delta: tp=+0 fp=+0`, McNemar b = c = 0 for both classes, `fallen: 0`. Also compare the two CSVs column by column except none should differ: `py -I -X utf8 -c` one-liner that asserts every row's `lib_verdict`, `score`, `top`, `cause` are equal. Any difference: stop and report.

- [ ] **Step 2: Serve check:** run `eval/decision_gate.sh diff` (see its header for arguments) between the main binary and the branch binary in serve mode; required: 0 changed decisions.
- [ ] **Step 3: OCSF smoke:** start `venusflytrap serve --bind 127.0.0.1:18089 --upstream http://127.0.0.1:9 --audit "$SCRATCH/a.jsonl" --ocsf "$SCRATCH/a.ocsf.jsonl" --monitor-only` in the background, send three requests with curl (a plain GET, a query with a union-select construct, a request to a configured decoy path), stop it, and check: 3 JSONL lines with distinct `event_id`s; OCSF lines = 3 HTTP Activity + one Detection Finding per Challenge/Block; every line parses as JSON.
- [ ] **Step 4: Results note** `eval/RESULTS-A-attack-ocsf.md`: what changed (fields only), the dev A/B line and serve-diff line, the confidence table (construct, TP, FP, confidence) with its source run, the ATT&CK mapping table, the OCSF smoke counts, and what it does not show (confidence is dev precision on one corpus; no SIEM was tested end to end).
- [ ] **Step 5: BENCHMARK status line:** "Status: A (ATT&CK tags, measured confidence, event and group IDs, OCSF 1.9.0 output) changes no detection: on dev ΔTP = ΔFP = 0 and no verdict changed; see eval/RESULTS-A-attack-ocsf.md."
- [ ] **Step 6: Commit** `docs: sub-project A results`.

---

### Task 8: Console — wire types, fixtures and Monitor columns

**Files:**
- Modify: `ui/src/lib/api/types.ts` (`HistoryRow` gains `technique: string | null`, `confidence: number | null`, `group_id: string | null`), `ui/src/lib/api/history.ts` (fixture judgments get `attack` and `confidence` from the deciding construct, `chain.episode_start_ms`, rows get the new fields), `ui/src/screens/Monitor.svelte` (two columns), tests in `ui/src/screens/monitor/monitor.test.ts` and `ui/src/lib/api/*.test.ts`.
- Create: `ui/src/lib/components/AttackChip.svelte`, `ui/src/lib/api/attack.ts` (TS copy of the Task 1 table: `techniquesFor(construct: string | null): AttackTag[]`, with a test that pins the same expectations as the Rust tests).

**Interfaces:**
- Consumes: `ui/src/gen/Judgment.ts`, `AttackTag.ts`, `ChainOutcome.ts` (Task 3/4), `confidenceOf` (Task 2).
- Produces: `AttackChip` props `{ tag: AttackTag; compact?: boolean }` — renders the technique id in the existing chip style (reuse `EvidenceChip`'s classes/tokens), full "tactic · technique name" in `title` and as visually-hidden text so it is not colour-only.

- [ ] **Step 1: Failing tests:**
  - `attack.test.ts`: `techniquesFor('cmd.chained-command').map(t => t.id)` equals `['T1190','T1059']`; `techniquesFor('honeypot.decoy-hit')[0].id === 'T1595.003'`; `techniquesFor('ai.anomaly-score')` is empty; `techniquesFor(null)` is empty.
  - fixture test: for 200 generated rows, every row's `technique` equals the first tag of `techniquesFor(row.construct)` (or null) and `confidence === confidenceOf(row.construct)`; every detail's `judgment.attack`/`confidence` match the same; `group_id` is `${ip}@${episode_start_ms}` when the chain is present.
  - Monitor test: the grid has column headers "Technique" and "Confidence"; a row with a construct renders its technique chip; confidence renders as a number or "—".
- [ ] **Step 2: Run** `npm test` in `ui/` — FAIL.
- [ ] **Step 3: Implement.** Columns go after "Construct": `{ key: 'technique', label: 'Technique', field: null }` and `{ key: 'confidence', label: 'Confidence', field: null, n: true }`; keep keyboard navigation (the existing tests that count ArrowRight steps must be updated to the new column order, not weakened). Fixtures obey the engine rules: tags and confidence come only from `decided_by.construct`.
- [ ] **Step 4: Run** `npm test` and `npm run check` — PASS / 0 errors.
- [ ] **Step 5: Commit** `feat(ui): ATT&CK and confidence in Monitor`.

---

### Task 9: Console — Request details: tags, confidence, IDs, OCSF view

**Files:**
- Create: `ui/src/lib/ocsf.ts` (TS port of `ocsf::encode`), `ui/src/lib/ocsf.test.ts`
- Modify: `ui/src/screens/RequestDetails.svelte`, `ui/src/screens/request/request.test.ts`

**Interfaces:**
- Consumes: `RequestDetail` (with `judgment.attack`, `judgment.confidence`, `row.group_id`), `AttackChip`.
- Produces: `export function encodeOcsf(detail: RequestDetail, eventId: string): Record<string, unknown>[]`.

- [ ] **Step 1: Failing tests:**
  - `ocsf.test.ts` reads `../../crates/vft-proxy/tests/fixtures/ocsf-sample.json` with `node:fs` (path relative to `ui/`), builds the minimal `RequestDetail` from `input`, and expects `encodeOcsf(...)` to deep-equal `expected`. Also: Allow → 1 record; Block → 2 records with class_uids 4002 and 2004.
  - `request.test.ts`: the details screen shows one `AttackChip` per tag with the tactic name visible; shows "Precision on dev" with the number (or "not measured" when null); shows the event ID and group ID each with a copy button whose accessible name is "Copy event ID" / "Copy group ID"; has a tab "View as OCSF" that, when selected, shows a `<pre>` containing `"class_uid": 4002`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** in the existing layout: the tags and confidence sit in the "why" panel header next to the verdict chip; the IDs go in the request metadata block; "View as OCSF" is a second tab beside the existing evidence view using the existing tab pattern in the screen (or `role="tablist"` buttons styled with existing tokens if none exists). The copy buttons use `navigator.clipboard.writeText` and announce "Copied" through the existing toast store. The confidence line reads "Precision on dev: 87" with a one-sentence `title`: "Share of this construct's blocks on the dev split that were attacks (lower 95 % bound). It does not change the score."
- [ ] **Step 4: Run** `npm test`, `npm run check` — PASS.
- [ ] **Step 5: Commit** `feat(ui): Request details shows ATT&CK, confidence, IDs and the OCSF view`.

---

### Task 10: Console — end-to-end, accessibility, budget, visual check

**Files:**
- Modify: `ui/e2e/console.spec.ts`

- [ ] **Step 1: Extend e2e:** Monitor shows the Technique column; opening a blocked request shows ATT&CK chips and the OCSF tab; axe has no violations on Monitor and Request details in light and dark.
- [ ] **Step 2: Run** `npm run build` (initial JS ≤ 150 KB gz per the existing budget check) and `npm run e2e` (Playwright, system Edge, as configured) — all pass.
- [ ] **Step 3: Visual check:** `npm run preview -- --port 5299 --strictPort`, open Monitor (light) and a blocked request's details (dark) in the browser pane, take screenshots; confirm chips, confidence and the OCSF tab match the existing style (no new colours, fonts or spacing scale).
- [ ] **Step 4: Commit** `test(ui): e2e and a11y for ATT&CK and OCSF`.

---

## Self-review

- Spec coverage: §3.1 → Task 1/3; §3.2 → Task 2/3; §3.3 → Task 4; §3.4–3.5 → Task 5; §3.6 → Task 6; §3.7 → Tasks 8–10; §6 acceptance → Task 7 and 10.
- Names used across tasks: `tags_for`, `techniques_for`, `confidence::confidence`, `Judgment::annotate`, `ChainOutcome.episode_start_ms`, `chain::group_id`, `EventIds::next`, `AuditSink::with_format`, `Format::Ocsf`, `ocsf::encode`, `confidenceOf`, `techniquesFor`, `encodeOcsf`, `AttackChip`.
