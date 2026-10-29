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
