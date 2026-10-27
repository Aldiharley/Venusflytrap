//! Option descriptor registry: one hand-written entry per config leaf, keyed
//! by its dotted path (`scoring.block_at`). The same key names the setting in
//! YAML, in `decided_by`, in the API, in the settings screen and in deep links.
//! Per-key bounds live here; `Config::validate` adds the cross-field rules.

use std::net::IpAddr;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::{ConfigError, ConfigIssue};

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OptionKind {
    Int { min: i64, max: i64 },
    Float { min: f64, max: f64 },
    Bool,
    Choice { values: &'static [&'static str] },
    /// A list of absolute URL paths.
    Paths,
    /// A list of exact IP addresses.
    Ips,
    /// A list of registered construct ids (`graph::sinks::constructs()`).
    ConstructIds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Expertise {
    Basic,
    Advanced,
    Expert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Apply {
    /// Takes effect on the next request after a reload.
    Live,
    /// Saved, but only takes effect after a restart.
    Restart,
}

#[derive(Debug, Serialize)]
pub struct OptionDescriptor {
    pub key: &'static str,
    pub kind: OptionKind,
    pub section: &'static str,
    /// Markdown.
    pub help: &'static str,
    pub level: Expertise,
    pub apply: Apply,
    /// Redacted in API responses, logs and debug bundles.
    pub sensitive: bool,
}

const MAX: i64 = i64::MAX;

const fn opt(key: &'static str, kind: OptionKind, section: &'static str, help: &'static str, level: Expertise, apply: Apply) -> OptionDescriptor {
    OptionDescriptor { key, kind, section, help, level, apply, sensitive: false }
}

use Apply::{Live, Restart};
use Expertise::{Advanced, Basic, Expert};
use OptionKind::{Bool, ConstructIds, Float, Int, Ips, Paths};

pub static REGISTRY: &[OptionDescriptor] = &[
    opt("version", Int { min: 1, max: 1 }, "general", "Config schema version. Only `1` exists.", Expert, Restart),
    // shield
    opt("shield.max_payload", Int { min: 1024, max: MAX }, "shield", "Characters of one field normalized as one chunk; longer fields are inspected in overlapping chunks.", Expert, Live),
    opt("shield.decode_cap", Int { min: 1, max: 32 }, "shield", "Most decode layers peeled from one field before stopping.", Expert, Live),
    opt("shield.deep_threshold", Int { min: 1, max: 32 }, "shield", "Decode depth at or above which a field counts as deeply nested. Must not exceed `shield.decode_cap`.", Expert, Live),
    opt("shield.max_graph_windows", Int { min: 1, max: 1024 }, "shield", "Token windows analyzed per field; past it the field is reported as `limit.graph-truncated`.", Expert, Live),
    opt("shield.max_inspect_bytes", Int { min: 1024, max: MAX }, "shield", "Bytes of one request inspected; past it the request hard-blocks as `limit.payload-truncated`. Must be at least `shield.max_payload`.", Expert, Live),
    opt("shield.max_normalize_work", Int { min: 1024, max: MAX }, "shield", "Folded characters all normalizations of one request may produce; reaching it hard-blocks as `limit.payload-truncated`. Must be at least `shield.max_payload`.", Expert, Live),
    opt("shield.disabled", ConstructIds, "shield", "Construct, decoder or limit ids switched off. Unknown ids are rejected.", Advanced, Live),
    // scoring
    opt("scoring.weight_graph", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of the taint-graph engine.", Advanced, Live),
    opt("scoring.weight_signature", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of literal signatures.", Advanced, Live),
    opt("scoring.weight_intent", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of request intent (sensitive-path recon) and scanner fingerprints.", Advanced, Live),
    opt("scoring.weight_api", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of API-safety checks and inspection limits.", Advanced, Live),
    opt("scoring.weight_ai", Float { min: 0.0, max: 2.0 }, "scoring", "Weight of the heuristic anomaly oracle.", Advanced, Live),
    opt("scoring.block_at", Int { min: 1, max: 100 }, "scoring", "Score at or above which a request is blocked.", Basic, Live),
    opt("scoring.challenge_at", Int { min: 1, max: 100 }, "scoring", "Score at or above which a request is challenged (answered 403 in enforce mode).", Basic, Live),
    opt("scoring.monitor_at", Int { min: 1, max: 100 }, "scoring", "Score at or above which a request is forwarded but flagged.", Basic, Live),
    opt("scoring.conflict_threshold", Float { min: 0.0, max: 1.0 }, "scoring", "Evidence weight above which Safe against Dangerous on one field is a real conflict.", Expert, Live),
    opt("scoring.chain_stage_bonus", Int { min: 0, max: 100 }, "scoring", "Points added when a source advances a kill-chain stage.", Advanced, Live),
    opt("scoring.corroboration_cap", Float { min: 0.0, max: 50.0 }, "scoring", "Most points that corroborating weaker signals may add in total.", Expert, Live),
    // chain
    opt("chain.window_secs", Int { min: 1, max: MAX }, "chain", "Seconds a source's events count toward its stage.", Advanced, Live),
    opt("chain.max_sources", Int { min: 640, max: MAX }, "chain", "Sources tracked at once (least recently seen are evicted; bans are kept separately).", Expert, Restart),
    opt("chain.events_per_source", Int { min: 1, max: MAX }, "chain", "Events remembered per source.", Expert, Restart),
    opt("chain.ipv6_prefix", Int { min: 1, max: 128 }, "chain", "IPv6 sources are grouped by this prefix length.", Expert, Restart),
    opt("chain.ban_policy.on_honeypot", Bool, "chain", "Ban a source that hits a honeypot decoy.", Basic, Live),
    opt("chain.ban_policy.on_exfiltration_block", Bool, "chain", "Ban a source on a single exfiltration block.", Advanced, Live),
    opt("chain.ban_policy.exploitation_blocks", Int { min: 1, max: u32::MAX as i64 }, "chain", "Ban after this many exploitation blocks within `chain.ban_policy.within_secs`.", Advanced, Live),
    opt("chain.ban_policy.within_secs", Int { min: 1, max: MAX }, "chain", "Window for counting exploitation blocks and the hostile share.", Advanced, Live),
    opt("chain.ban_policy.ttl_secs", Int { min: 1, max: MAX }, "chain", "Length of a first ban (and of a manual ban); doubles on each re-offence.", Advanced, Live),
    opt("chain.ban_policy.ttl_max_secs", Int { min: 1, max: MAX }, "chain", "Longest automatic ban. Must be at least `chain.ban_policy.ttl_secs`.", Advanced, Live),
    opt("chain.ban_policy.max_bans", Int { min: 640, max: MAX }, "chain", "Bans held at once; the soonest to expire are evicted first.", Expert, Restart),
    opt("chain.ban_policy.min_hostile_share", Float { min: 0.0, max: 1.0 }, "chain", "Share of a source's recent requests that must be hostile before any automatic ban; `0` turns the check off.", Advanced, Live),
    // honeypot
    opt("honeypot.decoy_paths", Paths, "honeypot", "Decoy paths no legitimate client requests; a hit hard-blocks.", Basic, Live),
    opt("honeypot.sensitive_paths", Paths, "honeypot", "Path prefixes whose probing counts as recon.", Basic, Live),
    // proxy
    opt("proxy.trusted_proxies", Ips, "proxy", "Peers whose `X-Forwarded-For` is trusted.", Basic, Restart),
    opt("proxy.decision_headers", OptionKind::Choice { values: &["off", "upstream"] }, "proxy", "`upstream` adds `X-Venusflytrap-*` headers to forwarded requests; never sent to clients.", Advanced, Restart),
    // limits
    opt("limits.max_body", Int { min: 1024, max: MAX }, "limits", "Largest request body in bytes; larger bodies get 413 before any upstream connection.", Basic, Restart),
    opt("limits.max_headers", Int { min: 8, max: 1000 }, "limits", "Most request headers accepted.", Advanced, Restart),
    opt("limits.max_connections", Int { min: 1, max: MAX }, "limits", "Concurrent client connections.", Advanced, Restart),
    opt("limits.header_read_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed to receive the request head.", Advanced, Restart),
    opt("limits.body_read_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed to receive the request body.", Advanced, Restart),
    opt("limits.upstream_connect_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed to connect to the upstream.", Advanced, Restart),
    opt("limits.upstream_response_timeout_ms", Int { min: 1, max: MAX }, "limits", "Time allowed for the upstream response head.", Advanced, Restart),
    opt("limits.response_idle_timeout_ms", Int { min: 1, max: MAX }, "limits", "Longest gap between upstream response-body chunks.", Advanced, Restart),
    opt("limits.max_connection_ms", Int { min: 1, max: MAX }, "limits", "Hard cap on one client connection's lifetime.", Advanced, Restart),
    // intel
    opt("intel.deny_ips", Ips, "intel", "Sources always blocked, unless also allow-listed.", Basic, Live),
    opt("intel.allow_ips", Ips, "intel", "Sources never banned or deny-listed; still inspected.", Basic, Live),
];

pub fn lookup(key: &str) -> Option<&'static OptionDescriptor> {
    REGISTRY.iter().find(|d| d.key == key)
}

/// True if `key` is a strict prefix section of some registered key (`chain`,
/// `chain.ban_policy`).
fn is_section(key: &str) -> bool {
    REGISTRY
        .iter()
        .any(|d| d.key.len() > key.len() && d.key.starts_with(key) && d.key.as_bytes()[key.len()] == b'.')
}

/// The problem with `v` as a value of `d`, if any.
pub fn check_value(d: &OptionDescriptor, v: &Value) -> Option<String> {
    match d.kind {
        OptionKind::Int { min, max } => match v.as_i64() {
            Some(n) if (min..=max).contains(&n) => None,
            _ if max == MAX => Some(format!("must be an integer >= {min}, got {v}")),
            _ => Some(format!("must be an integer in {min}..={max}, got {v}")),
        },
        OptionKind::Float { min, max } => match v.as_f64() {
            Some(x) if x.is_finite() && (min..=max).contains(&x) => None,
            _ => Some(format!("must be a finite number in [{min}, {max}], got {v}")),
        },
        OptionKind::Bool => (!v.is_boolean()).then(|| format!("must be true or false, got {v}")),
        OptionKind::Choice { values } => match v.as_str() {
            Some(s) if values.contains(&s) => None,
            _ => Some(format!("must be one of {}, got {v}", values.join(", "))),
        },
        OptionKind::Paths => strings(v, "a list of paths", |s| {
            (!s.starts_with('/')).then(|| format!("paths must start with '/', got {s:?}"))
        }),
        OptionKind::Ips => strings(v, "a list of IP addresses", |s| {
            s.parse::<IpAddr>().is_err().then(|| format!("not an IP address: {s:?}"))
        }),
        OptionKind::ConstructIds => strings(v, "a list of construct ids", |s| {
            crate::graph::sinks::lookup(s).is_none().then(|| format!("unknown construct id {s:?}"))
        }),
    }
}

fn strings(v: &Value, what: &str, bad: impl Fn(&str) -> Option<String>) -> Option<String> {
    let Some(items) = v.as_array() else {
        return Some(format!("must be {what}, got {v}"));
    };
    for item in items {
        let Some(s) = item.as_str() else {
            return Some(format!("must be {what}, got {v}"));
        };
        if let Some(m) = bad(s) {
            return Some(m);
        }
    }
    None
}

/// Every per-key problem in a config tree: unknown keys, wrong types, values
/// out of bounds. A `Null` root is an empty config.
pub fn check_tree(root: &Value) -> Vec<ConfigIssue> {
    let mut out = Vec::new();
    match root {
        Value::Null => {}
        Value::Object(m) => walk("", m, &mut out),
        _ => out.push(ConfigIssue { key: "<config>".into(), message: "must be a mapping of sections".into() }),
    }
    out
}

fn walk(prefix: &str, m: &Map<String, Value>, out: &mut Vec<ConfigIssue>) {
    for (k, v) in m {
        let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        if let Some(d) = lookup(&key) {
            if let Some(message) = check_value(d, v) {
                out.push(ConfigIssue { key, message });
            }
        } else if is_section(&key) {
            match v {
                Value::Object(c) => walk(&key, c, out),
                _ => out.push(ConfigIssue { key, message: "must be a mapping".into() }),
            }
        } else {
            out.push(ConfigIssue { key, message: "unknown option".into() });
        }
    }
}

/// Parse YAML into the JSON tree the checker reads. An empty document is `Null`.
pub(crate) fn yaml_tree(s: &str) -> Result<Value, ConfigError> {
    if s.trim().is_empty() {
        return Ok(Value::Null);
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(s)?;
    serde_json::to_value(yaml).map_err(|e| {
        ConfigError::Invalid(vec![ConfigIssue { key: "<config>".into(), message: format!("not a plain mapping: {e}") }])
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn leaves(prefix: &str, v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, c) in m {
                    let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    leaves(&p, c, out);
                }
            }
            _ => out.push(prefix.to_string()),
        }
    }

    #[test]
    fn every_config_leaf_has_exactly_one_descriptor() {
        let mut keys = Vec::new();
        leaves("", &serde_json::to_value(Config::default()).expect("serializes"), &mut keys);
        for k in &keys {
            assert_eq!(REGISTRY.iter().filter(|d| d.key == k).count(), 1, "leaf {k} needs exactly one descriptor");
        }
        for d in REGISTRY {
            assert!(keys.iter().any(|k| k == d.key), "descriptor {} is not a config leaf", d.key);
        }
    }

    #[test]
    fn sections_and_help_are_filled_in() {
        for d in REGISTRY {
            let want = d.key.split_once('.').map_or("general", |(s, _)| s);
            assert_eq!(d.section, want, "{}", d.key);
            assert!(!d.help.is_empty(), "{} has no help", d.key);
        }
    }

    #[test]
    fn defaults_pass_the_tree_check() {
        let tree = serde_json::to_value(Config::default()).expect("serializes");
        assert_eq!(check_tree(&tree), Vec::new());
    }

    #[test]
    fn check_value_reports_type_and_bounds() {
        let d = lookup("scoring.block_at").unwrap();
        assert!(check_value(d, &serde_json::json!(90)).is_none());
        assert!(check_value(d, &serde_json::json!(0)).is_some());
        assert!(check_value(d, &serde_json::json!("ninety")).is_some());
        let w = lookup("scoring.weight_ai").unwrap();
        assert!(check_value(w, &Value::Null).is_some(), "NaN serializes as null");
        assert!(check_value(w, &serde_json::json!(1)).is_none(), "an integer is a valid float");
        let c = lookup("proxy.decision_headers").unwrap();
        assert!(check_value(c, &serde_json::json!("upstream")).is_none());
        assert!(check_value(c, &serde_json::json!("client")).is_some());
    }

    #[test]
    fn unknown_keys_and_non_mappings_are_per_key() {
        let tree = serde_json::json!({ "scoring": { "blok_at": 10 }, "chain": 5, "nonsense": 1 });
        let mut keys: Vec<String> = check_tree(&tree).into_iter().map(|i| i.key).collect();
        keys.sort();
        assert_eq!(keys, vec!["chain", "nonsense", "scoring.blok_at"]);
    }
}
