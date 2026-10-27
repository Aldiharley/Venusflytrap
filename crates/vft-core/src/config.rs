//! FR8 — Configuration. Serde structs mirroring the article's YAML files, each
//! with a sensible `Default` so the engine runs with zero configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Config schema version. Only 1 exists.
    pub version: u32,
    pub shield: ShieldConfig,
    pub scoring: ScoringConfig,
    pub chain: ChainConfig,
    pub honeypot: HoneypotConfig,
    pub proxy: ProxyConfig,
    pub limits: LimitsConfig,
    pub intel: IntelConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 1,
            shield: ShieldConfig::default(),
            scoring: ScoringConfig::default(),
            chain: ChainConfig::default(),
            honeypot: HoneypotConfig::default(),
            proxy: ProxyConfig::default(),
            limits: LimitsConfig::default(),
            intel: IntelConfig::default(),
        }
    }
}

/// Data-plane settings that the engine itself does not use.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Peers whose `X-Forwarded-For` is trusted (exact IPs).
    pub trusted_proxies: Vec<String>,
    /// Whether decision headers are added to the forwarded request.
    pub decision_headers: DecisionHeaders,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionHeaders {
    /// Never emit decision headers.
    #[default]
    Off,
    /// Add X-Venusflytrap-* to the forwarded request only (never to the client).
    Upstream,
}

/// Source lists checked before inspection. Exact addresses; an IPv4-mapped
/// IPv6 entry is matched as IPv4.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntelConfig {
    /// Sources always answered with Block (a hard pin), unless also allow-listed.
    pub deny_ips: Vec<String>,
    /// Sources never banned and never deny-pinned. They are still inspected.
    pub allow_ips: Vec<String>,
}

/// Request-level limits on the data plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_body: usize,
    pub max_headers: usize,
    pub max_connections: usize,
    pub header_read_timeout_ms: u64,
    pub body_read_timeout_ms: u64,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_response_timeout_ms: u64,
    /// Max gap between upstream response-body frames before the response is aborted.
    pub response_idle_timeout_ms: u64,
    /// Hard cap on one client connection's lifetime; its slot is released on expiry.
    pub max_connection_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_body: 1024 * 1024,
            max_headers: 100,
            max_connections: 1024,
            header_read_timeout_ms: 10_000,
            body_read_timeout_ms: 30_000,
            upstream_connect_timeout_ms: 5_000,
            upstream_response_timeout_ms: 30_000,
            response_idle_timeout_ms: 30_000,
            max_connection_ms: 300_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShieldConfig {
    pub max_payload: usize,
    pub decode_cap: u8,
    pub deep_threshold: u8,
    /// Token windows (4096 tokens, overlapping by 64) analyzed per field before
    /// giving up. When they run out the field is reported as `limit.graph-truncated`.
    pub max_graph_windows: usize,
    /// Bytes of one request's fields inspected (each field charged once, so
    /// chunk overlap is free). Default 4 MiB: a 1 MiB body after lossy UTF-8
    /// inflation, plus headers.
    /// Past it the rest is skipped and the request is reported as
    /// `limit.payload-truncated`. Must be >= `max_payload`.
    ///
    /// Scale it together with `max_normalize_work` and the proxy's
    /// `limits.max_body`: lossy UTF-8 can triple a binary body (each invalid byte
    /// becomes a 3-byte U+FFFD), so raising `max_body` alone makes large binary
    /// uploads hard-block on this budget.
    pub max_inspect_bytes: usize,
    /// Folded chars all normalizations of one request may produce (field chunks,
    /// split pieces and the path). Default 8 Mi chars, 2 x `max_inspect_bytes`.
    /// A normalization that could pass it is not run: inspection stops and the
    /// request is reported as `limit.payload-truncated`. Must be >= `max_payload`.
    ///
    /// Scale it together with `max_inspect_bytes` and the proxy's
    /// `limits.max_body`: benign multi-MB text that NFKC expands (ligatures,
    /// squared CJK units, U+FDFA) can reach this cap and hard-block. Inspection
    /// time grows roughly linearly with it.
    pub max_normalize_work: usize,
    /// Construct or decoder ids switched off (see `venusflytrap ablate`).
    /// Every id must be registered; unknown ids fail validation.
    pub disabled: Vec<String>,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        ShieldConfig {
            max_payload: 64 * 1024,
            decode_cap: 14,
            deep_threshold: 3,
            max_graph_windows: 32,
            max_inspect_bytes: 4 * 1024 * 1024,
            max_normalize_work: 8 * 1024 * 1024,
            disabled: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScoringConfig {
    /// Per-engine weight multipliers.
    pub weight_graph: f32,
    pub weight_signature: f32,
    pub weight_intent: f32,
    pub weight_api: f32,
    pub weight_ai: f32,
    /// Verdict band thresholds (0..=100).
    pub block_at: u8,
    pub challenge_at: u8,
    pub monitor_at: u8,
    /// Conflict threshold for the lattice (weight above which Safe vs Dangerous
    /// is a real conflict).
    pub conflict_threshold: f32,
    /// How much a chain stage advance adds to the score.
    pub chain_stage_bonus: u8,
    /// Upper bound on the total points corroborating signals may add.
    pub corroboration_cap: f32,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        ScoringConfig {
            weight_graph: 1.0,
            weight_signature: 0.9,
            weight_intent: 0.7,
            weight_api: 0.6,
            weight_ai: 0.5,
            block_at: 90,
            challenge_at: 70,
            monitor_at: 40,
            conflict_threshold: 0.6,
            chain_stage_bonus: 15,
            corroboration_cap: 15.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChainConfig {
    /// Events older than this no longer count toward a source's stage.
    pub window_secs: u64,
    /// Bounded LRU of tracked sources (bans are tracked separately).
    pub max_sources: usize,
    pub events_per_source: usize,
    /// IPv6 sources are aggregated to this prefix length.
    pub ipv6_prefix: u8,
    pub ban_policy: BanPolicy,
}

impl Default for ChainConfig {
    fn default() -> Self {
        ChainConfig {
            window_secs: 3600,
            max_sources: 4096,
            events_per_source: 64,
            ipv6_prefix: 64,
            ban_policy: BanPolicy::default(),
        }
    }
}

/// When a source gets banned, and for how long.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BanPolicy {
    pub on_honeypot: bool,
    /// A single exfiltration block is a ban trigger. Off by default:
    /// exfiltration blocks still count toward `exploitation_blocks`.
    pub on_exfiltration_block: bool,
    /// Ban after this many exploitation blocks within `within_secs`.
    /// A "block" here is a Challenge or Block verdict: both are answered
    /// with 403 in enforce mode.
    pub exploitation_blocks: u32,
    pub within_secs: u64,
    /// First ban length; doubles on each re-offence up to `ttl_max_secs`.
    pub ttl_secs: u64,
    pub ttl_max_secs: u64,
    pub max_bans: usize,
    /// An automatic ban also needs hostile requests to be at least this share
    /// of the source's requests in the last `within_secs`, so a busy shared
    /// source (NAT) is not banned for a few blocks among benign traffic.
    /// 0 turns the gate off.
    pub min_hostile_share: f64,
}

impl Default for BanPolicy {
    fn default() -> Self {
        BanPolicy {
            on_honeypot: true,
            on_exfiltration_block: false,
            exploitation_blocks: 3,
            within_secs: 600,
            ttl_secs: 3600,
            ttl_max_secs: 86_400,
            max_bans: 100_000,
            min_hostile_share: 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HoneypotConfig {
    /// Decoy paths that no legitimate client should touch.
    pub decoy_paths: Vec<String>,
    /// Sensitive recon paths (CRS restricted-files flavored).
    pub sensitive_paths: Vec<String>,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        HoneypotConfig {
            decoy_paths: [
                "/admin/backup.zip",
                "/wp-admin/secret",
                "/.git/config",
                "/phpmyadmin/",
                "/_internal/debug",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            sensitive_paths: [
                "/.env",
                "/.git/",
                "/.npmrc",
                "/actuator",
                "/actuator/configprops",
                "/actuator/env",
                "/info.php",
                "/phpinfo.php",
                "/server-status",
                "/.aws/credentials",
                "/config.json",
                "/.ssh/id_rsa",
                "/wp-config.php",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

/// One problem with one option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIssue {
    pub key: String,
    pub message: String,
}

impl std::fmt::Display for ConfigIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

/// Error loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("invalid config: {}", .0.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("; "))]
    Invalid(Vec<ConfigIssue>),
}

impl Config {
    /// Load and validate a YAML file. A missing file is an error.
    pub fn load(path: &std::path::Path) -> Result<Config, ConfigError> {
        Config::from_yaml_str(&std::fs::read_to_string(path)?)
    }

    /// `None` means built-in defaults; `Some(path)` must exist and validate.
    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Config, ConfigError> {
        match path {
            Some(p) => Config::load(p),
            None => Ok(Config::default()),
        }
    }

    /// Parse and validate YAML. Unknown keys, wrong types and out-of-bounds
    /// values are reported per key, all at once.
    pub fn from_yaml_str(s: &str) -> Result<Config, ConfigError> {
        from_tree(crate::options::yaml_tree(s)?)
    }

    /// Per-key bounds (from `options::REGISTRY`) and cross-field rules. Every
    /// issue names its option key.
    pub fn validate(&self) -> Result<(), Vec<ConfigIssue>> {
        let mut v = match serde_json::to_value(self) {
            Ok(tree) => crate::options::check_tree(&tree),
            Err(e) => vec![ConfigIssue { key: "<config>".into(), message: e.to_string() }],
        };
        v.extend(self.cross_field_issues());
        if v.is_empty() {
            Ok(())
        } else {
            Err(v)
        }
    }

    fn cross_field_issues(&self) -> Vec<ConfigIssue> {
        let mut v: Vec<ConfigIssue> = Vec::new();
        let mut bad = |key: &str, message: String| v.push(ConfigIssue { key: key.into(), message });
        let sh = &self.shield;
        if sh.deep_threshold > sh.decode_cap {
            bad("shield.deep_threshold", format!("must be <= shield.decode_cap ({}), got {}", sh.decode_cap, sh.deep_threshold));
        }
        if sh.max_inspect_bytes < sh.max_payload {
            bad("shield.max_inspect_bytes", format!("must be >= shield.max_payload ({}), got {}", sh.max_payload, sh.max_inspect_bytes));
        }
        if sh.max_normalize_work < sh.max_payload {
            bad("shield.max_normalize_work", format!("must be >= shield.max_payload ({}), got {}", sh.max_payload, sh.max_normalize_work));
        }
        let s = &self.scoring;
        if !(s.monitor_at < s.challenge_at && s.challenge_at < s.block_at && s.block_at <= 100) {
            bad(
                "scoring.block_at",
                format!(
                    "bands must satisfy monitor_at < challenge_at < block_at <= 100, got {}/{}/{}",
                    s.monitor_at, s.challenge_at, s.block_at
                ),
            );
        }
        let b = &self.chain.ban_policy;
        if b.ttl_max_secs < b.ttl_secs {
            bad("chain.ban_policy.ttl_max_secs", format!("must be >= ttl_secs ({}), got {}", b.ttl_secs, b.ttl_max_secs));
        }
        v
    }
}

/// Check a config tree per key, deserialize it, then apply the cross-field rules.
pub(crate) fn from_tree(tree: serde_json::Value) -> Result<Config, ConfigError> {
    let issues = crate::options::check_tree(&tree);
    if !issues.is_empty() {
        return Err(ConfigError::Invalid(issues));
    }
    let tree = if tree.is_null() { serde_json::Value::Object(Default::default()) } else { tree };
    let cfg: Config = serde_json::from_value(tree)
        .map_err(|e| ConfigError::Invalid(vec![ConfigIssue { key: "<config>".into(), message: e.to_string() }]))?;
    cfg.validate().map_err(ConfigError::Invalid)?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issues(yaml: &str) -> Vec<ConfigIssue> {
        let cfg: Config = serde_yaml::from_str(yaml).expect("parses");
        cfg.validate().err().unwrap_or_default()
    }

    #[test]
    fn inspect_budget_at_least_one_field() {
        assert!(issues("shield:
  max_inspect_bytes: 1000
").iter().any(|i| i.key == "shield.max_inspect_bytes"));
        assert!(issues("shield:
  max_inspect_bytes: 1048576
").is_empty());
    }

    #[test]
    fn normalize_work_at_least_one_field() {
        assert_eq!(Config::default().shield.max_normalize_work, 2 * Config::default().shield.max_inspect_bytes);
        assert!(issues("shield:
  max_normalize_work: 1000
").iter().any(|i| i.key == "shield.max_normalize_work"));
        assert!(issues("shield:
  max_normalize_work: 65536
").is_empty());
    }

    #[test]
    fn graph_windows_bounds() {
        assert!(issues("shield:
  max_graph_windows: 0
").iter().any(|i| i.key == "shield.max_graph_windows"));
        assert!(issues("shield:
  max_graph_windows: 32
").is_empty());
    }

    #[test]
    fn disabled_ids_must_be_registered() {
        assert!(issues("shield:\n  disabled: [nope.nope]\n").iter().any(|i| i.key == "shield.disabled"));
        assert!(issues("shield:\n  disabled: [sqli.union-select]\n").is_empty());
    }

    #[test]
    fn defaults_and_shipped_yaml_validate() {
        assert!(Config::default().validate().is_ok());
        let shipped: Config =
            serde_yaml::from_str(include_str!("../../../config/shield.yaml")).expect("shipped yaml parses");
        assert!(shipped.validate().is_ok(), "{:?}", shipped.validate());
        assert_eq!(shipped.chain.ban_policy, BanPolicy::default());
    }

    #[test]
    fn hostile_share_must_be_a_fraction() {
        for bad in ["-0.1", "1.1", ".nan"] {
            let y = format!("chain:\n  ban_policy:\n    min_hostile_share: {bad}\n");
            assert!(issues(&y).iter().any(|i| i.key == "chain.ban_policy.min_hostile_share"), "{bad}");
        }
        assert!(issues("chain:\n  ban_policy:\n    min_hostile_share: 0\n").is_empty());
        assert!(issues("chain:\n  ban_policy:\n    min_hostile_share: 1\n").is_empty());
    }

    #[test]
    fn unknown_key_is_rejected() {
        let r: Result<Config, _> = serde_yaml::from_str("scoring:\n  blok_at: 10\n");
        assert!(r.is_err(), "typo must not be silently ignored");
    }

    #[test]
    fn bad_values_report_their_key() {
        assert!(issues("scoring:\n  block_at: 0\n").iter().any(|i| i.key == "scoring.block_at"));
        assert!(issues("scoring:\n  weight_ai: .nan\n").iter().any(|i| i.key == "scoring.weight_ai"));
        assert!(issues("shield:\n  max_payload: 0\n").iter().any(|i| i.key == "shield.max_payload"));
        assert!(issues("chain:\n  ban_policy:\n    ttl_max_secs: 1\n")
            .iter()
            .any(|i| i.key == "chain.ban_policy.ttl_max_secs"));
        assert!(issues("proxy:\n  trusted_proxies: [\"10.0.0.1\", \"proxy.example\"]\n")
            .iter()
            .any(|i| i.key == "proxy.trusted_proxies"));
        assert!(issues("proxy:\n  trusted_proxies: [\"10.0.0.1\", \"::1\"]\n").is_empty());
    }

    #[test]
    fn intel_lists_must_be_ip_addresses() {
        assert!(issues("intel:\n  deny_ips: [\"1.2.3.4\", \"nope\"]\n").iter().any(|i| i.key == "intel.deny_ips"));
        assert!(issues("intel:\n  allow_ips: [\"10.0.0.1:80\"]\n").iter().any(|i| i.key == "intel.allow_ips"));
        assert!(issues("intel:\n  deny_ips: [\"::1\"]\n  allow_ips: [\"192.0.2.1\"]\n").is_empty());
    }

    #[test]
    fn limits_are_validated() {
        for (yaml, key) in [
            ("limits:\n  max_body: 1000\n", "limits.max_body"),
            ("limits:\n  max_headers: 7\n", "limits.max_headers"),
            ("limits:\n  max_connections: 0\n", "limits.max_connections"),
            ("limits:\n  header_read_timeout_ms: 0\n", "limits.header_read_timeout_ms"),
            ("limits:\n  upstream_response_timeout_ms: 0\n", "limits.upstream_response_timeout_ms"),
            ("limits:\n  response_idle_timeout_ms: 0\n", "limits.response_idle_timeout_ms"),
            ("limits:\n  max_connection_ms: 0\n", "limits.max_connection_ms"),
        ] {
            assert!(issues(yaml).iter().any(|i| i.key == key), "{key}");
        }
        assert!(issues("proxy:\n  decision_headers: upstream\nlimits:\n  max_body: 2048\n").is_empty());
    }

    #[test]
    fn chain_capacity_minimums_leave_ten_slots_per_shard() {
        assert!(issues("chain:\n  max_sources: 639\n").iter().any(|i| i.key == "chain.max_sources"));
        assert!(issues("chain:\n  ban_policy:\n    max_bans: 639\n")
            .iter()
            .any(|i| i.key == "chain.ban_policy.max_bans"));
        assert!(issues("chain:\n  max_sources: 640\n  ban_policy:\n    max_bans: 640\n").is_empty());
    }

    #[test]
    fn missing_explicit_file_is_an_error() {
        let r = Config::load_or_default(Some(std::path::Path::new("Z:/definitely/not/here.yaml")));
        assert!(r.is_err());
    }

    #[test]
    fn version_defaults_to_one_and_other_versions_are_rejected() {
        assert_eq!(Config::default().version, 1);
        assert!(issues("version: 1\n").is_empty());
        assert!(issues("version: 2\n").iter().any(|i| i.key == "version"));
        let shipped: Config =
            serde_yaml::from_str(include_str!("../../../config/shield.yaml")).expect("shipped yaml parses");
        assert_eq!(shipped.version, 1);
    }

    #[test]
    fn m6_bad_inputs_yield_per_key_issues() {
        for (yaml, key) in [
            ("scoring:\n  blok_at: 10\n", "scoring.blok_at"),
            ("scoring:\n  block_at: 0\n", "scoring.block_at"),
            ("scoring:\n  weight_ai: .nan\n", "scoring.weight_ai"),
            ("shield:\n  max_payload: 0\n", "shield.max_payload"),
            ("shield:\n  decode_cap: banana\n", "shield.decode_cap"),
            ("nonsense: 1\n", "nonsense"),
        ] {
            match Config::from_yaml_str(yaml) {
                Err(ConfigError::Invalid(issues)) => {
                    assert!(issues.iter().any(|i| i.key == key), "{yaml:?}: {issues:?}")
                }
                other => panic!("{yaml:?}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn empty_and_shipped_files_load() {
        assert!(Config::from_yaml_str("").is_ok());
        assert!(Config::from_yaml_str(include_str!("../../../config/shield.yaml")).is_ok());
    }

    #[test]
    fn cross_field_rules_still_apply() {
        assert!(issues("shield:\n  decode_cap: 4\n  deep_threshold: 5\n").iter().any(|i| i.key == "shield.deep_threshold"));
        assert!(issues("scoring:\n  monitor_at: 80\n").iter().any(|i| i.key == "scoring.block_at"));
    }
}
