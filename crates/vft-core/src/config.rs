//! FR8 — Configuration. Serde structs mirroring the article's YAML files, each
//! with a sensible `Default` so the engine runs with zero configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub shield: ShieldConfig,
    pub scoring: ScoringConfig,
    pub chain: ChainConfig,
    pub honeypot: HoneypotConfig,
    pub proxy: ProxyConfig,
    pub limits: LimitsConfig,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BanPolicy {
    pub on_honeypot: bool,
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
}

impl Default for BanPolicy {
    fn default() -> Self {
        BanPolicy {
            on_honeypot: true,
            on_exfiltration_block: true,
            exploitation_blocks: 3,
            within_secs: 600,
            ttl_secs: 3600,
            ttl_max_secs: 86_400,
            max_bans: 100_000,
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
        let s = std::fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&s)?;
        cfg.validate().map_err(ConfigError::Invalid)?;
        Ok(cfg)
    }

    /// `None` means built-in defaults; `Some(path)` must exist and validate.
    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Config, ConfigError> {
        match path {
            Some(p) => Config::load(p),
            None => Ok(Config::default()),
        }
    }

    /// Per-key bounds and cross-field rules. Every issue names its option key.
    pub fn validate(&self) -> Result<(), Vec<ConfigIssue>> {
        let mut v: Vec<ConfigIssue> = Vec::new();
        let mut bad = |key: &str, message: String| v.push(ConfigIssue { key: key.into(), message });

        let sh = &self.shield;
        if sh.max_payload < 1024 {
            bad("shield.max_payload", format!("must be >= 1024, got {}", sh.max_payload));
        }
        if !(1..=32).contains(&sh.decode_cap) {
            bad("shield.decode_cap", format!("must be in 1..=32, got {}", sh.decode_cap));
        }
        if sh.deep_threshold == 0 || sh.deep_threshold > sh.decode_cap {
            bad("shield.deep_threshold", format!("must be in 1..=decode_cap, got {}", sh.deep_threshold));
        }
        for id in crate::graph::sinks::unknown_ids(&sh.disabled) {
            bad("shield.disabled", format!("unknown construct id {id:?}"));
        }

        let s = &self.scoring;
        for (key, w) in [
            ("scoring.weight_graph", s.weight_graph),
            ("scoring.weight_signature", s.weight_signature),
            ("scoring.weight_intent", s.weight_intent),
            ("scoring.weight_api", s.weight_api),
            ("scoring.weight_ai", s.weight_ai),
        ] {
            if !w.is_finite() || !(0.0..=2.0).contains(&w) {
                bad(key, format!("must be a finite number in [0, 2], got {w}"));
            }
        }
        if !s.conflict_threshold.is_finite() || !(0.0..=1.0).contains(&s.conflict_threshold) {
            bad("scoring.conflict_threshold", format!("must be in [0, 1], got {}", s.conflict_threshold));
        }
        if !s.corroboration_cap.is_finite() || !(0.0..=50.0).contains(&s.corroboration_cap) {
            bad("scoring.corroboration_cap", format!("must be in [0, 50], got {}", s.corroboration_cap));
        }
        if s.monitor_at == 0 {
            bad("scoring.monitor_at", "must be >= 1 (0 would flag every request)".into());
        }
        if !(s.monitor_at < s.challenge_at && s.challenge_at < s.block_at && s.block_at <= 100) {
            bad(
                "scoring.block_at",
                format!(
                    "bands must satisfy monitor_at < challenge_at < block_at <= 100, got {}/{}/{}",
                    s.monitor_at, s.challenge_at, s.block_at
                ),
            );
        }

        let c = &self.chain;
        if c.window_secs == 0 {
            bad("chain.window_secs", "must be >= 1".into());
        }
        if c.max_sources < 640 {
            bad("chain.max_sources", format!("must be >= 640 (at least 10 per shard), got {}", c.max_sources));
        }
        if c.events_per_source == 0 {
            bad("chain.events_per_source", "must be >= 1".into());
        }
        if !(1..=128).contains(&c.ipv6_prefix) {
            bad("chain.ipv6_prefix", format!("must be in 1..=128, got {}", c.ipv6_prefix));
        }
        let b = &c.ban_policy;
        if b.exploitation_blocks == 0 {
            bad("chain.ban_policy.exploitation_blocks", "must be >= 1".into());
        }
        if b.within_secs == 0 {
            bad("chain.ban_policy.within_secs", "must be >= 1".into());
        }
        if b.ttl_secs == 0 {
            bad("chain.ban_policy.ttl_secs", "must be >= 1".into());
        }
        if b.ttl_max_secs < b.ttl_secs {
            bad("chain.ban_policy.ttl_max_secs", format!("must be >= ttl_secs ({}), got {}", b.ttl_secs, b.ttl_max_secs));
        }
        if b.max_bans < 640 {
            bad("chain.ban_policy.max_bans", format!("must be >= 640 (at least 10 per shard), got {}", b.max_bans));
        }

        for p in &self.proxy.trusted_proxies {
            if p.parse::<std::net::IpAddr>().is_err() {
                bad("proxy.trusted_proxies", format!("not an IP address: {p:?}"));
            }
        }

        let l = &self.limits;
        if l.max_body < 1024 {
            bad("limits.max_body", format!("must be >= 1024, got {}", l.max_body));
        }
        if !(8..=1000).contains(&l.max_headers) {
            bad("limits.max_headers", format!("must be in 8..=1000, got {}", l.max_headers));
        }
        if l.max_connections == 0 {
            bad("limits.max_connections", "must be >= 1".into());
        }
        for (key, ms) in [
            ("limits.header_read_timeout_ms", l.header_read_timeout_ms),
            ("limits.body_read_timeout_ms", l.body_read_timeout_ms),
            ("limits.upstream_connect_timeout_ms", l.upstream_connect_timeout_ms),
            ("limits.upstream_response_timeout_ms", l.upstream_response_timeout_ms),
            ("limits.response_idle_timeout_ms", l.response_idle_timeout_ms),
            ("limits.max_connection_ms", l.max_connection_ms),
        ] {
            if ms == 0 {
                bad(key, "must be >= 1".into());
            }
        }

        for (key, list) in [
            ("honeypot.decoy_paths", &self.honeypot.decoy_paths),
            ("honeypot.sensitive_paths", &self.honeypot.sensitive_paths),
        ] {
            if let Some(p) = list.iter().find(|p| !p.starts_with('/')) {
                bad(key, format!("paths must start with '/', got {p:?}"));
            }
        }

        if v.is_empty() {
            Ok(())
        } else {
            Err(v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issues(yaml: &str) -> Vec<ConfigIssue> {
        let cfg: Config = serde_yaml::from_str(yaml).expect("parses");
        cfg.validate().err().unwrap_or_default()
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
}
