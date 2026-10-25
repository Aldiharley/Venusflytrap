//! FR8 — Configuration. Serde structs mirroring the article's YAML files, each
//! with a sensible `Default` so the engine runs with zero configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub shield: ShieldConfig,
    pub scoring: ScoringConfig,
    pub chain: ChainConfig,
    pub honeypot: HoneypotConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShieldConfig {
    pub max_payload: usize,
    pub decode_cap: u8,
    pub deep_threshold: u8,
}

impl Default for ShieldConfig {
    fn default() -> Self {
        ShieldConfig {
            max_payload: 64 * 1024,
            decode_cap: 14,
            deep_threshold: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
pub struct BanPolicy {
    pub on_honeypot: bool,
    pub on_exfiltration_block: bool,
    /// Ban after this many exploitation blocks within `within_secs`.
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
#[serde(default)]
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

/// Error loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] serde_yaml::Error),
}

impl Config {
    /// Load from a YAML file; missing file is not an error — defaults are used.
    pub fn load_or_default(path: Option<&std::path::Path>) -> Result<Config, ConfigError> {
        match path {
            Some(p) if p.exists() => {
                let s = std::fs::read_to_string(p)?;
                Ok(serde_yaml::from_str(&s)?)
            }
            _ => Ok(Config::default()),
        }
    }
}
