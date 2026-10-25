//! FR7 — File-backed (with embedded defaults) threat intelligence: IP/ASN
//! allow/deny lists and scanner/C2 user-agent fingerprints. Intel contributes
//! evidence; only an explicit deny-list entry hard-pins to block.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::lattice::{Evidence, FourValued};

/// Default scanner/recon user-agent substrings (lowercased).
const DEFAULT_SCANNER_UA: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "dirbuster",
    "gobuster",
    "wpscan",
    "nuclei",
    "acunetix",
    "nessus",
    "zgrab",
    "curl/7.", // bare curl probing is weakly suspicious, kept low-weight elsewhere
    "python-requests",
];

#[derive(Default)]
pub struct Intel {
    deny_ips: HashSet<IpAddr>,
    allow_ips: HashSet<IpAddr>,
    scanner_ua: Vec<String>,
}

impl Intel {
    pub fn with_defaults() -> Self {
        Intel {
            deny_ips: HashSet::new(),
            allow_ips: HashSet::new(),
            scanner_ua: DEFAULT_SCANNER_UA.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn add_deny_ip(&mut self, ip: IpAddr) {
        self.deny_ips.insert(ip);
    }
    pub fn add_allow_ip(&mut self, ip: IpAddr) {
        self.allow_ips.insert(ip);
    }
    pub fn add_scanner_ua(&mut self, ua: impl Into<String>) {
        self.scanner_ua.push(ua.into().to_lowercase());
    }

    pub fn is_denied(&self, ip: &IpAddr) -> bool {
        self.deny_ips.contains(ip)
    }
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.allow_ips.contains(ip)
    }

    /// Evidence from user-agent fingerprints.
    pub fn ua_evidence(&self, ua: Option<&str>) -> Evidence {
        let Some(ua) = ua else {
            return Evidence::none("no ua");
        };
        let lower = ua.to_lowercase();
        for sig in &self.scanner_ua {
            if lower.contains(sig) {
                // Known offensive tooling is a strong-ish signal but not a sole
                // block basis (UAs are spoofable) — Suspicious, decent weight.
                let weight = if sig.starts_with("curl") || sig.starts_with("python") {
                    0.25
                } else {
                    0.6
                };
                let value = if weight >= 0.5 {
                    FourValued::Suspicious
                } else {
                    FourValued::None
                };
                return Evidence::new(
                    value,
                    weight,
                    vec![crate::graph::sinks::INTEL_SCANNER_UA.pattern()],
                    format!("scanner user-agent fingerprint: {sig}"),
                );
            }
        }
        Evidence::none("ua clean")
    }

    /// Load newline lists from a directory if present (ip_blacklist.txt,
    /// ip_whitelist.txt, scanner_ua.txt). Unknown/malformed lines are skipped.
    pub fn load_dir(&mut self, dir: &std::path::Path) {
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        for line in read("ip_blacklist.txt").lines() {
            if let Ok(ip) = line.trim().parse() {
                self.deny_ips.insert(ip);
            }
        }
        for line in read("ip_whitelist.txt").lines() {
            if let Ok(ip) = line.trim().parse() {
                self.allow_ips.insert(ip);
            }
        }
        for line in read("scanner_ua.txt").lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') {
                self.scanner_ua.push(t.to_lowercase());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn sqlmap_ua_flagged() {
        let intel = Intel::with_defaults();
        let e = intel.ua_evidence(Some("sqlmap/1.7"));
        assert_eq!(e.value, FourValued::Suspicious);
    }

    #[test]
    fn deny_list_works() {
        let mut intel = Intel::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        intel.add_deny_ip(ip);
        assert!(intel.is_denied(&ip));
    }

    #[test]
    fn clean_ua_is_none() {
        let intel = Intel::with_defaults();
        assert_eq!(
            intel.ua_evidence(Some("Mozilla/5.0 (normal browser)")).value,
            FourValued::None
        );
    }
}
