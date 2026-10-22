//! FR5 — Honeypot: decoy paths no legitimate client should ever touch.

use crate::config::HoneypotConfig;
use crate::judgment::{Family, Pattern};
use crate::lattice::{Evidence, FourValued};
use crate::request::Request;

pub struct Honeypot {
    decoys: Vec<String>,
}

impl Honeypot {
    pub fn new(cfg: &HoneypotConfig) -> Self {
        Honeypot {
            decoys: cfg.decoy_paths.iter().map(|p| p.to_lowercase()).collect(),
        }
    }

    /// A decoy hit is a near-certain attacker: real users never request these.
    pub fn check(&self, req: &Request) -> Option<Evidence> {
        let path = req.path.to_lowercase();
        if self.decoys.iter().any(|d| path == *d || path.starts_with(d)) {
            Some(Evidence::new(
                FourValued::Dangerous,
                1.0,
                vec![Pattern::new(Family::Honeypot, "decoy-hit")],
                format!("honeypot decoy path hit: {path}"),
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HoneypotConfig;

    #[test]
    fn decoy_hit_is_dangerous() {
        let hp = Honeypot::new(&HoneypotConfig::default());
        let req = Request::get("/.git/config");
        let e = hp.check(&req).expect("should hit decoy");
        assert_eq!(e.value, FourValued::Dangerous);
    }

    #[test]
    fn ordinary_path_no_hit() {
        let hp = Honeypot::new(&HoneypotConfig::default());
        assert!(hp.check(&Request::get("/index.html")).is_none());
    }
}
