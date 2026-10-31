//! Component health board shared by the runtime, admin API and metrics.

use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

/// Health of a component, ordered from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Health {
    Ok,
    Warn,
    Degraded,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentStatus {
    pub name: &'static str,
    pub health: Health,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusRecord {
    /// Worst health across components.
    pub health: Health,
    /// proxy, config, bus, history — in that order.
    pub components: Vec<ComponentStatus>,
    pub config_rev: u64,
    pub restart_required: Vec<String>,
    /// Dropped events per bus consumer.
    pub drops: BTreeMap<String, u64>,
    pub version: &'static str,
    pub uptime_s: u64,
}

struct State {
    components: Vec<ComponentStatus>,
    config_rev: u64,
    restart_required: Vec<String>,
    drops: BTreeMap<String, u64>,
}

pub struct StatusBoard {
    state: Mutex<State>,
    start: Instant,
}

impl Default for StatusBoard {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusBoard {
    /// All components start `Ok`.
    pub fn new() -> Self {
        let components = ["proxy", "config", "bus", "history"]
            .into_iter()
            .map(|name| ComponentStatus {
                name,
                health: Health::Ok,
                reason: String::new(),
            })
            .collect();
        Self {
            state: Mutex::new(State {
                components,
                config_rev: 0,
                restart_required: Vec::new(),
                drops: BTreeMap::new(),
            }),
            start: Instant::now(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned board is still the best information we have.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Set a component's health and reason. An unknown name is appended.
    pub fn set(&self, name: &'static str, health: Health, reason: impl Into<String>) {
        let reason = reason.into();
        let mut st = self.lock();
        match st.components.iter_mut().find(|c| c.name == name) {
            Some(c) => {
                c.health = health;
                c.reason = reason;
            }
            None => st.components.push(ComponentStatus {
                name,
                health,
                reason,
            }),
        }
    }

    pub fn set_config(&self, rev: u64, restart_required: Vec<String>) {
        let mut st = self.lock();
        st.config_rev = rev;
        st.restart_required = restart_required;
    }

    pub fn add_drops(&self, consumer: &str, n: u64) {
        let mut st = self.lock();
        let slot = st.drops.entry(consumer.to_string()).or_insert(0);
        *slot = slot.saturating_add(n);
    }

    pub fn snapshot(&self) -> StatusRecord {
        let st = self.lock();
        StatusRecord {
            health: st
                .components
                .iter()
                .map(|c| c.health)
                .max()
                .unwrap_or(Health::Ok),
            components: st.components.clone(),
            config_rev: st.config_rev,
            restart_required: st.restart_required.clone(),
            drops: st.drops.clone(),
            version: env!("CARGO_PKG_VERSION"),
            uptime_s: self.start.elapsed().as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_board_is_all_ok_in_fixed_order() {
        let s = StatusBoard::new().snapshot();
        assert_eq!(s.health, Health::Ok);
        let names: Vec<_> = s.components.iter().map(|c| c.name).collect();
        assert_eq!(names, ["proxy", "config", "bus", "history"]);
        assert!(s.components.iter().all(|c| c.health == Health::Ok));
        assert_eq!(s.config_rev, 0);
        assert!(s.restart_required.is_empty());
        assert!(s.drops.is_empty());
        assert_eq!(s.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn health_rollup_is_worst_component() {
        let b = StatusBoard::new();
        b.set("bus", Health::Warn, "slow consumer");
        assert_eq!(b.snapshot().health, Health::Warn);
        b.set("history", Health::Critical, "disk full");
        b.set("config", Health::Degraded, "stale");
        let s = b.snapshot();
        assert_eq!(s.health, Health::Critical);
        b.set("history", Health::Ok, "");
        assert_eq!(b.snapshot().health, Health::Degraded);
    }

    #[test]
    fn snapshot_keeps_component_order_after_updates() {
        let b = StatusBoard::new();
        b.set("history", Health::Warn, "x");
        b.set("proxy", Health::Degraded, "y");
        let s = b.snapshot();
        let names: Vec<_> = s.components.iter().map(|c| c.name).collect();
        assert_eq!(names, ["proxy", "config", "bus", "history"]);
        assert_eq!(s.components[0].reason, "y");
        assert_eq!(s.components[3].health, Health::Warn);
    }

    #[test]
    fn config_and_drops_accumulate() {
        let b = StatusBoard::new();
        b.set_config(7, vec!["listen".to_string()]);
        b.add_drops("history", 2);
        b.add_drops("history", 3);
        b.add_drops("ocsf", 1);
        let s = b.snapshot();
        assert_eq!(s.config_rev, 7);
        assert_eq!(s.restart_required, ["listen"]);
        assert_eq!(s.drops["history"], 5);
        assert_eq!(s.drops["ocsf"], 1);
    }

    #[test]
    fn health_serialises_as_name_and_orders() {
        assert!(
            Health::Ok < Health::Warn
                && Health::Warn < Health::Degraded
                && Health::Degraded < Health::Critical
        );
        assert_eq!(
            serde_json::to_string(&Health::Degraded).unwrap(),
            "\"Degraded\""
        );
    }
}
