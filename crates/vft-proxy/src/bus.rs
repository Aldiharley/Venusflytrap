//! In-process event bus for the data plane: decisions, bans and config
//! changes. Publishing never blocks and never fails.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::broadcast;

/// One request that reached a decision (a fast-tracked ban included).
#[derive(Debug, Clone)]
pub struct DecisionEvent {
    pub event_id: String,
    pub group_id: Option<String>,
    pub ts_ms: u64,
    /// `SourceKey::ip()` as text, e.g. `"2001:db8:1:2::"` or `"192.0.2.7"`.
    pub src_key: Option<String>,
    pub ip: Option<IpAddr>,
    pub method: String,
    /// The `Host` header, or `""` when absent.
    pub host: String,
    /// The request path without the query string.
    pub path: String,
    pub judgment: vft_core::Judgment,
    /// Handler start to response headers (refusal or upstream headers ready).
    pub latency_us: u64,
    /// The status the upstream sent; `None` when nothing came from upstream
    /// (refused, or a 502/504 the proxy produced itself).
    pub upstream_status: Option<u16>,
    pub config_rev: u64,
    /// Matched-field snippets; filled only when `history.store_snippets` is on.
    pub snippets: Vec<(vft_core::FieldRef, String)>,
}

#[derive(Debug, Clone)]
pub enum BusEvent {
    Decision(Arc<DecisionEvent>),
    ConfigApplied { rev: u64, changed: Vec<String>, restart_required: Vec<String> },
    ConfigRejected { issues: Vec<String> },
    BanChanged { key: String, ban: Option<vft_core::BanRecord>, lifted: bool },
}

/// A cloneable handle on one broadcast channel. A subscriber that falls more
/// than [`EventBus::CAPACITY`] events behind loses the oldest ones and sees
/// `Lagged` on its next receive; the publisher is never slowed down.
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<BusEvent>,
}

impl EventBus {
    pub const CAPACITY: usize = 8192;

    pub fn new() -> Self {
        EventBus { tx: broadcast::channel(Self::CAPACITY).0 }
    }

    /// Never blocks; with no subscribers the event is discarded.
    pub fn publish(&self, ev: BusEvent) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.tx.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};

    fn rejected(n: usize) -> BusEvent {
        BusEvent::ConfigRejected { issues: vec![format!("issue {n}")] }
    }

    #[test]
    fn publish_without_a_subscriber_is_discarded() {
        let bus = EventBus::new();
        bus.publish(rejected(0));
        // A subscriber made afterwards sees nothing from before.
        let mut rx = bus.subscribe();
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn a_subscriber_receives_events_in_order_and_clones_share_the_channel() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let other = bus.clone();
        bus.publish(rejected(1));
        other.publish(rejected(2));
        for want in [1, 2] {
            match rx.try_recv() {
                Ok(BusEvent::ConfigRejected { issues }) => assert_eq!(issues, vec![format!("issue {want}")]),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn a_full_channel_neither_blocks_nor_panics_and_the_slow_subscriber_lags() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe(); // never reads while we publish
        for n in 0..9_000 {
            bus.publish(rejected(n));
        }
        match rx.try_recv() {
            Err(TryRecvError::Lagged(skipped)) => assert_eq!(skipped, 9_000 - EventBus::CAPACITY as u64),
            other => panic!("expected Lagged, got {other:?}"),
        }
        // After the lag notice the newest CAPACITY events are still readable.
        assert!(matches!(rx.try_recv(), Ok(BusEvent::ConfigRejected { .. })));
        let _ = RecvError::Closed; // keep the import honest for async users
    }
}
