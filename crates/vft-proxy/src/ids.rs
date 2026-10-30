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
            hi >> 32,
            (hi >> 16) & 0xffff,
            hi & 0xffff,
            lo >> 48,
            lo & 0xffff_ffff_ffff
        )
    }
}

impl Default for EventIds {
    fn default() -> Self {
        Self::new()
    }
}

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
        assert_eq!(&hex[12..13], "7"); // version
        assert!(matches!(&hex[16..17], "8" | "9" | "a" | "b")); // RFC 9562 variant
    }
}
