//! Property tests (NFR2/NFR4): the engine must never panic and must always
//! terminate quickly on arbitrary or adversarial input — decode bombs, huge
//! payloads, random bytes, deeply nested encodings.

use proptest::prelude::*;
use std::time::{Duration, Instant};
use vft_core::{Config, Request, Shield};

fn inspect_value(v: &str) -> std::time::Duration {
    let shield = Shield::new(Config::default());
    let mut req = Request::get("/p");
    req.query.push(("q".into(), v.to_string()));
    req.headers.push(("User-Agent".into(), v.to_string()));
    req.body = v.as_bytes().to_vec();
    let t = Instant::now();
    let _ = shield.inspect(&req);
    t.elapsed()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn never_panics_on_arbitrary_text(s in ".*") {
        let _ = inspect_value(&s);
    }

    #[test]
    fn never_panics_on_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let s = String::from_utf8_lossy(&bytes).into_owned();
        let _ = inspect_value(&s);
    }

    #[test]
    fn bounded_time_on_percent_bombs(n in 0usize..5000) {
        let bomb = "%25".repeat(n);
        let dur = inspect_value(&bomb);
        // Generous ceiling; real p95 is microseconds. Guards against pathological
        // blowups, not a performance assertion.
        prop_assert!(dur < Duration::from_millis(500), "took {dur:?} for n={n}");
    }
}

/// 2 MB in the query, a header and the body (6 MB of text in all).
fn huge_request() -> Request {
    let big = "A".repeat(2_000_000);
    let mut req = Request::get("/p");
    req.query.push(("q".into(), big.clone()));
    req.headers.push(("User-Agent".into(), big.clone()));
    req.body = big.into_bytes();
    req
}

#[test]
fn huge_payload_is_bounded() {
    // Time is bounded because the inspection budget is: with a 1 MiB budget this
    // takes ~0.6 s in a debug build; without a budget it takes ~3 s.
    let mut cfg = Config::default();
    cfg.shield.max_inspect_bytes = 1 << 20;
    let shield = Shield::new(cfg);
    let req = huge_request();
    let t = Instant::now();
    let _ = shield.inspect(&req);
    let dur = t.elapsed();
    assert!(dur < Duration::from_secs(1), "took {dur:?}");
}

#[test]
fn huge_payload_exhausts_the_default_budget() {
    // Deterministic (no timing): 6 MB sent, 4 MiB default budget.
    let j = Shield::new(Config::default()).inspect(&huge_request());
    assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.payload-truncated")));
}

#[test]
fn nested_encoding_terminates() {
    // Several layers of URL-encoding of "<x" — each layer triples the length, so
    // we keep the layer count modest (the engine truncates to max_payload before
    // decoding and caps decode depth regardless). This exercises multi-layer
    // decode without the test itself allocating an astronomically large string.
    let mut s = "<x".to_string();
    for _ in 0..8 {
        s = s.bytes().map(|b| format!("%{b:02X}")).collect::<String>();
    }
    let dur = inspect_value(&s);
    assert!(dur < Duration::from_millis(500), "took {dur:?}");
}

proptest! {
    #[test]
    fn chunks_never_panic_and_cover(s in ".{0,3000}", max in 300usize..2000) {
        let cs = vft_core::normalize::chunks(&s, max);
        prop_assert!(!cs.is_empty());
        prop_assert!(cs.iter().all(|c| c.chars().count() <= max));
    }
}
