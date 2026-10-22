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

#[test]
fn huge_payload_is_bounded() {
    let big = "A".repeat(2_000_000);
    let dur = inspect_value(&big);
    assert!(dur < Duration::from_secs(1), "took {dur:?}");
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
