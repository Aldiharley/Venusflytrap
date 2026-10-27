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
    assert_eq!(j.verdict, vft_core::Verdict::Block);
}

#[test]
fn nfkc_expansion_flood_terminates() {
    // 300,000 x U+FDFA (NFKC expands each to 18 chars) forces maximal splitting.
    // Deterministic guard: its lossless inspection needs more folded chars than
    // the default shield.max_normalize_work, so inspection stops at the cap and
    // the request hard-blocks (shield.rs unit tests assert the work count itself).
    let flood = "\u{FDFA}".repeat(300_000);
    let shield = Shield::new(Config::default());
    let mut req = Request::get("/p");
    req.query.push(("q".into(), flood));
    let j = shield.inspect(&req);
    assert!(j.contributions.iter().any(|c| c.construct.as_deref() == Some("limit.payload-truncated")));
    assert_eq!(j.verdict, vft_core::Verdict::Block);
    assert_eq!(j.decided_by.kind, vft_core::CauseKind::Limit);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn capped_fold_agrees_with_the_full_fold(s in r"\PC{0,200}", cap in 0usize..400) {
        let full: Vec<char> = vft_core::normalize::fold_unicode(&s).chars().collect();
        let want: String = full.iter().take(cap).collect();
        prop_assert_eq!(vft_core::normalize::fold_unicode_capped(&s, cap), (want, full.len() > cap));
    }
}

/// Release timings for the worst cases of recursive splitting (run with
/// `cargo test --release -p vft-core --test fuzz_props -- --ignored --nocapture`).
#[test]
#[ignore]
fn normalization_work_timings() {
    let fdfa = |n: usize| "\u{FDFA}".repeat(n);
    let body = |b: Vec<u8>| {
        let mut r = Request::get("/p");
        r.method = "POST".into();
        r.body = b;
        r
    };
    let query = |v: String| {
        let mut r = Request::get("/p");
        r.query.push(("q".into(), v));
        r
    };
    let mut many = Request::get("/p");
    for i in 0..64 {
        many.query.push((format!("q{i}"), fdfa(65_536)));
    }
    // The final review's mixed case: runs of five-layer percent-encoding and FDFA.
    let mixed_unit = format!("{}{}", "%252525252541".repeat(400), fdfa(400));
    let mixed = mixed_unit.repeat((4 << 20) / mixed_unit.len());
    let cases: Vec<(&str, Request)> = vec![
        ("1 MiB FDFA body", body(fdfa((1 << 20) / 3).into_bytes())),
        ("single 64 KiB FDFA field", query(fdfa(65_536))),
        ("300,000-FDFA query", query(fdfa(300_000))),
        ("4 MiB single FDFA field", query(fdfa((4 << 20) / 3))),
        ("64 fields x 64 KiB FDFA", many),
        ("ASCII 4 MiB body", body("a".repeat((4 << 20) - 1024).into_bytes())),
        ("4 MiB mixed decode + FDFA query", query(mixed)),
    ];
    let shield = Shield::new(Config::default());
    for (name, req) in &cases {
        let mut best = Duration::MAX;
        let mut j = shield.inspect(req); // warm-up
        for _ in 0..3 {
            let t = Instant::now();
            j = shield.inspect(req);
            best = best.min(t.elapsed());
        }
        eprintln!("{name}: {:?} score {} in {best:?} ({})", j.verdict, j.score, j.decided_by.msg);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn splitting_terminates_on_expanding_and_shrinking_text(
        parts in proptest::collection::vec(
            prop_oneof![Just("\u{FDFA}"), Just("%61"), Just("%2561"), Just("a"), Just(" union select 1 ")],
            0..3000,
        )
    ) {
        let mut cfg = Config::default();
        cfg.shield.max_payload = 1024;
        let mut req = Request::get("/p");
        req.query.push(("q".into(), parts.concat()));
        let j = Shield::new(cfg).inspect(&req);
        prop_assert!(j.score <= 100);
    }
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
