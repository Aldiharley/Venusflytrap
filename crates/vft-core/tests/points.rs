//! Σ contribution points reproduces the score (SP2 acceptance).

use proptest::prelude::*;
use vft_core::{Config, Judgment, Request, Shield};

fn sum(j: &Judgment) -> f32 {
    j.contributions.iter().map(|c| c.points).sum()
}

fn assert_adds_up(j: &Judgment, what: &str) {
    assert!((sum(j) - f32::from(j.score)).abs() <= 1.0, "{what}: Σ points {} vs score {}", sum(j), j.score);
}

#[test]
fn points_add_up_on_known_requests() {
    let s = Shield::new(Config::default());
    assert_adds_up(&s.inspect(&Request::get("/.git/config")), "honeypot");
    assert_adds_up(&s.inspect(&Request::get("/.env")), "recon");
    assert_adds_up(&s.inspect(&Request::get("/index.html")), "benign");
    let mut q = Request::get("/items");
    q.query.push(("id".into(), "1 union select password from users".into()));
    assert_adds_up(&s.inspect(&q), "sqli");
    let mut x = Request::get("/p");
    x.query.push(("q".into(), "<img src=x onerror=alert(1)>".into()));
    for i in 0..30 {
        x.query.push((format!("c{i}"), "red;blue".into()));
    }
    assert_adds_up(&s.inspect(&x), "xss plus capped corroboration");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn points_add_up_on_arbitrary_values(v in ".{0,300}", h in ".{0,100}") {
        let s = Shield::new(Config::default());
        let mut r = Request::get("/p");
        r.query.push(("q".into(), v));
        r.headers.push(("X-Test".into(), h));
        let j = s.inspect(&r);
        prop_assert!((sum(&j) - f32::from(j.score)).abs() <= 1.0, "Σ {} vs {}", sum(&j), j.score);
    }
}
