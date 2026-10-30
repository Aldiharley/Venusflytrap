//! An exception never raises a request's score or verdict.
use proptest::prelude::*;
use vft_core::exceptions::{parse_date, ExceptionClock, Exceptions};
use vft_core::{Config, Request, Shield};

const PAYLOADS: &[&str] = &[
    "1' or '1'='1", "1 union select a from b", "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "../../../etc/passwd", "a; cat /etc/passwd", "$(id)", "garden hose", "javascript:alert(1)", "1;drop table t--",
];
const CONSTRUCTS: &[&str] = &["sqli.*", "xss.*", "cmd.*", "path.*", "anomaly.*", "sqli.union-select", "xss.script-tag"];
const ACTIONS: &[&str] = &["ignore", "log-only", "skip-inspection"];
const FIELDS: &[&str] = &["", "      field: { loc: query, name: q }\n", "      field: { loc: header, name: referer }\n", "      field: { loc: query, name: \"*\" }\n"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn never_raises(q in 0..PAYLOADS.len(), r in 0..PAYLOADS.len(), a in 0..ACTIONS.len(), c in 0..CONSTRUCTS.len(), f in 0..FIELDS.len()) {
        let mut req = Request::get("/search");
        req.query.push(("q".into(), PAYLOADS[q].into()));
        req.headers.push(("Referer".into(), PAYLOADS[r].into()));
        let action = ACTIONS[a];
        let field = if action == "skip-inspection" && !FIELDS[f].contains("name: q") && !FIELDS[f].contains("referer") { FIELDS[1] } else { FIELDS[f] };
        let cs = if action == "skip-inspection" { String::new() } else { format!("    constructs: [{}]\n", CONSTRUCTS[c]) };
        let y = format!("version: 1\nexceptions:\n  - id: p\n    action: {action}\n{cs}    scope:\n      path_prefix: /\n{field}    owner: o\n    reason: r\n    created: 2026-10-30\n    modified: 2026-10-30\n    expires: 2026-11-30\n");
        let ex = Exceptions::from_yaml_str(&y, parse_date("2026-10-30").unwrap()).unwrap();
        let base = Shield::new(Config::default()).inspect(&req);
        let with = Shield::new(Config::default()).with_exceptions(ex, ExceptionClock::Fixed).inspect(&req);
        prop_assert!(with.score <= base.score, "score {} > {} for {y}", with.score, base.score);
        prop_assert!(with.verdict.rank() <= base.verdict.rank());
    }
}
