//! Shared exception-validation cases (also run by ui/src/lib/exceptions.test.ts),
//! and the construct registry JSON the console's validator reads.
//! Bless the registry: VFT_BLESS_TS=1 cargo test -p vft-core --test exceptions_shared

use serde_json::{json, Value};
use vft_core::exceptions::{parse_date, validate_entry, ExceptionEntry};

fn cases() -> Value {
    serde_json::from_str(include_str!("fixtures/exception-cases.json")).expect("cases parse")
}

fn apply(base: &Value, patch: &Value) -> Value {
    let mut out = base.clone();
    for (k, v) in patch.as_object().expect("patch is an object") {
        if k == "scope" {
            for (sk, sv) in v.as_object().expect("scope patch is an object") {
                out["scope"][sk] = sv.clone();
            }
        } else {
            out[k] = v.clone();
        }
    }
    out
}

#[test]
fn shared_cases_give_their_codes() {
    let c = cases();
    let as_of = parse_date(c["as_of"].as_str().unwrap()).unwrap();
    for case in c["cases"].as_array().unwrap() {
        let v = apply(&c["base"], &case["patch"]);
        let e: ExceptionEntry = serde_json::from_value(v).unwrap_or_else(|err| panic!("{}: {err}", case["name"]));
        let mut got: Vec<&str> = validate_entry(&e, as_of).iter().map(|i| i.code).collect();
        got.sort_unstable();
        got.dedup();
        let want: Vec<&str> = case["codes"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        assert_eq!(got, want, "case {}", case["name"]);
    }
}

#[test]
fn construct_registry_json_is_current() {
    let want: Vec<Value> = vft_core::graph::sinks::constructs()
        .iter()
        .map(|c| json!({ "id": c.id, "family": c.family.map(|f| format!("{f:?}")), "kind": format!("{:?}", c.kind) }))
        .collect();
    let want = serde_json::to_string_pretty(&want).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/construct-registry.json");
    if std::env::var_os("VFT_BLESS_TS").is_some() {
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
    assert_eq!(have, want, "stale construct-registry.json (re-run with VFT_BLESS_TS=1)");
}

/// The YAML the console writes (`toYaml` of its four fixture exceptions, committed by
/// ui/src/lib/exceptions.test.ts) is a file the engine reads. Expired entries are parsed, not validated.
#[test]
fn ui_yaml_deserializes() {
    use vft_core::exceptions::{ExceptionAction, ExceptionsFile, FieldLoc};
    let items = include_str!("../../../ui/src/lib/__fixtures__/exceptions-yaml.txt");
    let file = ExceptionsFile::parse(&format!("version: 1\nexceptions:\n{items}")).unwrap_or_else(|e| panic!("{e:?}"));
    let got: Vec<_> = file.exceptions.iter().map(|e| (e.id.as_str(), e.action)).collect();
    assert_eq!(
        got,
        [
            ("referer-sql", ExceptionAction::Ignore),
            ("utm-xss", ExceptionAction::LogOnly),
            ("hook-signature", ExceptionAction::SkipInspection),
            ("legacy-search", ExceptionAction::Ignore),
        ]
    );
    let by_id = |id: &str| file.exceptions.iter().find(|e| e.id == id).unwrap();
    let utm = by_id("utm-xss");
    assert_eq!(utm.constructs, ["xss.*"]);
    assert!(utm.scope.methods.is_empty());
    let f = utm.scope.field.as_ref().unwrap();
    assert_eq!((f.loc, f.name.as_str()), (FieldLoc::Query, "utm_*"));
    assert!(utm.reason.contains(": watch"), "a colon inside a quoted reason survives: {:?}", utm.reason);
    let hook = by_id("hook-signature");
    assert!(hook.constructs.is_empty());
    assert_eq!(hook.scope.methods, ["POST"]);
    assert_eq!(hook.scope.field.as_ref().map(|f| (f.loc, f.name.as_str())), Some((FieldLoc::Header, "x-signature")));
    // The three live entries are valid on the fixture clock the test blessed them at (2026-10-28); the fourth is only expired.
    let as_of = vft_core::exceptions::parse_date("2026-10-28").unwrap();
    for e in &file.exceptions[..3] {
        assert_eq!(validate_entry(e, as_of), vec![], "{}", e.id);
    }
    let codes: Vec<_> = validate_entry(&file.exceptions[3], as_of).iter().map(|i| i.code).collect();
    assert_eq!(codes, ["expired"]);
}
