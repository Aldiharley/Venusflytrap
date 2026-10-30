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
