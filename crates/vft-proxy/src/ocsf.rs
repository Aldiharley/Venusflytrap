//! Sub-project A — native OCSF 1.9.0 output. Every judgment becomes one HTTP
//! Activity (4002) record; Challenge and Block add one Detection Finding
//! (2004). Both carry the `security_control` profile.

use serde_json::{json, Map, Value};
use vft_core::{AttackTag, Judgment, Request, Verdict};

pub const VERSION: &str = "1.9.0";

// Enum values confirmed against the committed 1.9.0 schema fixtures.
const ACTION_ALLOWED: u8 = 1;
const ACTION_DENIED: u8 = 2;
const DISPOSITION_ALLOWED: u8 = 1;
const DISPOSITION_BLOCKED: u8 = 2;
const DISPOSITION_LOGGED: u8 = 17;
const CONFIDENCE_LOW: u8 = 1;
const CONFIDENCE_MEDIUM: u8 = 2;
const CONFIDENCE_HIGH: u8 = 3;

/// HTTP Activity `activity_id` for a request method.
/// Methods are case-sensitive (RFC 9110 section 9.1), so only the uppercase tokens match.
fn activity_id(method: &str) -> u32 {
    match method {
        "CONNECT" => 1,
        "DELETE" => 2,
        "GET" => 3,
        "HEAD" => 4,
        "OPTIONS" => 5,
        "POST" => 6,
        "PUT" => 7,
        "TRACE" => 8,
        "PATCH" => 9,
        _ => 99,
    }
}

fn severity_id(v: Verdict) -> u8 {
    match v {
        Verdict::Allow => 1,
        Verdict::Monitor => 2,
        Verdict::Challenge => 3,
        Verdict::Block => 4,
    }
}

fn confidence_id(c: u8) -> u8 {
    match c {
        70.. => CONFIDENCE_HIGH,
        40.. => CONFIDENCE_MEDIUM,
        _ => CONFIDENCE_LOW,
    }
}

/// The 4002 `action_id` and `disposition_id`. Unenforced (`serve --monitor-only`)
/// every request is forwarded, so it is Allowed and Logged whatever the verdict.
fn action_disposition(v: Verdict, enforced: bool) -> (u8, u8) {
    match v {
        _ if !enforced => (ACTION_ALLOWED, DISPOSITION_LOGGED),
        Verdict::Allow => (ACTION_ALLOWED, DISPOSITION_ALLOWED),
        Verdict::Monitor => (ACTION_ALLOWED, DISPOSITION_LOGGED),
        Verdict::Challenge | Verdict::Block => (ACTION_DENIED, DISPOSITION_BLOCKED),
    }
}

/// One OCSF `attack` object. A sub-technique id (`T1595.002`) goes in
/// `sub_technique`, with its parent (`T1595`) in `technique`; the combined
/// name `"Active Scanning: Vulnerability Scanning"` is split on `": "`.
fn attack(a: &AttackTag) -> Value {
    let tactic = json!({ "uid": a.tactic_id, "name": a.tactic });
    match a.id.split_once('.') {
        Some((parent, _)) => {
            let (technique, sub) = a.name.split_once(": ").unwrap_or((&a.name, &a.name));
            json!({
                "tactic": tactic,
                "technique": { "uid": parent, "name": technique },
                "sub_technique": { "uid": a.id, "name": sub },
            })
        }
        None => json!({ "tactic": tactic, "technique": { "uid": a.id, "name": a.name } }),
    }
}

/// Fields every record shares: time, metadata (without `uid`), message.
fn common(j: &Judgment, ts_ms: u64, group_id: Option<&str>) -> Map<String, Value> {
    let mut metadata = json!({
        "version": VERSION,
        "profiles": ["security_control"],
        "product": {
            "name": "Venusflytrap",
            "vendor_name": "Venusflytrap",
            "version": env!("CARGO_PKG_VERSION"),
        },
    });
    if let Some(g) = group_id {
        metadata["correlation_uid"] = json!(g);
    }
    let mut m = Map::new();
    m.insert("time".into(), json!(ts_ms));
    m.insert("metadata".into(), metadata);
    m.insert("message".into(), json!(j.decided_by.msg));
    m
}

/// The OCSF records for one judgment: a 4002, plus a 2004 for Challenge/Block.
///
/// `group_id` (the episode group ID of the decision's source key) becomes
/// `metadata.correlation_uid` on both. Only the 4002 has `metadata.uid =
/// event_id`; the 2004 links to it through `finding_info.uid = event_id`, so
/// no two records share a `metadata.uid`. `enforced` is false when the proxy
/// forwards every request (`serve --monitor-only`): the 4002 then says Allowed
/// and Logged for every verdict, and a Challenge or Block still has its 2004,
/// since the detection happened.
pub fn encode(req: &Request, j: &Judgment, ts_ms: u64, event_id: &str, group_id: Option<&str>, enforced: bool) -> Vec<Value> {
    let base = common(j, ts_ms, group_id);
    let severity = severity_id(j.verdict);
    let detected = matches!(j.verdict, Verdict::Challenge | Verdict::Block);

    let activity = activity_id(&req.method);
    let src_endpoint = req.src_ip.map(|ip| json!({ "ip": ip.to_string() }));
    let http_request = json!({ "http_method": req.method, "url": { "path": req.path } });
    let mut http = base.clone();
    http["metadata"]["uid"] = json!(event_id);
    http.insert("class_uid".into(), json!(4002));
    http.insert("category_uid".into(), json!(4));
    http.insert("activity_id".into(), json!(activity));
    http.insert("type_uid".into(), json!(400200 + activity));
    http.insert("severity_id".into(), json!(severity));
    if let Some(ep) = &src_endpoint {
        http.insert("src_endpoint".into(), ep.clone());
    }
    http.insert("http_request".into(), http_request.clone());
    let (action, disposition) = action_disposition(j.verdict, enforced);
    http.insert("action_id".into(), json!(action));
    http.insert("disposition_id".into(), json!(disposition));
    if let Some(c) = j.decided_by.construct.as_deref() {
        let mut rule = json!({ "uid": c });
        if let Some(info) = vft_core::graph::sinks::lookup(c) {
            rule["name"] = json!(info.summary);
        }
        http.insert("firewall_rule".into(), rule);
    }
    let mut out = vec![Value::Object(http)];

    if detected {
        let attacks: Vec<Value> = j.attack.iter().map(attack).collect();
        let mut f = base;
        f.insert("class_uid".into(), json!(2004));
        f.insert("category_uid".into(), json!(2));
        f.insert("activity_id".into(), json!(1));
        f.insert("type_uid".into(), json!(200401));
        f.insert("severity_id".into(), json!(severity));
        f.insert("is_alert".into(), json!(true));
        f.insert(
            "finding_info".into(),
            json!({ "uid": event_id, "title": j.decided_by.msg, "attacks": attacks }),
        );
        f.insert("attacks".into(), Value::Array(attacks));
        // Detection Finding has no top-level src_endpoint; the source goes in an
        // evidence. Without one the evidence would fail its at_least_one constraint.
        if let Some(ep) = src_endpoint {
            f.insert("evidences".into(), json!([{ "src_endpoint": ep, "http_request": http_request }]));
        }
        if let Some(c) = j.confidence {
            f.insert("confidence_score".into(), json!(c));
            f.insert("confidence_id".into(), json!(confidence_id(c)));
        }
        out.push(Value::Object(f));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vft_core::{Config, Shield, SourceKey};

    const HTTP: &str = include_str!("../tests/fixtures/ocsf-1.9.0-http_activity.json");
    const FINDING: &str = include_str!("../tests/fixtures/ocsf-1.9.0-detection_finding.json");
    const EVIDENCES: &str = include_str!("../tests/fixtures/ocsf-1.9.0-evidences.json");
    const ATTACK: &str = include_str!("../tests/fixtures/ocsf-1.9.0-attack.json");
    const SAMPLE: &str = include_str!("../tests/fixtures/ocsf-sample.json");

    const VERDICTS: [Verdict; 4] = [Verdict::Allow, Verdict::Monitor, Verdict::Challenge, Verdict::Block];

    fn required(schema: &Value) -> Vec<String> {
        schema["attributes"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, a)| a["requirement"] == "required")
            .map(|(k, _)| k.clone())
            .collect()
    }

    fn enum_ok(schema: &Value, attr: &str, v: &Value) -> bool {
        schema["attributes"][attr]["enum"].as_object().is_none_or(|e| e.contains_key(&v.to_string()))
    }

    /// Every attribute of `rec` that the schema gives an enum holds one of its
    /// values, and each of `must` is present and is such an enum attribute.
    fn assert_enums(schema: &Value, rec: &Value, must: &[&str], what: &str) {
        let attrs = schema["attributes"].as_object().unwrap();
        for (k, v) in rec.as_object().unwrap() {
            if attrs.get(k).is_some_and(|a| a.get("enum").is_some()) {
                assert!(enum_ok(schema, k, v), "{what}: {k}={v} not in the 1.9.0 enum");
            }
        }
        for k in must {
            assert!(attrs[*k].get("enum").is_some(), "{what}: {k} has no enum in the fixture");
            assert!(rec.get(*k).is_some(), "{what}: missing {k}: {rec}");
        }
    }

    fn union_select(method: &str) -> (Request, Judgment) {
        let mut req = Request::get("/x");
        req.method = method.into();
        req.src_ip = Some("192.0.2.1".parse().unwrap());
        req.query.push(("id".into(), "1 union select a,b".into()));
        let j = Shield::new(Config::default()).inspect(&req);
        assert_eq!(j.decided_by.construct.as_deref(), Some("sqli.union-select"), "{:?}", j.decided_by);
        (req, j)
    }

    const EID: &str = "018bcfe5-6800-7abc-8def-0123456789ab";

    #[test]
    fn http_activity_has_required_fields_and_allowed_enums() {
        let schema: Value = serde_json::from_str(HTTP).unwrap();
        let (req, mut j) = union_select("POST");
        j.verdict = Verdict::Block;
        let recs = encode(&req, &j, 1_700_000_000_000, EID, None, true);
        assert!(!recs.is_empty(), "no records");
        let r = &recs[0];
        let req_keys = required(&schema);
        assert!(!req_keys.is_empty());
        for k in &req_keys {
            assert!(r.get(k).is_some(), "4002 record missing required {k}: {r}");
        }
        assert_eq!(r["class_uid"], 4002, "{r}");
        assert_eq!(r["category_uid"], 4, "{r}");
        assert_eq!(r["activity_id"], 6, "{r}");
        assert_eq!(r["type_uid"], 400206, "{r}");
        assert_eq!(r["metadata"]["version"], "1.9.0", "{r}");
        assert_eq!(r["metadata"]["uid"], EID, "{r}");
    }

    #[test]
    fn every_enum_attribute_of_both_records_is_allowed() {
        let http: Value = serde_json::from_str(HTTP).unwrap();
        let finding: Value = serde_json::from_str(FINDING).unwrap();
        let (req, base) = union_select("POST");
        let http_must = ["class_uid", "category_uid", "activity_id", "type_uid", "severity_id", "action_id", "disposition_id"];
        for method in ["GET", "POST", "PATCH", "get", "BREW"] {
            let mut req = req.clone();
            req.method = method.into();
            for v in VERDICTS {
                for enforced in [true, false] {
                    for conf in [Some(1u8), Some(39), Some(40), Some(69), Some(70), Some(100), None] {
                        let mut j = base.clone();
                        j.verdict = v;
                        j.confidence = conf;
                        let recs = encode(&req, &j, 1, EID, None, enforced);
                        let what = format!("{method} {v:?} enforced={enforced} {conf:?}");
                        assert_enums(&http, &recs[0], &http_must, &format!("4002 {what}"));
                        if let Some(f) = recs.get(1) {
                            let mut must = vec!["class_uid", "category_uid", "activity_id", "type_uid", "severity_id"];
                            if conf.is_some() {
                                must.push("confidence_id");
                            }
                            assert_enums(&finding, f, &must, &format!("2004 {what}"));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn detection_finding_only_for_challenge_and_block() {
        let schema: Value = serde_json::from_str(FINDING).unwrap();
        let (req, base) = union_select("POST");
        for v in [Verdict::Allow, Verdict::Monitor] {
            let mut j = base.clone();
            j.verdict = v;
            assert_eq!(encode(&req, &j, 1, EID, None, true).len(), 1, "{v:?}");
        }
        for v in [Verdict::Challenge, Verdict::Block] {
            for conf in [Some(85u8), None] {
                let mut j = base.clone();
                j.verdict = v;
                j.confidence = conf;
                let recs = encode(&req, &j, 1, EID, Some("192.0.2.1@5"), true);
                assert_eq!(recs.len(), 2, "{v:?}");
                let r = &recs[1];
                for k in required(&schema) {
                    assert!(r.get(&k).is_some(), "2004 record missing required {k}: {r}");
                }
                assert_eq!(r["class_uid"], 2004, "{r}");
                assert_eq!(r["type_uid"], 200401, "{r}");
                assert_eq!(r["finding_info"]["uid"], EID, "{r}");
                // Only the 4002 carries metadata.uid; both carry the group.
                assert!(r["metadata"].get("uid").is_none(), "{r}");
                assert_eq!(recs[0]["metadata"]["uid"], EID);
                for rec in &recs {
                    assert_eq!(rec["metadata"]["correlation_uid"], "192.0.2.1@5", "{rec}");
                }
                assert_eq!(r["finding_info"]["attacks"][0]["technique"]["uid"], "T1190", "{r}");
                match j.confidence {
                    Some(c) => assert_eq!(r["confidence_score"], c, "{r}"),
                    None => assert!(r.get("confidence_score").is_none(), "{r}"),
                }
            }
        }
    }

    #[test]
    fn unenforced_requests_are_allowed_and_logged_but_detections_keep_their_finding() {
        let (req, base) = union_select("POST");
        for v in VERDICTS {
            let mut j = base.clone();
            j.verdict = v;
            let off = encode(&req, &j, 1, EID, None, false);
            assert_eq!((&off[0]["action_id"], &off[0]["disposition_id"]), (&json!(1), &json!(17)), "{v:?}");
            assert_eq!(off[0]["severity_id"], severity_id(v), "severity still follows the verdict");
            let detected = matches!(v, Verdict::Challenge | Verdict::Block);
            assert_eq!(off.len(), if detected { 2 } else { 1 }, "{v:?}");
            // Enforced, the mapping follows the verdict.
            let on = encode(&req, &j, 1, EID, None, true);
            let want = match v {
                Verdict::Allow => (1, 1),
                Verdict::Monitor => (1, 17),
                Verdict::Challenge | Verdict::Block => (2, 2),
            };
            assert_eq!((&on[0]["action_id"], &on[0]["disposition_id"]), (&json!(want.0), &json!(want.1)), "{v:?}");
            // The finding does not depend on enforcement.
            assert_eq!(off.get(1), on.get(1), "{v:?}");
        }
    }

    #[test]
    fn sub_techniques_go_in_sub_technique_with_their_parent_in_technique() {
        let schema: Value = serde_json::from_str(ATTACK).unwrap();
        let attrs = schema["attributes"].as_object().unwrap();
        assert!(attrs.contains_key("sub_technique") && attrs.contains_key("technique"), "1.9.0 attack object");
        let tag = |id: &str, name: &str| AttackTag {
            tactic_id: "TA0043".into(),
            tactic: "Reconnaissance".into(),
            id: id.into(),
            name: name.into(),
        };
        let sub = attack(&tag("T1595.002", "Active Scanning: Vulnerability Scanning"));
        assert_eq!(sub["technique"], json!({ "uid": "T1595", "name": "Active Scanning" }));
        assert_eq!(sub["sub_technique"], json!({ "uid": "T1595.002", "name": "Vulnerability Scanning" }));
        let plain = attack(&tag("T1190", "Exploit Public-Facing Application"));
        assert_eq!(plain["technique"], json!({ "uid": "T1190", "name": "Exploit Public-Facing Application" }));
        assert!(plain.get("sub_technique").is_none(), "{plain}");
        // Every key is an attack attribute, and at_least_one holds.
        for a in [&sub, &plain] {
            assert_valid(&schema, a, "attack");
        }
        // The engine's own tags, end to end: a decoy hit is a Wordlist Scanning sub-technique.
        let mut req = Request::get("/.git/config");
        req.src_ip = Some("192.0.2.1".parse().unwrap());
        let mut j = Judgment::allow();
        j.verdict = Verdict::Block;
        j.attack = vft_core::attack::tags_for("honeypot.decoy-hit");
        let f = &encode(&req, &j, 1, EID, None, true)[1];
        for a in [&f["attacks"][0], &f["finding_info"]["attacks"][0]] {
            assert_eq!(a["technique"]["uid"], "T1595", "{f}");
            assert_eq!(a["sub_technique"], json!({ "uid": "T1595.003", "name": "Wordlist Scanning" }), "{f}");
        }
    }

    /// Every key of `rec` is an attribute of `schema`, and each of the
    /// schema's `at_least_one` constraints is met.
    fn assert_valid(schema: &Value, rec: &Value, what: &str) {
        let attrs = schema["attributes"].as_object().unwrap();
        for k in rec.as_object().unwrap().keys() {
            assert!(attrs.contains_key(k), "{what}: `{k}` is not a 1.9.0 attribute: {rec}");
        }
        if let Some(one) = schema["constraints"]["at_least_one"].as_array() {
            assert!(
                one.iter().any(|k| rec.get(k.as_str().unwrap()).is_some()),
                "{what}: none of the at_least_one attributes {one:?}: {rec}"
            );
        }
    }

    #[test]
    fn records_use_only_schema_attributes() {
        let http: Value = serde_json::from_str(HTTP).unwrap();
        let finding: Value = serde_json::from_str(FINDING).unwrap();
        let evidences: Value = serde_json::from_str(EVIDENCES).unwrap();
        let (req, base) = union_select("POST");
        let mut no_ip = req.clone();
        no_ip.src_ip = None;
        for r in [&req, &no_ip] {
            for v in VERDICTS {
                for enforced in [true, false] {
                    let mut j = base.clone();
                    j.verdict = v;
                    let recs = encode(r, &j, 1, EID, Some("192.0.2.1@5"), enforced);
                    assert_valid(&http, &recs[0], "4002");
                    assert_eq!(recs[0].get("src_endpoint").is_some(), r.src_ip.is_some(), "{}", recs[0]);
                    if let Some(f) = recs.get(1) {
                        assert_valid(&finding, f, "2004");
                        assert!(f.get("src_endpoint").is_none(), "2004 has no top-level src_endpoint: {f}");
                        match r.src_ip {
                            Some(ip) => {
                                let ev = f["evidences"].as_array().unwrap();
                                assert_eq!(ev.len(), 1, "{f}");
                                assert_valid(&evidences, &ev[0], "evidences");
                                assert_eq!(ev[0]["src_endpoint"]["ip"], ip.to_string(), "{f}");
                                assert_eq!(ev[0]["http_request"]["http_method"], "POST", "{f}");
                                assert_eq!(ev[0]["http_request"]["url"]["path"], "/x", "{f}");
                            }
                            // An evidence with only http_request would break at_least_one.
                            None => assert!(f.get("evidences").is_none(), "{f}"),
                        }
                    }
                }
            }
        }
    }

    /// The Judgment a shared-sample case describes.
    fn sample_judgment(name: &str, i: &Value) -> Judgment {
        let s = |k: &str| i[k].as_str().map(str::to_string);
        let mut j = Judgment::allow();
        j.verdict = match s("verdict").unwrap().as_str() {
            "Allow" => Verdict::Allow,
            "Monitor" => Verdict::Monitor,
            "Challenge" => Verdict::Challenge,
            "Block" => Verdict::Block,
            other => panic!("{name}: unknown verdict {other}"),
        };
        j.score = i["score"].as_u64().unwrap() as u8;
        let construct = s("construct");
        if let Some(c) = &construct {
            let summary = vft_core::graph::sinks::lookup(c).map(|c| c.summary);
            assert_eq!(summary, s("construct_summary").as_deref(), "{name}: construct_summary must match the registry");
        }
        j.decided_by.construct = construct;
        j.decided_by.msg = s("msg").unwrap();
        j.confidence = i["confidence"].as_u64().map(|c| c as u8);
        j.attack = i["attack"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| AttackTag {
                tactic_id: a["tactic_id"].as_str().unwrap().into(),
                tactic: a["tactic"].as_str().unwrap().into(),
                id: a["id"].as_str().unwrap().into(),
                name: a["name"].as_str().unwrap().into(),
            })
            .collect();
        j
    }

    #[test]
    fn shared_sample_matches() {
        let sample: Value = serde_json::from_str(SAMPLE).unwrap();
        let cases = sample["cases"].as_array().unwrap();
        assert!(cases.len() >= 4, "{} cases", cases.len());
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let i = &case["input"];
            let s = |k: &str| i[k].as_str().map(str::to_string);
            let mut req = Request::get(s("path").unwrap());
            req.method = s("method").unwrap();
            req.src_ip = s("src_ip").map(|ip| ip.parse().unwrap());
            let j = sample_judgment(name, i);
            let group = s("group_id");
            // A sample group ID is one the chain would give the source's key.
            if let Some(g) = &group {
                let start: u64 = g.rsplit_once('@').unwrap().1.parse().unwrap();
                let key = SourceKey::new(req.src_ip.unwrap(), 64);
                let o = vft_core::ChainOutcome { episode_start_ms: Some(start), ..Default::default() };
                assert_eq!(vft_core::chain::group_id(key, &o).as_ref(), Some(g), "{name}");
            }
            let enforced = i["enforced"].as_bool().unwrap();

            let ts = i["ts_ms"].as_u64().unwrap();
            let mut got = encode(&req, &j, ts, &s("event_id").unwrap(), group.as_deref(), enforced);
            let mut expected = case["expected"].as_array().unwrap().clone();
            assert_eq!(got.len(), expected.len(), "{name}: {}", json!(got));
            // product.version tracks the crate: assert it here, keep it out of the shared file.
            for r in &got {
                assert_eq!(r["metadata"]["product"]["version"], env!("CARGO_PKG_VERSION"), "{name}: {r}");
            }
            for r in got.iter_mut().chain(expected.iter_mut()) {
                r["metadata"]["product"].as_object_mut().unwrap().remove("version");
            }
            for (g, e) in got.iter().zip(&expected) {
                assert_eq!(g, e, "{name}\n got: {g}\nwant: {e}");
            }
        }
    }
}
