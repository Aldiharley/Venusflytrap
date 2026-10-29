//! Sub-project A — native OCSF 1.9.0 output. Every judgment becomes one HTTP
//! Activity (4002) record; Challenge and Block add one Detection Finding
//! (2004). Both carry the `security_control` profile.

use serde_json::{json, Map, Value};
use vft_core::{Judgment, Request, Verdict};

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

/// Fields every record shares: time, metadata, message.
fn common(req: &Request, j: &Judgment, ts_ms: u64, event_id: &str) -> Map<String, Value> {
    let mut metadata = json!({
        "version": VERSION,
        "uid": event_id,
        "profiles": ["security_control"],
        "product": {
            "name": "Venusflytrap",
            "vendor_name": "Venusflytrap",
            "version": env!("CARGO_PKG_VERSION"),
        },
    });
    if let Some(g) = req.src_ip.zip(j.chain.as_ref()).and_then(|(ip, o)| vft_core::chain::group_id(ip, o)) {
        metadata["correlation_uid"] = Value::String(g);
    }
    let mut m = Map::new();
    m.insert("time".into(), json!(ts_ms));
    m.insert("metadata".into(), metadata);
    m.insert("message".into(), json!(j.decided_by.msg));
    m
}

/// The OCSF records for one judgment: a 4002, plus a 2004 for Challenge/Block.
pub fn encode(req: &Request, j: &Judgment, ts_ms: u64, event_id: &str) -> Vec<Value> {
    let base = common(req, j, ts_ms, event_id);
    let severity = severity_id(j.verdict);
    let stopped = matches!(j.verdict, Verdict::Challenge | Verdict::Block);

    let activity = activity_id(&req.method);
    let src_endpoint = req.src_ip.map(|ip| json!({ "ip": ip.to_string() }));
    let http_request = json!({ "http_method": req.method, "url": { "path": req.path } });
    let mut http = base.clone();
    http.insert("class_uid".into(), json!(4002));
    http.insert("category_uid".into(), json!(4));
    http.insert("activity_id".into(), json!(activity));
    http.insert("type_uid".into(), json!(400200 + activity));
    http.insert("severity_id".into(), json!(severity));
    if let Some(ep) = &src_endpoint {
        http.insert("src_endpoint".into(), ep.clone());
    }
    http.insert("http_request".into(), http_request.clone());
    http.insert("action_id".into(), json!(if stopped { ACTION_DENIED } else { ACTION_ALLOWED }));
    let disposition = match j.verdict {
        Verdict::Allow => DISPOSITION_ALLOWED,
        Verdict::Monitor => DISPOSITION_LOGGED,
        Verdict::Challenge | Verdict::Block => DISPOSITION_BLOCKED,
    };
    http.insert("disposition_id".into(), json!(disposition));
    if let Some(c) = j.decided_by.construct.as_deref() {
        let mut rule = json!({ "uid": c });
        if let Some(info) = vft_core::graph::sinks::lookup(c) {
            rule["name"] = json!(info.summary);
        }
        http.insert("firewall_rule".into(), rule);
    }
    let mut out = vec![Value::Object(http)];

    if stopped {
        let attacks: Vec<Value> = j
            .attack
            .iter()
            .map(|a| {
                json!({
                    "tactic": { "uid": a.tactic_id, "name": a.tactic },
                    "technique": { "uid": a.id, "name": a.name },
                })
            })
            .collect();
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
    use vft_core::{AttackTag, ChainOutcome, Config, Shield, Verdict};

    const HTTP: &str = include_str!("../tests/fixtures/ocsf-1.9.0-http_activity.json");
    const FINDING: &str = include_str!("../tests/fixtures/ocsf-1.9.0-detection_finding.json");
    const EVIDENCES: &str = include_str!("../tests/fixtures/ocsf-1.9.0-evidences.json");
    const SAMPLE: &str = include_str!("../tests/fixtures/ocsf-sample.json");

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
        let recs = encode(&req, &j, 1_700_000_000_000, EID);
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
        for attr in ["activity_id", "severity_id", "action_id", "disposition_id"] {
            assert!(r.get(attr).is_some(), "missing {attr}: {r}");
            assert!(enum_ok(&schema, attr, &r[attr]), "{attr}={} not in the 4002 enum", r[attr]);
        }
    }

    #[test]
    fn detection_finding_only_for_challenge_and_block() {
        let schema: Value = serde_json::from_str(FINDING).unwrap();
        let (req, base) = union_select("POST");
        for v in [Verdict::Allow, Verdict::Monitor] {
            let mut j = base.clone();
            j.verdict = v;
            assert_eq!(encode(&req, &j, 1, EID).len(), 1, "{v:?}");
        }
        for v in [Verdict::Challenge, Verdict::Block] {
            for conf in [Some(85u8), None] {
                let mut j = base.clone();
                j.verdict = v;
                j.confidence = conf;
                let recs = encode(&req, &j, 1, EID);
                assert_eq!(recs.len(), 2, "{v:?}");
                let r = &recs[1];
                for k in required(&schema) {
                    assert!(r.get(&k).is_some(), "2004 record missing required {k}: {r}");
                }
                assert_eq!(r["class_uid"], 2004, "{r}");
                assert_eq!(r["type_uid"], 200401, "{r}");
                assert_eq!(r["finding_info"]["uid"], EID, "{r}");
                assert_eq!(r["finding_info"]["attacks"][0]["technique"]["uid"], "T1190", "{r}");
                match j.confidence {
                    Some(c) => assert_eq!(r["confidence_score"], c, "{r}"),
                    None => assert!(r.get("confidence_score").is_none(), "{r}"),
                }
            }
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
            for v in [Verdict::Allow, Verdict::Monitor, Verdict::Challenge, Verdict::Block] {
                let mut j = base.clone();
                j.verdict = v;
                j.chain = Some(ChainOutcome { episode_start_ms: Some(5), ..Default::default() });
                let recs = encode(r, &j, 1, EID);
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

    #[test]
    fn shared_sample_matches() {
        let sample: Value = serde_json::from_str(SAMPLE).unwrap();
        let i = &sample["input"];
        let s = |k: &str| i[k].as_str().unwrap().to_string();
        let mut req = Request::get(s("path"));
        req.method = s("method");
        req.src_ip = Some(s("src_ip").parse().unwrap());
        let mut j = Judgment::allow();
        j.verdict = match s("verdict").as_str() {
            "Allow" => Verdict::Allow,
            "Monitor" => Verdict::Monitor,
            "Challenge" => Verdict::Challenge,
            "Block" => Verdict::Block,
            other => panic!("unknown verdict {other}"),
        };
        j.score = i["score"].as_u64().unwrap() as u8;
        let construct = s("construct");
        let summary = vft_core::graph::sinks::lookup(&construct).map(|c| c.summary);
        assert_eq!(summary, Some(s("construct_summary").as_str()), "construct_summary must match the registry");
        j.decided_by.construct = Some(construct);
        j.decided_by.msg = s("msg");
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
        // group_id is "{ip}@{episode_start_ms}": carry it through the chain outcome.
        let group = s("group_id");
        let start: u64 = group.rsplit_once('@').unwrap().1.parse().unwrap();
        j.chain = Some(ChainOutcome { episode_start_ms: Some(start), ..Default::default() });
        assert_eq!(vft_core::chain::group_id(req.src_ip.unwrap(), j.chain.as_ref().unwrap()), Some(group));

        let mut got = encode(&req, &j, i["ts_ms"].as_u64().unwrap(), &s("event_id"));
        let mut expected = sample["expected"].as_array().unwrap().clone();
        assert_eq!(got.len(), expected.len(), "{}", json!(got));
        // product.version tracks the crate: assert it here, keep it out of the shared file.
        for r in &got {
            assert_eq!(r["metadata"]["product"]["version"], env!("CARGO_PKG_VERSION"), "{r}");
        }
        for r in got.iter_mut().chain(expected.iter_mut()) {
            r["metadata"]["product"].as_object_mut().unwrap().remove("version");
        }
        for (g, e) in got.iter().zip(&expected) {
            assert_eq!(g, e, "\n got: {g}\nwant: {e}");
        }
    }
}
