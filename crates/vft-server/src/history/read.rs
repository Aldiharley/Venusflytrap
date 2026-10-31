//! Running history queries against a read-only connection.

use super::query::{compile, QueryError, Request};
use rusqlite::types::ValueRef;
use rusqlite::{params_from_iter, Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

/// One page of results: rows, or (when grouped) `(value, count)` pairs, and a
/// cursor for the next page of rows.
#[derive(Debug, serde::Serialize)]
pub struct Page {
    pub rows: Vec<serde_json::Value>,
    pub groups: Option<Vec<(String, u64)>>,
    pub next: Option<String>,
}

/// Open `<dir>/history.db` read-only; a missing file is an error (nothing is created).
pub fn open_read_only(dir: &Path) -> anyhow::Result<Connection> {
    let path = dir.join("history.db");
    if !path.is_file() {
        anyhow::bail!("no history database at {}", path.display());
    }
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?;
    conn.busy_timeout(Duration::from_secs(5))?;
    Ok(conn)
}

fn db_error(e: rusqlite::Error) -> QueryError {
    QueryError {
        pos: 0,
        len: 0,
        msg: format!("database error: {e}"),
    }
}

/// A result cell as JSON.
fn cell(v: ValueRef<'_>) -> serde_json::Value {
    match v {
        ValueRef::Null | ValueRef::Blob(_) => serde_json::Value::Null,
        ValueRef::Integer(i) => i.into(),
        ValueRef::Real(f) => {
            serde_json::Number::from_f64(f).map_or(serde_json::Value::Null, Into::into)
        }
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned().into(),
    }
}

/// One `requests` row as a JSON object: the columns by name, except that
/// `exceptions` is a list of ids, `sampled` a bool and `extra` the parsed JSON.
fn row_json(names: &[String], row: &rusqlite::Row<'_>) -> rusqlite::Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    for (i, name) in names.iter().enumerate() {
        let v = match (name.as_str(), row.get_ref(i)?) {
            ("exceptions", ValueRef::Text(t)) => String::from_utf8_lossy(t)
                .split(',')
                .filter(|id| !id.is_empty())
                .collect::<Vec<_>>()
                .into(),
            ("sampled", ValueRef::Integer(n)) => (n != 0).into(),
            ("extra", ValueRef::Text(t)) => {
                serde_json::from_slice(t).unwrap_or(serde_json::Value::Null)
            }
            (_, raw) => cell(raw),
        };
        obj.insert(name.clone(), v);
    }
    Ok(serde_json::Value::Object(obj))
}

/// Compile and run `req`. A row query returns at most `limit` rows and, when
/// more match, the cursor of the next page; a grouped one returns the `limit`
/// biggest groups, by count then value.
pub fn run(conn: &Connection, req: &Request) -> Result<Page, QueryError> {
    let c = compile(req)?;
    let mut stmt = conn.prepare(&c.sql).map_err(db_error)?;
    let names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut rows = stmt
        .query(params_from_iter(c.params.iter()))
        .map_err(db_error)?;
    if req.group_by.is_some() {
        let mut groups = Vec::new();
        while let Some(r) = rows.next().map_err(db_error)? {
            let label: String = r.get(0).map_err(db_error)?;
            let n: i64 = r.get(1).map_err(db_error)?;
            groups.push((label, u64::try_from(n).unwrap_or(0)));
        }
        return Ok(Page {
            rows: Vec::new(),
            groups: Some(groups),
            next: None,
        });
    }
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(db_error)? {
        out.push(row_json(&names, r).map_err(db_error)?);
    }
    let mut next = None;
    if out.len() > req.limit as usize {
        out.truncate(req.limit as usize);
        if let Some(last) = out.last() {
            if let (Some(ts), Some(id)) = (last["ts_ms"].as_i64(), last["event_id"].as_str()) {
                next = Some(format!("{ts}:{id}"));
            }
        }
    }
    Ok(Page {
        rows: out,
        groups: None,
        next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::query::GroupBy;
    use crate::history::schema;
    use rusqlite::params;
    use serde_json::json;
    use std::collections::HashSet;

    const VERDICTS: [&str; 4] = ["Allow", "Monitor", "Challenge", "Block"];

    struct Tmp(std::path::PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let d = std::env::temp_dir().join(format!("vft-query-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Fifty rows, five per timestamp (ties), covering every kind of value.
    fn fill(conn: &Connection) {
        for i in 0..50u32 {
            let verdict = VERDICTS[(i % 4) as usize];
            let construct = match i % 3 {
                0 => Some("sqli.union-select"),
                1 => Some("xss.script"),
                _ => None,
            };
            conn.execute(
                "INSERT INTO requests (event_id, ts_ms, src_key, ip, method, host, path, verdict, score, stage, families,
                   construct, technique, confidence, group_id, cause_kind, decided_option, config_rev, latency_us,
                   upstream_status, sampled, exceptions, extra)
                 VALUES (?1, ?2, ?3, ?4, 'GET', 'h', ?5, ?6, ?7, ?8, 1, ?9, NULL, NULL, NULL, 'Detection', 'scoring.block_at', 1, 10, NULL, ?10, ?11, ?12)",
                params![
                    format!("e{i:02}"),
                    1000 + i64::from(i / 5) * 10,
                    format!("10.0.0.{}", i % 5),
                    format!("10.0.0.{}", i % 5),
                    format!("/p/{}", i % 2),
                    verdict,
                    i64::from(i),
                    (verdict == "Block").then_some("Exploitation"),
                    construct,
                    i64::from(verdict == "Allow"),
                    if i % 10 == 0 { "referer-sql" } else { "" },
                    json!({"n": i}).to_string(),
                ],
            )
            .unwrap();
        }
    }

    fn db(tag: &str) -> (Tmp, Connection) {
        let t = Tmp::new(tag);
        let conn = schema::open(&t.0.join("history.db")).unwrap();
        fill(&conn);
        (t, conn)
    }

    fn req(q: &str) -> Request {
        Request {
            q: q.into(),
            from_ms: 0,
            to_ms: 10_000,
            group_by: None,
            limit: 100,
            cursor: None,
        }
    }

    fn ids(p: &Page) -> Vec<String> {
        p.rows
            .iter()
            .map(|r| r["event_id"].as_str().unwrap().to_string())
            .collect()
    }

    /// The ids `0..50` for which `f` holds, formatted as event ids.
    fn expect(f: impl Fn(u32) -> bool) -> HashSet<String> {
        (0..50)
            .filter(|&i| f(i))
            .map(|i| format!("e{i:02}"))
            .collect()
    }

    fn set(p: &Page) -> HashSet<String> {
        ids(p).into_iter().collect()
    }

    #[test]
    fn filters_select_the_right_rows() {
        let (_t, c) = db("filters");
        let cases: Vec<(&str, HashSet<String>)> = vec![
            ("verdict:block", expect(|i| i % 4 == 3)),
            ("VERDICT:Block", expect(|i| i % 4 == 3)),
            ("construct:sqli.*", expect(|i| i % 3 == 0)),
            ("construct:xss.script", expect(|i| i % 3 == 1)),
            ("-verdict:allow", expect(|i| i % 4 != 0)),
            ("-construct:sqli.*", expect(|i| i % 3 != 0)), // rows without a construct stay
            ("exception:referer-sql", expect(|i| i % 10 == 0)),
            ("exception:referer", expect(|_| false)),
            ("stage:none", expect(|i| i % 4 != 3)),
            ("stage:exploitation", expect(|i| i % 4 == 3)),
            ("src:10.0.0.3", expect(|i| i % 5 == 3)),
            ("src:10.0.0.0/24", expect(|_| true)),
            ("src:10.0.0.0/8 -src:10.0.0.1", expect(|i| i % 5 != 1)),
            ("src:11.0.0.0/8", expect(|_| false)),
            ("path:/p/1", expect(|i| i % 2 == 1)),
            ("score>=45", expect(|i| i >= 45)),
            ("score:7", expect(|i| i == 7)),
            ("sampled:true", expect(|i| i % 4 == 0)),
            (
                "verdict:block construct:sqli.* score<30",
                expect(|i| i % 4 == 3 && i % 3 == 0 && i < 30),
            ),
            ("method:get cause:detection", expect(|_| true)),
            ("", expect(|_| true)),
        ];
        for (q, want) in cases {
            let page = run(&c, &req(q)).unwrap_or_else(|e| panic!("{q}: {e}"));
            assert_eq!(set(&page), want, "{q}");
            assert!(page.groups.is_none() && page.next.is_none(), "{q}");
        }
    }

    #[test]
    fn rows_are_ordered_newest_first_and_shaped() {
        let (_t, c) = db("shape");
        let page = run(&c, &req("exception:referer-sql")).unwrap();
        assert_eq!(ids(&page), ["e40", "e30", "e20", "e10", "e00"]);
        let r = &page.rows[0];
        assert_eq!(r["ts_ms"], 1080);
        assert_eq!(r["verdict"], "Allow");
        assert_eq!(r["exceptions"], json!(["referer-sql"]));
        assert_eq!(r["sampled"], true);
        assert_eq!(r["extra"], json!({"n": 40}));
        assert!(r["stage"].is_null() && r["technique"].is_null());
        assert_eq!(r["score"], 40);
        let none = run(&c, &req("verdict:block")).unwrap();
        assert_eq!(none.rows[0]["exceptions"], json!([]));
        assert_eq!(none.rows[0]["stage"], "Exploitation");
    }

    #[test]
    fn window_is_half_open() {
        let (_t, c) = db("window");
        let mut r = req("");
        r.from_ms = 1010;
        r.to_ms = 1020;
        let page = run(&c, &r).unwrap();
        assert_eq!(set(&page), expect(|i| (5..10).contains(&i)));
    }

    #[test]
    fn group_by_counts_values() {
        let (_t, c) = db("groups");
        let mut r = req("");
        r.group_by = Some(GroupBy::Construct);
        let p = run(&c, &r).unwrap();
        assert!(p.rows.is_empty() && p.next.is_none());
        let g = p.groups.unwrap();
        let n = |m: u32| (0..50).filter(|i| i % 3 == m).count() as u64;
        assert_eq!(
            g,
            vec![
                ("sqli.union-select".to_string(), n(0)),
                ("xss.script".to_string(), n(1)),
                ("(none)".to_string(), n(2)),
            ]
        );

        r.q = "-verdict:allow".into();
        r.group_by = Some(GroupBy::Verdict);
        let g = run(&c, &r).unwrap().groups.unwrap();
        assert_eq!(g.iter().map(|(_, n)| n).sum::<u64>(), 37);
        // Count descending, ties by value.
        assert_eq!(
            g,
            vec![
                ("Monitor".to_string(), 13),
                ("Block".to_string(), 12),
                ("Challenge".to_string(), 12)
            ]
        );
        r.group_by = Some(GroupBy::Stage);
        let g = run(&c, &r).unwrap().groups.unwrap();
        assert!(
            g.contains(&("(none)".to_string(), 25))
                && g.contains(&("Exploitation".to_string(), 12))
        );
        r.group_by = Some(GroupBy::Src);
        r.limit = 2;
        assert_eq!(run(&c, &r).unwrap().groups.unwrap().len(), 2);
        r.group_by = Some(GroupBy::Path);
        r.limit = 10;
        assert_eq!(run(&c, &r).unwrap().groups.unwrap().len(), 2);
    }

    #[test]
    fn cursor_pages_without_overlap_or_gap() {
        let (_t, c) = db("paging");
        let mut r = req("");
        r.limit = 7;
        let mut seen: Vec<String> = Vec::new();
        let mut pages = 0;
        loop {
            let p = run(&c, &r).unwrap();
            pages += 1;
            assert!(p.rows.len() <= 7);
            seen.extend(ids(&p));
            match p.next {
                Some(cur) => {
                    assert_eq!(p.rows.len(), 7);
                    let last = p.rows.last().unwrap();
                    assert_eq!(
                        cur,
                        format!("{}:{}", last["ts_ms"], last["event_id"].as_str().unwrap())
                    );
                    r.cursor = Some(cur);
                }
                None => break,
            }
        }
        assert_eq!(pages, 8);
        assert_eq!(seen.len(), 50);
        let all: HashSet<_> = seen.iter().cloned().collect();
        assert_eq!(all, expect(|_| true), "no overlap, no gap");
        let mut want: Vec<String> = (0..50).map(|i| format!("e{i:02}")).collect();
        want.reverse();
        assert_eq!(
            seen, want,
            "newest first across pages (ties by event id descending)"
        );

        // Exactly one page of rows: no next cursor.
        r.cursor = None;
        r.limit = 50;
        let p = run(&c, &r).unwrap();
        assert_eq!((p.rows.len(), p.next), (50, None));
        r.limit = 49;
        assert!(run(&c, &r).unwrap().next.is_some());

        // Two pages, filtered, mid-tie cursor.
        let mut r = req("-verdict:allow");
        r.limit = 20;
        let p1 = run(&c, &r).unwrap();
        r.cursor = p1.next.clone();
        let p2 = run(&c, &r).unwrap();
        assert!(set(&p1).is_disjoint(&set(&p2)));
        assert_eq!((p1.rows.len(), p2.rows.len(), p2.next), (20, 17, None));
    }

    #[test]
    fn query_errors_come_back_as_query_errors() {
        let (_t, c) = db("errors");
        let e = run(&c, &req("verdict:maybe")).unwrap_err();
        assert_eq!((e.pos, e.len), (8, 5));
        let mut r = req("");
        r.cursor = Some("garbage".into());
        assert!(run(&c, &r).unwrap_err().msg.contains("cursor"));
    }

    #[test]
    fn open_read_only_refuses_missing_files_and_writes() {
        let t = Tmp::new("open");
        let e = open_read_only(&t.0).unwrap_err().to_string();
        assert!(
            e.contains("history.db") && e.contains("no history database"),
            "{e}"
        );
        assert!(!t.0.join("history.db").exists(), "nothing is created");

        drop(schema::open(&t.0.join("history.db")).unwrap());
        let c = open_read_only(&t.0).unwrap();
        assert_eq!(run(&c, &req("")).unwrap().rows.len(), 0);
        assert!(c.execute("DELETE FROM requests", []).is_err(), "read-only");
    }

    #[test]
    fn a_database_error_is_reported_not_panicked() {
        let t = Tmp::new("dberr");
        let c = Connection::open(t.0.join("empty.db")).unwrap(); // no requests table
        let e = run(&c, &req("")).unwrap_err();
        assert!(e.msg.contains("database"), "{e}");
    }
}
