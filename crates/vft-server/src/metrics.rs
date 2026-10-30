//! Lock-free counters rendered as Prometheus text exposition format 0.0.4.

use crate::status::StatusRecord;
use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use vft_core::Verdict;

/// Upper bounds of the latency buckets in microseconds, with their `le` label in seconds.
/// The implicit last bucket is `+Inf`.
const BUCKETS: [(u64, &str); 9] = [
    (500, "0.0005"),
    (1_000, "0.001"),
    (2_500, "0.0025"),
    (5_000, "0.005"),
    (10_000, "0.01"),
    (25_000, "0.025"),
    (50_000, "0.05"),
    (100_000, "0.1"),
    (250_000, "0.25"),
];

const VERDICTS: [(&str, usize); 4] = [("allow", 0), ("monitor", 1), ("challenge", 2), ("block", 3)];

pub struct Metrics {
    requests: [AtomicU64; 4],
    /// Non-cumulative per-bucket counts; index 9 is `+Inf`.
    latency_buckets: [AtomicU64; 10],
    latency_sum_us: AtomicU64,
    latency_count: AtomicU64,
    reloads_applied: AtomicU64,
    reloads_rejected: AtomicU64,
    history_written: AtomicU64,
    history_dropped: AtomicU64,
    history_queue: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: Default::default(),
            latency_buckets: Default::default(),
            latency_sum_us: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            reloads_applied: AtomicU64::new(0),
            reloads_rejected: AtomicU64::new(0),
            history_written: AtomicU64::new(0),
            history_dropped: AtomicU64::new(0),
            history_queue: AtomicU64::new(0),
        }
    }

    pub fn observe_decision(&self, verdict: Verdict, latency_us: u64) {
        let v = match verdict {
            Verdict::Allow => 0,
            Verdict::Monitor => 1,
            Verdict::Challenge => 2,
            Verdict::Block => 3,
        };
        self.requests[v].fetch_add(1, Relaxed);
        let idx = BUCKETS
            .iter()
            .position(|(le, _)| latency_us <= *le)
            .unwrap_or(BUCKETS.len());
        self.latency_buckets[idx].fetch_add(1, Relaxed);
        self.latency_sum_us.fetch_add(latency_us, Relaxed);
        self.latency_count.fetch_add(1, Relaxed);
    }

    pub fn reload(&self, applied: bool) {
        let c = if applied {
            &self.reloads_applied
        } else {
            &self.reloads_rejected
        };
        c.fetch_add(1, Relaxed);
    }

    pub fn history_written(&self, rows: u64) {
        self.history_written.fetch_add(rows, Relaxed);
    }

    pub fn history_dropped(&self, rows: u64) {
        self.history_dropped.fetch_add(rows, Relaxed);
    }

    pub fn set_history_queue(&self, depth: u64) {
        self.history_queue.store(depth, Relaxed);
    }

    /// Prometheus text exposition format 0.0.4.
    pub fn render(&self, status: &StatusRecord) -> String {
        let mut o = String::with_capacity(2048);
        let head = |o: &mut String, name: &str, ty: &str, help: &str| {
            let _ = writeln!(o, "# HELP {name} {help}");
            let _ = writeln!(o, "# TYPE {name} {ty}");
        };

        head(
            &mut o,
            "vft_requests_total",
            "counter",
            "Requests decided, by verdict.",
        );
        for (label, i) in VERDICTS {
            let _ = writeln!(
                o,
                "vft_requests_total{{verdict=\"{label}\"}} {}",
                self.requests[i].load(Relaxed)
            );
        }

        head(
            &mut o,
            "vft_request_latency_seconds",
            "histogram",
            "Time to decide a request, in seconds.",
        );
        let mut cumulative = 0u64;
        for (i, (_, le)) in BUCKETS.iter().enumerate() {
            cumulative += self.latency_buckets[i].load(Relaxed);
            let _ = writeln!(
                o,
                "vft_request_latency_seconds_bucket{{le=\"{le}\"}} {cumulative}"
            );
        }
        cumulative += self.latency_buckets[BUCKETS.len()].load(Relaxed);
        let _ = writeln!(
            o,
            "vft_request_latency_seconds_bucket{{le=\"+Inf\"}} {cumulative}"
        );
        let sum_s = self.latency_sum_us.load(Relaxed) as f64 / 1e6;
        let _ = writeln!(o, "vft_request_latency_seconds_sum {sum_s}");
        // The +Inf bucket and _count must agree, so both come from the bucket total.
        let _ = writeln!(o, "vft_request_latency_seconds_count {cumulative}");

        head(
            &mut o,
            "vft_bus_dropped_total",
            "counter",
            "Events dropped by the event bus, by consumer.",
        );
        for (consumer, n) in &status.drops {
            let _ = writeln!(
                o,
                "vft_bus_dropped_total{{consumer=\"{}\"}} {n}",
                escape_label(consumer)
            );
        }

        head(
            &mut o,
            "vft_reloads_total",
            "counter",
            "Configuration reload attempts, by result.",
        );
        let _ = writeln!(
            o,
            "vft_reloads_total{{result=\"applied\"}} {}",
            self.reloads_applied.load(Relaxed)
        );
        let _ = writeln!(
            o,
            "vft_reloads_total{{result=\"rejected\"}} {}",
            self.reloads_rejected.load(Relaxed)
        );

        head(
            &mut o,
            "vft_history_rows_written_total",
            "counter",
            "History rows written to storage.",
        );
        let _ = writeln!(
            o,
            "vft_history_rows_written_total {}",
            self.history_written.load(Relaxed)
        );
        head(
            &mut o,
            "vft_history_rows_dropped_total",
            "counter",
            "History rows dropped before storage.",
        );
        let _ = writeln!(
            o,
            "vft_history_rows_dropped_total {}",
            self.history_dropped.load(Relaxed)
        );
        head(
            &mut o,
            "vft_history_queue_depth",
            "gauge",
            "Rows waiting in the history writer queue.",
        );
        let _ = writeln!(
            o,
            "vft_history_queue_depth {}",
            self.history_queue.load(Relaxed)
        );
        head(
            &mut o,
            "vft_config_rev",
            "gauge",
            "Revision of the active configuration.",
        );
        let _ = writeln!(o, "vft_config_rev {}", status.config_rev);
        head(&mut o, "vft_up", "gauge", "1 while the service is running.");
        let _ = writeln!(o, "vft_up 1");
        o
    }
}

fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::StatusBoard;
    use std::collections::{BTreeMap, BTreeSet};

    struct Sample {
        name: String,
        labels: BTreeMap<String, String>,
        value: f64,
    }

    struct Parsed {
        help: BTreeSet<String>,
        types: BTreeMap<String, String>,
        samples: Vec<Sample>,
    }

    fn parse(text: &str) -> Parsed {
        assert!(text.ends_with('\n'), "exposition must end with a newline");
        let mut p = Parsed {
            help: BTreeSet::new(),
            types: BTreeMap::new(),
            samples: Vec::new(),
        };
        for line in text.lines() {
            assert!(!line.is_empty(), "no blank lines");
            if let Some(rest) = line.strip_prefix("# HELP ") {
                let (name, help) = rest.split_once(' ').expect("HELP has text");
                assert!(!help.is_empty());
                assert!(p.help.insert(name.to_string()), "duplicate HELP for {name}");
            } else if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, ty) = rest.split_once(' ').expect("TYPE has a type");
                assert!(["counter", "gauge", "histogram"].contains(&ty), "type {ty}");
                assert!(p.types.insert(name.to_string(), ty.to_string()).is_none());
            } else {
                assert!(!line.starts_with('#'), "unknown comment: {line}");
                let (head, value) = line.rsplit_once(' ').expect("name{labels} value");
                let value: f64 = value
                    .parse()
                    .unwrap_or_else(|_| panic!("bad value in {line}"));
                let (name, labels) = match head.split_once('{') {
                    None => (head.to_string(), BTreeMap::new()),
                    Some((n, rest)) => {
                        let body = rest.strip_suffix('}').expect("closing brace");
                        let mut m = BTreeMap::new();
                        for kv in body.split(',') {
                            let (k, v) = kv.split_once('=').expect("k=v");
                            let v = v
                                .strip_prefix('"')
                                .and_then(|v| v.strip_suffix('"'))
                                .expect("quoted");
                            m.insert(k.to_string(), v.to_string());
                        }
                        (n.to_string(), m)
                    }
                };
                p.samples.push(Sample {
                    name,
                    labels,
                    value,
                });
            }
        }
        p
    }

    fn family_of(p: &Parsed, sample: &str) -> String {
        if p.types.contains_key(sample) {
            return sample.to_string();
        }
        for suffix in ["_bucket", "_sum", "_count"] {
            if let Some(base) = sample.strip_suffix(suffix) {
                if p.types.get(base).map(String::as_str) == Some("histogram") {
                    return base.to_string();
                }
            }
        }
        panic!("sample {sample} has no TYPE");
    }

    fn get(p: &Parsed, name: &str, labels: &[(&str, &str)]) -> f64 {
        p.samples
            .iter()
            .find(|s| {
                s.name == name
                    && labels
                        .iter()
                        .all(|(k, v)| s.labels.get(*k).map(String::as_str) == Some(*v))
            })
            .unwrap_or_else(|| panic!("missing {name}{labels:?}"))
            .value
    }

    fn status_with_drops() -> StatusRecord {
        let b = StatusBoard::new();
        b.set_config(9, vec![]);
        b.add_drops("history", 4);
        b.add_drops("ocsf", 1);
        b.snapshot()
    }

    #[test]
    fn render_is_well_formed_prometheus_text() {
        let m = Metrics::new();
        m.observe_decision(Verdict::Allow, 100);
        m.observe_decision(Verdict::Block, 700);
        let text = m.render(&status_with_drops());
        let p = parse(&text);
        let families: BTreeSet<_> = p.types.keys().cloned().collect();
        assert_eq!(families, p.help, "every family has HELP and TYPE");
        for s in &p.samples {
            let fam = family_of(&p, &s.name);
            assert!(p.help.contains(&fam));
        }
        for expected in [
            "vft_requests_total",
            "vft_request_latency_seconds",
            "vft_bus_dropped_total",
            "vft_reloads_total",
            "vft_history_rows_written_total",
            "vft_history_rows_dropped_total",
            "vft_history_queue_depth",
            "vft_config_rev",
            "vft_up",
        ] {
            assert!(families.contains(expected), "missing family {expected}");
        }
        assert_eq!(p.types["vft_request_latency_seconds"], "histogram");
        assert_eq!(p.types["vft_requests_total"], "counter");
        assert_eq!(p.types["vft_history_queue_depth"], "gauge");
        assert_eq!(get(&p, "vft_up", &[]), 1.0);
    }

    #[test]
    fn verdict_counters_and_reload_results() {
        let m = Metrics::new();
        for _ in 0..3 {
            m.observe_decision(Verdict::Allow, 10);
        }
        m.observe_decision(Verdict::Monitor, 10);
        m.observe_decision(Verdict::Challenge, 10);
        m.observe_decision(Verdict::Block, 10);
        m.observe_decision(Verdict::Block, 10);
        m.reload(true);
        m.reload(true);
        m.reload(false);
        let p = parse(&m.render(&StatusBoard::new().snapshot()));
        assert_eq!(get(&p, "vft_requests_total", &[("verdict", "allow")]), 3.0);
        assert_eq!(
            get(&p, "vft_requests_total", &[("verdict", "monitor")]),
            1.0
        );
        assert_eq!(
            get(&p, "vft_requests_total", &[("verdict", "challenge")]),
            1.0
        );
        assert_eq!(get(&p, "vft_requests_total", &[("verdict", "block")]), 2.0);
        assert_eq!(get(&p, "vft_reloads_total", &[("result", "applied")]), 2.0);
        assert_eq!(get(&p, "vft_reloads_total", &[("result", "rejected")]), 1.0);
    }

    #[test]
    fn history_and_status_driven_series() {
        let m = Metrics::new();
        m.history_written(5);
        m.history_written(2);
        m.history_dropped(3);
        m.set_history_queue(11);
        m.set_history_queue(4);
        let p = parse(&m.render(&status_with_drops()));
        assert_eq!(get(&p, "vft_history_rows_written_total", &[]), 7.0);
        assert_eq!(get(&p, "vft_history_rows_dropped_total", &[]), 3.0);
        assert_eq!(get(&p, "vft_history_queue_depth", &[]), 4.0);
        assert_eq!(get(&p, "vft_config_rev", &[]), 9.0);
        assert_eq!(
            get(&p, "vft_bus_dropped_total", &[("consumer", "history")]),
            4.0
        );
        assert_eq!(
            get(&p, "vft_bus_dropped_total", &[("consumer", "ocsf")]),
            1.0
        );
    }

    #[test]
    fn latency_histogram_is_cumulative_and_closed_by_inf() {
        let m = Metrics::new();
        // microseconds: boundaries are 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000
        for us in [
            100, 500, 501, 1000, 3000, 20_000, 249_999, 250_000, 250_001, 5_000_000,
        ] {
            m.observe_decision(Verdict::Allow, us);
        }
        let p = parse(&m.render(&StatusBoard::new().snapshot()));
        let les = [
            "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "+Inf",
        ];
        let buckets: Vec<(String, f64)> = p
            .samples
            .iter()
            .filter(|s| s.name == "vft_request_latency_seconds_bucket")
            .map(|s| (s.labels["le"].clone(), s.value))
            .collect();
        let got_les: Vec<&str> = buckets.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(got_les, les, "buckets in order, ending with +Inf");
        let counts: Vec<f64> = buckets.iter().map(|(_, v)| *v).collect();
        assert!(
            counts.windows(2).all(|w| w[0] <= w[1]),
            "cumulative: {counts:?}"
        );
        assert_eq!(
            counts,
            vec![2.0, 4.0, 4.0, 5.0, 5.0, 6.0, 6.0, 6.0, 8.0, 10.0]
        );
        let count = get(&p, "vft_request_latency_seconds_count", &[]);
        assert_eq!(count, 10.0);
        assert_eq!(*counts.last().unwrap(), count);
        let sum_us: u64 = [
            100, 500, 501, 1000, 3000, 20_000, 249_999, 250_000, 250_001, 5_000_000,
        ]
        .iter()
        .sum();
        let sum = get(&p, "vft_request_latency_seconds_sum", &[]);
        assert!((sum - sum_us as f64 / 1e6).abs() < 1e-9, "sum {sum}");
    }

    #[test]
    fn consumer_label_is_escaped() {
        let b = StatusBoard::new();
        b.add_drops("we\"ird\\name\nx", 1);
        let text = Metrics::new().render(&b.snapshot());
        assert!(text.contains(r#"consumer="we\"ird\\name\nx""#), "{text}");
        assert!(text.lines().all(|l| !l.is_empty()));
    }
}
