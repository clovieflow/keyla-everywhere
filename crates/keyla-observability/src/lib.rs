//! Prometheus exposition registry.
//!
//! A direct port of `src/observability/metrics.ts`: same metric names, help
//! strings, label sets, bucket boundaries, cardinality guards, and byte-level
//! text format. The registry is a process-wide singleton ([`METRICS`]); callers
//! obtain pre-registered families as named fields.

use std::sync::{LazyLock, Mutex, MutexGuard};

/// Cardinality guards prevent unbounded label expansion from untrusted input.
pub const MAX_SERIES: usize = 100;
pub const MAX_LABELS: usize = 8;
pub const MAX_LABEL_VALUE_LENGTH: usize = 64;

/// Label pairs supplied by a caller. Names not declared on the metric are
/// ignored, matching the object-shaped labels of the TypeScript implementation.
pub type Labels<'a> = &'a [(&'a str, &'a str)];

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

fn serialize_labels(label_names: &[String], labels: &[(String, String)]) -> String {
    label_names
        .iter()
        .map(|name| {
            labels
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
                .unwrap_or("")
        })
        .collect::<Vec<_>>()
        .join("\u{1}")
}

fn render_label_set(label_names: &[String], labels: &[(String, String)]) -> String {
    if label_names.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = label_names
        .iter()
        .map(|name| {
            let value = labels
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
                .unwrap_or("");
            format!("{name}=\"{}\"", escape_label_value(value))
        })
        .collect();
    format!("{{{}}}", parts.join(","))
}

/// Sanitizes and truncates labels, keeping at most [`MAX_LABELS`] declared
/// names in declaration order.
pub fn normalize_labels(label_names: &[String], labels: Labels<'_>) -> Vec<(String, String)> {
    if label_names.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(label_names.len().min(MAX_LABELS));
    for name in label_names.iter().take(MAX_LABELS) {
        let raw = labels
            .iter()
            .find(|(key, _)| *key == name.as_str())
            .map(|(_, value)| *value)
            .unwrap_or("");
        let mut value: String = raw
            .chars()
            .map(|ch| match ch {
                '\n' | '\r' | '"' => '_',
                other => other,
            })
            .collect();
        if value.chars().count() > MAX_LABEL_VALUE_LENGTH {
            value = value.chars().take(MAX_LABEL_VALUE_LENGTH).collect();
        }
        out.push((name.clone(), value.trim().to_owned()));
    }
    out
}

/// Formats a metric value the way JavaScript's default number-to-string does
/// for finite values: shortest round-trip representation, no trailing `.0`.
fn format_value(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_positive() {
            "Infinity".to_owned()
        } else {
            "-Infinity".to_owned()
        };
    }
    format!("{value}")
}

#[derive(Debug, Clone)]
struct Sample {
    key: String,
    labels: Vec<(String, String)>,
    value: f64,
}

/// Scalar sample storage shared by counters and gauges.
#[derive(Debug)]
struct ScalarStore {
    label_names: Vec<String>,
    samples: Mutex<Vec<Sample>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarKind {
    Counter,
    Gauge,
}

impl ScalarStore {
    fn new(name: &str, label_names: &[&str]) -> Self {
        assert!(
            label_names.len() <= MAX_LABELS,
            "metric {name}: too many label names {} > {MAX_LABELS}",
            label_names.len()
        );
        Self {
            label_names: label_names.iter().map(|name| (*name).to_owned()).collect(),
            samples: Mutex::new(Vec::new()),
        }
    }

    fn write(&self, value: f64, labels: Labels<'_>, accumulate: bool) {
        let normalized = normalize_labels(&self.label_names, labels);
        let key = serialize_labels(&self.label_names, &normalized);
        let mut samples = lock(&self.samples);
        if let Some(sample) = samples.iter_mut().find(|sample| sample.key == key) {
            if accumulate {
                sample.value += value;
            } else {
                sample.value = value;
            }
            return;
        }
        if samples.len() >= MAX_SERIES {
            return;
        }
        samples.push(Sample {
            key,
            labels: normalized,
            value,
        });
    }

    fn render(&self, name: &str, help: &str, kind: ScalarKind) -> Vec<String> {
        let type_word = match kind {
            ScalarKind::Counter => "counter",
            ScalarKind::Gauge => "gauge",
        };
        let mut lines = vec![
            format!("# HELP {name} {}", escape_help(help)),
            format!("# TYPE {name} {type_word}"),
        ];
        let samples = lock(&self.samples);
        for sample in samples.iter() {
            lines.push(format!(
                "{name}{} {}",
                render_label_set(&self.label_names, &sample.labels),
                format_value(sample.value)
            ));
        }
        lines
    }
}

/// Monotonic counter.
#[derive(Debug)]
pub struct Counter {
    name: String,
    help: String,
    store: ScalarStore,
}

impl Counter {
    fn new(name: &str, help: &str, label_names: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            help: help.to_owned(),
            store: ScalarStore::new(name, label_names),
        }
    }

    pub fn inc(&self, value: f64, labels: Labels<'_>) {
        self.store.write(value, labels, true);
    }

    pub fn inc_one(&self) {
        self.inc(1.0, &[]);
    }

    fn render(&self) -> Vec<String> {
        self.store
            .render(&self.name, &self.help, ScalarKind::Counter)
    }
}

/// Value that can go up and down.
#[derive(Debug)]
pub struct Gauge {
    name: String,
    help: String,
    store: ScalarStore,
}

impl Gauge {
    fn new(name: &str, help: &str, label_names: &[&str]) -> Self {
        Self {
            name: name.to_owned(),
            help: help.to_owned(),
            store: ScalarStore::new(name, label_names),
        }
    }

    pub fn set(&self, value: f64, labels: Labels<'_>) {
        self.store.write(value, labels, false);
    }

    pub fn inc(&self, value: f64, labels: Labels<'_>) {
        self.store.write(value, labels, true);
    }

    pub fn dec(&self, value: f64, labels: Labels<'_>) {
        self.store.write(-value, labels, true);
    }

    fn render(&self) -> Vec<String> {
        self.store.render(&self.name, &self.help, ScalarKind::Gauge)
    }
}

#[derive(Debug, Clone)]
struct HistogramSeries {
    labels: Vec<(String, String)>,
    sum: f64,
    count: u64,
    bucket_counts: Vec<u64>,
}

/// Cumulative histogram with fixed upper bounds.
#[derive(Debug)]
pub struct Histogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    /// Fixed by the first labelled observation. A Prometheus metric family
    /// exposes one consistent label set, so later observations are normalized
    /// against this set instead of creating an incompatible series.
    label_names: Mutex<Vec<String>>,
    series: Mutex<Vec<(String, HistogramSeries)>>,
}

impl Histogram {
    fn new(name: &str, help: &str, buckets: &[f64]) -> Self {
        Self {
            name: name.to_owned(),
            help: help.to_owned(),
            buckets: buckets.to_vec(),
            label_names: Mutex::new(Vec::new()),
            series: Mutex::new(Vec::new()),
        }
    }

    pub fn observe(&self, value: f64, labels: Labels<'_>) {
        {
            let mut label_names = lock(&self.label_names);
            if label_names.is_empty() && !labels.is_empty() {
                let mut names: Vec<String> = Vec::new();
                for (name, _) in labels {
                    if !names.iter().any(|existing| existing == name) {
                        names.push((*name).to_owned());
                    }
                }
                names.sort();
                *label_names = names;
            }
        }
        let label_names = lock(&self.label_names).clone();
        let normalized = normalize_labels(&label_names, labels);
        let key = serialize_labels(&label_names, &normalized);
        let mut series = lock(&self.series);
        let index = if let Some(index) = series.iter().position(|(existing, _)| *existing == key) {
            index
        } else {
            if series.len() >= MAX_SERIES {
                return;
            }
            series.push((
                key,
                HistogramSeries {
                    labels: normalized,
                    sum: 0.0,
                    count: 0,
                    bucket_counts: vec![0; self.buckets.len()],
                },
            ));
            series.len() - 1
        };
        let sample = &mut series[index].1;
        sample.sum += value;
        sample.count += 1;
        for (position, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                sample.bucket_counts[position] += 1;
            }
        }
    }

    fn render(&self) -> Vec<String> {
        let mut lines = vec![
            format!("# HELP {} {}", self.name, escape_help(&self.help)),
            format!("# TYPE {} histogram", self.name),
        ];
        let label_names = lock(&self.label_names).clone();
        let series = lock(&self.series);
        let samples: Vec<HistogramSeries> = if series.is_empty() {
            vec![HistogramSeries {
                labels: Vec::new(),
                sum: 0.0,
                count: 0,
                bucket_counts: vec![0; self.buckets.len()],
            }]
        } else {
            series.iter().map(|(_, sample)| sample.clone()).collect()
        };
        for sample in &samples {
            let suffix = render_label_set(&label_names, &sample.labels);
            for (position, bucket) in self.buckets.iter().enumerate() {
                lines.push(format!(
                    "{}_bucket{{{}}} {}",
                    self.name,
                    self.bucket_labels(
                        &label_names,
                        &sample.labels,
                        &format!("le=\"{}\"", format_value(*bucket))
                    ),
                    sample.bucket_counts[position]
                ));
            }
            lines.push(format!(
                "{}_bucket{{{}}} {}",
                self.name,
                self.bucket_labels(&label_names, &sample.labels, "le=\"+Inf\""),
                sample.count
            ));
            lines.push(format!(
                "{}_sum{suffix} {}",
                self.name,
                format_value(sample.sum)
            ));
            lines.push(format!("{}_count{suffix} {}", self.name, sample.count));
        }
        lines
    }

    fn bucket_labels(
        &self,
        label_names: &[String],
        labels: &[(String, String)],
        le: &str,
    ) -> String {
        let mut parts: Vec<String> = label_names
            .iter()
            .map(|name| {
                let value = labels
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
                    .unwrap_or("");
                format!("{name}=\"{}\"", escape_label_value(value))
            })
            .collect();
        parts.push(le.to_owned());
        parts.join(",")
    }
}

const REQUEST_LATENCY_BUCKETS: [f64; 10] = [
    10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];
const ADAPTER_LOAD_BUCKETS: [f64; 10] = [
    1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0,
];

/// The process-wide registry.
#[derive(Debug)]
pub struct PrometheusRegistry {
    pub keyla_pg_pool_total: Gauge,
    pub keyla_pg_pool_idle: Gauge,
    pub keyla_pg_pool_waiting: Gauge,
    pub keyla_redis_up: Gauge,
    pub proxy_requests_total: Counter,
    pub proxy_admission_total: Counter,
    pub proxy_in_flight: Gauge,
    pub proxy_request_latency_ms: Histogram,
    pub keyla_telemetry_buffered: Gauge,
    pub keyla_telemetry_dropped_total: Counter,
    pub keyla_memory_rss_bytes: Gauge,
    pub keyla_memory_heap_used_bytes: Gauge,
    pub keyla_memory_heap_total_bytes: Gauge,
    pub keyla_memory_limit_bytes: Gauge,
    pub keyla_routing_roundrobin_entries: Gauge,
    pub keyla_ip_abuse_keys: Gauge,
    pub keyla_quota_cache_entries: Gauge,
    pub keyla_pool_agent_entries: Gauge,
    pub keyla_proxy_dial_dns_fallback_total: Counter,
    pub proxy_provider_adapter_load_ms: Histogram,
    pub pool_cooldown_record_failed: Counter,
    pub quota_cache_invalidate_failed: Counter,
}

impl Default for PrometheusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PrometheusRegistry {
    pub fn new() -> Self {
        Self {
            keyla_pg_pool_total: Gauge::new(
                "keyla_pg_pool_total",
                "Total connections in the Postgres pool",
                &[],
            ),
            keyla_pg_pool_idle: Gauge::new(
                "keyla_pg_pool_idle",
                "Idle connections in the Postgres pool",
                &[],
            ),
            keyla_pg_pool_waiting: Gauge::new(
                "keyla_pg_pool_waiting",
                "Clients waiting for a Postgres pool connection",
                &[],
            ),
            keyla_redis_up: Gauge::new("keyla_redis_up", "Redis connectivity (1 = ready)", &[]),
            proxy_requests_total: Counter::new(
                "proxy_requests_total",
                "Completed proxy requests by outcome status",
                &["status"],
            ),
            proxy_admission_total: Counter::new(
                "proxy_admission_total",
                "Admission decisions by reason",
                &["reason"],
            ),
            proxy_in_flight: Gauge::new(
                "proxy_in_flight",
                "Provider dispatch requests currently in flight on this process",
                &[],
            ),
            proxy_request_latency_ms: Histogram::new(
                "proxy_request_latency_ms",
                "Request latency in milliseconds",
                &REQUEST_LATENCY_BUCKETS,
            ),
            keyla_telemetry_buffered: Gauge::new(
                "keyla_telemetry_buffered",
                "Telemetry events waiting to be flushed",
                &[],
            ),
            keyla_telemetry_dropped_total: Counter::new(
                "keyla_telemetry_dropped_total",
                "Telemetry events dropped because the buffer was full",
                &[],
            ),
            keyla_memory_rss_bytes: Gauge::new(
                "keyla_memory_rss_bytes",
                "Resident set size of the process in bytes",
                &[],
            ),
            keyla_memory_heap_used_bytes: Gauge::new(
                "keyla_memory_heap_used_bytes",
                "JavaScript heap used in bytes",
                &[],
            ),
            keyla_memory_heap_total_bytes: Gauge::new(
                "keyla_memory_heap_total_bytes",
                "JavaScript heap reserved in bytes",
                &[],
            ),
            keyla_memory_limit_bytes: Gauge::new(
                "keyla_memory_limit_bytes",
                "Container/cgroup memory limit in bytes (0 when unknown)",
                &[],
            ),
            keyla_routing_roundrobin_entries: Gauge::new(
                "keyla_routing_roundrobin_entries",
                "Round-robin routing state entries by scope",
                &["scope"],
            ),
            keyla_ip_abuse_keys: Gauge::new(
                "keyla_ip_abuse_keys",
                "Tracked keys in the in-memory IP abuse store (0 when Redis-backed)",
                &[],
            ),
            keyla_quota_cache_entries: Gauge::new(
                "keyla_quota_cache_entries",
                "Entries in the in-process provider quota cache",
                &[],
            ),
            keyla_pool_agent_entries: Gauge::new(
                "keyla_pool_agent_entries",
                "Cached per-pool egress agents",
                &[],
            ),
            keyla_proxy_dial_dns_fallback_total: Counter::new(
                "keyla_proxy_dial_dns_fallback_total",
                "Pool/relay-bound dials whose local DNS resolution failed and were downgraded to proxy-resolved egress",
                &[],
            ),
            proxy_provider_adapter_load_ms: Histogram::new(
                "proxy_provider_adapter_load_ms",
                "Time to load a provider adapter on first use",
                &ADAPTER_LOAD_BUCKETS,
            ),
            pool_cooldown_record_failed: Counter::new(
                "pool_cooldown_record_failed",
                "Pool cooldown writes that failed after a provider rate limit",
                &[],
            ),
            quota_cache_invalidate_failed: Counter::new(
                "quota_cache_invalidate_failed",
                "Quota cache invalidations that failed",
                &[],
            ),
        }
    }

    /// Renders the complete registry in declaration order.
    pub fn render(&self) -> String {
        let families: [Vec<String>; 22] = [
            self.keyla_pg_pool_total.render(),
            self.keyla_pg_pool_idle.render(),
            self.keyla_pg_pool_waiting.render(),
            self.keyla_redis_up.render(),
            self.proxy_requests_total.render(),
            self.proxy_admission_total.render(),
            self.proxy_in_flight.render(),
            self.proxy_request_latency_ms.render(),
            self.keyla_telemetry_buffered.render(),
            self.keyla_telemetry_dropped_total.render(),
            self.keyla_memory_rss_bytes.render(),
            self.keyla_memory_heap_used_bytes.render(),
            self.keyla_memory_heap_total_bytes.render(),
            self.keyla_memory_limit_bytes.render(),
            self.keyla_routing_roundrobin_entries.render(),
            self.keyla_ip_abuse_keys.render(),
            self.keyla_quota_cache_entries.render(),
            self.keyla_pool_agent_entries.render(),
            self.keyla_proxy_dial_dns_fallback_total.render(),
            self.proxy_provider_adapter_load_ms.render(),
            self.pool_cooldown_record_failed.render(),
            self.quota_cache_invalidate_failed.render(),
        ];
        let lines: Vec<String> = families.into_iter().flatten().collect();
        format!("{}\n", lines.join("\n"))
    }
}

/// Process-wide metrics singleton.
pub static METRICS: LazyLock<PrometheusRegistry> = LazyLock::new(PrometheusRegistry::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_renders_exact_lines_and_accumulates() {
        let registry = PrometheusRegistry::new();
        registry.proxy_requests_total.inc(2.0, &[]);
        registry.proxy_requests_total.inc(1.0, &[]);
        let rendered = registry.render();
        assert!(
            rendered.contains(
                "# HELP proxy_requests_total Completed proxy requests by outcome status\n"
            )
        );
        assert!(rendered.contains("# TYPE proxy_requests_total counter\n"));
        assert!(rendered.contains("\nproxy_requests_total{status=\"\"} 3\n"));
    }

    #[test]
    fn labels_are_sanitized_and_escaped() {
        let registry = PrometheusRegistry::new();
        registry
            .proxy_requests_total
            .inc(1.0, &[("status", "a\"b\nc")]);
        let rendered = registry.render();
        assert!(rendered.contains("proxy_requests_total{status=\"a_b_c\"} 1"));
    }

    #[test]
    fn label_values_are_truncated_to_64_chars() {
        let registry = PrometheusRegistry::new();
        let long = "x".repeat(100);
        registry.proxy_requests_total.inc(1.0, &[("status", &long)]);
        let rendered = registry.render();
        assert!(rendered.contains(&format!(
            "proxy_requests_total{{status=\"{}\"}} 1",
            "x".repeat(64)
        )));
    }

    #[test]
    fn histogram_renders_zeroed_buckets_before_any_observation() {
        let registry = PrometheusRegistry::new();
        let rendered = registry.render();
        assert!(rendered.contains("proxy_request_latency_ms_bucket{le=\"10\"} 0"));
        assert!(rendered.contains("proxy_request_latency_ms_bucket{le=\"+Inf\"} 0"));
        assert!(rendered.contains("proxy_request_latency_ms_sum 0"));
        assert!(rendered.contains("proxy_request_latency_ms_count 0"));
    }

    #[test]
    fn histogram_counts_cumulative_buckets() {
        let registry = PrometheusRegistry::new();
        registry.proxy_request_latency_ms.observe(12.0, &[]);
        registry.proxy_request_latency_ms.observe(400.0, &[]);
        let rendered = registry.render();
        assert!(rendered.contains("proxy_request_latency_ms_bucket{le=\"10\"} 0"));
        assert!(rendered.contains("proxy_request_latency_ms_bucket{le=\"25\"} 1"));
        assert!(rendered.contains("proxy_request_latency_ms_bucket{le=\"500\"} 2"));
        assert!(rendered.contains("proxy_request_latency_ms_bucket{le=\"+Inf\"} 2"));
        assert!(rendered.contains("proxy_request_latency_ms_sum 412"));
        assert!(rendered.contains("proxy_request_latency_ms_count 2"));
    }

    #[test]
    fn cardinality_guard_stops_new_series() {
        let registry = PrometheusRegistry::new();
        for index in 0..(MAX_SERIES + 10) {
            let label = format!("s{index}");
            registry
                .proxy_admission_total
                .inc(1.0, &[("reason", &label)]);
        }
        let rendered = registry.render();
        let series = rendered
            .lines()
            .filter(|line| line.starts_with("proxy_admission_total{"))
            .count();
        assert_eq!(series, MAX_SERIES);
    }

    #[test]
    fn histogram_label_names_are_sorted_once() {
        let registry = PrometheusRegistry::new();
        registry
            .proxy_provider_adapter_load_ms
            .observe(3.0, &[("z", "2"), ("a", "1")]);
        registry
            .proxy_provider_adapter_load_ms
            .observe(4.0, &[("a", "1"), ("z", "2")]);
        let rendered = registry.render();
        assert!(rendered.contains("proxy_provider_adapter_load_ms_count{a=\"1\",z=\"2\"} 2"));
    }
}
