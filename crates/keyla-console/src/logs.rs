//! In-memory console log ring: captures tracing events for the Log page and
//! serves them as a snapshot plus a live SSE stream.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::{SecondsFormat, Utc};
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::access::{authorize_tenant, console_error_body, console_response};
use crate::routes::ConsoleState;

const CAPACITY: usize = 1000;
const LEVELS: [&str; 4] = ["debug", "info", "warn", "error"];

struct Ring {
    lines: Mutex<VecDeque<Value>>,
    sequence: AtomicU64,
    sender: broadcast::Sender<Change>,
}

#[derive(Clone)]
enum Change {
    Line(Value),
    Clear,
}

fn ring() -> &'static Ring {
    static RING: OnceLock<Ring> = OnceLock::new();
    RING.get_or_init(|| {
        let (sender, _) = broadcast::channel(1024);
        Ring {
            lines: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            sequence: AtomicU64::new(0),
            sender,
        }
    })
}

fn push(level: &str, message: String) {
    let ring = ring();
    let sequence = ring.sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let line = json!({
        "seq": sequence,
        "ts": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "level": level,
        "msg": message,
    });
    if let Ok(mut lines) = ring.lines.lock() {
        if lines.len() >= CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line.clone());
    }
    let _ = ring.sender.send(Change::Line(line));
}

fn snapshot() -> Vec<Value> {
    ring()
        .lines
        .lock()
        .map(|lines| lines.iter().cloned().collect())
        .unwrap_or_default()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    console_response(status, console_error_body(code, message))
}

/// `tracing` layer that copies every event into the console ring.
#[derive(Default)]
pub struct ConsoleLogLayer;

#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Vec<String>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields.push(format!("{}={value}", field.name()));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ConsoleLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let mut message = visitor.message;
        if !visitor.fields.is_empty() {
            if !message.is_empty() {
                message.push(' ');
            }
            message.push_str(&visitor.fields.join(" "));
        }
        if message.is_empty() {
            message = event.metadata().name().to_owned();
        }
        push(
            &event.metadata().level().as_str().to_ascii_lowercase(),
            message,
        );
    }
}

fn parse_limit(raw: Option<&String>) -> usize {
    raw.and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 500)
}

/// `GET /console/api/logs?level=&limit=`.
pub async fn list_logs(
    State(state): State<ConsoleState>,
    axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    let level = query.get("level");
    if let Some(level) = level {
        if !LEVELS.contains(&level.as_str()) {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_level",
                &format!("Unsupported log level: {level}. Use debug, info, warn, or error."),
            );
        }
    }
    let limit = parse_limit(query.get("limit"));
    let mut lines = snapshot();
    if let Some(level) = level {
        lines.retain(|line| line.get("level").and_then(Value::as_str) == Some(level.as_str()));
    }
    if lines.len() > limit {
        lines = lines.split_off(lines.len() - limit);
    }
    console_response(StatusCode::OK, json!({"lines": lines}))
}

/// `DELETE /console/api/logs`.
pub async fn clear_logs(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:write").await {
        return response;
    }
    if let Ok(mut lines) = ring().lines.lock() {
        lines.clear();
    }
    let _ = ring().sender.send(Change::Clear);
    console_response(StatusCode::OK, json!({"success": true}))
}

/// `GET /console/api/logs/stream`.
pub async fn stream_logs(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    let initial = snapshot();
    let mut receiver = ring().sender.subscribe();
    let body = async_stream::stream! {
        yield Ok::<Event, std::convert::Infallible>(
            Event::default().event("init").json_data(json!({"lines": initial})).unwrap_or_default(),
        );
        loop {
            match receiver.recv().await {
                Ok(Change::Line(line)) => {
                    yield Ok(Event::default().event("line").json_data(line).unwrap_or_default());
                }
                Ok(Change::Clear) => {
                    yield Ok(Event::default().event("clear").json_data(json!({})).unwrap_or_default());
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(body)
        .keep_alive(KeepAlive::default())
        .into_response()
}

use axum::response::IntoResponse;
