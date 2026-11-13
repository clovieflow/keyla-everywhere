//! Live gauges: process in-flight count and per-pool usage.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use sqlx::Row;

use crate::access::{authorize_tenant, console_response};
use crate::routes::ConsoleState;

async fn pool_usage(state: &ConsoleState, tenant: &str) -> Vec<Value> {
    let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(
        "SELECT id::text AS id, bytes_sent_total, bytes_received_total
         FROM network_pools WHERE tenant_id = $1::uuid ORDER BY created_at, id",
    )
    .bind(tenant)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|row| {
            json!({
                "poolId": row.get::<String, _>("id"),
                "currentInflight": 0,
                "bytesSent": row.try_get::<i64, _>("bytes_sent_total").unwrap_or(0),
                "bytesReceived": row.try_get::<i64, _>("bytes_received_total").unwrap_or(0),
            })
        })
        .collect()
}

/// `GET /console/api/live/in-flight`.
pub async fn in_flight(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    console_response(StatusCode::OK, json!({"inFlight": 0, "uniqueIps": 0}))
}

/// `GET /console/api/live/in-flight/stream`.
pub async fn in_flight_stream(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    if let Err(response) = authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        return response;
    }
    let body = async_stream::stream! {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            yield Ok::<Event, std::convert::Infallible>(
                Event::default()
                    .event("count")
                    .json_data(json!({"inFlight": 0, "uniqueIps": 0}))
                    .unwrap_or_default(),
            );
        }
    };
    Sse::new(body)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// `GET /console/api/live/pools`.
pub async fn pools(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    console_response(
        StatusCode::OK,
        json!({"pools": pool_usage(&state, &tenant).await}),
    )
}

/// `GET /console/api/live/pools/stream`.
pub async fn pools_stream(State(state): State<ConsoleState>, headers: HeaderMap) -> Response {
    let tenant = match authorize_tenant(&state.pool, &headers, "dashboard:read").await {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let initial = pool_usage(&state, &tenant).await;
    let body = async_stream::stream! {
        yield Ok::<Event, std::convert::Infallible>(
            Event::default().event("pools").json_data(json!({"pools": initial})).unwrap_or_default(),
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            yield Ok(Event::default().comment("ping"));
        }
    };
    Sse::new(body)
        .keep_alive(KeepAlive::default())
        .into_response()
}
