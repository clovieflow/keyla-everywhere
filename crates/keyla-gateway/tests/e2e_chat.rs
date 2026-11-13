//! End-to-end Chat Completions: real PostgreSQL, real HTTP mock upstream,
//! authentication, routing, failover, streaming, denial, and upstream errors.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::{Json, Router};
use http_body_util::BodyExt;
use keyla_db::apply_sql_migrations;
use keyla_gateway::{AppState, GatewayRuntime, StaticAssets, UnavailableDependencies, build_app};
use keyla_security::{
    encrypt_credential, invalidate_api_key_cache, set_credential_encryption_key_for_testing,
    token_hash,
};
use postgresql_embedded::{PostgreSQL, SettingsBuilder};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::util::ServiceExt;

const TENANT: &str = "11111111-1111-1111-1111-111111111111";
const ACCOUNT_A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const ACCOUNT_B: &str = "aaaaaaaa-0000-0000-0000-000000000002";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Json,
    Sse,
    Error(u16),
}

#[derive(Debug, Clone)]
struct Seen {
    authorization: Option<String>,
    model: String,
    user_content: String,
    trusted_instructions: String,
}

#[derive(Clone)]
struct MockState {
    mode: Arc<Mutex<Mode>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl MockState {
    fn new() -> Self {
        Self {
            mode: Arc::new(Mutex::new(Mode::Json)),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn clear(&self) {
        self.seen.lock().unwrap().clear();
    }
}

fn error_body(kind: &str, message: &str) -> Value {
    json!({"error": {"type": kind, "message": message}})
}

async fn mock_handler(
    State(state): State<MockState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let messages = body.get("messages").and_then(Value::as_array);
    let user_content = messages
        .and_then(|messages| messages.last())
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let trusted_instructions = messages
        .into_iter()
        .flatten()
        .filter(|message| {
            matches!(
                message.get("role").and_then(Value::as_str),
                Some("system" | "developer")
            )
        })
        .filter_map(|message| message.get("content").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    state.seen.lock().unwrap().push(Seen {
        authorization: authorization.clone(),
        model: model.clone(),
        user_content,
        trusted_instructions,
    });
    if authorization.as_deref() == Some("Bearer sk-bad") {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&error_body("invalid_api_key", "bad credential")).unwrap(),
            ))
            .unwrap();
    }
    let mode = *state.mode.lock().unwrap();
    match mode {
        Mode::Error(status) => Response::builder()
            .status(StatusCode::from_u16(status).unwrap())
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&error_body("rate_limit_error", "slow down")).unwrap(),
            ))
            .unwrap(),
        Mode::Json => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "id": "chatcmpl-mock",
                    "object": "chat.completion",
                    "created": 1_700_000_000,
                    "model": model,
                    "system_fingerprint": "fp_mock",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "hello from mock"},
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 7,
                        "completion_tokens": 3,
                        "prompt_tokens_details": {"cached_tokens": 2}
                    }
                }))
                .unwrap(),
            ))
            .unwrap(),
        Mode::Sse => {
            let frames = [
                json!({"id":"chatcmpl-mock","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}),
                json!({"id":"chatcmpl-mock","choices":[{"index":0,"delta":{"content":"hel"}}]}),
                json!({"id":"chatcmpl-mock","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}]}),
                json!({"id":"chatcmpl-mock","choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2}}),
            ];
            let mut body = String::new();
            for frame in frames {
                body.push_str(&format!("data: {frame}\n\n"));
            }
            body.push_str("data: [DONE]\n\n");
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/event-stream")
                .body(Body::from(body))
                .unwrap()
        }
    }
}

fn check_bad_auth(headers: &axum::http::HeaderMap) -> Option<Response> {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some("Bearer sk-bad")
    {
        return Some(
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&error_body("invalid_api_key", "bad credential")).unwrap(),
                ))
                .unwrap(),
        );
    }
    None
}

async fn mock_messages(
    State(state): State<MockState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    state.seen.lock().unwrap().push(Seen {
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .or_else(|| {
                headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            }),
        model: model.clone(),
        user_content: String::new(),
        trusted_instructions: String::new(),
    });
    if let Some(response) = check_bad_auth(&headers) {
        return response;
    }
    let mode = *state.mode.lock().unwrap();
    if let Mode::Error(status) = mode {
        return Response::builder()
            .status(StatusCode::from_u16(status).unwrap())
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&error_body("rate_limit_error", "slow down")).unwrap(),
            ))
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "id": "msg_mock",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": "hello from anthropic"}],
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {"input_tokens": 6, "output_tokens": 2}
            }))
            .unwrap(),
        ))
        .unwrap()
}

async fn mock_responses(
    State(state): State<MockState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    state.seen.lock().unwrap().push(Seen {
        authorization: headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        model: model.clone(),
        user_content: String::new(),
        trusted_instructions: String::new(),
    });
    if let Some(response) = check_bad_auth(&headers) {
        return response;
    }
    let mode = *state.mode.lock().unwrap();
    if let Mode::Error(status) = mode {
        return Response::builder()
            .status(StatusCode::from_u16(status).unwrap())
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&error_body("rate_limit_error", "slow down")).unwrap(),
            ))
            .unwrap();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "id": "resp_mock",
                "object": "response",
                "created_at": 1_700_000_000,
                "status": "completed",
                "model": model,
                "output": [{
                    "type": "message",
                    "id": "msg_1",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "hello from responses", "annotations": []}]
                }],
                "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7}
            }))
            .unwrap(),
        ))
        .unwrap()
}

async fn spawn_mock() -> (String, MockState) {
    let state = MockState::new();
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_handler))
        .route("/v1/messages", post(mock_messages))
        .route("/v1/responses", post(mock_responses))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), state)
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn post_path(path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn post_chat(token: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_completions_end_to_end() {
    set_credential_encryption_key_for_testing(Some([7u8; 32]));
    invalidate_api_key_cache(None);

    let mut postgresql = PostgreSQL::new(
        SettingsBuilder::new()
            .temporary(true)
            .username("postgres")
            .password("keyla")
            .build(),
    );
    postgresql.setup().await.unwrap();
    postgresql.start().await.unwrap();
    let url = postgresql.settings().url("postgres");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("migrations");
    apply_sql_migrations(&pool, &migrations).await.unwrap();

    let (mock_url, mock) = spawn_mock().await;

    sqlx::query("INSERT INTO tenants (id, name, status) VALUES ($1::uuid, 'test', 'active')")
        .bind(TENANT)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO providers (id, tenant_id, base_url, requires_account, enabled)
         VALUES ('mock', NULL, $1, true, true)",
    )
    .bind(&mock_url)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO models (provider_id, model_id, wire_family, service_kind, endpoint_path)
         VALUES ('mock', 'gpt-test', 'chat', 'llm', '/v1/chat/completions')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO providers (id, tenant_id, base_url, requires_account, enabled)
         VALUES ('mockmsg', NULL, $1, true, true), ('mockresp', NULL, $1, true, true)",
    )
    .bind(&mock_url)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO models (provider_id, model_id, wire_family, service_kind, endpoint_path)
         VALUES ('mockmsg', 'claude-test', 'messages', 'llm', '/v1/messages'),
                ('mockresp', 'gpt-resp', 'responses', 'llm', '/v1/responses')",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (id, label, secret) in [(ACCOUNT_A, "A", "sk-bad"), (ACCOUNT_B, "B", "sk-good")] {
        let ciphertext = encrypt_credential(secret.as_bytes()).unwrap();
        sqlx::query(
            "INSERT INTO provider_accounts
               (id, provider_id, tenant_id, label, credential_kind, credential_ciphertext, status)
             VALUES ($1::uuid, 'mock', NULL, $2, 'api_key', $3, 'active')",
        )
        .bind(id)
        .bind(label)
        .bind(ciphertext)
        .execute(&pool)
        .await
        .unwrap();
    }
    for (id, provider) in [
        ("aaaaaaaa-0000-0000-0000-000000000003", "mockmsg"),
        ("aaaaaaaa-0000-0000-0000-000000000004", "mockresp"),
    ] {
        let ciphertext = encrypt_credential(b"sk-good").unwrap();
        sqlx::query(
            "INSERT INTO provider_accounts
               (id, provider_id, tenant_id, label, credential_kind, credential_ciphertext, status)
             VALUES ($1::uuid, $2, NULL, 'good', 'api_key', $3, 'active')",
        )
        .bind(id)
        .bind(provider)
        .bind(ciphertext)
        .execute(&pool)
        .await
        .unwrap();
    }
    let key_hash = token_hash("sk-test").unwrap();
    let denied_hash = token_hash("sk-denied").unwrap();
    sqlx::query(
        "INSERT INTO api_keys
           (id, tenant_id, key_hash, key_mode, label, scopes, enabled, model_access_mode)
         VALUES ('cccccccc-0000-0000-0000-000000000001', $1::uuid, $2, 'personal',
                 'main', '[\"routing:invoke\"]'::jsonb, true, 'whitelist'),
                ('cccccccc-0000-0000-0000-000000000002', $1::uuid, $3, 'personal',
                 'denied', '[\"routing:invoke\"]'::jsonb, true, 'blacklist')",
    )
    .bind(TENANT)
    .bind(&key_hash)
    .bind(&denied_hash)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE api_keys SET model_list = '[\"gpt-test\"]'::jsonb
         WHERE id = 'cccccccc-0000-0000-0000-000000000002'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO console_settings (tenant_id, preferences)
         VALUES ($1::uuid, '{\"promptInjection\":{\"enabled\":true,\"prompt\":\"Injected operator policy.\",\"targetModels\":[\"mock/gpt-test\"],\"placement\":\"developer\"}}'::jsonb)",
    )
    .bind(TENANT)
    .execute(&pool)
    .await
    .unwrap();

    let runtime = Arc::new(GatewayRuntime::new(pool.clone(), None).unwrap());
    let state = AppState::new(
        StaticAssets::new("/nonexistent-dashboard"),
        Arc::new(UnavailableDependencies),
    )
    .with_runtime(runtime);
    let app = build_app(state);

    // 1. Non-streaming: first account has a bad credential, so failover must
    // reach the second and return a normal completion.
    mock.set_mode(Mode::Json);
    let (status, _, body) = call(
        &app,
        post_chat(
            Some("sk-test"),
            json!({"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["object"], "chat.completion");
    assert_eq!(
        response["choices"][0]["message"]["content"],
        "hello from mock"
    );
    assert_eq!(response["choices"][0]["finish_reason"], "stop");
    assert_eq!(response["usage"]["total_tokens"], 10);
    assert_eq!(response["system_fingerprint"], "fp_mock");
    let seen = mock.seen();
    assert_eq!(seen.len(), 2, "one failed attempt then failover");
    assert_eq!(seen[0].authorization.as_deref(), Some("Bearer sk-bad"));
    assert_eq!(seen[1].authorization.as_deref(), Some("Bearer sk-good"));
    assert_eq!(seen[1].model, "gpt-test");
    assert_eq!(seen[1].user_content, "hi");
    assert!(
        seen[1]
            .trusted_instructions
            .contains("Injected operator policy."),
        "prompt injection did not reach the upstream chat body: {}",
        seen[1].trusted_instructions
    );

    // 2. Streaming: the same failover, then canonical SSE re-encoded for the
    // client with a single terminal frame and [DONE].
    mock.clear();
    mock.set_mode(Mode::Sse);
    let (status, headers, body) = call(
        &app,
        post_chat(
            Some("sk-test"),
            json!({"model": "gpt-test", "stream": true,
                   "messages": [{"role": "user", "content": "stream please"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "no-cache, no-transform"
    );
    assert_eq!(headers.get("x-accel-buffering").unwrap(), "no");
    assert!(body.contains("\"role\":\"assistant\""));
    assert!(body.contains("\"content\":\"hel\""));
    assert!(body.contains("\"content\":\"lo\""));
    assert!(body.contains("\"finish_reason\":\"stop\""));
    assert!(body.ends_with("data: [DONE]\n\n"));
    assert_eq!(
        mock.seen().len(),
        2,
        "stream failover happened before bytes"
    );

    // 3. Authentication failures never reach the upstream.
    mock.clear();
    let (status, _, body) = call(
        &app,
        post_chat(None, json!({"model": "gpt-test", "messages": []})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("invalid_request"));
    let (status, _, _) = call(
        &app,
        post_chat(
            Some("sk-unknown"),
            json!({"model": "gpt-test", "messages": []}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(mock.seen().is_empty());

    // 4. Per-key model access is enforced before dispatch with a 404 envelope.
    let (status, _, body) = call(
        &app,
        post_chat(
            Some("sk-denied"),
            json!({"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("model_not_found"));
    assert!(body.contains("model-denied"));
    assert!(mock.seen().is_empty(), "denial never reaches the provider");

    // 5. Unknown model resolves to a 404 before any dispatch.
    let (status, _, body) = call(
        &app,
        post_chat(
            Some("sk-test"),
            json!({"model": "nope", "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("model_not_found"));

    // 6. Upstream 429 is classified and surfaced after exhausting candidates.
    mock.clear();
    mock.set_mode(Mode::Error(429));
    let (status, _, body) = call(
        &app,
        post_chat(
            Some("sk-test"),
            json!({"model": "gpt-test", "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("quota_exceeded"));
    assert_eq!(mock.seen().len(), 2, "both accounts were tried");

    // 7. Anthropic surface translated onto the Chat upstream.
    mock.clear();
    mock.set_mode(Mode::Json);
    let (status, _, body) = call(
        &app,
        post_path(
            "/v1/messages",
            Some("sk-test"),
            json!({"model": "gpt-test", "max_tokens": 64,
                   "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["type"], "message");
    assert_eq!(response["content"][0]["type"], "text");
    assert_eq!(response["content"][0]["text"], "hello from mock");
    assert_eq!(response["stop_reason"], "end_turn");

    // 8. Messages surface against a native Messages upstream.
    mock.clear();
    let (status, _, body) = call(
        &app,
        post_path(
            "/v1/messages",
            Some("sk-test"),
            json!({"model": "claude-test", "max_tokens": 64,
                   "messages": [{"role": "user", "content": "hi"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["type"], "message");
    assert_eq!(response["content"][0]["text"], "hello from anthropic");

    // 9. Messages streaming from the Chat upstream uses Anthropic frames.
    mock.clear();
    mock.set_mode(Mode::Sse);
    let (status, headers, body) = call(
        &app,
        post_path(
            "/v1/messages",
            Some("sk-test"),
            json!({"model": "gpt-test", "max_tokens": 64, "stream": true,
                   "messages": [{"role": "user", "content": "stream"}]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert!(body.contains("event: message_start"), "{body}");
    assert!(body.contains("event: content_block_delta"), "{body}");
    assert!(body.contains("event: message_stop"), "{body}");
    assert!(
        !body.contains("[DONE]"),
        "Messages streams do not send [DONE]"
    );

    // 10. Responses surface translated onto the Chat upstream.
    mock.clear();
    mock.set_mode(Mode::Json);
    for (body, expected) in [
        (
            json!({"model": "gpt-test", "input": "hi", "max_output_tokens": 64}),
            "hello from mock",
        ),
        (
            json!({"model": "gpt-resp", "input": "hi", "max_output_tokens": 64}),
            "hello from responses",
        ),
    ] {
        let (status, _, body) = call(&app, post_path("/v1/responses", Some("sk-test"), body)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(response["object"], "response");
        let text = response["output"]
            .as_array()
            .and_then(|output| output.first())
            .and_then(|item| item.get("content"))
            .and_then(Value::as_array)
            .and_then(|content| content.first())
            .and_then(|part| part.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(text, expected);
    }

    // 11. Responses streaming from the Chat upstream uses Responses frames.
    mock.clear();
    mock.set_mode(Mode::Sse);
    let (status, _, body) = call(
        &app,
        post_path(
            "/v1/responses",
            Some("sk-test"),
            json!({"model": "gpt-test", "input": "stream", "stream": true}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("event: response.created"), "{body}");
    assert!(body.contains("event: response.output_text.delta"), "{body}");
    assert!(body.contains("event: response.completed"), "{body}");
    assert!(!body.contains("[DONE]"));

    // 12. Legacy Completions surface, non-streaming and streaming.
    mock.clear();
    mock.set_mode(Mode::Json);
    let (status, _, body) = call(
        &app,
        post_path(
            "/v1/completions",
            Some("sk-test"),
            json!({"model": "gpt-test", "prompt": "hello", "max_tokens": 32}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["object"], "text_completion");
    assert_eq!(response["choices"][0]["text"], "hello from mock");
    assert_eq!(response["choices"][0]["finish_reason"], "stop");

    mock.set_mode(Mode::Sse);
    let (status, headers, body) = call(
        &app,
        post_path(
            "/v1/completions",
            Some("sk-test"),
            json!({"model": "gpt-test", "prompt": "hello", "stream": true}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(headers.get("content-type").unwrap(), "text/event-stream");
    assert!(body.contains("\"object\":\"text_completion\""));
    assert!(body.contains("\"text\":\"hel\""));
    assert!(body.ends_with("data: [DONE]\n\n"));

    // 12. Model discovery is authenticated and lists routable models.
    let request = Request::builder()
        .uri("/v1/models")
        .header("authorization", "Bearer sk-test")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_str(&body).unwrap();
    let ids: Vec<&str> = response["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .collect();
    for expected in ["gpt-test", "claude-test", "gpt-resp"] {
        assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
    }

    // 13. Console auth is mounted beside the data plane when a runtime exists.
    let request = Request::builder()
        .uri("/console/api/auth/first-boot")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    let response: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["requires_setup"], true);

    pool.close().await;
    postgresql.stop().await.unwrap();
    let _ = BTreeMap::<String, String>::new();
}
