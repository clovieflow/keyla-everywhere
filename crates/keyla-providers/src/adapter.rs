//! OpenAI-compatible Chat dispatch: canonical request in, canonical events
//! out. The generic path behind every API-key provider.

use std::collections::BTreeMap;

use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt};
use keyla_core::{
    CanonicalEvent, CanonicalRequest, GatewayError, GatewayErrorCode, GatewayErrorOrigin,
};
use keyla_protocol::failure::{
    classify_upstream_error, extract_upstream_message, upstream_error_identifier,
};
use keyla_protocol::primitives::endpoint_url;
use keyla_protocol::request::chat::canonical_to_chat_payload;
use keyla_protocol::response::chat::{ChatSseDecoder, parse_chat_response_to_events};
use keyla_protocol::streaming::SseDecoder;
use serde_json::{Map, Value, json};

/// One provider/model route the adapter is allowed to contact.
#[derive(Debug, Clone)]
pub struct DispatchTarget {
    pub provider_id: String,
    pub model_id: String,
    pub endpoint_path: String,
}

/// Resolved credential and provider identity for one attempt.
#[derive(Debug, Clone)]
pub struct DispatchCredential {
    pub credential_kind: String,
    pub secret: Option<String>,
    pub base_url: String,
    pub user_agent: Option<String>,
    pub extra_headers: BTreeMap<String, String>,
    pub auth_state: Option<Value>,
    pub account_id: Option<String>,
}

pub enum DispatchOutput {
    Events(Vec<CanonicalEvent>),
    Stream(BoxStream<'static, Result<CanonicalEvent, GatewayError>>),
}

const MAX_ERROR_BYTES: usize = 500;

fn network_error(message: String) -> GatewayError {
    GatewayError::new(
        GatewayErrorCode::TransportUnavailable,
        502,
        message,
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Network)
}

fn sanitize(message: &str) -> String {
    let collapsed: String = message
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect();
    collapsed.trim().chars().take(MAX_ERROR_BYTES).collect()
}

pub(crate) fn upstream_http_error(status: u16, body: &str, provider_id: &str) -> GatewayError {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let identifier = parsed
        .as_ref()
        .and_then(upstream_error_identifier)
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|value| value.get("error"))
                .and_then(|value| value.get("code"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let classification = classify_upstream_error(Some(status), identifier.as_deref());
    let message = parsed
        .as_ref()
        .map(extract_upstream_message)
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| sanitize(body));
    let mut details = Map::new();
    details.insert("providerId".into(), json!(provider_id));
    details.insert("providerStatus".into(), json!(status));
    if let Some(identifier) = identifier {
        details.insert("providerCode".into(), json!(identifier));
    }
    if !message.is_empty() {
        details.insert("raw".into(), json!(message));
    }
    GatewayError::new(
        classification.code,
        classification.status,
        if message.is_empty() {
            format!("Provider returned HTTP {status}.")
        } else {
            message
        },
        details,
    )
    .with_origin(classification.origin)
}

fn build_headers(credential: &DispatchCredential, stream: bool) -> reqwest::header::HeaderMap {
    use reqwest::header::{
        ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue, USER_AGENT,
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(if stream {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    if let Some(secret) = &credential.secret {
        if credential.credential_kind == "api_key" || credential.credential_kind == "oauth" {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {secret}")) {
                headers.insert(AUTHORIZATION, value);
            }
        }
    }
    if let Some(user_agent) = credential.user_agent.as_deref() {
        if let Ok(value) = HeaderValue::from_str(user_agent) {
            headers.insert(USER_AGENT, value);
        }
    }
    for (name, value) in &credential.extra_headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

/// Dispatches one canonical Chat request to an OpenAI-compatible upstream.
pub async fn dispatch_chat(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let mut upstream_request = request.clone();
    upstream_request.model = target.model_id.clone();
    let payload = canonical_to_chat_payload(&upstream_request, true);
    let url = endpoint_url(Some(&credential.base_url), &target.endpoint_path, false);
    let response = client
        .post(&url)
        .headers(build_headers(credential, request.stream))
        .json(&payload)
        .send()
        .await
        .map_err(|error| network_error(format!("upstream request failed: {error}")))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(
            status.as_u16(),
            &body,
            &target.provider_id,
        ));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if request.stream && content_type.contains("text/event-stream") {
        let model = target.model_id.clone();
        let mut upstream = response.bytes_stream();
        let stream = async_stream::try_stream! {
            let mut sse = SseDecoder::new();
            let mut decoder = ChatSseDecoder::new(model);
            // Hold the synthetic start frames until the upstream has actually
            // produced a body byte. If its first frame is an error the attempt
            // can still be retried on another candidate, because nothing has
            // been committed to the client yet.
            let mut start: Vec<CanonicalEvent> = decoder.start();
            let mut emitted_start = false;
            while let Some(chunk) = upstream.next().await {
                let chunk: Bytes = chunk.map_err(|error| network_error(format!("upstream stream error: {error}")))?;
                for frame in sse.push(&chunk) {
                    let events = decoder.push(&frame.data)?;
                    if !emitted_start {
                        for event in start.drain(..) {
                            yield event;
                        }
                        emitted_start = true;
                    }
                    for event in events {
                        yield event;
                    }
                }
            }
            if !emitted_start {
                for event in start.drain(..) {
                    yield event;
                }
            }
            for frame in sse.finish() {
                for event in decoder.push(&frame.data)? {
                    yield event;
                }
            }
            for event in decoder.finish(false) {
                yield event;
            }
        };
        return Ok(DispatchOutput::Stream(Box::pin(stream)));
    }

    let body = response
        .bytes()
        .await
        .map_err(|error| network_error(format!("upstream body error: {error}")))?;
    let value: Value = serde_json::from_slice(&body).map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::PlatformUnavailable,
            502,
            format!("Malformed upstream JSON: {error}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream)
    })?;
    Ok(DispatchOutput::Events(parse_chat_response_to_events(
        &value,
        &target.model_id,
    )))
}

fn messages_headers(
    credential: &DispatchCredential,
    stream: bool,
    is_oauth: bool,
) -> reqwest::header::HeaderMap {
    use reqwest::header::{
        ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue, USER_AGENT,
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(if stream {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    headers.insert(
        HeaderName::from_static("anthropic-version"),
        HeaderValue::from_static("2023-06-01"),
    );
    if let Some(secret) = &credential.secret {
        if is_oauth {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {secret}")) {
                headers.insert(AUTHORIZATION, value);
            }
        } else if let Ok(value) = HeaderValue::from_str(secret) {
            headers.insert(HeaderName::from_static("x-api-key"), value);
        }
    }
    if let Some(user_agent) = credential.user_agent.as_deref() {
        if let Ok(value) = HeaderValue::from_str(user_agent) {
            headers.insert(USER_AGENT, value);
        }
    }
    for (name, value) in &credential.extra_headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

fn responses_headers(credential: &DispatchCredential, stream: bool) -> reqwest::header::HeaderMap {
    use reqwest::header::{
        ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue, USER_AGENT,
    };
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(if stream {
            "text/event-stream"
        } else {
            "application/json"
        }),
    );
    if let Some(secret) = &credential.secret {
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {secret}")) {
            headers.insert(AUTHORIZATION, value);
        }
    }
    if let Some(user_agent) = credential.user_agent.as_deref() {
        if let Ok(value) = HeaderValue::from_str(user_agent) {
            headers.insert(USER_AGENT, value);
        }
    }
    for (name, value) in &credential.extra_headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

/// Dispatches one canonical request to an Anthropic Messages upstream.
pub async fn dispatch_messages(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let is_oauth = credential.credential_kind == "oauth";
    let mut upstream_request = request.clone();
    upstream_request.model = target.model_id.clone();
    let payload = keyla_protocol::request::messages::canonical_to_messages_payload(
        &upstream_request,
        is_oauth,
    );
    let url = endpoint_url(Some(&credential.base_url), &target.endpoint_path, is_oauth);
    let response = client
        .post(&url)
        .headers(messages_headers(credential, request.stream, is_oauth))
        .json(&payload)
        .send()
        .await
        .map_err(|error| network_error(format!("upstream request failed: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(
            status.as_u16(),
            &body,
            &target.provider_id,
        ));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if request.stream && content_type.contains("text/event-stream") {
        let model = target.model_id.clone();
        let is_oauth = credential.credential_kind == "oauth";
        let mut upstream = response.bytes_stream();
        let stream = async_stream::try_stream! {
            let mut sse = SseDecoder::new();
            let mut state = keyla_protocol::response::messages::MessagesStreamState::with_oauth(is_oauth);
            while let Some(chunk) = upstream.next().await {
                let chunk: Bytes = chunk.map_err(|error| network_error(format!("upstream stream error: {error}")))?;
                for frame in sse.push(&chunk) {
                    for event in keyla_protocol::response::messages::parse_messages_sse_event(
                        frame.event.as_deref(),
                        &frame.data,
                        &mut state,
                    ) {
                        yield event;
                    }
                }
            }
            for frame in sse.finish() {
                for event in keyla_protocol::response::messages::parse_messages_sse_event(
                    frame.event.as_deref(),
                    &frame.data,
                    &mut state,
                ) {
                    yield event;
                }
            }
            if !state.saw_message_stop() {
                for event in state.finish() {
                    yield event;
                }
            }
            let _ = model;
        };
        return Ok(DispatchOutput::Stream(Box::pin(stream)));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| network_error(format!("upstream body error: {error}")))?;
    let value: Value = serde_json::from_slice(&body).map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::PlatformUnavailable,
            502,
            format!("Malformed upstream JSON: {error}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream)
    })?;
    Ok(DispatchOutput::Events(
        keyla_protocol::response::messages::parse_messages_response(&value, &target.model_id),
    ))
}

/// Dispatches one canonical request to an OpenAI Responses upstream.
pub async fn dispatch_responses(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let mut upstream_request = request.clone();
    upstream_request.model = target.model_id.clone();
    let options = keyla_protocol::request::responses::ResponsesPayloadOptions::default()
        .with_stream(request.stream);
    let payload = keyla_protocol::request::responses::canonical_to_responses_payload(
        &upstream_request,
        options,
    );
    let url = endpoint_url(Some(&credential.base_url), &target.endpoint_path, false);
    let response = client
        .post(&url)
        .headers(responses_headers(credential, request.stream))
        .json(&payload)
        .send()
        .await
        .map_err(|error| network_error(format!("upstream request failed: {error}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(
            status.as_u16(),
            &body,
            &target.provider_id,
        ));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if request.stream && content_type.contains("text/event-stream") {
        let model = target.model_id.clone();
        let mut upstream = response.bytes_stream();
        let stream = async_stream::try_stream! {
            let mut sse = SseDecoder::new();
            let mut state = keyla_protocol::response::responses::ResponsesStreamState::new(model);
            while let Some(chunk) = upstream.next().await {
                let chunk: Bytes = chunk.map_err(|error| network_error(format!("upstream stream error: {error}")))?;
                for frame in sse.push(&chunk) {
                    for event in keyla_protocol::response::responses::parse_responses_sse_event(
                        frame.event.as_deref(),
                        &frame.data,
                        &mut state,
                    ) {
                        yield event;
                    }
                }
            }
            for frame in sse.finish() {
                for event in keyla_protocol::response::responses::parse_responses_sse_event(
                    frame.event.as_deref(),
                    &frame.data,
                    &mut state,
                ) {
                    yield event;
                }
            }
            for event in state.finish() {
                yield event;
            }
        };
        return Ok(DispatchOutput::Stream(Box::pin(stream)));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| network_error(format!("upstream body error: {error}")))?;
    let value: Value = serde_json::from_slice(&body).map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::PlatformUnavailable,
            502,
            format!("Malformed upstream JSON: {error}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream)
    })?;
    Ok(DispatchOutput::Events(
        keyla_protocol::response::responses::parse_responses_response(&value, &target.model_id),
    ))
}
