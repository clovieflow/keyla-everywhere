//! Qoder (COSY) chat adapter.
//!
//! Qoder's wire is a signed envelope around an OpenAI-chat-shaped SSE stream:
//! AES-128-CBC identity, RSA-PKCS1 key wrapping, MD5 signatures, an
//! alphabet-scrambled base64 body, and `{statusCodeValue, body}` SSE frames.
//! Ported from `src/providers/integrations/qoder.ts`; the protocol is
//! unverified without a live Qoder account.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cbc::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use futures_util::stream::{BoxStream, StreamExt};
use keyla_core::{
    CanonicalEvent, CanonicalRequest, CanonicalStopReason, ContentPart, GatewayError,
    GatewayErrorCode, GatewayErrorOrigin, TerminalState, UsageRecord,
};
use rsa::PublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget};

const QODER_VERSION: &str = "1.1.65";
const QODER_BUSINESS_VERSION: &str = "1.0.22";
const QODER_APPCODE: &str = "cosy";
const QODER_SIG_SECRET: &str = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw==";
const QODER_JOB_TOKEN_URL: &str = "https://center.qoder.sh/algo/api/v3/user/jobToken?Encode=1";
const QODER_STANDARD_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const QODER_ALPHABET: &str = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!";
const QODER_RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc\n4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l\n6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17\nXcW+ML9FoCI6AOvOzwIDAQAB\n-----END PUBLIC KEY-----";

#[derive(Debug, Clone)]
struct QoderAuth {
    user_id: String,
    user_name: String,
    user_type: String,
    security_oauth_token: String,
    refresh_token: String,
    machine_id: String,
}

#[derive(Debug, Clone)]
struct ModelConfig {
    display_name: String,
    max_input_tokens: i64,
    max_output_tokens: i64,
    is_vl: bool,
    is_reasoning: bool,
    source: String,
}

fn model_config(model_id: &str) -> ModelConfig {
    let (display, input, output, vl, reasoning) = match model_id {
        "auto" => ("Auto", 180_000, 32_768, true, false),
        "ultimate" => ("Ultimate", 180_000, 32_768, true, true),
        "performance" => ("Performance", 272_000, 32_768, true, false),
        "efficient" => ("Efficient", 180_000, 32_768, true, false),
        "lite" => ("Lite", 180_000, 32_768, false, true),
        "qmodel" => ("Qwen 3.6 Plus", 180_000, 32_768, true, false),
        "qmodel_latest" => ("Qwen 3.7 Max", 1_000_000, 32_768, true, false),
        "qmodel_preview" => ("Qwen 3.8 Max", 1_000_000, 32_768, true, false),
        "dmodel" => ("DeepSeek V4 Pro", 180_000, 32_768, true, true),
        "dfmodel" => ("DeepSeek V4 Flash", 180_000, 32_768, true, true),
        "gm51model" => ("GLM 5.1", 180_000, 32_768, true, true),
        "kmodel" => ("Kimi K2.6", 256_000, 32_768, true, false),
        "mmodel" => ("MiniMax M2.7", 180_000, 32_768, true, false),
        "kmodel_latest" => ("Kimi K2.7 Latest", 256_000, 32_768, true, false),
        other => (other, 180_000, 32_768, true, false),
    };
    ModelConfig {
        display_name: display.to_owned(),
        max_input_tokens: input,
        max_output_tokens: output,
        is_vl: vl,
        is_reasoning: reasoning,
        source: "system".to_owned(),
    }
}

fn md5_hex(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", md5::compute(value))
}

fn path_signature(url: &str) -> String {
    let path = url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|index| &rest[index..]))
        .unwrap_or(url);
    path.strip_prefix("/algo").unwrap_or(path).to_owned()
}

fn utc_http_date() -> String {
    chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn static_headers(machine_id: &str) -> BTreeMap<String, String> {
    let date = utc_http_date();
    let mut headers = BTreeMap::new();
    for (name, value) in [
        ("cosy-machinetoken", machine_id),
        ("cosy-machinetype", "5"),
        ("cosy-machineid", machine_id),
        ("cosy-clienttype", "5"),
        ("cosy-version", QODER_VERSION),
        ("login-version", "v2"),
        ("appcode", QODER_APPCODE),
        ("accept", "application/json"),
        ("accept-encoding", "identity"),
        ("content-type", "application/json"),
        ("user-agent", "Go-http-client/2.0"),
    ] {
        headers.insert(name.to_owned(), value.to_owned());
    }
    headers.insert("date".into(), date.clone());
    headers.insert(
        "signature".into(),
        md5_hex(format!("{QODER_APPCODE}&{QODER_SIG_SECRET}&{date}")),
    );
    headers
}

fn transform_body(plaintext: &str) -> Vec<u8> {
    let base64 = BASE64.encode(plaintext.as_bytes());
    let third = base64.len() / 3;
    let reordered = format!(
        "{}{}{}",
        &base64[base64.len() - third..],
        &base64[third..base64.len() - third],
        &base64[..third]
    );
    reordered
        .chars()
        .map(|character| {
            if character == '=' {
                '$'
            } else {
                QODER_STANDARD_ALPHABET
                    .find(character)
                    .and_then(|index| QODER_ALPHABET.as_bytes().get(index))
                    .map(|byte| *byte as char)
                    .unwrap_or(character)
            }
        })
        .collect::<String>()
        .into_bytes()
}

fn qoder_machine_os() -> &'static str {
    "aarch64_macos"
}

fn cosy_headers(body: &[u8], url: &str, auth: &QoderAuth) -> BTreeMap<String, String> {
    let key = Uuid::new_v4().simple().to_string()[..16].to_owned();
    let identity = json!({
        "name": auth.user_name,
        "aid": auth.user_id,
        "uid": auth.user_id,
        "yx_uid": "",
        "organization_id": "",
        "organization_name": "",
        "user_type": auth.user_type,
        "security_oauth_token": auth.security_oauth_token,
        "refresh_token": auth.refresh_token,
    })
    .to_string();
    let ciphertext = cbc::Encryptor::<Aes128>::new_from_slices(key.as_bytes(), key.as_bytes())
        .expect("16-byte key")
        .encrypt_padded_vec_mut::<Pkcs7>(identity.as_bytes());
    let info = BASE64.encode(ciphertext);
    let cosy_key = PublicKey::from_public_key_pem(QODER_RSA_PUBLIC_KEY)
        .or_else(|_| PublicKey::from_pkcs1_pem(QODER_RSA_PUBLIC_KEY))
        .ok()
        .and_then(|public| public.pkcs1v15_encrypt(key.as_bytes()).ok())
        .map(|bytes| BASE64.encode(bytes))
        .unwrap_or_default();
    let payload = BASE64.encode(
        json!({
            "version": "v1",
            "requestId": Uuid::new_v4().to_string(),
            "info": info,
            "cosyVersion": QODER_VERSION,
            "ideVersion": "",
        })
        .to_string(),
    );
    let date = chrono::Utc::now().timestamp().to_string();
    let body_latin: String = body.iter().map(|byte| *byte as char).collect();
    let signature = md5_hex(format!(
        "{payload}\n{cosy_key}\n{date}\n{body_latin}\n{}",
        path_signature(url)
    ));
    let mut headers = static_headers(&auth.machine_id);
    for (name, value) in [
        (
            "authorization",
            format!("Bearer COSY.{payload}.{signature}"),
        ),
        ("cosy-data-policy", "agree".to_owned()),
        ("cosy-machinetype", "5".to_owned()),
        ("cosy-machineos", qoder_machine_os().to_owned()),
        ("cosy-clienttype", "5".to_owned()),
        ("cosy-date", date.clone()),
        ("cosy-user", auth.user_id.clone()),
        ("cosy-key", cosy_key),
        ("cosy-bodyhash", md5_hex(body)),
        ("cosy-bodylength", body.len().to_string()),
        ("cosy-sigpath", path_signature(url)),
        ("cosy-organization-id", String::new()),
        ("cosy-organization-tags", String::new()),
        ("x-request-id", Uuid::new_v4().to_string()),
        ("cosy-business-product", "cli".to_owned()),
        ("cosy-business-type", "agent".to_owned()),
        ("cosy-business-version", QODER_BUSINESS_VERSION.to_owned()),
        ("cosy-scene", "assistant".to_owned()),
        ("cosy-version", QODER_VERSION.to_owned()),
        ("login-version", "v2".to_owned()),
        ("appcode", QODER_APPCODE.to_owned()),
        ("accept", "application/json".to_owned()),
        ("accept-encoding", "identity".to_owned()),
        ("content-type", "application/json".to_owned()),
        ("user-agent", "Go-http-client/2.0".to_owned()),
    ] {
        headers.insert(name.to_owned(), value);
    }
    let date = utc_http_date();
    headers.insert("date".into(), date.clone());
    headers.insert(
        "signature".into(),
        md5_hex(format!("{QODER_APPCODE}&{QODER_SIG_SECRET}&{date}")),
    );
    headers
}

fn parse_auth_state(value: Option<&Value>) -> Result<(String, String), GatewayError> {
    let state = value.ok_or_else(|| {
        GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "Qoder OAuth account is missing its user identity; sign in again",
            Map::new(),
        )
    })?;
    let user_id = state
        .get("userId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "Qoder OAuth account is missing its user identity; sign in again",
                Map::new(),
            )
        })?;
    let machine_id = state
        .get("machineId")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    Ok((user_id.to_owned(), machine_id))
}

fn machine_id_for_pat(pat: &str) -> String {
    let digest = md5_hex(pat);
    format!(
        "{}-{}-{}-{}-{}",
        &digest[0..8],
        &digest[8..12],
        &digest[12..16],
        &digest[16..20],
        &digest[20..32]
    )
}

async fn exchange_pat(
    client: &reqwest::Client,
    pat: &str,
    machine_id: &str,
) -> Result<QoderAuth, GatewayError> {
    let plaintext = json!({
        "payload": json!({
            "personalToken": pat,
            "securityOauthToken": "",
            "refreshToken": "",
            "needRefresh": false,
            "authInfo": {},
        }).to_string(),
        "encodeVersion": "1",
    })
    .to_string();
    let encoded = transform_body(&plaintext);
    let mut request = client.post(QODER_JOB_TOKEN_URL).body(encoded);
    for (name, value) in static_headers(machine_id) {
        request = request.header(name, value);
    }
    let response = request.send().await.map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::TransportUnavailable,
            502,
            format!("Qoder PAT exchange failed: {error}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Network)
    })?;
    let status = response.status();
    let payload: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            format!("Qoder PAT exchange returned HTTP {}", status.as_u16()),
            Map::new(),
        ));
    }
    let user_id = payload.get("id").and_then(Value::as_str).ok_or_else(|| {
        GatewayError::new(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "Qoder PAT exchange omitted id",
            Map::new(),
        )
    })?;
    let token = payload
        .get("securityOauthToken")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "Qoder PAT exchange omitted securityOauthToken",
                Map::new(),
            )
        })?;
    Ok(QoderAuth {
        user_id: user_id.to_owned(),
        user_name: payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        user_type: payload
            .get("userType")
            .and_then(Value::as_str)
            .unwrap_or("personal_standard")
            .to_owned(),
        security_oauth_token: token.to_owned(),
        refresh_token: payload
            .get("refreshToken")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        machine_id: machine_id.to_owned(),
    })
}

fn flatten_content(parts: &[ContentPart]) -> String {
    parts
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.clone()),
            ContentPart::ToolResult { content, .. } => Some(match content {
                keyla_core::ToolResultContent::Text(text) => text.clone(),
                keyla_core::ToolResultContent::Parts(parts) => flatten_content(parts),
            }),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn stable_hash(prefix: &str, parts: &[&str]) -> String {
    let mut material = prefix.to_owned();
    for part in parts {
        material.push('\0');
        material.push_str(part);
    }
    md5_hex(material)[..16].to_owned()
}

fn requested_max_tokens(request: &CanonicalRequest, config: &ModelConfig) -> i64 {
    let requested = request
        .generation_controls
        .max_tokens
        .or(request.generation_controls.max_output_tokens)
        .filter(|value| *value > 0);
    requested.map_or(config.max_output_tokens, |value| {
        value.min(config.max_output_tokens)
    })
}

fn build_body(
    request: &CanonicalRequest,
    model_id: &str,
    config: &ModelConfig,
    auth: &QoderAuth,
) -> Value {
    let mut system_parts = Vec::new();
    for part in request
        .system
        .iter()
        .flatten()
        .chain(request.instructions.iter().flatten())
    {
        if let ContentPart::Text { text } = part {
            system_parts.push(text.clone());
        }
    }
    for message in &request.messages {
        if matches!(
            message.role,
            keyla_core::Role::System | keyla_core::Role::Developer
        ) {
            let text = flatten_content(&message.content);
            if !text.is_empty() {
                system_parts.push(text);
            }
        }
    }
    let system_prompt = system_parts.join("\n\n").trim().to_owned();
    let mut messages = Vec::new();
    if !system_prompt.is_empty() {
        messages.push(json!({
            "role": "system",
            "content": system_prompt,
            "contents": [{"type": "text", "text": system_prompt}],
        }));
    }
    for message in &request.messages {
        if matches!(
            message.role,
            keyla_core::Role::System | keyla_core::Role::Developer
        ) {
            continue;
        }
        let results: Vec<&ContentPart> = message
            .content
            .iter()
            .filter(|part| matches!(part, ContentPart::ToolResult { .. }))
            .collect();
        if !results.is_empty() {
            for part in &results {
                if let ContentPart::ToolResult {
                    call_id, content, ..
                } = part
                {
                    let text = match content {
                        keyla_core::ToolResultContent::Text(text) => text.clone(),
                        keyla_core::ToolResultContent::Parts(parts) => flatten_content(parts),
                    };
                    messages.push(json!({
                        "role": "tool",
                        "content": text,
                        "contents": [{"type": "text", "text": text}],
                        "tool_call_id": call_id,
                    }));
                }
            }
            let remaining: Vec<ContentPart> = message
                .content
                .iter()
                .filter(|part| !matches!(part, ContentPart::ToolResult { .. }))
                .cloned()
                .collect();
            if remaining.is_empty() {
                continue;
            }
            let flat = flatten_content(&remaining);
            messages.push(json!({
                "role": "user",
                "content": flat,
                "contents": [{"type": "text", "text": flat}],
            }));
            continue;
        }
        let flat = flatten_content(&message.content);
        messages.push(json!({
            "role": if matches!(message.role, keyla_core::Role::Assistant) { "assistant" } else { "user" },
            "content": flat,
            "contents": [{"type": "text", "text": flat}],
        }));
    }
    let latest_user = messages
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let max_tokens = requested_max_tokens(request, config);
    let session_id = stable_hash("qoder-session", &[&auth.user_id, model_id]);
    let record_id = stable_hash(
        "qoder-record",
        &[
            model_id,
            &flatten_content(
                request
                    .messages
                    .iter()
                    .flat_map(|message| message.content.clone())
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        ],
    );
    json!({
        "request_id": Uuid::new_v4().to_string(),
        "request_set_id": record_id,
        "chat_record_id": record_id,
        "session_id": session_id,
        "stream": true,
        "aliyun_user_type": "",
        "chat_task": "FREE_INPUT",
        "is_reply": true,
        "is_retry": false,
        "source": 1,
        "version": "3",
        "session_type": "qodercli",
        "agent_id": "agent_common",
        "task_id": "common",
        "code_language": "",
        "chat_prompt": system_prompt,
        "image_urls": Value::Null,
        "chat_context": {
            "chatPrompt": system_prompt,
            "imageUrls": Value::Null,
            "extra": {"context": [], "modelConfig": {"key": model_id, "is_reasoning": config.is_reasoning}, "originalContent": latest_user},
            "features": [],
            "text": latest_user,
        },
        "model_config": {
            "key": model_id,
            "display_name": config.display_name,
            "is_vl": config.is_vl,
            "is_reasoning": config.is_reasoning,
            "max_input_tokens": config.max_input_tokens,
            "max_output_tokens": config.max_output_tokens,
            "source": config.source,
        },
        "messages": messages,
        "max_tokens": max_tokens,
    })
}

fn map_stop(raw: Option<&str>) -> Option<CanonicalStopReason> {
    match raw? {
        "stop" => Some(CanonicalStopReason::Stop),
        "length" => Some(CanonicalStopReason::Length),
        "tool_calls" => Some(CanonicalStopReason::ToolUse),
        "content_filter" => Some(CanonicalStopReason::ContentFilter),
        _ => None,
    }
}

fn envelope_frames(data: &str) -> Result<Vec<String>, GatewayError> {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed == "[DONE]" {
        return Ok(vec!["[DONE]".to_owned()]);
    }
    let Ok(envelope) = serde_json::from_str::<Value>(trimmed) else {
        return Ok(Vec::new());
    };
    if let Some(status) = envelope.get("statusCodeValue").and_then(Value::as_i64) {
        if status != 200 {
            let message = envelope
                .get("body")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && *value != "[DONE]")
                .unwrap_or("Qoder stream envelope returned an error");
            return Err(GatewayError::new(
                GatewayErrorCode::UpstreamConflict,
                status.clamp(400, 599) as u16,
                message,
                Map::new(),
            )
            .with_origin(GatewayErrorOrigin::Upstream));
        }
    }
    match envelope.get("body") {
        Some(Value::String(body)) if body == "[DONE]" => Ok(vec!["[DONE]".to_owned()]),
        Some(Value::String(body)) => Ok(vec![body.replace(['\r', '\n'], "")]),
        _ => Ok(Vec::new()),
    }
}

fn stream_events(
    body: reqwest::Response,
    model: String,
) -> BoxStream<'static, Result<CanonicalEvent, GatewayError>> {
    let stream = async_stream::stream! {
        let mut sequence = 1u64;
        yield Ok(CanonicalEvent::ResponseStart {
            sequence_number: sequence,
            event_id: None,
            response_id: None,
            model: Some(model.clone()),
            system_fingerprint: None,
            timestamp: None,
        });
        sequence += 1;
        let mut decoder = keyla_protocol::streaming::SseDecoder::new();
        let mut finish_reason: Option<String> = None;
        let mut usage: Option<Value> = None;
        let mut bytes = body.bytes_stream();
        while let Some(chunk) = bytes.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    yield Err(GatewayError::new(
                        GatewayErrorCode::TransportUnavailable,
                        502,
                        format!("Qoder stream failed: {error}"),
                        Map::new(),
                    ).with_origin(GatewayErrorOrigin::Network));
                    return;
                }
            };
            let events = decoder.push(&chunk);
            for event in events {
                let frames = match envelope_frames(&event.data) {
                    Ok(frames) => frames,
                    Err(error) => { yield Err(error); return; }
                };
                for frame in frames {
                    if frame == "[DONE]" { continue; }
                    let Ok(payload) = serde_json::from_str::<Value>(&frame) else { continue };
                    if let Some(value) = payload.get("usage").filter(|value| value.is_object()) {
                        usage = Some(value.clone());
                    }
                    if let Some(reason) = payload.get("finish_reason").and_then(Value::as_str) {
                        finish_reason = Some(reason.to_owned());
                    }
                    for choice in payload.get("choices").and_then(Value::as_array).into_iter().flatten() {
                        if let Some(delta) = choice.get("delta") {
                            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                                if !text.is_empty() {
                                    yield Ok(CanonicalEvent::ContentDelta {
                                        sequence_number: sequence,
                                        content: ContentPart::Text { text: text.to_owned() },
                                        event_id: None, response_id: None, item_id: None,
                                        output_index: None, content_index: None, timestamp: None,
                                    });
                                    sequence += 1;
                                }
                            }
                            let reasoning = delta
                                .get("reasoning_content")
                                .or_else(|| delta.get("reasoning"))
                                .and_then(|value| value.as_str().or_else(|| value.get("text").and_then(Value::as_str)));
                            if let Some(text) = reasoning.filter(|text| !text.is_empty()) {
                                yield Ok(CanonicalEvent::ContentDelta {
                                    sequence_number: sequence,
                                    content: ContentPart::Reasoning { payload: Value::Null, opaque: None, summary: Some(text.to_owned()), summary_index: None, signature: None, encrypted_content: None },
                                    event_id: None, response_id: None, item_id: None,
                                    output_index: None, content_index: None, timestamp: None,
                                });
                                sequence += 1;
                            }
                            for (index, call) in delta.get("tool_calls").and_then(Value::as_array).into_iter().flatten().enumerate() {
                                let function = call.get("function");
                                yield Ok(CanonicalEvent::ToolCallDelta {
                                    sequence_number: sequence,
                                    call_id: call.get("id").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| format!("call_{index}")),
                                    index: Some(index as i64),
                                    name: function.and_then(|value| value.get("name")).and_then(Value::as_str).map(str::to_owned),
                                    arguments_delta: function.and_then(|value| value.get("arguments")).and_then(Value::as_str).map(str::to_owned),
                                    event_id: None, response_id: None, item_id: None, output_index: None, timestamp: None,
                                });
                                sequence += 1;
                            }
                        }
                        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                            finish_reason = Some(reason.to_owned());
                        }
                        if let Some(value) = choice.get("usage").filter(|value| value.is_object()) {
                            usage = Some(value.clone());
                        }
                    }
                }
            }
        }
        let stop = map_stop(finish_reason.as_deref());
        let usage_record: Option<UsageRecord> = usage.as_ref().and_then(|value| keyla_protocol::surface::usage::usage_from_provider(Some(value)));
        yield Ok(CanonicalEvent::Terminal {
            sequence_number: sequence,
            state: TerminalState::Complete,
            stop_reason: stop,
            provider_stop_reason: finish_reason,
            stop_details: None,
            usage: usage_record,
            event_id: None, response_id: None, timestamp: None,
        });
    };
    stream.boxed()
}

pub async fn dispatch_qoder(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let secret = credential
        .secret
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            GatewayError::new(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "Qoder credential is required",
                Map::new(),
            )
        })?;
    let model_id = if target.model_id.is_empty() {
        request.model.clone()
    } else {
        target.model_id.clone()
    };
    let config = model_config(&model_id);
    let auth = if secret.starts_with("pt-") {
        exchange_pat(client, secret, &machine_id_for_pat(secret)).await?
    } else {
        let (user_id, machine_id) = parse_auth_state(credential.auth_state.as_ref())?;
        QoderAuth {
            user_id,
            user_name: String::new(),
            user_type: "personal_standard".to_owned(),
            security_oauth_token: secret.to_owned(),
            refresh_token: String::new(),
            machine_id,
        }
    };
    let body = build_body(request, &model_id, &config, &auth);
    let url = if target.endpoint_path.starts_with("http") {
        target.endpoint_path.clone()
    } else {
        format!(
            "https://api2.qoder.sh{}",
            if target.endpoint_path.starts_with('/') {
                target.endpoint_path.clone()
            } else {
                format!("/{}", target.endpoint_path)
            }
        )
    };
    let encoded = transform_body(&body.to_string());
    let headers = cosy_headers(&encoded, &url, &auth);
    let mut outbound = client
        .post(&url)
        .header("accept", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("accept-encoding", "identity")
        .header("x-model-key", &model_id)
        .header("x-model-source", &config.source)
        .body(encoded);
    for (name, value) in headers {
        outbound = outbound.header(name, value);
    }
    let response = outbound.send().await.map_err(|error| {
        GatewayError::new(
            GatewayErrorCode::TransportUnavailable,
            502,
            format!("Qoder request failed: {error}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Network)
    })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        return Err(crate::adapter::upstream_http_error(status, &text, "qoder"));
    }
    Ok(DispatchOutput::Stream(stream_events(
        response,
        request.model.clone(),
    )))
}

#[allow(dead_code)]
fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{QODER_ALPHABET, path_signature, transform_body};

    #[test]
    fn path_signature_drops_algo_prefix() {
        assert_eq!(
            path_signature("https://api2.qoder.sh/algo/api/v2/chat?x=1"),
            "/api/v2/chat?x=1"
        );
    }

    #[test]
    fn transformed_body_uses_scrambled_alphabet() {
        let encoded = transform_body("{\"model\":\"auto\"}");
        assert!(!encoded.is_empty());
        for byte in encoded {
            let character = byte as char;
            assert!(character == '$' || QODER_ALPHABET.contains(character));
        }
    }
}
