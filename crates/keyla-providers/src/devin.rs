//! Devin (Codeium Cascade) provider adapter.
//!
//! Port of `src/providers/integrations/devin/{devin,devin-catalog,devin-oauth,devin-quota}.ts`.
//! The wire is Connect+protobuf over HTTP/1.1: a 5-byte frame envelope
//! (`flags:u8 | length:u32be | payload`) carrying gzip-compressed protobuf
//! messages, with a final end-of-stream frame whose payload is a JSON trailer.
//! Protobuf is encoded/decoded by hand here (no `prost`, no generated code).
//!
//! # Schema summary (field numbers from the generated TS descriptors)
//!
//! `exa.codeium_common_pb.Metadata`
//!   1  ide_name (string)            2  extension_version (string)
//!   3  api_key (string)             4  locale (string)
//!   7  ide_version (string)        12  extension_name (string)
//!  21  user_jwt (string)
//!
//! `exa.auth_pb.GetUserJwtRequest`
//!   1  metadata (Metadata)
//! `exa.auth_pb.GetUserJwtResponse`
//!   1  user_jwt (string)            2  custom_api_server_url (string)
//!
//! `exa.api_server_pb.GetCliModelConfigsRequest`
//!   1  metadata (Metadata)
//! `exa.api_server_pb.GetCliModelConfigsResponse`
//!   1  client_model_configs (repeated ClientModelConfig)
//! `exa.codeium_common_pb.ClientModelConfig`
//!   1  label (string)               2  model_or_alias (ModelOrAlias)
//!   4  disabled (bool)              5  supports_images (bool)
//!  18  max_tokens (int32)          22  model_uid (string)
//!  23  model_info (ModelInfo)
//! `exa.codeium_common_pb.ModelOrAlias` (oneof)
//!   1  model (Model enum)           2  alias (ModelAlias enum)
//!   3  model_uid (string)
//! `exa.codeium_common_pb.ModelInfo`
//!   4  max_tokens (int32)           6  model_features (ModelFeatures)
//!  13  max_output_tokens (int32)
//! `exa.codeium_common_pb.ModelFeatures`
//!  11  supports_images (bool)      12  supports_tool_calls (bool)
//!  15  supports_thinking (bool)    21  supports_parallel_tool_calls (bool)
//!
//! `exa.api_server_pb.GetChatMessageRequest`
//!   1  metadata (Metadata)          2  prompt (string)
//!   3  chat_message_prompts (repeated ChatMessagePrompt)
//!   7  request_type (ChatMessageRequestType; CASCADE = 5)
//!   8  configuration (CompletionConfiguration)
//!   9  experiment_config (ExperimentConfig)
//!  10  tools (repeated ChatToolDefinition)
//!  11  disable_parallel_tool_calls (bool)
//!  12  tool_choice (ChatToolChoice)
//!  13  system_prompt_cache_options (PromptCacheOptions)
//!  16  cascade_id (string)         20  planner_mode (ConversationalPlannerMode; DEFAULT = 1)
//!  21  chat_model_uid (string)     22  execution_id (string)
//! `exa.chat_pb.ChatMessagePrompt`
//!   1  message_id (string)          2  source (ChatMessageSource)
//!   3  prompt (string)              6  tool_calls (repeated ChatToolCall)
//!   7  tool_call_id (string)        9  tool_result_is_error (bool)
//!  10  images (repeated ImageData)
//! `exa.codeium_common_pb.ChatToolCall`
//!   1  id (string)                  2  name (string)
//!   3  arguments_json (string)      6  is_custom_tool_call (bool)
//! `exa.codeium_common_pb.ImageData`
//!   1  base64_data (string)         2  mime_type (string)
//!   3  caption (string)
//! `exa.chat_pb.ChatToolDefinition`
//!   1  name (string)                2  description (string)
//!   3  json_schema_string (string)  9  is_custom_tool (optional bool)
//!  12  strict (bool)
//! `exa.chat_pb.ChatToolChoice` (oneof)
//!   1  option_name (string)         2  tool_name (string)
//! `exa.chat_pb.PromptCacheOptions`
//!   1  type (CacheControlType; EPHEMERAL = 1)
//! `exa.codeium_common_pb.CompletionConfiguration`
//!   1  num_completions (uint64)     2  max_tokens (uint64)
//!   3  max_newlines (uint64)        5  temperature (double)
//!   6  first_temperature (double)   7  top_k (uint64)
//!   8  top_p (double)               9  stop_patterns (repeated string)
//!  11  fim_eot_prob_threshold (double)
//! `exa.codeium_common_pb.ExperimentConfig`
//!   4  force_enable_experiment_strings (repeated string)
//!
//! `exa.api_server_pb.GetChatMessageResponse`
//!   1  message_id (string)          3  delta_text (string)
//!   4  delta_tokens (uint32)        5  stop_reason (StopReason)
//!   6  delta_tool_calls (repeated ChatToolCall)
//!   7  usage (ModelUsageStats)      9  delta_thinking (string)
//! `exa.codeium_common_pb.ModelUsageStats`
//!   2  input_tokens (uint64)        3  output_tokens (uint64)
//!   4  cache_write_tokens (uint64)  5  cache_read_tokens (uint64)
//!
//! Enums used: `ChatMessageRequestType.CASCADE = 5`,
//! `ChatMessageSource.{USER = 1, SYSTEM = 2, TOOL = 4}`,
//! `ConversationalPlannerMode.DEFAULT = 1`, `CacheControlType.EPHEMERAL = 1`,
//! `StopReason.{UNSPECIFIED = 0, INCOMPLETE = 1, STOP_PATTERN = 2, MAX_TOKENS = 3}`.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use futures_util::stream::{BoxStream, StreamExt};
use keyla_core::{
    CanonicalEvent, CanonicalMessage, CanonicalRequest, CanonicalStopReason, ContentPart,
    GatewayError, GatewayErrorCode, GatewayErrorOrigin, Role, StopSequence, TerminalState,
    TokenCount, ToolDefinition, ToolResultContent, ToolType, UsageRecord, join_text_parts,
};
use keyla_protocol::failure::classify_upstream_error;
use keyla_protocol::primitives::endpoint_url;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget, upstream_http_error};

pub const DEVIN_PROVIDER_ID: &str = "devin";
pub const DEVIN_BASE_URL: &str = "https://server.codeium.com";
pub const DEVIN_CHAT_PATH: &str = "/exa.api_server_pb.ApiServerService/GetChatMessage";
const DEVIN_AUTH_PATH: &str = "/exa.auth_pb.AuthService/GetUserJwt";
const DEVIN_CONFIGS_PATH: &str = "/exa.api_server_pb.ApiServerService/GetCliModelConfigs";
const DEVIN_USER_STATUS_URL: &str = "https://server.self-serve.windsurf.com/exa.seat_management_pb.SeatManagementService/GetUserStatus";

const DEVIN_AUTHORIZE_URL: &str = "https://app.devin.ai/auth/cli/continue";
const DEVIN_TOKEN_URL: &str = "https://api.devin.ai/auth/cli/token";

const DEVIN_IDE_VERSION: &str = "3.10.35";
const DEVIN_EXTENSION_VERSION: &str = "1.49.2";
const DEVIN_SESSION_TOKEN_PREFIX: &str = "devin-session-token$";

const DEVIN_DEFAULT_STOP_PATTERNS: [&str; 5] = [
    "<|user|>",
    "<|bot|>",
    "<|context_request|>",
    "<|endoftext|>",
    "<|end_of_turn|>",
];

const MAX_CONNECT_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
const DEFAULT_DEVIN_OUTPUT_LIMIT: i64 = 64_000;
const MAX_UPSTREAM_LABEL_LENGTH: usize = 256;
const MAX_UPSTREAM_LIST_ITEMS: usize = 10_000;
const MAX_UPSTREAM_ERROR_BYTES: usize = 500;
const USER_JWT_TTL: Duration = Duration::from_secs(10 * 60);
const USER_JWT_CACHE_MAX: usize = 1024;
const DEVIN_JWT_FALLBACK_MS: i64 = 31_536_000_000;

const CONNECT_COMPRESSED_FLAG: u8 = 0x01;
const CONNECT_END_STREAM_FLAG: u8 = 0x02;

const CHAT_MESSAGE_REQUEST_TYPE_CASCADE: u64 = 5;
const CHAT_MESSAGE_SOURCE_USER: u64 = 1;
const CHAT_MESSAGE_SOURCE_SYSTEM: u64 = 2;
const CHAT_MESSAGE_SOURCE_TOOL: u64 = 4;
const CONVERSATIONAL_PLANNER_MODE_DEFAULT: u64 = 1;
const CACHE_CONTROL_TYPE_EPHEMERAL: u64 = 1;
const STOP_REASON_MAX_TOKENS: u32 = 3;

/// One catalog row projected from `ClientModelConfig`. The routing/catalog
/// layer maps this into whatever model registry it owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevinModel {
    pub model_id: String,
    pub context_limit: Option<i64>,
    pub output_limit: Option<i64>,
    pub supports_images: bool,
    pub supports_thinking: bool,
    pub supports_tool_calls: bool,
}

/// Static fallback catalog. Live discovery runs through
/// `GetCliModelConfigs`; this mirrors the TS `DEVIN_MODELS` entry.
pub fn static_devin_models() -> Vec<DevinModel> {
    vec![DevinModel {
        model_id: "swe-1-6-slow".to_owned(),
        context_limit: Some(200_000),
        output_limit: Some(64_000),
        supports_images: true,
        supports_thinking: true,
        supports_tool_calls: true,
    }]
}

/// Browser PKCE token result. Devin returns the same JWT for access and
/// refresh; there is no refresh grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevinOAuthToken {
    pub access: String,
    pub refresh: String,
    pub expires_at: DateTime<Utc>,
    pub account_label: Option<String>,
}

// ---------------------------------------------------------------------------
// Public dispatch
// ---------------------------------------------------------------------------

/// Dispatches one canonical request to the Devin Cascade chat RPC.
pub async fn dispatch_devin(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    if credential.credential_kind != "oauth" && credential.credential_kind != "api_key" {
        return Err(provider_error(
            GatewayErrorCode::InvalidRequest,
            400,
            "Devin requires an API key or OAuth credential",
        ));
    }
    let secret = credential
        .secret
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            provider_error(
                GatewayErrorCode::AuthenticationFailed,
                401,
                "Missing Devin credential",
            )
        })?;
    if (request.tools.as_deref().unwrap_or(&[]))
        .iter()
        .any(|tool| {
            !matches!(
                tool.tool_type,
                None | Some(ToolType::Function) | Some(ToolType::WebSearch)
            )
        })
    {
        return Err(provider_error(
            GatewayErrorCode::CapabilityUnsupported,
            400,
            "Devin supports function and web_search tools only",
        ));
    }

    let api_key = normalize_devin_session_token(Some(secret.trim()));
    if api_key.is_empty() {
        return Err(provider_error(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "Empty Devin credential",
        ));
    }

    let base_url = if credential.base_url.trim().is_empty() {
        DEVIN_BASE_URL.to_owned()
    } else {
        credential.base_url.trim_end_matches('/').to_owned()
    };
    let (user_jwt, resolved_base) = fetch_user_jwt(client, &api_key, &base_url).await?;

    let controls = &request.generation_controls;
    let system_prompt = join_system_prompt(request);
    let model_id = if target.model_id.is_empty() {
        request.model.clone()
    } else {
        target.model_id.clone()
    };
    let stop_sequences = match controls.stop.as_ref() {
        Some(StopSequence::One(value)) => vec![value.clone()],
        Some(StopSequence::Many(values)) => values.clone(),
        None => Vec::new(),
    };
    let options = DevinChatRequestOptions {
        max_tokens: controls.max_output_tokens.or(controls.max_tokens),
        temperature: controls.temperature,
        stop_sequences: &stop_sequences,
        conversation_id: request
            .conversation
            .as_ref()
            .and_then(|conversation| conversation.conversation_id.as_deref()),
        web_search: false,
    };
    let request_bytes = build_devin_chat_request(
        &model_id,
        &request.messages,
        &system_prompt,
        request.tools.as_deref().unwrap_or(&[]),
        &options,
        &api_key,
        &user_jwt,
    );
    let compressed = gzip_compress(&request_bytes)?;
    let frame = frame_connect_message(&compressed, CONNECT_COMPRESSED_FLAG);

    let url = endpoint_url(Some(&resolved_base), DEVIN_CHAT_PATH, false);
    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/connect+proto")
        .header("connect-protocol-version", "1")
        .header("connect-content-encoding", "gzip")
        .header("accept-encoding", "identity")
        .header("user-agent", "connect-go/1.18.1 (go1.26.3)")
        .header("connect-accept-encoding", "gzip")
        .body(frame)
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(upstream_http_error(
            status.as_u16(),
            &body,
            DEVIN_PROVIDER_ID,
        ));
    }
    if status.as_u16() == 204 || response.content_length() == Some(0) {
        return Err(provider_error(
            GatewayErrorCode::PlatformUnavailable,
            502,
            "Devin API error: empty body",
        )
        .with_origin(GatewayErrorOrigin::Upstream));
    }

    let model_name = request.model.clone();
    let mut upstream = response.bytes_stream();
    let stream: BoxStream<'static, Result<CanonicalEvent, GatewayError>> =
        async_stream::try_stream! {
            let mut sequence: u64 = 0;
            let mut latest_stop = CanonicalStopReason::Stop;
            let mut active_tool_call_id: Option<String> = None;
            let mut input_tokens: i64 = 0;
            let mut output_tokens: i64 = 0;
            let mut cache_read_tokens: i64 = 0;
            let mut cache_write_tokens: i64 = 0;

            yield CanonicalEvent::ResponseStart {
                sequence_number: sequence,
                event_id: None,
                response_id: None,
                model: Some(model_name),
                system_fingerprint: None,
                timestamp: None,
            };
            sequence += 1;

            let mut pending: Vec<u8> = Vec::new();
            while let Some(chunk) = upstream.next().await {
                let chunk: Bytes = chunk.map_err(|error| {
                    network_error(format!("Devin stream error: {error}"))
                })?;
                if chunk.is_empty() {
                    continue;
                }
                pending.extend_from_slice(&chunk);
                let (frames, consumed) =
                    consume_connect_frames(&pending, MAX_CONNECT_FRAME_PAYLOAD)?;
                pending.drain(..consumed);

                for frame in frames {
                    if frame.flags & CONNECT_END_STREAM_FLAG != 0 {
                        let trailer = if frame.flags & CONNECT_COMPRESSED_FLAG != 0 {
                            gzip_decompress(&frame.payload)?
                        } else {
                            frame.payload
                        };
                        let text = String::from_utf8_lossy(&trailer);
                        if let Some((code, message)) = read_trailer_error(text.trim()) {
                            Err::<(), GatewayError>(trailer_error(&code, &message, 500))?;
                        }
                        continue;
                    }

                    let raw = if frame.flags & CONNECT_COMPRESSED_FLAG != 0 {
                        gzip_decompress(&frame.payload)?
                    } else {
                        frame.payload
                    };
                    let message = decode_chat_response(&raw)?;

                    if !message.delta_thinking.is_empty() {
                        yield CanonicalEvent::ContentDelta {
                            sequence_number: sequence,
                            content: ContentPart::Reasoning {
                                payload: Value::Null,
                                opaque: None,
                                summary: Some(message.delta_thinking),
                                summary_index: None,
                                signature: None,
                                encrypted_content: None,
                            },
                            event_id: None,
                            response_id: None,
                            item_id: None,
                            output_index: None,
                            content_index: None,
                            timestamp: None,
                        };
                        sequence += 1;
                    }
                    if !message.delta_text.is_empty() {
                        yield CanonicalEvent::ContentDelta {
                            sequence_number: sequence,
                            content: ContentPart::Text {
                                text: message.delta_text,
                            },
                            event_id: None,
                            response_id: None,
                            item_id: None,
                            output_index: None,
                            content_index: None,
                            timestamp: None,
                        };
                        sequence += 1;
                    }
                    for tool_call in message.delta_tool_calls {
                        let name = tool_call.name.trim().to_owned();
                        let call_id = {
                            let id = tool_call.id.trim();
                            if id.is_empty() {
                                match active_tool_call_id.as_ref() {
                                    Some(active) => active.clone(),
                                    // A nameless frame without an established
                                    // call cannot be routed safely.
                                    None => continue,
                                }
                            } else {
                                id.to_owned()
                            }
                        };
                        if !name.is_empty() {
                            active_tool_call_id = Some(call_id.clone());
                            latest_stop = CanonicalStopReason::ToolUse;
                        }
                        let arguments_delta = if tool_call.arguments_json.is_empty() {
                            None
                        } else {
                            Some(tool_call.arguments_json)
                        };
                        yield CanonicalEvent::ToolCallDelta {
                            sequence_number: sequence,
                            call_id,
                            index: None,
                            name: if name.is_empty() { None } else { Some(name) },
                            arguments_delta,
                            event_id: None,
                            response_id: None,
                            item_id: None,
                            output_index: None,
                            timestamp: None,
                        };
                        sequence += 1;
                    }
                    if message.stop_reason != 0 {
                        let mapped = if message.stop_reason == STOP_REASON_MAX_TOKENS {
                            CanonicalStopReason::Length
                        } else {
                            CanonicalStopReason::Stop
                        };
                        if latest_stop != CanonicalStopReason::ToolUse
                            || mapped == CanonicalStopReason::Length
                        {
                            latest_stop = mapped;
                        }
                    }
                    if let Some(usage) = message.usage {
                        input_tokens = token_i64(usage.input_tokens);
                        output_tokens = token_i64(usage.output_tokens);
                        cache_read_tokens = token_i64(usage.cache_read_tokens);
                        cache_write_tokens = token_i64(usage.cache_write_tokens);
                        yield CanonicalEvent::Usage {
                            sequence_number: sequence,
                            usage: devin_usage(
                                input_tokens,
                                output_tokens,
                                cache_read_tokens,
                                cache_write_tokens,
                            ),
                            event_id: None,
                            response_id: None,
                            timestamp: None,
                        };
                        sequence += 1;
                    }
                }
            }

            yield CanonicalEvent::Terminal {
                sequence_number: sequence,
                state: TerminalState::Complete,
                stop_reason: Some(latest_stop),
                provider_stop_reason: None,
                stop_details: None,
                usage: Some(devin_usage(
                    input_tokens,
                    output_tokens,
                    cache_read_tokens,
                    cache_write_tokens,
                )),
                event_id: None,
                response_id: None,
                timestamp: None,
            };
        }
        .boxed();
    Ok(DispatchOutput::Stream(stream))
}

fn join_system_prompt(request: &CanonicalRequest) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in request
        .system
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .chain(request.instructions.as_deref().unwrap_or(&[]).iter())
    {
        if let ContentPart::Text { text } = part {
            parts.push(text);
        }
    }
    parts.join("\n")
}

// ---------------------------------------------------------------------------
// Live model discovery
// ---------------------------------------------------------------------------

/// Live per-account model discovery. Returns `None` on any failure so callers
/// fall back to the static catalog; discovery problems never surface as errors.
pub async fn fetch_devin_models(
    client: &reqwest::Client,
    credential: &str,
) -> Option<Vec<DevinModel>> {
    let api_key = normalize_devin_session_token(Some(credential.trim()));
    if api_key.is_empty() {
        return None;
    }
    let metadata = encode_metadata(&api_key, "", "WINDSURF", "1.0.0", "", "1.0.0", "");
    let body = encode_metadata_message(&metadata);
    let url = format!("{DEVIN_BASE_URL}{DEVIN_CONFIGS_PATH}");
    let response = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {api_key}"))
        .header("connect-protocol-version", "1")
        .header(reqwest::header::CONTENT_TYPE, "application/proto")
        .header(reqwest::header::ACCEPT, "application/proto")
        .body(body)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let mut payload = response.bytes().await.ok()?.to_vec();
    if payload.len() >= 2 && payload[0] == 0x1f && payload[1] == 0x8b {
        // Non-gzip or corrupt frame payload falls back to raw payload.
        if let Ok(decoded) = gzip_decompress(&payload) {
            payload = decoded;
        }
    }
    if payload.len() >= 5 && payload[0] <= 0x03 {
        let length = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;
        if 5 + length <= payload.len() {
            let flags = payload[0];
            let mut encoded = payload[5..5 + length].to_vec();
            if flags & CONNECT_COMPRESSED_FLAG != 0 {
                if let Ok(decoded) = gzip_decompress(&encoded) {
                    encoded = decoded;
                }
            }
            if flags & CONNECT_END_STREAM_FLAG == 0 {
                payload = encoded;
            }
        }
    }
    let configs = decode_client_model_configs(&payload).ok()?;
    let models = configs
        .iter()
        .take(MAX_UPSTREAM_LIST_ITEMS)
        .filter_map(devin_model_from_config)
        .collect::<Vec<_>>();
    if models.is_empty() {
        None
    } else {
        Some(models)
    }
}

fn devin_model_from_config(config: &ClientModelConfig) -> Option<DevinModel> {
    if config.disabled {
        return None;
    }
    let raw_uid = sanitize_upstream_label(&config.model_uid).unwrap_or_default();
    let alias_uid = config
        .model_or_alias_uid
        .as_deref()
        .and_then(sanitize_upstream_label)
        .unwrap_or_default();
    let candidate = if !raw_uid.is_empty() {
        raw_uid
    } else if !alias_uid.is_empty() {
        alias_uid
    } else {
        config.label.clone()
    };
    let id = sanitize_upstream_label(&candidate)?;

    let info = config.model_info.as_ref();
    let context_limit = info
        .and_then(|info| bounded_upstream_number(info.max_tokens))
        .or_else(|| bounded_upstream_number(config.max_tokens));
    let declared_output = info
        .and_then(|info| bounded_upstream_number(info.max_output_tokens))
        .or_else(|| bounded_upstream_number(config.max_tokens));
    let output_limit = declared_output.map(|declared| {
        declared
            .min(context_limit.unwrap_or(DEFAULT_DEVIN_OUTPUT_LIMIT))
            .min(DEFAULT_DEVIN_OUTPUT_LIMIT)
    });

    let features = info.and_then(|info| info.model_features.as_ref());
    let (supports_images, supports_thinking, supports_tool_calls) = match features {
        Some(features) => (
            features.supports_images,
            features.supports_thinking,
            features.supports_tool_calls,
        ),
        None => (config.supports_images, false, true),
    };
    Some(DevinModel {
        model_id: id,
        context_limit,
        output_limit,
        supports_images,
        supports_thinking,
        supports_tool_calls,
    })
}

fn bounded_upstream_number(value: i32) -> Option<i64> {
    let value = i64::from(value);
    (1..=100_000_000).contains(&value).then_some(value)
}

// ---------------------------------------------------------------------------
// Token handling (+ short-TTL user JWT cache)
// ---------------------------------------------------------------------------

/// Normalizes a stored credential to the upstream session-token form.
pub fn normalize_devin_session_token(api_key: Option<&str>) -> String {
    match api_key {
        None => String::new(),
        Some("") => String::new(),
        Some(value) if value.starts_with(DEVIN_SESSION_TOKEN_PREFIX) => value.to_owned(),
        Some(value) => format!("{DEVIN_SESSION_TOKEN_PREFIX}{value}"),
    }
}

#[derive(Debug, Clone)]
struct CachedUserJwt {
    user_jwt: String,
    base_url: String,
    expires_at: Instant,
}

#[derive(Default)]
struct UserJwtCache {
    entries: HashMap<String, CachedUserJwt>,
    order: VecDeque<String>,
}

static USER_JWT_CACHE: LazyLock<Mutex<UserJwtCache>> =
    LazyLock::new(|| Mutex::new(UserJwtCache::default()));

/// Test hook: forgets cached `GetUserJwt` results.
pub fn reset_devin_auth_cache() {
    let mut cache = USER_JWT_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.entries.clear();
    cache.order.clear();
}

fn lock_user_jwt_cache() -> std::sync::MutexGuard<'static, UserJwtCache> {
    USER_JWT_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cache_key(api_key: &str) -> String {
    let digest = Sha256::digest(api_key.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

async fn fetch_user_jwt(
    client: &reqwest::Client,
    api_key: &str,
    base_url: &str,
) -> Result<(String, String), GatewayError> {
    let key = cache_key(api_key);
    {
        let cache = lock_user_jwt_cache();
        if let Some(cached) = cache.entries.get(&key) {
            if cached.expires_at > Instant::now() {
                return Ok((cached.user_jwt.clone(), cached.base_url.clone()));
            }
        }
    }

    let metadata = encode_metadata(
        api_key,
        "",
        "windsurf",
        DEVIN_IDE_VERSION,
        "windsurf",
        DEVIN_EXTENSION_VERSION,
        "en",
    );
    let body = encode_get_user_jwt_request(&metadata);
    let url = format!("{base_url}{DEVIN_AUTH_PATH}");
    let response = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .header(reqwest::header::ACCEPT, "*/*")
        .body(body)
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    let payload = response
        .bytes()
        .await
        .map_err(|error| network_error(format!("Devin auth body failed: {error}")))?
        .to_vec();
    if !status.is_success() {
        let text = truncate_text(&String::from_utf8_lossy(&payload), MAX_UPSTREAM_ERROR_BYTES);
        let message = format!("Devin auth error {}: {text}", status.as_u16());
        let code = if status.as_u16() == 401 || status.as_u16() == 403 {
            GatewayErrorCode::AuthenticationFailed
        } else {
            GatewayErrorCode::PlatformUnavailable
        };
        return Err(provider_error(code, status.as_u16(), message)
            .with_origin(GatewayErrorOrigin::Upstream));
    }
    let decoded = match decode_get_user_jwt_response(&payload) {
        Ok(decoded) => decoded,
        Err(primary) => match gzip_decompress(&payload) {
            Ok(decoded) => decode_get_user_jwt_response(&decoded).map_err(|_| primary)?,
            Err(_) => return Err(primary),
        },
    };
    if decoded.user_jwt.is_empty() {
        return Err(provider_error(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "Devin auth error: GetUserJwt returned an empty user JWT",
        )
        .with_origin(GatewayErrorOrigin::Upstream));
    }
    let resolved_base = validate_upstream_base_url(&decoded.custom_api_server_url)
        .unwrap_or_else(|| base_url.to_owned());
    {
        let mut cache = lock_user_jwt_cache();
        if !cache.entries.contains_key(&key) {
            cache.order.push_back(key.clone());
        }
        cache.entries.insert(
            key,
            CachedUserJwt {
                user_jwt: decoded.user_jwt.clone(),
                base_url: resolved_base.clone(),
                expires_at: Instant::now() + USER_JWT_TTL,
            },
        );
        while cache.entries.len() > USER_JWT_CACHE_MAX {
            let Some(oldest) = cache.order.pop_front() else {
                break;
            };
            cache.entries.remove(&oldest);
        }
    }
    Ok((decoded.user_jwt, resolved_base))
}

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

/// Options for one Cascade turn.
pub struct DevinChatRequestOptions<'a> {
    pub max_tokens: Option<i64>,
    pub temperature: Option<f64>,
    pub stop_sequences: &'a [String],
    pub conversation_id: Option<&'a str>,
    pub web_search: bool,
}

#[derive(Debug, Clone, Default)]
struct ChatToolCallWire {
    id: String,
    name: String,
    arguments_json: String,
    is_custom_tool_call: bool,
}

#[derive(Debug, Clone, Default)]
struct ChatImageWire {
    base64_data: String,
    mime_type: String,
    caption: String,
}

#[derive(Debug, Clone, Default)]
struct ChatPromptWire {
    message_id: String,
    source: u64,
    prompt: String,
    tool_calls: Vec<ChatToolCallWire>,
    tool_call_id: String,
    tool_result_is_error: bool,
    images: Vec<ChatImageWire>,
}

/// Builds the `GetChatMessageRequest` proto bytes for one Cascade turn.
pub fn build_devin_chat_request(
    model_id: &str,
    messages: &[CanonicalMessage],
    system_prompt: &str,
    tools: &[ToolDefinition],
    options: &DevinChatRequestOptions<'_>,
    api_key: &str,
    user_jwt: &str,
) -> Vec<u8> {
    let cascade_id = options
        .conversation_id
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut stop_patterns: Vec<String> = DEVIN_DEFAULT_STOP_PATTERNS
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect();
    if !options.stop_sequences.is_empty() {
        stop_patterns.extend(options.stop_sequences.iter().cloned());
    }
    let has_web_search = options.web_search
        || tools
            .iter()
            .any(|tool| tool.tool_type == Some(ToolType::WebSearch) || tool.name == "web_search");
    let function_tools: Vec<&ToolDefinition> = tools
        .iter()
        .filter(|tool| {
            !tool.name.trim().is_empty()
                && tool.tool_type != Some(ToolType::WebSearch)
                && tool.name != "web_search"
        })
        .collect();

    let metadata = encode_metadata(
        api_key,
        user_jwt,
        "windsurf",
        DEVIN_IDE_VERSION,
        "windsurf",
        DEVIN_EXTENSION_VERSION,
        "en",
    );
    let tool_choice = encode_tool_choice("auto");
    let cache_options = encode_prompt_cache_options(CACHE_CONTROL_TYPE_EPHEMERAL);
    let configuration = encode_completion_configuration(
        options.max_tokens.unwrap_or(DEFAULT_DEVIN_OUTPUT_LIMIT),
        options.temperature.unwrap_or(0.4),
        &stop_patterns,
    );
    let experiments = encode_experiment_config(&if has_web_search {
        vec!["CASCADE_WEB_SEARCH_ENABLED".to_owned()]
    } else {
        Vec::new()
    });

    let mut writer = ProtoWriter::default();
    writer.message(1, &encode_metadata_message(&metadata));
    writer.string(2, system_prompt);
    for prompt in build_chat_message_prompts(messages) {
        writer.message(3, &encode_chat_prompt(&prompt));
    }
    writer.string(21, model_id);
    writer.uint64_field(7, CHAT_MESSAGE_REQUEST_TYPE_CASCADE);
    writer.message(8, &configuration);
    writer.message(9, &experiments);
    for tool in function_tools {
        writer.message(10, &encode_tool_definition(tool));
    }
    writer.bool_field(11, true);
    writer.message(12, &tool_choice);
    writer.message(13, &cache_options);
    writer.string(16, &cascade_id);
    writer.uint64_field(20, CONVERSATIONAL_PLANNER_MODE_DEFAULT);
    writer.string(22, &Uuid::new_v4().to_string());
    writer.finish()
}

fn build_chat_message_prompts(messages: &[CanonicalMessage]) -> Vec<ChatPromptWire> {
    let mut prompts = Vec::new();
    for message in messages {
        // Answers live in `tool` turns or in `user` turns (the Messages ledger
        // re-homes them), so results are extracted before the role branches.
        let mut has_results = false;
        for part in &message.content {
            let ContentPart::ToolResult {
                call_id,
                content,
                is_error,
                ..
            } = part
            else {
                continue;
            };
            has_results = true;
            let text = match content {
                ToolResultContent::Text(text) => text.clone(),
                ToolResultContent::Parts(parts) => join_text_parts(parts),
            };
            prompts.push(ChatPromptWire {
                message_id: Uuid::new_v4().to_string(),
                source: CHAT_MESSAGE_SOURCE_TOOL,
                prompt: text,
                tool_call_id: call_id.clone(),
                tool_result_is_error: is_error.unwrap_or(false),
                ..ChatPromptWire::default()
            });
        }
        if has_results && message.role == Role::Tool {
            continue;
        }
        match message.role {
            Role::User | Role::Developer => {
                prompts.push(ChatPromptWire {
                    message_id: Uuid::new_v4().to_string(),
                    source: CHAT_MESSAGE_SOURCE_USER,
                    prompt: join_text_parts(&message.content),
                    images: message
                        .content
                        .iter()
                        .filter_map(|part| match part {
                            ContentPart::Image { payload } => parse_devin_image(payload),
                            _ => None,
                        })
                        .collect(),
                    ..ChatPromptWire::default()
                });
            }
            Role::Assistant => {
                let tool_calls: Vec<ChatToolCallWire> = message
                    .content
                    .iter()
                    .filter_map(|part| match part {
                        ContentPart::ToolCall {
                            call_id,
                            name,
                            arguments,
                            ..
                        } => Some(ChatToolCallWire {
                            id: call_id.clone(),
                            name: name.clone(),
                            arguments_json: match arguments {
                                Value::String(value) => value.clone(),
                                value => serde_json::to_string(value)
                                    .unwrap_or_else(|_| "null".to_owned()),
                            },
                            is_custom_tool_call: true,
                        }),
                        _ => None,
                    })
                    .collect();
                prompts.push(ChatPromptWire {
                    message_id: Uuid::new_v4().to_string(),
                    source: CHAT_MESSAGE_SOURCE_SYSTEM,
                    prompt: join_text_parts(&message.content),
                    tool_calls,
                    ..ChatPromptWire::default()
                });
            }
            Role::System | Role::Tool => {}
        }
    }
    prompts
}

fn parse_devin_image(payload: &Value) -> Option<ChatImageWire> {
    let object = payload.as_object()?;
    if let Some(source) = object.get("source").and_then(Value::as_object) {
        if let Some(data) = source.get("data").and_then(Value::as_str) {
            let mime_type = source
                .get("media_type")
                .and_then(Value::as_str)
                .unwrap_or("image/png");
            return Some(ChatImageWire {
                base64_data: data.to_owned(),
                mime_type: mime_type.to_owned(),
                caption: String::new(),
            });
        }
    }
    let raw_base64 = object
        .get("base64_data")
        .and_then(Value::as_str)
        .or_else(|| object.get("base64Data").and_then(Value::as_str));
    if let Some(raw_base64) = raw_base64 {
        let mime = object
            .get("mime_type")
            .and_then(Value::as_str)
            .or_else(|| object.get("mimeType").and_then(Value::as_str))
            .unwrap_or("image/png");
        return Some(ChatImageWire {
            base64_data: raw_base64.to_owned(),
            mime_type: mime.to_owned(),
            caption: object
                .get("caption")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        });
    }
    let raw_url = object
        .get("url")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("image_url")
                .and_then(|value| value.get("url"))
                .and_then(Value::as_str)
        })
        .or_else(|| object.get("image_url").and_then(Value::as_str))?;
    let (mime_type, base64_data) = parse_data_url(raw_url)?;
    Some(ChatImageWire {
        base64_data: base64_data.to_owned(),
        mime_type: mime_type.to_owned(),
        caption: String::new(),
    })
}

fn parse_data_url(value: &str) -> Option<(&str, &str)> {
    let rest = value.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let mime = meta.strip_suffix(";base64")?;
    if mime.is_empty() || mime.contains(';') || data.is_empty() || data.contains('\n') {
        return None;
    }
    Some((mime, data))
}

fn encode_tool_definition(tool: &ToolDefinition) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.string(1, &tool.name);
    writer.string(2, tool.description.as_deref().unwrap_or(""));
    let schema = serde_json::to_string(&tool.json_schema).unwrap_or_else(|_| "null".to_owned());
    writer.string(3, &schema);
    // `is_custom_tool` is always set by the TS builder; `strict` carries the
    // caller's trailing `strict: true` flag.
    writer.optional_bool(9, true);
    writer.bool_field(12, tool.strict.unwrap_or(false));
    writer.finish()
}

fn encode_chat_prompt(prompt: &ChatPromptWire) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.string(1, &prompt.message_id);
    writer.uint64_field(2, prompt.source);
    writer.string(3, &prompt.prompt);
    for call in &prompt.tool_calls {
        writer.message(6, &encode_chat_tool_call(call));
    }
    writer.string(7, &prompt.tool_call_id);
    writer.bool_field(9, prompt.tool_result_is_error);
    for image in &prompt.images {
        writer.message(10, &encode_image(image));
    }
    writer.finish()
}

fn encode_chat_tool_call(call: &ChatToolCallWire) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.string(1, &call.id);
    writer.string(2, &call.name);
    writer.string(3, &call.arguments_json);
    writer.bool_field(6, call.is_custom_tool_call);
    writer.finish()
}

fn encode_image(image: &ChatImageWire) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.string(1, &image.base64_data);
    writer.string(2, &image.mime_type);
    writer.string(3, &image.caption);
    writer.finish()
}

fn encode_tool_choice(option_name: &str) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.string(1, option_name);
    writer.finish()
}

fn encode_prompt_cache_options(cache_type: u64) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.uint64_field(1, cache_type);
    writer.finish()
}

fn encode_completion_configuration(
    max_tokens: i64,
    temperature: f64,
    stop_patterns: &[String],
) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.uint64_field(1, 1);
    writer.uint64_field(2, max_tokens as u64);
    writer.uint64_field(3, 200);
    writer.double_field(5, temperature);
    writer.double_field(6, temperature);
    writer.uint64_field(7, 50);
    writer.double_field(8, 1.0);
    for pattern in stop_patterns {
        writer.string(9, pattern);
    }
    writer.double_field(11, 1.0);
    writer.finish()
}

fn encode_experiment_config(force_enable: &[String]) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    for experiment in force_enable {
        writer.string(4, experiment);
    }
    writer.finish()
}

#[allow(clippy::too_many_arguments)]
fn encode_metadata(
    api_key: &str,
    user_jwt: &str,
    ide_name: &str,
    ide_version: &str,
    extension_name: &str,
    extension_version: &str,
    locale: &str,
) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.string(1, ide_name);
    writer.string(2, extension_version);
    writer.string(3, api_key);
    writer.string(4, locale);
    writer.string(7, ide_version);
    writer.string(12, extension_name);
    writer.string(21, user_jwt);
    writer.finish()
}

fn encode_metadata_message(metadata: &[u8]) -> Vec<u8> {
    let mut writer = ProtoWriter::default();
    writer.message(1, metadata);
    writer.finish()
}

fn encode_get_user_jwt_request(metadata: &[u8]) -> Vec<u8> {
    encode_metadata_message(metadata)
}

// ---------------------------------------------------------------------------
// Streaming helpers
// ---------------------------------------------------------------------------

fn read_trailer_error(text: &str) -> Option<(String, String)> {
    if text.is_empty() {
        return None;
    }
    let parsed: Value = serde_json::from_str(text).ok()?;
    let error = parsed.get("error")?.as_object()?;
    let code = error.get("code").and_then(Value::as_str).unwrap_or("");
    let message = error.get("message").and_then(Value::as_str).unwrap_or("");
    if code.is_empty() && message.is_empty() {
        return None;
    }
    Some((code.to_owned(), message.to_owned()))
}

fn trailer_error(code: &str, message: &str, status: u16) -> GatewayError {
    let classification = classify_upstream_error(
        Some(status),
        if code.is_empty() { None } else { Some(code) },
    );
    let formatted = if code.is_empty() {
        format!("Devin stream error: {message}")
    } else {
        format!("Devin stream error {code}: {message}")
    };
    let mut details = Map::new();
    details.insert("providerId".into(), json!(DEVIN_PROVIDER_ID));
    details.insert("providerStatus".into(), json!(status));
    if !code.is_empty() {
        details.insert("providerCode".into(), json!(code));
    }
    if classification.credential_evidence {
        details.insert("credentialEvidence".into(), json!(true));
    }
    if classification.rate_limit_scope_provider {
        details.insert("rateLimitScope".into(), json!("provider"));
    }
    GatewayError::new(
        classification.code,
        classification.status,
        formatted,
        details,
    )
    .with_origin(classification.origin)
}

/// Builds the canonical usage record from Devin's protobuf usage counters.
fn devin_usage(
    input_tokens: i64,
    output_tokens: i64,
    cache_read: i64,
    cache_write: i64,
) -> UsageRecord {
    UsageRecord {
        input_tokens,
        cached_input_tokens: if cache_read > 0 {
            TokenCount::Number(cache_read)
        } else {
            TokenCount::Unavailable
        },
        cache_write_tokens: if cache_write > 0 {
            TokenCount::Number(cache_write)
        } else {
            TokenCount::Unavailable
        },
        uncached_input_tokens: if cache_read > 0 {
            TokenCount::Number((input_tokens - cache_read).max(0))
        } else {
            TokenCount::Unavailable
        },
        output_tokens,
        reasoning_tokens: TokenCount::Unavailable,
        estimated_cost: None,
        credit_used: None,
        total_tokens: Some(TokenCount::Number(input_tokens + output_tokens)),
        details: None,
    }
}

fn token_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

#[derive(Debug, Clone)]
struct ConnectFrame {
    flags: u8,
    payload: Vec<u8>,
}

/// Wraps `payload` in a 5-byte Connect envelope.
fn frame_connect_message(payload: &[u8], flags: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(flags);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Splits every complete Connect frame out of `buffer`, in order. Returns the
/// frames and the number of bytes they consumed; the tail stays for the next
/// read.
fn consume_connect_frames(
    buffer: &[u8],
    max_payload: usize,
) -> Result<(Vec<ConnectFrame>, usize), GatewayError> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while buffer.len().saturating_sub(offset) >= 5 {
        let flags = buffer[offset];
        let length = u32::from_be_bytes([
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
        ]) as usize;
        if length > max_payload {
            return Err(gzip_or_proto_error(format!(
                "Devin Connect frame length {length} exceeds cap"
            )));
        }
        let end = offset + 5 + length;
        if end > buffer.len() {
            break;
        }
        frames.push(ConnectFrame {
            flags,
            payload: buffer[offset + 5..end].to_vec(),
        });
        offset = end;
    }
    Ok((frames, offset))
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, GatewayError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|error| gzip_error(format!("Devin gzip encode failed: {error}")))?;
    encoder
        .finish()
        .map_err(|error| gzip_error(format!("Devin gzip encode failed: {error}")))
}

fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, GatewayError> {
    let mut decoder = GzDecoder::new(data);
    let mut decoded = Vec::new();
    decoder
        .read_to_end(&mut decoded)
        .map_err(|error| gzip_error(format!("Devin gzip decode failed: {error}")))?;
    Ok(decoded)
}

fn gzip_error(message: String) -> GatewayError {
    gzip_or_proto_error(message)
}

fn gzip_or_proto_error(message: String) -> GatewayError {
    provider_error(GatewayErrorCode::PlatformUnavailable, 502, message)
        .with_origin(GatewayErrorOrigin::Upstream)
}

fn proto_error(message: impl Into<String>) -> GatewayError {
    gzip_or_proto_error(format!("Malformed Devin protobuf: {}", message.into()))
}

// ---------------------------------------------------------------------------
// Protobuf wire encoding (hand-written; see schema summary at the top)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ProtoWriter {
    buf: Vec<u8>,
}

impl ProtoWriter {
    fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn varint(&mut self, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }

    fn key(&mut self, field: u32, wire: u8) {
        self.varint((u64::from(field) << 3) | u64::from(wire));
    }

    fn uint64_field(&mut self, field: u32, value: u64) {
        if value == 0 {
            return;
        }
        self.key(field, 0);
        self.varint(value);
    }

    fn bool_field(&mut self, field: u32, value: bool) {
        if !value {
            return;
        }
        self.key(field, 0);
        self.varint(1);
    }

    /// proto3 `optional bool`: explicit presence, so `false` is still encoded.
    fn optional_bool(&mut self, field: u32, value: bool) {
        self.key(field, 0);
        self.varint(u64::from(value));
    }

    fn double_field(&mut self, field: u32, value: f64) {
        if value == 0.0 {
            return;
        }
        self.key(field, 1);
        self.buf.extend_from_slice(&value.to_bits().to_le_bytes());
    }

    fn string(&mut self, field: u32, value: &str) {
        if value.is_empty() {
            return;
        }
        self.key(field, 2);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
    }

    fn message(&mut self, field: u32, value: &[u8]) {
        self.key(field, 2);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value);
    }
}

struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_varint(&mut self) -> Result<u64, GatewayError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            if self.pos >= self.buf.len() {
                return Err(proto_error("truncated varint"));
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(proto_error("varint exceeds 10 bytes"))
    }

    fn read_key(&mut self) -> Result<(u32, u8), GatewayError> {
        let key = self.read_varint()?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return Err(proto_error("field number 0"));
        }
        Ok((field, wire))
    }

    fn read_len(&mut self) -> Result<&'a [u8], GatewayError> {
        let length = self.read_varint()? as usize;
        let end = self
            .pos
            .checked_add(length)
            .ok_or_else(|| proto_error("length overflow"))?;
        if end > self.buf.len() {
            return Err(proto_error("truncated length-delimited field"));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_string(&mut self) -> Result<String, GatewayError> {
        let bytes = self.read_len()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| proto_error("invalid UTF-8"))
    }

    fn skip(&mut self, wire: u8) -> Result<(), GatewayError> {
        match wire {
            0 => {
                self.read_varint()?;
            }
            1 => {
                if self.remaining() < 8 {
                    return Err(proto_error("truncated fixed64"));
                }
                self.pos += 8;
            }
            2 => {
                self.read_len()?;
            }
            5 => {
                if self.remaining() < 4 {
                    return Err(proto_error("truncated fixed32"));
                }
                self.pos += 4;
            }
            other => return Err(proto_error(format!("unsupported wire type {other}"))),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct UsageCounts {
    input_tokens: u64,
    output_tokens: u64,
    cache_write_tokens: u64,
    cache_read_tokens: u64,
}

#[derive(Debug, Clone, Default)]
struct ChatResponse {
    delta_text: String,
    delta_thinking: String,
    stop_reason: u32,
    delta_tool_calls: Vec<ChatToolCallWire>,
    usage: Option<UsageCounts>,
}

fn decode_chat_response(bytes: &[u8]) -> Result<ChatResponse, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut message = ChatResponse::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (3, 2) => message.delta_text = reader.read_string()?,
            (5, 0) => message.stop_reason = reader.read_varint()? as u32,
            (6, 2) => message
                .delta_tool_calls
                .push(decode_chat_tool_call(reader.read_len()?)?),
            (7, 2) => message.usage = Some(decode_usage_counts(reader.read_len()?)?),
            (9, 2) => message.delta_thinking = reader.read_string()?,
            _ => reader.skip(wire)?,
        }
    }
    Ok(message)
}

fn decode_chat_tool_call(bytes: &[u8]) -> Result<ChatToolCallWire, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut call = ChatToolCallWire::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, 2) => call.id = reader.read_string()?,
            (2, 2) => call.name = reader.read_string()?,
            (3, 2) => call.arguments_json = reader.read_string()?,
            (6, 0) => call.is_custom_tool_call = reader.read_varint()? != 0,
            _ => reader.skip(wire)?,
        }
    }
    Ok(call)
}

fn decode_usage_counts(bytes: &[u8]) -> Result<UsageCounts, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut usage = UsageCounts::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (2, 0) => usage.input_tokens = reader.read_varint()?,
            (3, 0) => usage.output_tokens = reader.read_varint()?,
            (4, 0) => usage.cache_write_tokens = reader.read_varint()?,
            (5, 0) => usage.cache_read_tokens = reader.read_varint()?,
            _ => reader.skip(wire)?,
        }
    }
    Ok(usage)
}

#[derive(Debug, Clone, Default)]
struct JwtResponse {
    user_jwt: String,
    custom_api_server_url: String,
}

fn decode_get_user_jwt_response(bytes: &[u8]) -> Result<JwtResponse, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut response = JwtResponse::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, 2) => response.user_jwt = reader.read_string()?,
            (2, 2) => response.custom_api_server_url = reader.read_string()?,
            _ => reader.skip(wire)?,
        }
    }
    Ok(response)
}

#[derive(Debug, Clone, Default)]
struct ModelFeaturesRaw {
    supports_images: bool,
    supports_thinking: bool,
    supports_tool_calls: bool,
}

#[derive(Debug, Clone, Default)]
struct ModelInfoRaw {
    max_tokens: i32,
    max_output_tokens: i32,
    model_features: Option<ModelFeaturesRaw>,
}

#[derive(Debug, Clone, Default)]
struct ClientModelConfig {
    label: String,
    model_uid: String,
    model_or_alias_uid: Option<String>,
    max_tokens: i32,
    supports_images: bool,
    disabled: bool,
    model_info: Option<ModelInfoRaw>,
}

fn decode_client_model_configs(bytes: &[u8]) -> Result<Vec<ClientModelConfig>, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut configs = Vec::new();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, 2) => configs.push(decode_client_model_config(reader.read_len()?)?),
            _ => reader.skip(wire)?,
        }
    }
    Ok(configs)
}

fn decode_client_model_config(bytes: &[u8]) -> Result<ClientModelConfig, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut config = ClientModelConfig::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, 2) => config.label = reader.read_string()?,
            (2, 2) => config.model_or_alias_uid = decode_model_or_alias(reader.read_len()?)?,
            (4, 0) => config.disabled = reader.read_varint()? != 0,
            (5, 0) => config.supports_images = reader.read_varint()? != 0,
            (18, 0) => config.max_tokens = reader.read_varint()? as i32,
            (22, 2) => config.model_uid = reader.read_string()?,
            (23, 2) => config.model_info = Some(decode_model_info(reader.read_len()?)?),
            _ => reader.skip(wire)?,
        }
    }
    Ok(config)
}

fn decode_model_or_alias(bytes: &[u8]) -> Result<Option<String>, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut model_uid = None;
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (3, 2) => model_uid = Some(reader.read_string()?),
            // Fields 1 (`Model`) and 2 (`ModelAlias`) are enums with no string
            // identity; the TS projection reads only the model_uid case.
            _ => reader.skip(wire)?,
        }
    }
    Ok(model_uid)
}

fn decode_model_info(bytes: &[u8]) -> Result<ModelInfoRaw, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut info = ModelInfoRaw::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (4, 0) => info.max_tokens = reader.read_varint()? as i32,
            (6, 2) => info.model_features = Some(decode_model_features(reader.read_len()?)?),
            (13, 0) => info.max_output_tokens = reader.read_varint()? as i32,
            _ => reader.skip(wire)?,
        }
    }
    Ok(info)
}

fn decode_model_features(bytes: &[u8]) -> Result<ModelFeaturesRaw, GatewayError> {
    let mut reader = ProtoReader::new(bytes);
    let mut features = ModelFeaturesRaw::default();
    while reader.remaining() > 0 {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (11, 0) => features.supports_images = reader.read_varint()? != 0,
            (12, 0) => features.supports_tool_calls = reader.read_varint()? != 0,
            (15, 0) => features.supports_thinking = reader.read_varint()? != 0,
            (21, 0) => {
                let _ = reader.read_varint()?;
            }
            _ => reader.skip(wire)?,
        }
    }
    Ok(features)
}

// ---------------------------------------------------------------------------
// Endpoint metadata helpers (local mirrors of provider-metadata.ts)
// ---------------------------------------------------------------------------

fn sanitize_upstream_label(value: &str) -> Option<String> {
    sanitize_upstream_label_with(value, MAX_UPSTREAM_LABEL_LENGTH)
}

fn sanitize_upstream_label_with(value: &str, max_length: usize) -> Option<String> {
    let cleaned: String = value
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(max_length).collect())
}

fn validate_upstream_base_url(value: &str) -> Option<String> {
    let raw = sanitize_upstream_label_with(value, 2_048)?;
    let mut url = url::Url::parse(&raw).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    if url.scheme() != "https" {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string().trim_end_matches('/').to_owned())
}

fn truncate_text(value: &str, max_length: usize) -> String {
    value.chars().take(max_length).collect()
}

fn provider_error(code: GatewayErrorCode, status: u16, message: impl Into<String>) -> GatewayError {
    let mut details = Map::new();
    details.insert("providerId".into(), json!(DEVIN_PROVIDER_ID));
    GatewayError::new(code, status, message, details)
}

fn network_error(message: String) -> GatewayError {
    provider_error(GatewayErrorCode::TransportUnavailable, 502, message)
        .with_origin(GatewayErrorOrigin::Network)
}

fn transport_error(error: reqwest::Error) -> GatewayError {
    if error.is_timeout() {
        provider_error(
            GatewayErrorCode::TransportClosed,
            499,
            "request was cancelled",
        )
    } else {
        network_error(format!("Devin transport failed: {error}"))
    }
}

// ---------------------------------------------------------------------------
// OAuth (browser PKCE; no refresh grant)
// ---------------------------------------------------------------------------

fn decode_jwt_payload(token: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(parts[1]))
        .ok()?;
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    value.as_object().cloned()
}

/// JWT `exp` claim; falls back to 365 days for opaque tokens.
pub fn expiry_from_devin_jwt(token: &str) -> DateTime<Utc> {
    if let Some(exp) = decode_jwt_payload(token)
        .and_then(|payload| payload.get("exp").and_then(Value::as_f64))
        .filter(|exp| exp.is_finite())
    {
        if let Some(date) = DateTime::<Utc>::from_timestamp(exp as i64, 0) {
            return date;
        }
    }
    Utc::now() + chrono::Duration::milliseconds(DEVIN_JWT_FALLBACK_MS)
}

/// Devin exposes its account identity through these claims, in priority order.
pub fn devin_account_label_from_jwt(token: &str) -> Option<String> {
    let payload = decode_jwt_payload(token)?;
    for key in ["email", "sub", "user_id", "org_id", "name"] {
        if let Some(value) = payload.get(key).and_then(Value::as_str) {
            if let Some(label) = sanitize_upstream_label(value) {
                return Some(label);
            }
        }
    }
    None
}

/// Builds the Devin browser-PKCE authorize URL.
pub fn build_devin_authorize_url(code_challenge: &str, state: &str, redirect_uri: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("prompt", "select_account")
        .finish();
    format!("{DEVIN_AUTHORIZE_URL}?{query}")
}

/// Exchanges a browser authorization code for Devin's access token. Access and
/// refresh are the same JWT; there is no refresh grant.
pub async fn exchange_devin_oauth_code(
    client: &reqwest::Client,
    code: &str,
    code_verifier: &str,
) -> Result<DevinOAuthToken, GatewayError> {
    let response = client
        .post(DEVIN_TOKEN_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&json!({ "code": code, "code_verifier": code_verifier }))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(transport_error)?;
    let payload = read_json_response(response, "Devin token exchange").await?;
    let token = extract_oauth_token(&payload).ok_or_else(|| {
        provider_error(
            GatewayErrorCode::AuthenticationFailed,
            401,
            "Devin token exchange returned no token (expected { token })",
        )
        .with_origin(GatewayErrorOrigin::Upstream)
    })?;
    let account_label = devin_account_label_from_jwt(&token);
    Ok(DevinOAuthToken {
        access: token.clone(),
        refresh: token.clone(),
        expires_at: expiry_from_devin_jwt(&token),
        account_label,
    })
}

/// Devin declares no refresh grant; this is the typed error callers surface.
pub fn devin_oauth_refresh_unsupported() -> GatewayError {
    provider_error(
        GatewayErrorCode::CapabilityUnsupported,
        400,
        "Devin does not support token refresh",
    )
}

fn extract_oauth_token(payload: &Value) -> Option<String> {
    const KEYS: [&str; 5] = ["token", "access_token", "accessToken", "jwt", "id_token"];
    let root = payload.as_object()?;
    for key in KEYS {
        if let Some(value) = root
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(value.to_owned());
        }
    }
    let nested = root.get("data")?.as_object()?;
    for key in KEYS {
        if let Some(value) = nested
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(value.to_owned());
        }
    }
    None
}

async fn read_json_response(
    response: reqwest::Response,
    label: &str,
) -> Result<Value, GatewayError> {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let body = truncate_text(&text, MAX_UPSTREAM_ERROR_BYTES);
        return Err(provider_error(
            GatewayErrorCode::PlatformUnavailable,
            status.as_u16(),
            format!("{label} request failed ({}): {body}", status.as_u16()),
        )
        .with_origin(GatewayErrorOrigin::Upstream));
    }
    serde_json::from_str(&text).map_err(|_| {
        provider_error(
            GatewayErrorCode::PlatformUnavailable,
            502,
            format!("{label} returned invalid JSON"),
        )
        .with_origin(GatewayErrorOrigin::Upstream)
    })
}

// ---------------------------------------------------------------------------
// Quota (SeatManagement GetUserStatus)
// ---------------------------------------------------------------------------

/// Fetches the Devin seat-management quota and projects it into the console's
/// `{source, plan, windows, error}` shape.
pub async fn fetch_devin_quota(
    client: &reqwest::Client,
    credential: &str,
) -> Result<Value, GatewayError> {
    let parsed: Option<Value> = if credential.starts_with('{') {
        serde_json::from_str(credential).ok()
    } else {
        None
    };
    let raw = parsed
        .as_ref()
        .and_then(|value| value.get("accessToken"))
        .and_then(text_value)
        .or_else(|| {
            let trimmed = credential.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });
    let Some(raw) = raw else {
        return Err(provider_error(
            GatewayErrorCode::InvalidRequest,
            400,
            "Devin credential is empty.",
        ));
    };
    let token = normalize_devin_session_token(Some(&raw));
    let body = json!({
        "metadata": {
            "ide_name": "WINDSURF",
            "ide_version": "1.0.0",
            "extension_version": "1.0.0",
            "api_key": token.clone(),
        }
    });
    let response = client
        .post(DEVIN_USER_STATUS_URL)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .header("connect-protocol-version", "1")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&body)
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    let text_body = response.text().await.unwrap_or_default();
    let parsed_body: Value = if text_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text_body).unwrap_or(Value::Null)
    };
    if !status.is_success() {
        let detail = parsed_body
            .get("error")
            .and_then(text_value)
            .or_else(|| parsed_body.get("message").and_then(text_value))
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        return Err(provider_error(
            GatewayErrorCode::PlatformUnavailable,
            status.as_u16(),
            format!("Quota endpoint rejected request: {detail}"),
        )
        .with_origin(GatewayErrorOrigin::Upstream));
    }
    if parsed_body.get("success") == Some(&Value::Bool(false)) {
        let detail = parsed_body
            .get("error")
            .and_then(text_value)
            .unwrap_or_else(|| "Quota endpoint rejected the request.".to_owned());
        return Err(
            provider_error(GatewayErrorCode::PlatformUnavailable, 502, detail)
                .with_origin(GatewayErrorOrigin::Upstream),
        );
    }
    let root = if parsed_body.get("success") == Some(&Value::Bool(true))
        && parsed_body.get("data").is_some()
    {
        parsed_body.get("data").cloned().unwrap_or(Value::Null)
    } else {
        parsed_body
    };
    Ok(project_devin_quota(&root))
}

fn project_devin_quota(root: &Value) -> Value {
    let root = quota_record(root);
    let user_status = root
        .get("userStatus")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let plan_status = user_status
        .get("planStatus")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let plan_info = root
        .get("planInfo")
        .and_then(Value::as_object)
        .or_else(|| plan_status.get("planInfo").and_then(Value::as_object))
        .cloned()
        .unwrap_or_default();
    let reset = iso_date(plan_status.get("planEnd")).or_else(|| iso_date(plan_info.get("planEnd")));

    let mut windows = Vec::new();
    if let Some(window) = credit_window(
        &plan_status,
        &["availablePromptCredits", "available_prompt_credits"],
        &["usedPromptCredits", "used_prompt_credits"],
        "prompt-credits",
        "Prompt Credits",
        reset.clone(),
    ) {
        windows.push(window);
    }
    if let Some(window) = remaining_window(
        &plan_status,
        &["dailyRemainingPercent", "dailyQuotaRemainingPercent"],
        "daily",
        "Daily Usage",
        unix_seconds_date(
            plan_status
                .get("dailyResetAtUnix")
                .or_else(|| plan_status.get("dailyQuotaResetAtUnix")),
        ),
    ) {
        windows.push(window);
    }
    if let Some(window) = remaining_window(
        &plan_status,
        &["weeklyRemainingPercent", "weeklyQuotaRemainingPercent"],
        "weekly",
        "Weekly Usage",
        unix_seconds_date(
            plan_status
                .get("weeklyResetAtUnix")
                .or_else(|| plan_status.get("weeklyQuotaResetAtUnix")),
        ),
    ) {
        windows.push(window);
    }

    let plan = plan_info
        .get("planName")
        .and_then(text_value)
        .or_else(|| user_status.get("teamsTier").and_then(text_value));
    json!({
        "source": "devin",
        "plan": plan,
        "windows": windows,
        "error": Value::Null,
    })
}

fn quota_record(root: &Value) -> &Value {
    if let Some(object) = root.as_object() {
        for key in ["data", "result", "usage"] {
            if let Some(inner) = object.get(key).filter(|value| value.is_object()) {
                return inner;
            }
        }
    }
    root
}

fn credit_window(
    plan_status: &Map<String, Value>,
    available_keys: &[&str],
    used_keys: &[&str],
    kind: &str,
    label: &str,
    reset: Option<String>,
) -> Option<Value> {
    let available = first_number(plan_status, available_keys);
    let used = first_number(plan_status, used_keys);
    if available.is_none() && used.is_none() {
        return None;
    }
    if used.unwrap_or(0.0) <= 0.0 {
        return None;
    }
    let total = available.unwrap_or(0.0) + used.unwrap_or(0.0);
    if total <= 0.0 {
        return None;
    }
    Some(percent_window(
        kind,
        label,
        Some(used.unwrap_or(0.0) / total * 100.0),
        reset,
        used,
        Some(total),
    ))
}

fn remaining_window(
    plan_status: &Map<String, Value>,
    keys: &[&str],
    kind: &str,
    label: &str,
    reset: Option<String>,
) -> Option<Value> {
    let remaining = first_number(plan_status, keys)?;
    Some(percent_window(
        kind,
        label,
        Some(100.0 - remaining),
        reset,
        None,
        None,
    ))
}

fn percent_window(
    kind: &str,
    label: &str,
    used: Option<f64>,
    resets_at: Option<String>,
    used_value: Option<f64>,
    limit: Option<f64>,
) -> Value {
    let used_percent = used.map(|value| value.clamp(0.0, 100.0));
    let remaining_percent = used_percent.map(|value| (100.0 - value).max(0.0));
    json!({
        "kind": kind,
        "label": label,
        "usedPercent": used_percent,
        "remainingPercent": remaining_percent,
        "resetsAt": resets_at,
        "used": used_value,
        "limit": limit,
    })
}

fn first_number(map: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    for key in keys {
        if let Some(value) = map.get(*key).and_then(number_value) {
            return Some(value);
        }
    }
    None
}

fn text_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn number_value(value: &Value) -> Option<f64> {
    if let Some(number) = value.as_f64() {
        return number.is_finite().then_some(number);
    }
    let parsed = value.as_str()?.trim().parse::<f64>().ok()?;
    parsed.is_finite().then_some(parsed)
}

fn iso_date(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if let Some(number) = number_value(value) {
        let millis = number > 1_000_000_000_000.0;
        let timestamp = if millis {
            DateTime::<Utc>::from_timestamp_millis(number as i64)?
        } else {
            DateTime::<Utc>::from_timestamp(number as i64, 0)?
        };
        return Some(format_timestamp(timestamp));
    }
    let raw = text_value(value)?;
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&raw) {
        return Some(format_timestamp(parsed.with_timezone(&Utc)));
    }
    if let Ok(parsed) = NaiveDateTime::parse_from_str(&raw, "%Y-%m-%dT%H:%M:%S%.f") {
        return Some(format_timestamp(Utc.from_utc_datetime(&parsed)));
    }
    if let Ok(date) = NaiveDate::parse_from_str(&raw, "%Y-%m-%d") {
        let parsed = date.and_hms_opt(0, 0, 0)?;
        return Some(format_timestamp(Utc.from_utc_datetime(&parsed)));
    }
    None
}

fn unix_seconds_date(value: Option<&Value>) -> Option<String> {
    let seconds = number_value(value?)?;
    let timestamp = DateTime::<Utc>::from_timestamp(seconds as i64, 0)?;
    Some(format_timestamp(timestamp))
}

fn format_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_test_tool_call(id: &str, name: &str, args: &str) -> Vec<u8> {
        encode_chat_tool_call(&ChatToolCallWire {
            id: id.to_owned(),
            name: name.to_owned(),
            arguments_json: args.to_owned(),
            is_custom_tool_call: true,
        })
    }

    #[test]
    fn varint_encodes_fixed_vectors() {
        let mut writer = ProtoWriter::default();
        writer.varint(0);
        writer.varint(1);
        writer.varint(127);
        writer.varint(128);
        writer.varint(300);
        writer.varint(u64::MAX);
        assert_eq!(
            writer.finish(),
            vec![
                0x00, 0x01, 0x7f, 0x80, 0x01, 0xac, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0x01,
            ]
        );
    }

    #[test]
    fn connect_frame_roundtrip_and_partial_tail() {
        let frame = frame_connect_message(&[1, 2, 3], 0);
        assert_eq!(frame, vec![0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]);

        let (frames, consumed) =
            consume_connect_frames(&frame[..7], MAX_CONNECT_FRAME_PAYLOAD).unwrap();
        assert!(frames.is_empty());
        assert_eq!(consumed, 0);

        let (frames, consumed) = consume_connect_frames(&frame, MAX_CONNECT_FRAME_PAYLOAD).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].flags, 0);
        assert_eq!(frames[0].payload, vec![1, 2, 3]);
    }

    #[test]
    fn connect_compressed_flag_survives_framing() {
        let frammed = frame_connect_message(&[9, 9], CONNECT_COMPRESSED_FLAG);
        let (frames, consumed) =
            consume_connect_frames(&frammed, MAX_CONNECT_FRAME_PAYLOAD).unwrap();
        assert_eq!(consumed, frammed.len());
        assert_eq!(
            frames[0].flags & CONNECT_COMPRESSED_FLAG,
            CONNECT_COMPRESSED_FLAG
        );
    }

    #[test]
    fn oversized_connect_frame_is_rejected() {
        let mut header = vec![0u8];
        header.extend_from_slice(&((MAX_CONNECT_FRAME_PAYLOAD as u32) + 1).to_be_bytes());
        assert!(consume_connect_frames(&header, MAX_CONNECT_FRAME_PAYLOAD).is_err());
    }

    #[test]
    fn gzip_roundtrip_and_compressed_frame() {
        let raw = build_devin_chat_request(
            "swe-1-6-slow",
            &[],
            "system",
            &[],
            &DevinChatRequestOptions {
                max_tokens: Some(128),
                temperature: Some(0.2),
                stop_sequences: &[],
                conversation_id: Some("cascade-fixed"),
                web_search: true,
            },
            "devin-session-token$key",
            "user.jwt.value",
        );
        let compressed = gzip_compress(&raw).unwrap();
        assert_eq!(gzip_decompress(&compressed).unwrap(), raw);

        let framed = frame_connect_message(&compressed, CONNECT_COMPRESSED_FLAG);
        let (frames, consumed) =
            consume_connect_frames(&framed, MAX_CONNECT_FRAME_PAYLOAD).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(
            gzip_decompress(&frames[0].payload).unwrap(),
            raw,
            "compressed Connect payload must round-trip"
        );
    }

    #[test]
    fn chat_tool_call_round_trip() {
        let bytes = encode_test_tool_call("call_1", "printf", r#"{"text":"hi"}"#);
        let decoded = decode_chat_tool_call(&bytes).unwrap();
        assert_eq!(decoded.id, "call_1");
        assert_eq!(decoded.name, "printf");
        assert_eq!(decoded.arguments_json, r#"{"text":"hi"}"#);
        assert!(decoded.is_custom_tool_call);
    }

    #[test]
    fn get_user_jwt_response_decodes_fixed_vector() {
        let mut bytes = vec![0x0a, 0x05];
        bytes.extend_from_slice(b"a.b.c");
        bytes.extend_from_slice(&[0x12, 0x09]);
        bytes.extend_from_slice(b"https://x");
        let decoded = decode_get_user_jwt_response(&bytes).unwrap();
        assert_eq!(decoded.user_jwt, "a.b.c");
        assert_eq!(decoded.custom_api_server_url, "https://x");
    }

    #[test]
    fn chat_response_decodes_fixed_vector() {
        let mut tool_call = vec![0x0a, 0x02];
        tool_call.extend_from_slice(b"id");
        tool_call.extend_from_slice(&[0x12, 0x01]);
        tool_call.push(b'f');
        tool_call.extend_from_slice(&[0x1a, 0x02]);
        tool_call.extend_from_slice(b"{}");

        let mut usage = vec![0x10, 0x05, 0x18, 0x07, 0x20, 0x02, 0x28, 0x03];

        let mut bytes = vec![0x1a, 0x02];
        bytes.extend_from_slice(b"hi");
        bytes.push(0x28);
        bytes.push(0x03);
        bytes.push(0x32);
        bytes.push(tool_call.len() as u8);
        bytes.append(&mut tool_call);
        bytes.push(0x3a);
        bytes.push(usage.len() as u8);
        bytes.append(&mut usage);
        bytes.extend_from_slice(&[0x4a, 0x01]);
        bytes.push(b't');

        let decoded = decode_chat_response(&bytes).unwrap();
        assert_eq!(decoded.delta_text, "hi");
        assert_eq!(decoded.delta_thinking, "t");
        assert_eq!(decoded.stop_reason, STOP_REASON_MAX_TOKENS);
        assert_eq!(decoded.delta_tool_calls.len(), 1);
        assert_eq!(decoded.delta_tool_calls[0].id, "id");
        assert_eq!(decoded.delta_tool_calls[0].name, "f");
        assert_eq!(decoded.delta_tool_calls[0].arguments_json, "{}");
        let usage = decoded.usage.expect("usage present");
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(usage.output_tokens, 7);
        assert_eq!(usage.cache_write_tokens, 2);
        assert_eq!(usage.cache_read_tokens, 3);
    }

    #[test]
    fn client_model_configs_decode_fixed_vector() {
        let mut model_info = vec![0x20, 0xe8, 0x07]; // field 4 max_tokens = 1000
        model_info.extend_from_slice(&[0x68, 0x90, 0x01]); // field 13 max_output_tokens = 144
        let mut features = vec![0x58, 0x01]; // field 11 supports_images
        features.extend_from_slice(&[0x60, 0x01]); // field 12 supports_tool_calls
        features.extend_from_slice(&[0x78, 0x01]); // field 15 supports_thinking
        model_info.extend_from_slice(&[0x32, features.len() as u8]);
        model_info.append(&mut features);

        let mut config = vec![0x0a, 0x01];
        config.push(b'm'); // field 1 label
        config.extend_from_slice(&[0x20, 0x00]); // field 4 disabled = false
        config.extend_from_slice(&[0x28, 0x01]); // field 5 supports_images
        config.extend_from_slice(&[0x90, 0x01, 0xe8, 0x07]); // field 18 max_tokens = 1000
        config.extend_from_slice(&[0xb2, 0x01, 0x03]);
        config.extend_from_slice(b"uid"); // field 22 model_uid
        config.extend_from_slice(&[0xba, 0x01, model_info.len() as u8]);
        config.append(&mut model_info);

        let mut response = vec![0x0a, config.len() as u8];
        response.append(&mut config);
        let configs = decode_client_model_configs(&response).unwrap();
        assert_eq!(configs.len(), 1);
        let model = devin_model_from_config(&configs[0]).expect("enabled model");
        assert_eq!(model.model_id, "uid");
        assert_eq!(model.context_limit, Some(1000));
        assert_eq!(model.output_limit, Some(144));
        assert!(model.supports_images);
        assert!(model.supports_thinking);
        assert!(model.supports_tool_calls);
    }

    #[test]
    fn usage_projection_matches_ts_rules() {
        let usage = devin_usage(10, 4, 3, 0);
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 4);
        assert_eq!(usage.cached_input_tokens, TokenCount::Number(3));
        assert_eq!(usage.uncached_input_tokens, TokenCount::Number(7));
        assert_eq!(usage.cache_write_tokens, TokenCount::Unavailable);
        assert_eq!(usage.total_tokens, Some(TokenCount::Number(14)));

        let without_cache = devin_usage(10, 4, 0, 0);
        assert_eq!(without_cache.cached_input_tokens, TokenCount::Unavailable);
        assert_eq!(without_cache.uncached_input_tokens, TokenCount::Unavailable);
    }

    #[test]
    fn trailer_error_reads_connect_json() {
        assert_eq!(
            read_trailer_error(r#"{"error":{"code":"unauthenticated","message":"bad jwt"}}"#),
            Some(("unauthenticated".to_owned(), "bad jwt".to_owned()))
        );
        assert_eq!(read_trailer_error("{}"), None);
        assert_eq!(read_trailer_error(""), None);
    }

    #[test]
    fn session_token_normalization() {
        assert_eq!(normalize_devin_session_token(None), "");
        assert_eq!(normalize_devin_session_token(Some("")), "");
        assert_eq!(
            normalize_devin_session_token(Some("abc")),
            "devin-session-token$abc"
        );
        assert_eq!(
            normalize_devin_session_token(Some("devin-session-token$abc")),
            "devin-session-token$abc"
        );
    }

    #[test]
    fn label_and_base_url_sanitize() {
        assert_eq!(
            sanitize_upstream_label("  mod\0el\n "),
            Some("model".to_owned())
        );
        assert_eq!(
            validate_upstream_base_url("https://server.example.com/path/"),
            Some("https://server.example.com/path".to_owned())
        );
        assert_eq!(
            validate_upstream_base_url("http://server.example.com"),
            None
        );
        assert_eq!(
            validate_upstream_base_url("https://user:pass@server.example.com"),
            None
        );
    }
}
