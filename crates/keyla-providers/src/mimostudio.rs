//! Xiaomi MiMo Studio bot-chat adapter.
//!
//! The endpoint accepts one `query` string, keeps conversation history
//! server-side, and streams in-band `message` / `usage` / `finish` frames.
//! Tool calls travel in the model's own `<tool_call>` convention. Ported from
//! `src/providers/integrations/xiaomi-mimo/`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures_util::stream::{BoxStream, StreamExt};
use keyla_core::{
    CanonicalEvent, CanonicalMessage, CanonicalRequest, CanonicalStopReason, ContentPart,
    GatewayError, GatewayErrorCode, GatewayErrorOrigin, Role, TerminalState, UsageRecord,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapter::{DispatchCredential, DispatchOutput, DispatchTarget};

const BASE_URL: &str = "https://aistudio.xiaomimimo.com";
const CHAT_PATH: &str = "/open-apis/bot/chat";
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const MAX_QUERY_CHARS: usize = 48_000;
const SESSION_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_SESSIONS: usize = 256;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub service_token: String,
    pub user_id: String,
    pub ph_token: String,
}

fn clean_quoted(value: &str) -> String {
    let trimmed = value.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        trimmed[1..trimmed.len() - 1].trim().to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub fn parse_credential(raw: &str) -> Result<Credentials, GatewayError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "MiMo Studio credential cannot be empty",
            Map::new(),
        ));
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
        if let Some(array) = parsed.as_array() {
            let cookies = array
                .first()
                .and_then(|first| first.get("cookies"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| array.clone());
            let mut service = String::new();
            let mut user = String::new();
            let mut ph = String::new();
            for item in cookies {
                let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                let value = item.get("value").and_then(Value::as_str).unwrap_or("");
                match name {
                    "xiaomichatbot_serviceToken" | "serviceToken" => service = clean_quoted(value),
                    "userId" => user = clean_quoted(value),
                    "xiaomichatbot_ph" => ph = clean_quoted(value),
                    _ => {}
                }
            }
            if !service.is_empty() && !user.is_empty() {
                return Ok(Credentials {
                    service_token: service,
                    user_id: user,
                    ph_token: ph,
                });
            }
        }
        if let Some(object) = parsed.as_object() {
            let target = object
                .get("xiaomi")
                .and_then(Value::as_object)
                .unwrap_or(object);
            let service = [
                "service_token",
                "serviceToken",
                "xiaomichatbot_serviceToken",
            ]
            .iter()
            .find_map(|key| target.get(*key).and_then(Value::as_str))
            .unwrap_or("");
            let user = ["user_id", "userId"]
                .iter()
                .find_map(|key| {
                    target
                        .get(*key)
                        .map(|value| value.to_string().trim_matches('"').to_owned())
                })
                .unwrap_or_default();
            let ph = ["ph_token", "phToken", "xiaomichatbot_ph"]
                .iter()
                .find_map(|key| target.get(*key).and_then(Value::as_str))
                .unwrap_or("");
            if !service.is_empty() && !user.is_empty() {
                return Ok(Credentials {
                    service_token: clean_quoted(service),
                    user_id: clean_quoted(&user),
                    ph_token: clean_quoted(ph),
                });
            }
        }
    }
    let cookies = trimmed
        .split("Cookie:")
        .nth(1)
        .unwrap_or(trimmed)
        .split(['\n', '\r'])
        .next()
        .unwrap_or(trimmed);
    let find = |name: &str| {
        cookies
            .split(';')
            .find_map(|part| {
                let (key, value) = part.split_once('=')?;
                (key.trim() == name).then(|| clean_quoted(value))
            })
            .unwrap_or_default()
    };
    let mut service = find("xiaomichatbot_serviceToken");
    if service.is_empty() {
        service = find("serviceToken");
    }
    let user = find("userId");
    let mut ph = find("xiaomichatbot_ph");
    if ph.is_empty() {
        if let Some(query) = trimmed.split("xiaomichatbot_ph=").nth(1) {
            ph = query
                .split(['&', '\'', '"', ' ', '\\'])
                .next()
                .unwrap_or("")
                .to_owned();
        }
    }
    if service.is_empty() || user.is_empty() {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "MiMo Studio credential must contain serviceToken and userId",
            Map::new(),
        ));
    }
    Ok(Credentials {
        service_token: service,
        user_id: user,
        ph_token: ph,
    })
}

pub fn encode_credential(creds: &Credentials) -> String {
    json!({"serviceToken": creds.service_token, "userId": creds.user_id, "phToken": creds.ph_token})
        .to_string()
}

pub fn cookie_header(creds: &Credentials) -> String {
    format!(
        "xiaomichatbot_serviceToken={}; userId={}; xiaomichatbot_ph={}",
        creds.service_token, creds.user_id, creds.ph_token
    )
}

// ── thinking splitter ──────────────────────────────────────────────────────

const OPEN_TAGS: [&str; 2] = ["<thinking>", " thinking"];
const CLOSE_TAGS: [&str; 2] = ["</thinking>", "</think>"];

fn dangling_tag_prefix(text: &str) -> String {
    let tags = OPEN_TAGS.iter().chain(CLOSE_TAGS.iter());
    let max_length = tags.clone().map(|tag| tag.len()).max().unwrap_or(1) - 1;
    let limit = max_length.min(text.len());
    for length in (1..=limit).rev() {
        let start = text.len() - length;
        if !text.is_char_boundary(start) {
            continue;
        }
        let suffix = &text[start..];
        if tags.clone().any(|tag| tag.starts_with(suffix)) {
            return suffix.to_owned();
        }
    }
    String::new()
}

#[derive(Default)]
struct ThinkSplitter {
    buffer: String,
    in_reasoning: bool,
}

#[derive(Default)]
struct ThinkSplit {
    text: String,
    reasoning: String,
}

impl ThinkSplitter {
    fn push(&mut self, chunk: &str) -> ThinkSplit {
        self.buffer.push_str(&chunk.replace('\0', ""));
        let mut split = ThinkSplit::default();
        loop {
            if !self.in_reasoning {
                let Some((index, length)) = OPEN_TAGS
                    .iter()
                    .filter_map(|tag| self.buffer.find(tag).map(|index| (index, tag.len())))
                    .min_by_key(|(index, _)| *index)
                else {
                    break;
                };
                split.text.push_str(&self.buffer[..index]);
                self.buffer.drain(..index + length);
                self.in_reasoning = true;
                continue;
            }
            let Some((index, length)) = CLOSE_TAGS
                .iter()
                .filter_map(|tag| self.buffer.find(tag).map(|index| (index, tag.len())))
                .min_by_key(|(index, _)| *index)
            else {
                break;
            };
            split.reasoning.push_str(&self.buffer[..index]);
            self.buffer.drain(..index + length);
            self.in_reasoning = false;
        }
        let held = dangling_tag_prefix(&self.buffer);
        let settled = self.buffer.len() - held.len();
        let settled = self.buffer[..settled].to_owned();
        self.buffer = held;
        if self.in_reasoning {
            split.reasoning.push_str(&settled);
        } else {
            split.text.push_str(&settled);
        }
        split
    }

    fn flush(&mut self) -> ThinkSplit {
        let rest = std::mem::take(&mut self.buffer);
        if self.in_reasoning {
            self.in_reasoning = false;
            ThinkSplit {
                text: String::new(),
                reasoning: rest,
            }
        } else {
            ThinkSplit {
                text: rest,
                reasoning: String::new(),
            }
        }
    }
}

// ── tool protocol ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ToolCall {
    name: String,
    arguments: String,
}

fn parameter_value(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return json!("");
    }
    if !matches!(
        trimmed.chars().next(),
        Some('{' | '[' | '"' | 't' | 'f' | 'n')
    ) {
        return json!(raw);
    }
    serde_json::from_str(trimmed).unwrap_or_else(|_| json!(raw))
}

fn parse_function_body(body: &str) -> Option<ToolCall> {
    let name_end = body.find('>')?;
    let name = body[..name_end].trim();
    if name.is_empty() {
        return None;
    }
    let mut arguments = Map::new();
    let rest = &body[name_end + 1..];
    let mut cursor = 0;
    while let Some(open) = rest[cursor..].find("<parameter=") {
        let open = cursor + open;
        let Some(key_end) = rest[open + 11..].find('>') else {
            break;
        };
        let key_end = open + 11 + key_end;
        let key = rest[open + 11..key_end].trim();
        let Some(close) = rest[key_end + 1..].find("</parameter>") else {
            break;
        };
        let close = key_end + 1 + close;
        arguments.insert(key.to_owned(), parameter_value(&rest[key_end + 1..close]));
        cursor = close + 12;
    }
    Some(ToolCall {
        name: name.to_owned(),
        arguments: Value::Object(arguments).to_string(),
    })
}

fn parse_call_block(block: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();
    let mut cursor = 0;
    while let Some(open) = block[cursor..].find("<function=") {
        let open = cursor + open;
        let Some(close) = block[open + 10..].find("</function>") else {
            break;
        };
        let close = open + 10 + close;
        if let Some(call) = parse_function_body(&block[open + 10..close]) {
            calls.push(call);
        }
        cursor = close + 11;
    }
    calls
}

#[derive(Default)]
struct ToolExtractor {
    pending: String,
    in_call: bool,
    block: String,
    call_count: usize,
}

impl ToolExtractor {
    fn push(&mut self, chunk: &str) -> (String, Vec<ToolCall>) {
        let buffer = format!("{}{}", std::mem::take(&mut self.pending), chunk);
        let mut text = String::new();
        let mut calls = Vec::new();
        let mut cursor = 0;
        loop {
            if !self.in_call {
                let Some(open) = buffer[cursor..].find('<') else {
                    text.push_str(&buffer[cursor..]);
                    break;
                };
                let open = cursor + open;
                text.push_str(&buffer[cursor..open]);
                cursor = open;
                let rest = &buffer[cursor..];
                if rest.starts_with("<tool_call>") {
                    cursor += 11;
                    self.in_call = true;
                    self.block.clear();
                    continue;
                }
                if "<tool_call>".starts_with(rest) {
                    self.pending = rest.to_owned();
                    break;
                }
                text.push('<');
                cursor += 1;
                continue;
            }
            let combined = format!("{}{}", self.block, &buffer[cursor..]);
            let Some(close) = combined.find("</tool_call>") else {
                if combined.len() > 65_536 {
                    text.push_str("<tool_call>");
                    text.push_str(&combined);
                    self.block.clear();
                    self.in_call = false;
                } else {
                    self.block = combined;
                }
                break;
            };
            let inner = &combined[..close];
            cursor += close + 12 - self.block.len();
            self.block.clear();
            self.in_call = false;
            let parsed = parse_call_block(inner);
            if parsed.is_empty() {
                text.push_str("<tool_call>");
                text.push_str(inner);
                text.push_str("</tool_call>");
                continue;
            }
            self.call_count += parsed.len();
            calls.extend(parsed);
        }
        (text, calls)
    }

    fn flush(&mut self) -> String {
        let held = std::mem::take(&mut self.pending);
        if self.in_call {
            let unclosed = format!("<tool_call>{}", std::mem::take(&mut self.block));
            self.in_call = false;
            return format!("{held}{unclosed}");
        }
        held
    }
}

fn render_tool_instruction(tools: &[keyla_core::ToolDefinition]) -> String {
    let lines: Vec<String> = tools
        .iter()
        .map(|tool| {
            let description = tool.description.as_deref().unwrap_or("").trim();
            format!(
                "- {}{}\n  arguments: {}",
                tool.name,
                if description.is_empty() {
                    String::new()
                } else {
                    format!(": {description}")
                },
                tool.json_schema
            )
        })
        .collect();
    [
        "You can call tools. To call one, emit only this block:".to_owned(),
        "<tool_call><function=NAME><parameter=KEY>VALUE</parameter></function></tool_call>".to_owned(),
        "Repeat the `<parameter=…>` element for each argument; nest JSON in VALUE for object or array arguments.".to_owned(),
        "Emit only tool-call blocks when calling a tool, and wait for the result before answering.".to_owned(),
        "Available tools:".to_owned(),
        lines.join("\n"),
    ].join("\n")
}

fn tool_result_text(content: &keyla_core::ToolResultContent) -> String {
    match content {
        keyla_core::ToolResultContent::Text(text) => text.clone(),
        keyla_core::ToolResultContent::Parts(parts) => parts
            .iter()
            .map(|part| match part {
                ContentPart::Text { text } => text.clone(),
                other => serde_json::to_string(other).unwrap_or_default(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn tool_history(messages: &[CanonicalMessage]) -> Vec<CanonicalMessage> {
    messages
        .iter()
        .map(|message| {
            let mut texts = Vec::new();
            let mut kept = Vec::new();
            for part in &message.content {
                match part {
                    ContentPart::ToolCall {
                        name, arguments, ..
                    } => {
                        let mut parameters = String::new();
                        let parsed = match arguments {
                            Value::String(raw) => {
                                serde_json::from_str::<Value>(raw).unwrap_or(Value::Null)
                            }
                            value => value.clone(),
                        };
                        if let Some(object) = parsed.as_object() {
                            for (key, value) in object {
                                let rendered = value
                                    .as_str()
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| value.to_string());
                                parameters
                                    .push_str(&format!("<parameter={key}>{rendered}</parameter>"));
                            }
                        }
                        texts.push(format!(
                            "<tool_call><function={name}>{parameters}</function></tool_call>"
                        ));
                    }
                    ContentPart::ToolResult { content, .. } => {
                        texts.push(format!(
                            "<tool_result>\n{}\n</tool_result>",
                            tool_result_text(content)
                        ));
                    }
                    other => kept.push(other.clone()),
                }
            }
            if texts.is_empty() {
                return message.clone();
            }
            let text = texts.join("");
            let mut content = vec![ContentPart::Text {
                text: if text.is_empty() {
                    String::new()
                } else {
                    format!("{text}\n")
                },
            }];
            content.extend(kept);
            CanonicalMessage {
                role: if matches!(message.role, Role::Tool) {
                    Role::User
                } else {
                    message.role
                },
                content,
                phase: message.phase,
            }
        })
        .collect()
}

fn content_text(parts: &[ContentPart]) -> String {
    parts
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.clone()),
            ContentPart::Reasoning {
                summary: Some(text),
                ..
            } => Some(format!("[Thinking]\n{text}")),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ── conversation store ─────────────────────────────────────────────────────

#[derive(Clone)]
struct Tracked {
    conversation_id: String,
    start: usize,
    signatures: Vec<String>,
    last_used: Instant,
}

fn turn_signature(message: &CanonicalMessage) -> String {
    let mut parts = vec![format!("{:?}", message.role)];
    for part in &message.content {
        match part {
            ContentPart::Text { text } => parts.push(format!("t:{}", text.trim())),
            ContentPart::ToolCall {
                name, arguments, ..
            } => parts.push(format!("c:{name}:{arguments}")),
            ContentPart::ToolResult { content, .. } => {
                parts.push(format!("r:{}", tool_result_text(content)))
            }
            _ => {}
        }
    }
    format!("{:x}", Sha256::digest(parts.join("\u{0}").as_bytes()))
}

fn signatures(request: &CanonicalRequest) -> Vec<String> {
    request
        .messages
        .iter()
        .filter(|message| !matches!(message.role, Role::System))
        .map(turn_signature)
        .collect()
}

fn inbound_session(request: &CanonicalRequest) -> Option<String> {
    request
        .session_id
        .clone()
        .or_else(|| request.thread_id.clone())
        .or_else(|| request.conversation_id.clone())
        .or_else(|| {
            request.metadata.as_ref().and_then(|metadata| {
                [
                    "session_id",
                    "sessionId",
                    "conversation_id",
                    "conversationId",
                ]
                .iter()
                .find_map(|key| {
                    metadata
                        .get(*key)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
            })
        })
}

#[derive(Clone)]
struct Conversation {
    conversation_id: String,
    skip_turns: usize,
    known_start: usize,
    key: String,
}

fn sessions() -> &'static Mutex<HashMap<String, Tracked>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Tracked>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn matches_stored(current: &[String], tracked: &Tracked) -> bool {
    let end = tracked.start + tracked.signatures.len();
    end < current.len() && current[tracked.start..end] == tracked.signatures[..]
}

fn resolve_conversation(request: &CanonicalRequest, account: &str) -> Conversation {
    let current = signatures(request);
    let now = Instant::now();
    let mut store = sessions().lock().unwrap_or_else(|error| error.into_inner());
    store.retain(|_, tracked| now.duration_since(tracked.last_used) <= SESSION_TTL);
    while store.len() > MAX_SESSIONS {
        let Some(key) = store.keys().next().cloned() else {
            break;
        };
        store.remove(&key);
    }
    if let Some(session) = inbound_session(request) {
        let key = format!("{account}\0{session}");
        if let Some(tracked) = store.get_mut(&key) {
            tracked.last_used = now;
            if matches_stored(&current, tracked) {
                return Conversation {
                    conversation_id: tracked.conversation_id.clone(),
                    skip_turns: tracked.start + tracked.signatures.len(),
                    known_start: tracked.start,
                    key,
                };
            }
            return Conversation {
                conversation_id: tracked.conversation_id.clone(),
                skip_turns: 0,
                known_start: 0,
                key,
            };
        }
        return Conversation {
            conversation_id: mint_conversation(),
            skip_turns: 0,
            known_start: 0,
            key,
        };
    }
    let prefix = format!("{account}\0");
    let found = store
        .iter()
        .find(|(key, tracked)| {
            key.starts_with(&prefix) && tracked.start == 0 && matches_stored(&current, tracked)
        })
        .map(|(key, tracked)| (key.clone(), tracked.clone()));
    if let Some((key, tracked)) = found {
        if let Some(entry) = store.get_mut(&key) {
            entry.last_used = now;
        }
        return Conversation {
            conversation_id: tracked.conversation_id,
            skip_turns: tracked.signatures.len(),
            known_start: 0,
            key,
        };
    }
    Conversation {
        conversation_id: mint_conversation(),
        skip_turns: 0,
        known_start: 0,
        key: format!("{prefix}{}", Uuid::new_v4()),
    }
}

fn mint_conversation() -> String {
    format!(
        "conv_{}",
        Uuid::new_v4().simple().to_string()[..24].to_owned()
    )
}

fn commit(
    request: &CanonicalRequest,
    conversation: &Conversation,
    forwarded_start: usize,
    forwarded_turns: usize,
) {
    if forwarded_turns == 0 {
        return;
    }
    let current = signatures(request);
    let end = (conversation.skip_turns + forwarded_start + forwarded_turns).min(current.len());
    let start = if conversation.skip_turns > 0 {
        conversation.known_start
    } else {
        conversation.skip_turns + forwarded_start
    };
    if end <= start {
        return;
    }
    let mut stored = current[start..end].to_vec();
    let mut range_start = start;
    if stored.len() > 512 {
        range_start += stored.len() - 512;
        stored = stored[stored.len() - 512..].to_vec();
    }
    let mut store = sessions().lock().unwrap_or_else(|error| error.into_inner());
    if let Some(existing) = store.get(&conversation.key) {
        if existing.start + existing.signatures.len() >= range_start + stored.len() {
            return;
        }
    }
    store.insert(
        conversation.key.clone(),
        Tracked {
            conversation_id: conversation.conversation_id.clone(),
            start: range_start,
            signatures: stored,
            last_used: Instant::now(),
        },
    );
}

// ── request/stream ─────────────────────────────────────────────────────────

fn serialize_messages(request: &CanonicalRequest, skip_turns: usize) -> (String, usize, usize) {
    let mut system = Vec::new();
    for message in &request.messages {
        if matches!(message.role, Role::System) {
            let text = content_text(&message.content).trim().to_owned();
            if !text.is_empty() {
                system.push(text);
            }
        }
    }
    if let Some(tools) = request.tools.as_ref().filter(|tools| !tools.is_empty()) {
        if request.tool_choice != Some(keyla_core::ToolChoice::None) {
            system.push(render_tool_instruction(tools));
        }
    }
    let system_block = if system.is_empty() {
        String::new()
    } else {
        format!("[系统指令]\n{}", system.join("\n"))
    };
    let messages = tool_history(&request.messages);
    let non_system: Vec<&CanonicalMessage> = messages
        .iter()
        .filter(|message| !matches!(message.role, Role::System))
        .collect();
    let non_system = if skip_turns < non_system.len() {
        &non_system[skip_turns..]
    } else {
        &[]
    };
    let turns: Vec<String> = non_system
        .iter()
        .enumerate()
        .map(|(index, message)| {
            let content = content_text(&message.content).trim().to_owned();
            if index + 1 == non_system.len() && matches!(message.role, Role::User) {
                format!("[当前问题]\n{content}")
            } else {
                format!("{:?}: {content}", message.role).to_lowercase()
            }
        })
        .collect();
    let mut dropped = 0;
    let mut body = turns.join("\n\n");
    let mut total = system_block.len() + body.len() + 2;
    while total > MAX_QUERY_CHARS && turns.len() - dropped > 1 {
        dropped += 1;
        body = turns[dropped..].join("\n\n");
        total = system_block.len() + body.len() + 2;
    }
    if dropped > 0 {
        body = format!("[提示]\n较早的对话轮次因长度限制已省略。\n\n{body}");
    }
    let query = if system_block.is_empty() {
        body
    } else {
        format!("{system_block}\n\n{body}")
    };
    (query, dropped, turns.len() - dropped)
}

fn error_frame(message: &str) -> GatewayError {
    let normalized = message.to_lowercase();
    if normalized.contains("too long") {
        return GatewayError::new(
            GatewayErrorCode::ContextLengthExceeded,
            413,
            format!("MiMo Studio rejected the request: {message}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream);
    }
    if normalized.contains("do not submit repeatedly") {
        return GatewayError::new(
            GatewayErrorCode::UpstreamConflict,
            409,
            format!("MiMo Studio rejected the request: {message}"),
            Map::new(),
        )
        .with_origin(GatewayErrorOrigin::Upstream);
    }
    GatewayError::new(
        GatewayErrorCode::UpstreamUnprocessable,
        422,
        format!("MiMo Studio error: {message}"),
        Map::new(),
    )
    .with_origin(GatewayErrorOrigin::Upstream)
}

fn extract_tool_events(
    mut source: BoxStream<'static, Result<CanonicalEvent, GatewayError>>,
    enabled: bool,
) -> BoxStream<'static, Result<CanonicalEvent, GatewayError>> {
    if !enabled {
        return source;
    }
    async_stream::stream! {
        let mut extractor = ToolExtractor::default();
        let mut extracted = false;
        while let Some(event) = source.next().await {
            let Ok(event) = event else { yield event; continue };
            match event {
                CanonicalEvent::ContentDelta { sequence_number, content: ContentPart::Text { text }, event_id, response_id, item_id, output_index, content_index, timestamp } => {
                    let (text, calls) = extractor.push(&text);
                    if !text.is_empty() {
                        yield Ok(CanonicalEvent::ContentDelta { sequence_number, content: ContentPart::Text { text }, event_id, response_id, item_id, output_index, content_index, timestamp });
                    }
                    let mut seq = sequence_number;
                    for call in calls {
                        extracted = true;
                        seq += 1;
                        yield Ok(CanonicalEvent::ToolCallDelta {
                            sequence_number: seq,
                            call_id: format!("call_{seq}"),
                            index: None, name: Some(call.name), arguments_delta: Some(call.arguments),
                            event_id: None, response_id: None, item_id: None, output_index: None, timestamp: None,
                        });
                    }
                }
                CanonicalEvent::Terminal { sequence_number, state, stop_reason, provider_stop_reason, stop_details, usage, event_id, response_id, timestamp } => {
                    let trailing = extractor.flush();
                    let mut seq = sequence_number;
                    if !trailing.is_empty() {
                        seq += 1;
                        yield Ok(CanonicalEvent::ContentDelta { sequence_number: seq, content: ContentPart::Text { text: trailing }, event_id: None, response_id: None, item_id: None, output_index: None, content_index: None, timestamp: None });
                    }
                    let stop = if extracted && state == TerminalState::Complete && matches!(stop_reason, Some(CanonicalStopReason::Stop) | None) {
                        Some(CanonicalStopReason::ToolUse)
                    } else { stop_reason };
                    yield Ok(CanonicalEvent::Terminal { sequence_number: seq + 1, state, stop_reason: stop, provider_stop_reason, stop_details, usage, event_id, response_id, timestamp });
                }
                other => yield Ok(other),
            }
        }
    }.boxed()
}

fn usage_from_frame(data: &Value) -> Option<UsageRecord> {
    let prompt = data
        .get("promptTokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let completion = data
        .get("completionTokens")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let reasoning = data
        .get("nativeUsage")
        .and_then(|native| native.get("completion_tokens_details"))
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    keyla_protocol::surface::usage::usage_from_provider(Some(&json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "reasoning_tokens": if reasoning > 0 { Some(reasoning) } else { None },
    })))
}

pub async fn dispatch_mimostudio(
    client: &reqwest::Client,
    request: &CanonicalRequest,
    target: &DispatchTarget,
    credential: &DispatchCredential,
) -> Result<DispatchOutput, GatewayError> {
    let secret = credential.secret.as_deref().ok_or_else(|| {
        GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            400,
            "MiMo Studio credential is required",
            Map::new(),
        )
    })?;
    let creds = parse_credential(secret)?;
    let account = credential.account_id.as_deref().unwrap_or("mimostudio");
    let model = target.model_id.clone();
    let conversation = resolve_conversation(request, account);
    let (query, forwarded_start, forwarded_turns) =
        serialize_messages(request, conversation.skip_turns);
    commit(request, &conversation, forwarded_start, forwarded_turns);
    let endpoint = if target.endpoint_path.starts_with('/') {
        target.endpoint_path.clone()
    } else {
        CHAT_PATH.to_owned()
    };
    let mut url = format!("{BASE_URL}{endpoint}");
    if !creds.ph_token.is_empty() {
        url = format!("{url}?xiaomichatbot_ph={}", percent_encode(&creds.ph_token));
    }
    let body = json!({
        "msgId": Uuid::new_v4().simple().to_string()[..32].to_owned(),
        "conversationId": conversation.conversation_id,
        "query": query,
        "modelConfig": {"model": model, "enableThinking": true, "webSearchStatus": "disabled"},
        "multiMedias": [],
    });
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("cookie", cookie_header(&creds))
        .header("origin", BASE_URL)
        .header("referer", format!("{BASE_URL}/"))
        .header("user-agent", USER_AGENT)
        .header("x-timezone", "Asia/Shanghai")
        .header("accept", "text/event-stream")
        .json(&body)
        .send()
        .await
        .map_err(|error| {
            GatewayError::new(
                GatewayErrorCode::TransportUnavailable,
                502,
                format!("MiMo Studio request failed: {error}"),
                Map::new(),
            )
            .with_origin(GatewayErrorOrigin::Network)
        })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        return Err(GatewayError::new(
            GatewayErrorCode::TransportUnavailable,
            status,
            format!(
                "MiMo Studio returned HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            ),
            Map::new(),
        ));
    }
    let enabled = request
        .tools
        .as_ref()
        .is_some_and(|tools| !tools.is_empty())
        && request.tool_choice != Some(keyla_core::ToolChoice::None);
    let stream = stream_response(response, model);
    Ok(DispatchOutput::Stream(extract_tool_events(stream, enabled)))
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn stream_response(
    response: reqwest::Response,
    model: String,
) -> BoxStream<'static, Result<CanonicalEvent, GatewayError>> {
    async_stream::stream! {
        let mut sequence = 0u64;
        yield Ok(CanonicalEvent::ResponseStart { sequence_number: sequence, event_id: None, response_id: None, model: Some(model), system_fingerprint: None, timestamp: None });
        sequence += 1;
        let mut think = ThinkSplitter::default();
        let mut buffer = String::new();
        let mut event = String::new();
        let mut terminal = false;
        let mut bytes = response.bytes_stream();
        while let Some(chunk) = bytes.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    yield Err(GatewayError::new(GatewayErrorCode::TransportUnavailable, 502, format!("MiMo Studio stream failed: {error}"), Map::new()).with_origin(GatewayErrorOrigin::Network));
                    return;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            let lines: Vec<String> = buffer.split('\n').map(str::to_owned).collect();
            buffer = lines.last().cloned().unwrap_or_default();
            for line in &lines[..lines.len().saturating_sub(1)] {
                let trimmed = line.trim();
                if trimmed.is_empty() { event.clear(); continue; }
                if let Some(name) = trimmed.strip_prefix("event:") { event = name.trim().to_owned(); continue; }
                let Some(data) = trimmed.strip_prefix("data:") else { continue };
                let data = data.trim();
                if data == "[DONE]" {
                    if !terminal {
                        let split = think.flush();
                        for text in [(false, split.reasoning), (true, split.text)] {
                            if !text.1.is_empty() {
                                let content = if text.0 { ContentPart::Text { text: text.1 } } else { ContentPart::Reasoning { payload: Value::Null, opaque: None, summary: Some(text.1), summary_index: None, signature: None, encrypted_content: None } };
                                yield Ok(CanonicalEvent::ContentDelta { sequence_number: sequence, content, event_id: None, response_id: None, item_id: None, output_index: None, content_index: None, timestamp: None });
                                sequence += 1;
                            }
                        }
                        yield Ok(CanonicalEvent::Terminal { sequence_number: sequence, state: TerminalState::Complete, stop_reason: Some(CanonicalStopReason::Stop), provider_stop_reason: None, stop_details: None, usage: None, event_id: None, response_id: None, timestamp: None });
                        terminal = true;
                    }
                    continue;
                }
                let Ok(payload) = serde_json::from_str::<Value>(data) else { continue };
                if event == "error" {
                    let message = payload.get("content").and_then(Value::as_str).unwrap_or("unspecified upstream error");
                    yield Err(error_frame(message));
                    return;
                }
                if event == "message" || (event.is_empty() && payload.get("content").and_then(Value::as_str).is_some()) {
                    if let Some(text) = payload.get("content").and_then(Value::as_str) {
                        if !text.is_empty() {
                            let split = think.push(text);
                            for piece in [(false, split.reasoning), (true, split.text)] {
                                if !piece.1.is_empty() {
                                    let content = if piece.0 { ContentPart::Text { text: piece.1 } } else { ContentPart::Reasoning { payload: Value::Null, opaque: None, summary: Some(piece.1), summary_index: None, signature: None, encrypted_content: None } };
                                    yield Ok(CanonicalEvent::ContentDelta { sequence_number: sequence, content, event_id: None, response_id: None, item_id: None, output_index: None, content_index: None, timestamp: None });
                                    sequence += 1;
                                }
                            }
                        }
                    }
                } else if event == "usage" {
                    if let Some(usage) = usage_from_frame(&payload) {
                        yield Ok(CanonicalEvent::Usage { sequence_number: sequence, usage, event_id: None, response_id: None, timestamp: None });
                        sequence += 1;
                    }
                } else if event == "finish" && !terminal {
                    let split = think.flush();
                    for piece in [(false, split.reasoning), (true, split.text)] {
                        if !piece.1.is_empty() {
                            let content = if piece.0 { ContentPart::Text { text: piece.1 } } else { ContentPart::Reasoning { payload: Value::Null, opaque: None, summary: Some(piece.1), summary_index: None, signature: None, encrypted_content: None } };
                            yield Ok(CanonicalEvent::ContentDelta { sequence_number: sequence, content, event_id: None, response_id: None, item_id: None, output_index: None, content_index: None, timestamp: None });
                            sequence += 1;
                        }
                    }
                    yield Ok(CanonicalEvent::Terminal { sequence_number: sequence, state: TerminalState::Complete, stop_reason: Some(CanonicalStopReason::Stop), provider_stop_reason: None, stop_details: None, usage: None, event_id: None, response_id: None, timestamp: None });
                    terminal = true;
                }
            }
        }
        if !terminal {
            let split = think.flush();
            for piece in [(false, split.reasoning), (true, split.text)] {
                if !piece.1.is_empty() {
                    let content = if piece.0 { ContentPart::Text { text: piece.1 } } else { ContentPart::Reasoning { payload: Value::Null, opaque: None, summary: Some(piece.1), summary_index: None, signature: None, encrypted_content: None } };
                    yield Ok(CanonicalEvent::ContentDelta { sequence_number: sequence, content, event_id: None, response_id: None, item_id: None, output_index: None, content_index: None, timestamp: None });
                    sequence += 1;
                }
            }
            yield Ok(CanonicalEvent::Terminal { sequence_number: sequence, state: TerminalState::Failed, stop_reason: Some(CanonicalStopReason::Error), provider_stop_reason: None, stop_details: None, usage: None, event_id: None, response_id: None, timestamp: None });
        }
    }.boxed()
}

pub fn parse_usage(payload: &Value) -> Value {
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let remaining = data.get("percent").and_then(Value::as_f64);
    let used = remaining.map(|value| ((100.0 - value).clamp(0.0, 100.0) * 10.0).round() / 10.0);
    let reset = data
        .get("resetAt")
        .and_then(Value::as_f64)
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds as i64, 0))
        .map(|value| value.to_rfc3339())
        .or_else(|| {
            data.get("resetDate")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let windows = if used.is_some() || reset.is_some() {
        vec![json!({
            "kind": "weekly", "label": "Weekly Quota",
            "usedPercent": used,
            "remainingPercent": used.map(|value| 100.0 - value),
            "resetsAt": reset, "used": Value::Null, "limit": Value::Null,
            "remaining": Value::Null, "recurring": true,
        })]
    } else {
        Vec::new()
    };
    json!({"source": "mimostudio", "plan": "MiMo Studio", "windows": windows, "error": Value::Null})
}

#[cfg(test)]
mod tests {
    use super::{ThinkSplitter, ToolExtractor, parse_credential};

    #[test]
    fn parses_cookie_and_json_credentials() {
        let cookie = parse_credential(
            "Cookie: xiaomichatbot_serviceToken=abc; userId=42; xiaomichatbot_ph=ph1",
        )
        .unwrap();
        assert_eq!(cookie.service_token, "abc");
        assert_eq!(cookie.user_id, "42");
        assert_eq!(cookie.ph_token, "ph1");
        let json = parse_credential(r#"{"serviceToken":"tok","userId":7}"#).unwrap();
        assert_eq!(json.service_token, "tok");
        assert_eq!(json.user_id, "7");
    }

    #[test]
    fn splitter_handles_tags_across_chunks_and_nul() {
        let mut splitter = ThinkSplitter::default();
        let first = splitter.push("hello <thinkin");
        assert_eq!(first.text, "hello ");
        assert!(first.reasoning.is_empty());
        let second = splitter.push("g>why\u{0} now</thinking> answer");
        assert_eq!(second.reasoning, "why now");
        assert_eq!(second.text, " answer");
    }

    #[test]
    fn extractor_recovers_calls_and_releases_prose() {
        let mut extractor = ToolExtractor::default();
        let (text, calls) = extractor.push(
            "before <tool_call><function=search><parameter=q>rust</parameter></function></tool_call> after",
        );
        assert_eq!(text, "before  after");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "search");
        assert!(calls[0].arguments.contains("rust"));
    }
}
