//! AWS EventStream framing and Kiro response-event decoding.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use thiserror::Error;

const MAX_EVENT_STREAM_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
static KIRO_EVENT_UUID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A decoded Kiro event, including its modeled JSON payload.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KiroEvent {
    /// The value of the `:event-type` EventStream header.
    pub(crate) event_type: String,
    /// The modeled event payload object.
    pub(crate) payload: Map<String, Value>,
}

/// A completed Kiro tool-use block assembled from one or more event fragments.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KiroToolUse {
    /// The upstream or generated tool-use identifier.
    pub(crate) tool_use_id: String,
    /// The Kiro tool name.
    pub(crate) name: String,
    /// The decoded JSON object supplied to the tool.
    pub(crate) input: Map<String, Value>,
}

/// Errors raised while decoding AWS EventStream frames or modeled Kiro events.
#[derive(Debug, Error)]
pub(crate) enum KiroEventStreamError {
    /// The frame's total length is outside the supported EventStream bounds.
    #[error("invalid Kiro event frame length {0}")]
    InvalidFrameLength(u32),
    /// The frame's header section cannot fit in its total length.
    #[error("invalid Kiro event header length {0}")]
    InvalidHeaderLength(u32),
    /// The CRC protecting the EventStream prelude did not match.
    #[error("Kiro event prelude CRC mismatch")]
    PreludeCrcMismatch,
    /// The CRC protecting the complete EventStream message did not match.
    #[error("Kiro event message CRC mismatch")]
    MessageCrcMismatch,
    /// An EventStream header name was missing or malformed.
    #[error("malformed header name")]
    MalformedHeaderName,
    /// A variable-length EventStream header did not contain its length prefix.
    #[error("truncated variable header length")]
    TruncatedVariableHeaderLength,
    /// An EventStream header value type is not supported by this decoder.
    #[error("unsupported header value type {0}")]
    UnsupportedHeaderValueType(u8),
    /// An EventStream header value ended before its declared length.
    #[error("truncated header value")]
    TruncatedHeaderValue,
    /// The JSON body was not a modeled object payload.
    #[error("decode Kiro event payload: {0}")]
    PayloadJson(serde_json::Error),
    /// Kiro reported an error or exception event in the upstream stream.
    #[error("Kiro upstream stream error: {0}")]
    UpstreamStreamError(String),
    /// The stream ended with bytes that do not make a complete frame.
    #[error("incomplete Kiro event frame: {0} buffered bytes")]
    IncompleteFrame(usize),
    /// A completed tool-use fragment did not contain valid JSON input.
    #[error("decode Kiro tool input: {0}")]
    ToolInputJson(serde_json::Error),
    /// The stream closed without any visible Claude content blocks.
    #[error("Kiro stream ended before producing output")]
    EmptyStream,
    /// A Claude SSE frame could not be encoded.
    #[error("encode Claude SSE event: {0}")]
    ClaudeSseJson(serde_json::Error),
}

/// Incrementally decodes fragmented AWS EventStream messages from Kiro.
#[derive(Debug, Default)]
pub(crate) struct KiroEventStreamDecoder {
    buffer: Vec<u8>,
}

impl KiroEventStreamDecoder {
    /// Feeds bytes into the decoder and returns every complete event now available.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Result<Vec<KiroEvent>, KiroEventStreamError> {
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();

        loop {
            if self.buffer.len() < 12 {
                return Ok(events);
            }

            let total_length = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]);
            let headers_length = u32::from_be_bytes([
                self.buffer[4],
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
            ]);
            let total_length_usize = total_length as usize;
            let headers_length_usize = headers_length as usize;
            if !(16..=MAX_EVENT_STREAM_MESSAGE_SIZE).contains(&total_length_usize) {
                return Err(KiroEventStreamError::InvalidFrameLength(total_length));
            }
            if headers_length_usize > total_length_usize - 16 {
                return Err(KiroEventStreamError::InvalidHeaderLength(headers_length));
            }
            let expected_prelude_crc = u32::from_be_bytes([
                self.buffer[8],
                self.buffer[9],
                self.buffer[10],
                self.buffer[11],
            ]);
            if crc32_ieee(&self.buffer[..8]) != expected_prelude_crc {
                return Err(KiroEventStreamError::PreludeCrcMismatch);
            }
            if self.buffer.len() < total_length_usize {
                return Ok(events);
            }

            let frame = &self.buffer[..total_length_usize];
            let expected_message_crc = u32::from_be_bytes([
                frame[total_length_usize - 4],
                frame[total_length_usize - 3],
                frame[total_length_usize - 2],
                frame[total_length_usize - 1],
            ]);
            if crc32_ieee(&frame[..total_length_usize - 4]) != expected_message_crc {
                return Err(KiroEventStreamError::MessageCrcMismatch);
            }

            let headers = parse_event_stream_headers(&frame[12..12 + headers_length_usize])?;
            let payload_bytes = &frame[12 + headers_length_usize..total_length_usize - 4];
            let payload = if payload_bytes.is_empty() {
                Map::new()
            } else {
                serde_json::from_slice::<Map<String, Value>>(payload_bytes)
                    .map_err(KiroEventStreamError::PayloadJson)?
            };
            let message_type = headers
                .get(":message-type")
                .map(String::as_str)
                .unwrap_or_default();
            if message_type == "error" || message_type == "exception" {
                let message = first_string_field(&payload, &["message", "errorMessage"])
                    .or_else(|| nonempty_header(&headers, ":error-message"))
                    .or_else(|| nonempty_header(&headers, ":exception-type"))
                    .unwrap_or_else(|| message_type.to_owned());
                return Err(KiroEventStreamError::UpstreamStreamError(message));
            }

            events.push(KiroEvent {
                event_type: headers.get(":event-type").cloned().unwrap_or_default(),
                payload,
            });
            self.buffer = self.buffer.split_off(total_length_usize);
        }
    }

    /// Rejects a stream that ends before all buffered EventStream bytes form a frame.
    pub(crate) fn finish(&self) -> Result<(), KiroEventStreamError> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(KiroEventStreamError::IncompleteFrame(self.buffer.len()))
        }
    }
}

fn parse_event_stream_headers(
    data: &[u8],
) -> Result<HashMap<String, String>, KiroEventStreamError> {
    let mut headers = HashMap::new();
    let mut offset = 0;
    while offset < data.len() {
        let name_length = data[offset] as usize;
        offset += 1;
        if name_length == 0 || offset + name_length >= data.len() {
            return Err(KiroEventStreamError::MalformedHeaderName);
        }
        let name = String::from_utf8_lossy(&data[offset..offset + name_length]).into_owned();
        offset += name_length;
        let value_type = data[offset];
        offset += 1;
        let value_length = match value_type {
            0 | 1 => 0,
            2 => 1,
            3 => 2,
            4 => 4,
            5 | 8 => 8,
            9 => 16,
            6 | 7 => {
                if offset + 2 > data.len() {
                    return Err(KiroEventStreamError::TruncatedVariableHeaderLength);
                }
                let length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                length
            }
            other => return Err(KiroEventStreamError::UnsupportedHeaderValueType(other)),
        };
        if offset + value_length > data.len() {
            return Err(KiroEventStreamError::TruncatedHeaderValue);
        }
        if value_type == 7 {
            headers.insert(
                name,
                String::from_utf8_lossy(&data[offset..offset + value_length]).into_owned(),
            );
        }
        offset += value_length;
    }
    Ok(headers)
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[derive(Debug)]
struct PendingToolUse {
    id: String,
    name: String,
    input_json: String,
    generated: bool,
}

/// Collects fragmented Kiro tool-use events until each tool input is complete.
#[derive(Debug, Default)]
pub(crate) struct KiroPendingToolUses {
    by_id: HashMap<String, PendingToolUse>,
    order: Vec<String>,
    last_id: String,
}

impl KiroPendingToolUses {
    /// Accepts one modeled event and returns tools marked complete by that event.
    pub(crate) fn accept_event(
        &mut self,
        event: &Map<String, Value>,
    ) -> Result<Vec<KiroToolUse>, KiroEventStreamError> {
        let mut id = first_string_field(event, &["toolUseId", "toolUseID", "tool_use_id", "id"])
            .unwrap_or_default();
        let name =
            first_string_field(event, &["name", "toolName", "tool_name"]).unwrap_or_default();
        let stop = first_bool_field(event, &["stop", "isStop", "done"]);
        if id.is_empty() {
            id = self.last_id.clone();
        }
        let generated = if id.is_empty() && !name.is_empty() {
            id = format!("toolu_{}", generate_kiro_event_uuid().replace('-', ""));
            true
        } else {
            false
        };
        if id.is_empty() {
            return Ok(Vec::new());
        }

        let mut state = self.by_id.remove(&id);
        if state.is_none() && !generated && !self.last_id.is_empty() {
            if let Some(previous) = self.by_id.remove(&self.last_id) {
                if previous.generated && (name.is_empty() || previous.name == name) {
                    let old_id = previous.id.clone();
                    for order_id in &mut self.order {
                        if order_id.as_str() == old_id.as_str() {
                            *order_id = id.clone();
                            break;
                        }
                    }
                    let mut adopted = previous;
                    adopted.id = id.clone();
                    adopted.generated = false;
                    state = Some(adopted);
                } else {
                    self.by_id.insert(previous.id.clone(), previous);
                }
            }
        }
        let mut state = state.unwrap_or_else(|| PendingToolUse {
            id: id.clone(),
            name: name.clone(),
            input_json: String::new(),
            generated,
        });
        if state.name.is_empty() {
            state.name = name;
        }
        self.last_id = id.clone();
        if let Some(fragment) = event.get("input").and_then(Value::as_str) {
            state.input_json.push_str(fragment);
        } else if let Some(input) = event.get("input").and_then(Value::as_object) {
            state.input_json =
                serde_json::to_string(input).map_err(KiroEventStreamError::ToolInputJson)?;
        }
        if !self.order.iter().any(|existing| existing == &id) {
            self.order.push(id.clone());
        }
        if !stop {
            self.by_id.insert(id, state);
            return Ok(Vec::new());
        }
        let tool = finish_pending_tool(&state)?;
        self.remove(&id);
        Ok(vec![tool])
    }

    /// Flushes named pending tools at the end of a response stream.
    pub(crate) fn flush(&mut self) -> Result<Vec<KiroToolUse>, KiroEventStreamError> {
        let order = self.order.clone();
        let mut tools = Vec::with_capacity(order.len());
        for id in order {
            if let Some(state) = self.by_id.get(&id) {
                if !state.name.is_empty() {
                    tools.push(finish_pending_tool(state)?);
                }
            }
        }
        self.by_id.clear();
        self.order.clear();
        self.last_id.clear();
        Ok(tools)
    }

    fn remove(&mut self, id: &str) {
        self.by_id.remove(id);
        self.order.retain(|existing| existing != id);
        if self.last_id == id {
            self.last_id.clear();
        }
    }
}

fn finish_pending_tool(state: &PendingToolUse) -> Result<KiroToolUse, KiroEventStreamError> {
    let input = if state.input_json.is_empty() {
        Map::new()
    } else {
        serde_json::from_str::<Map<String, Value>>(&state.input_json)
            .map_err(KiroEventStreamError::ToolInputJson)?
    };
    Ok(KiroToolUse {
        tool_use_id: state.id.clone(),
        name: state.name.clone(),
        input,
    })
}

fn nonempty_header(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get(name).filter(|value| !value.is_empty()).cloned()
}

fn first_string_field(values: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        values
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn first_bool_field(values: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| values.get(*key).and_then(Value::as_bool))
        .unwrap_or(false)
}

fn numeric_event_value(values: &Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| match values.get(*key) {
        Some(Value::Number(value)) => value.as_f64(),
        Some(Value::String(value)) => value.parse::<f64>().ok(),
        _ => None,
    })
}

/// Updates input and output token totals from a Kiro event and nested usage maps.
pub(crate) fn update_kiro_usage_totals(
    event: &Map<String, Value>,
    mut input_tokens: u64,
    mut output_tokens: u64,
) -> (u64, u64) {
    let mut candidates = vec![event];
    append_nested_usage_maps(event, &mut candidates);
    for key in ["metrics", "metadata"] {
        if let Some(container) = event.get(key).and_then(Value::as_object) {
            candidates.push(container);
            append_nested_usage_maps(container, &mut candidates);
        }
    }
    for candidate in candidates {
        if let Some(value) = numeric_event_value(
            candidate,
            &[
                "outputTokens",
                "completionTokens",
                "totalOutputTokens",
                "output_tokens",
                "completion_tokens",
                "total_output_tokens",
            ],
        ) {
            output_tokens = nonnegative_token_count(value);
        }
        if let Some(value) = numeric_event_value(
            candidate,
            &[
                "inputTokens",
                "promptTokens",
                "totalInputTokens",
                "input_tokens",
                "prompt_tokens",
                "total_input_tokens",
            ],
        ) {
            input_tokens = nonnegative_token_count(value);
            continue;
        }
        let uncached =
            numeric_event_value(candidate, &["uncachedInputTokens", "uncached_input_tokens"])
                .unwrap_or(0.0);
        let cache_read = numeric_event_value(
            candidate,
            &["cacheReadInputTokens", "cache_read_input_tokens"],
        )
        .unwrap_or(0.0);
        let cache_write = numeric_event_value(
            candidate,
            &[
                "cacheWriteInputTokens",
                "cache_write_input_tokens",
                "cacheCreationInputTokens",
                "cache_creation_input_tokens",
            ],
        )
        .unwrap_or(0.0);
        if uncached + cache_read + cache_write > 0.0 {
            input_tokens = nonnegative_token_count(uncached + cache_read + cache_write);
            continue;
        }
        match numeric_event_value(candidate, &["totalTokens", "total_tokens"]) {
            Some(total) if total > output_tokens as f64 => {
                input_tokens = nonnegative_token_count(total - output_tokens as f64);
            }
            _ => {}
        }
    }
    (input_tokens, output_tokens)
}

fn nonnegative_token_count(value: f64) -> u64 {
    if value.is_finite() && value > 0.0 {
        value as u64
    } else {
        0
    }
}

fn append_nested_usage_maps<'a>(
    value: &'a Map<String, Value>,
    candidates: &mut Vec<&'a Map<String, Value>>,
) {
    for key in ["usage", "tokenUsage", "token_usage"] {
        if let Some(nested) = value.get(key).and_then(Value::as_object) {
            candidates.push(nested);
        }
    }
}

fn generate_kiro_event_uuid() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64);
    let counter = KIRO_EVENT_UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = (now, counter ^ now.rotate_left(17));
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&mixed.0.to_be_bytes());
    bytes[8..].copy_from_slice(&mixed.1.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// One Claude content block assembled from Kiro response events.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ClaudeContentBlock {
    /// Claude block type: `text`, `tool_use`, or `thinking`.
    pub(crate) block_type: String,
    /// Visible text for a `text` block.
    pub(crate) text: String,
    /// Thinking text, retained only if a thinking block is ever emitted.
    pub(crate) thinking: String,
    /// Tool-use identifier.
    pub(crate) id: String,
    /// Claude-facing tool name after remapping.
    pub(crate) name: String,
    /// Decoded tool input object.
    pub(crate) input: Map<String, Value>,
}

/// Accumulates Kiro events into the exact Claude stop/usage response structure.
#[derive(Debug)]
pub(crate) struct ClaudeResponseAccumulator {
    /// Kiro model identifier copied onto the Claude message.
    pub(crate) model: String,
    /// Claude message identifier (`msg_` plus a dash-stripped UUID).
    pub(crate) id: String,
    /// Maps sanitized Kiro tool names back to the original Claude names.
    tool_names: HashMap<String, String>,
    estimated_input_tokens: i64,
    /// Provider or estimated input token count.
    pub(crate) input_tokens: i64,
    /// Provider or estimated output token count.
    pub(crate) output_tokens: i64,
    hidden_reasoning_tokens: i64,
    /// Final Claude `stop_reason`.
    pub(crate) stop_reason: String,
    /// Metered Kiro credits from `meteringEvent`.
    pub(crate) credits: f64,
    context_usage_percentage: f64,
    /// Completed Claude content blocks in stream order.
    pub(crate) blocks: Vec<ClaudeContentBlock>,
    pending_tools: KiroPendingToolUses,
}

impl ClaudeResponseAccumulator {
    /// Starts an accumulator for one Kiro payload's model, tool names, and input estimate.
    pub(crate) fn new(
        model: impl Into<String>,
        tool_names: HashMap<String, String>,
        estimated_input_tokens: i64,
    ) -> Self {
        Self {
            model: model.into(),
            id: format!("msg_{}", generate_kiro_event_uuid().replace('-', "")),
            tool_names,
            estimated_input_tokens,
            input_tokens: 0,
            output_tokens: 0,
            hidden_reasoning_tokens: 0,
            stop_reason: String::new(),
            credits: 0.0,
            context_usage_percentage: 0.0,
            blocks: Vec::new(),
            pending_tools: KiroPendingToolUses::default(),
        }
    }

    /// Applies one modeled Kiro event and returns newly completed Claude blocks.
    pub(crate) fn accept(
        &mut self,
        event: &KiroEvent,
    ) -> Result<Vec<ClaudeContentBlock>, KiroEventStreamError> {
        let (input_tokens, output_tokens) = update_kiro_usage_totals(
            &event.payload,
            self.input_tokens.max(0) as u64,
            self.output_tokens.max(0) as u64,
        );
        self.input_tokens = input_tokens as i64;
        self.output_tokens = output_tokens as i64;
        match event.event_type.as_str() {
            "assistantResponseEvent" => {
                if let Some(text) = first_string_field(&event.payload, &["content", "text"]) {
                    let block = ClaudeContentBlock {
                        block_type: "text".into(),
                        text,
                        ..ClaudeContentBlock::default()
                    };
                    self.append_fragment(&block);
                    return Ok(vec![block]);
                }
            }
            "reasoningContentEvent" => {
                // Kiro does not return an Anthropic-verifiable signature. Omit its
                // reasoning instead of emitting a Claude thinking block that clients
                // cannot safely replay.
                if let Some(text) = first_string_field(&event.payload, &["content", "text"]) {
                    self.hidden_reasoning_tokens += estimate_approx_tokens(&text);
                }
            }
            "toolUseEvent" => {
                let tools = self.pending_tools.accept_event(&event.payload)?;
                let mut blocks = Vec::with_capacity(tools.len());
                for tool in tools {
                    let block = self.claude_tool_block(tool);
                    self.blocks.push(block.clone());
                    blocks.push(block);
                }
                return Ok(blocks);
            }
            "metadataEvent" => {
                if let Some(reason) =
                    first_string_field(&event.payload, &["stopReason", "stop_reason"])
                {
                    self.stop_reason = map_kiro_stop_reason(&reason).to_owned();
                }
            }
            "meteringEvent" => {
                if let Some(credits) = event.payload.get("usage").and_then(Value::as_f64) {
                    self.credits += credits;
                }
            }
            "contextUsageEvent" => {
                if let Some(percentage) = numeric_event_value(
                    &event.payload,
                    &["contextUsagePercentage", "context_usage_percentage"],
                ) {
                    if percentage > 0.0 {
                        self.context_usage_percentage = percentage;
                    }
                }
            }
            _ => {}
        }
        Ok(Vec::new())
    }

    fn claude_tool_block(&self, tool: KiroToolUse) -> ClaudeContentBlock {
        let name = self
            .tool_names
            .get(&tool.name)
            .cloned()
            .filter(|value| !value.is_empty())
            .unwrap_or(tool.name);
        ClaudeContentBlock {
            block_type: "tool_use".into(),
            id: tool.tool_use_id,
            name,
            input: tool.input,
            ..ClaudeContentBlock::default()
        }
    }

    fn append_fragment(&mut self, block: &ClaudeContentBlock) {
        if let Some(last) = self.blocks.last_mut() {
            if last.block_type == block.block_type {
                if last.block_type == "text" {
                    last.text.push_str(&block.text);
                    return;
                }
                if last.block_type == "thinking" {
                    last.thinking.push_str(&block.thinking);
                    return;
                }
            }
        }
        self.blocks.push(block.clone());
    }

    /// Flushes pending tools, chooses the stop reason, and fills missing usage.
    pub(crate) fn finish(&mut self) -> Result<(), KiroEventStreamError> {
        let tools = self.pending_tools.flush()?;
        for tool in tools {
            self.blocks.push(self.claude_tool_block(tool));
        }
        if self.blocks.is_empty() {
            return Err(KiroEventStreamError::EmptyStream);
        }
        if self.stop_reason.is_empty() {
            self.stop_reason = if self
                .blocks
                .iter()
                .any(|block| block.block_type == "tool_use")
            {
                "tool_use".into()
            } else {
                "end_turn".into()
            };
        }
        if self.input_tokens <= 0 {
            self.input_tokens = self.current_input_tokens();
        }
        if self.output_tokens <= 0 {
            self.output_tokens =
                estimate_claude_output_tokens(&self.blocks) + self.hidden_reasoning_tokens;
        }
        Ok(())
    }

    /// Input tokens for `message_start`, preferring provider, then context usage, then the request estimate.
    pub(crate) fn current_input_tokens(&self) -> i64 {
        if self.input_tokens > 0 {
            return self.input_tokens;
        }
        if self.context_usage_percentage > 0.0 {
            return (self.context_usage_percentage * context_window_tokens(&self.model) as f64
                / 100.0) as i64;
        }
        self.estimated_input_tokens
    }

    /// Serializes the completed Claude Messages response object.
    pub(crate) fn response_json(&self) -> Value {
        json!({
            "id": self.id,
            "type": "message",
            "role": "assistant",
            "content": self.blocks.iter().map(claude_content_block_json).collect::<Vec<_>>(),
            "model": self.model,
            "stop_reason": self.stop_reason,
            "stop_sequence": Value::Null,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens
            }
        })
    }
}

fn claude_content_block_json(block: &ClaudeContentBlock) -> Value {
    match block.block_type.as_str() {
        "tool_use" => json!({
            "type": "tool_use",
            "id": block.id,
            "name": block.name,
            "input": block.input
        }),
        "thinking" => json!({
            "type": "thinking",
            "thinking": block.thinking
        }),
        _ => json!({
            "type": "text",
            "text": block.text
        }),
    }
}

/// Maps a Kiro metadata stop reason onto Claude's `stop_reason` vocabulary.
pub(crate) fn map_kiro_stop_reason(reason: &str) -> &'static str {
    match reason.trim().to_ascii_lowercase().as_str() {
        "max_tokens" | "max-tokens" | "max tokens" | "length" | "max_tokens_reached" => {
            "max_tokens"
        }
        "tool_use" | "tool-use" | "tool use" | "tool_call" => "tool_use",
        "stop_sequence" | "stop-sequence" => "stop_sequence",
        _ => "end_turn",
    }
}

/// Writes Anthropic SSE frames from accumulated Claude content blocks.
#[derive(Debug, Default)]
pub(crate) struct ClaudeSseWriter {
    started: bool,
    block_index: i64,
    open_type: String,
    open_index: i64,
}

impl ClaudeSseWriter {
    /// Creates a writer that tracks open content-block indices for one response.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Emits `message_start` once, including the current input-token estimate.
    pub(crate) fn start(
        &mut self,
        accumulator: &ClaudeResponseAccumulator,
    ) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
        if self.started {
            return Ok(Vec::new());
        }
        self.started = true;
        let message = json!({
            "id": accumulator.id,
            "type": "message",
            "role": "assistant",
            "model": accumulator.model,
            "content": [],
            "stop_reason": Value::Null,
            "stop_sequence": Value::Null,
            "usage": {
                "input_tokens": accumulator.current_input_tokens(),
                "output_tokens": 0
            }
        });
        marshal_claude_sse_event(
            "message_start",
            &json!({"type": "message_start", "message": message}),
        )
    }

    /// Emits Claude content-block SSE frames for newly completed blocks.
    pub(crate) fn blocks(
        &mut self,
        blocks: &[ClaudeContentBlock],
    ) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
        let mut frames = Vec::new();
        for block in blocks {
            match block.block_type.as_str() {
                "thinking" => frames.extend(self.fragment(
                    "thinking",
                    &json!({"type": "thinking", "thinking": ""}),
                    &json!({"type": "thinking_delta", "thinking": block.thinking}),
                )?),
                "tool_use" => {
                    frames.extend(self.close_open_block()?);
                    let index = self.block_index;
                    self.block_index += 1;
                    let content_block = json!({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": {}
                    });
                    let input_json = serde_json::to_string(&block.input)
                        .map_err(KiroEventStreamError::ClaudeSseJson)?;
                    let delta = json!({"type": "input_json_delta", "partial_json": input_json});
                    frames.extend(marshal_claude_complete_content_block(
                        index,
                        &content_block,
                        &delta,
                    )?);
                }
                _ => frames.extend(self.fragment(
                    "text",
                    &json!({"type": "text", "text": ""}),
                    &json!({"type": "text_delta", "text": block.text}),
                )?),
            }
        }
        Ok(frames)
    }

    fn fragment(
        &mut self,
        block_type: &str,
        content_block: &Value,
        delta: &Value,
    ) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
        let mut frames = Vec::new();
        if self.open_type != block_type {
            frames.extend(self.close_open_block()?);
            self.open_type = block_type.to_owned();
            self.open_index = self.block_index;
            self.block_index += 1;
            frames.extend(marshal_claude_sse_event(
                "content_block_start",
                &json!({
                    "type": "content_block_start",
                    "index": self.open_index,
                    "content_block": content_block
                }),
            )?);
        }
        frames.extend(marshal_claude_sse_event(
            "content_block_delta",
            &json!({
                "type": "content_block_delta",
                "index": self.open_index,
                "delta": delta
            }),
        )?);
        Ok(frames)
    }

    fn close_open_block(&mut self) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
        if self.open_type.is_empty() {
            return Ok(Vec::new());
        }
        let index = self.open_index;
        self.open_type.clear();
        marshal_claude_sse_event(
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": index}),
        )
    }

    /// Emits the final stop, usage, and `message_stop` SSE frames.
    pub(crate) fn finish(
        &mut self,
        accumulator: &ClaudeResponseAccumulator,
    ) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
        let mut frames = self.close_open_block()?;
        frames.extend(marshal_claude_sse_event(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {
                    "stop_reason": accumulator.stop_reason,
                    "stop_sequence": Value::Null
                },
                "usage": {
                    "input_tokens": accumulator.input_tokens,
                    "output_tokens": accumulator.output_tokens
                }
            }),
        )?);
        frames.extend(marshal_claude_sse_event(
            "message_stop",
            &json!({"type": "message_stop"}),
        )?);
        Ok(frames)
    }
}

fn marshal_claude_complete_content_block(
    index: i64,
    content_block: &Value,
    delta: &Value,
) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
    let mut frames = marshal_claude_sse_event(
        "content_block_start",
        &json!({
            "type": "content_block_start",
            "index": index,
            "content_block": content_block
        }),
    )?;
    frames.extend(marshal_claude_sse_event(
        "content_block_delta",
        &json!({
            "type": "content_block_delta",
            "index": index,
            "delta": delta
        }),
    )?);
    frames.extend(marshal_claude_sse_event(
        "content_block_stop",
        &json!({"type": "content_block_stop", "index": index}),
    )?);
    Ok(frames)
}

fn marshal_claude_sse_event(
    event: &str,
    value: &Value,
) -> Result<Vec<Vec<u8>>, KiroEventStreamError> {
    let raw = serde_json::to_string(value).map_err(KiroEventStreamError::ClaudeSseJson)?;
    Ok(vec![format!("event: {event}\ndata: {raw}\n\n").into_bytes()])
}

fn estimate_approx_tokens(text: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    let runes: Vec<char> = text.chars().collect();
    if runes.len() < 5 {
        return ((runes.len() as f64) / 3.0).ceil().max(1.0) as i64;
    }
    let mut ascii = 0_f64;
    let mut digits = 0_f64;
    let mut symbols = 0_f64;
    let mut non_ascii = 0_f64;
    for value in runes {
        let code = value as u32;
        if code >= 0x80 {
            non_ascii += 1.0;
        } else if value.is_ascii_digit() {
            digits += 1.0;
        } else if matches!(code, 0x21..=0x2f | 0x3a..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e) {
            symbols += 1.0;
        } else {
            ascii += 1.0;
        }
    }
    let estimated = (ascii / 4.5 + digits / 2.0 + symbols / 1.5 + non_ascii / 1.5).ceil() as i64;
    estimated.max(1)
}

fn estimate_claude_output_tokens(blocks: &[ClaudeContentBlock]) -> i64 {
    blocks
        .iter()
        .map(|block| match block.block_type.as_str() {
            "text" => estimate_approx_tokens(&block.text),
            "thinking" => estimate_approx_tokens(&block.thinking),
            "tool_use" => {
                estimate_approx_tokens(&block.name)
                    + estimate_json_tokens(&Value::Object(block.input.clone()))
            }
            _ => 0,
        })
        .sum()
}

fn estimate_json_tokens(value: &Value) -> i64 {
    serde_json::to_string(value)
        .map(|raw| estimate_approx_tokens(&raw))
        .unwrap_or(0)
}

fn context_window_tokens(model: &str) -> i64 {
    let model = model.to_ascii_lowercase();
    if is_claude_dated_snapshot(&model) {
        return 200_000;
    }
    if let Some((major, minor)) = claude_version_parts(&model) {
        if major > 4 || (major == 4 && minor >= 6) {
            return 1_000_000;
        }
    }
    200_000
}

fn is_claude_dated_snapshot(model: &str) -> bool {
    let Some(rest) = model.strip_prefix("claude-") else {
        return false;
    };
    let Some(rest) = rest
        .strip_prefix("opus-")
        .or_else(|| rest.strip_prefix("sonnet-"))
        .or_else(|| rest.strip_prefix("haiku-"))
    else {
        return false;
    };
    let mut parts = rest.split('-');
    let Some(version) = parts.next() else {
        return false;
    };
    if !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Some(date) = parts.next() else {
        return false;
    };
    date.len() >= 8
        && date.as_bytes()[..8]
            .iter()
            .all(|byte| byte.is_ascii_digit())
}

fn claude_version_parts(model: &str) -> Option<(i32, i32)> {
    let rest = model.strip_prefix("claude-")?;
    let rest = rest
        .strip_prefix("opus-")
        .or_else(|| rest.strip_prefix("sonnet-"))
        .or_else(|| rest.strip_prefix("haiku-"))?;
    let mut chars = rest.chars();
    let mut major = String::new();
    for ch in chars.by_ref() {
        if ch.is_ascii_digit() {
            major.push(ch);
        } else if ch == '.' || ch == '-' {
            break;
        } else {
            return None;
        }
    }
    let major = major.parse().ok()?;
    let mut minor = String::new();
    for ch in chars {
        if ch.is_ascii_digit() {
            minor.push(ch);
        } else {
            break;
        }
    }
    let minor = if minor.is_empty() {
        0
    } else {
        minor.parse().ok()?
    };
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_header(name: &str, value: &str) -> Vec<u8> {
        let mut header = vec![name.len() as u8];
        header.extend_from_slice(name.as_bytes());
        header.push(7);
        header.extend_from_slice(&(value.len() as u16).to_be_bytes());
        header.extend_from_slice(value.as_bytes());
        header
    }

    fn event_frame(event_type: &str, payload: &str) -> Vec<u8> {
        let mut headers = event_header(":message-type", "event");
        headers.extend(event_header(":event-type", event_type));
        let total_length = 16 + headers.len() + payload.len();
        let mut frame = vec![0; total_length];
        frame[..4].copy_from_slice(&(total_length as u32).to_be_bytes());
        frame[4..8].copy_from_slice(&(headers.len() as u32).to_be_bytes());
        let prelude_crc = crc32_ieee(&frame[..8]);
        frame[8..12].copy_from_slice(&prelude_crc.to_be_bytes());
        frame[12..12 + headers.len()].copy_from_slice(&headers);
        frame[12 + headers.len()..total_length - 4].copy_from_slice(payload.as_bytes());
        let message_crc = crc32_ieee(&frame[..total_length - 4]);
        frame[total_length - 4..].copy_from_slice(&message_crc.to_be_bytes());
        frame
    }

    fn fixture_frame_hex(name: &str) -> Vec<u8> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/eventstream.json"))
                .expect("eventstream fixture");
        let hex = fixture["frames"]
            .as_array()
            .expect("frames")
            .iter()
            .find(|frame| frame["name"] == name)
            .and_then(|frame| frame["hex"].as_str())
            .expect("named frame hex");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
            .collect()
    }

    #[test]
    fn decoder_handles_every_event_stream_frame_split_boundary() {
        let frame = event_frame("assistantResponseEvent", r#"{"content":"boundary"}"#);
        for split in 0..frame.len() {
            let mut decoder = KiroEventStreamDecoder::default();
            assert!(
                decoder
                    .feed(&frame[..split])
                    .expect("prefix at every boundary is accepted")
                    .is_empty(),
                "split {split} unexpectedly produced an event"
            );
            let events = decoder
                .feed(&frame[split..])
                .expect("suffix at every boundary completes frame");
            assert_eq!(events.len(), 1, "split {split} produced wrong event count");
            assert_eq!(events[0].event_type, "assistantResponseEvent");
            decoder.finish().expect("boundary split leaves no bytes");
        }
        let mut decoder = KiroEventStreamDecoder::default();
        let events = decoder
            .feed(&frame)
            .expect("an unsplit frame completes normally");
        assert_eq!(events.len(), 1);
        decoder.finish().expect("unsplit frame leaves no bytes");
    }

    #[test]
    fn decoder_preserves_empty_and_stalled_chunks_until_done() {
        let frame = event_frame("assistantResponseEvent", r#"{"content":"after stall"}"#);
        let mut decoder = KiroEventStreamDecoder::default();
        for _ in 0..3 {
            assert!(decoder
                .feed(&[])
                .expect("empty chunk is not an error")
                .is_empty());
        }
        assert!(
            decoder
                .feed(&frame)
                .expect("later data still decodes")
                .len()
                == 1
        );
        decoder
            .finish()
            .expect("stalled chunks leave no buffered bytes");
    }

    #[test]
    fn accumulator_reports_empty_stream_only_at_finish() {
        let mut accumulator =
            ClaudeResponseAccumulator::new("claude-sonnet-4.5", HashMap::new(), 0);
        let error = accumulator
            .finish()
            .expect_err("empty upstream stream must remain an explicit terminal error");
        assert!(matches!(error, KiroEventStreamError::EmptyStream));
    }

    #[test]
    fn accumulator_keeps_stalled_stream_open_until_content_arrives() {
        let mut accumulator =
            ClaudeResponseAccumulator::new("claude-sonnet-4.5", HashMap::new(), 0);
        assert!(accumulator.blocks.is_empty());
        accumulator
            .accept(&KiroEvent {
                event_type: "assistantResponseEvent".into(),
                payload: serde_json::from_str(r#"{"content":"eventual"}"#).expect("payload"),
            })
            .expect("content after stall is accepted");
        accumulator
            .finish()
            .expect("content stream finishes normally");
        assert_eq!(accumulator.blocks.len(), 1);
    }

    #[test]
    fn decoder_handles_split_event_stream_frame() {
        let frame = event_frame("assistantResponseEvent", r#"{"content":"hello"}"#);
        let mut decoder = KiroEventStreamDecoder::default();
        assert!(decoder
            .feed(&frame[..7])
            .expect("split prelude is accepted")
            .is_empty());
        let events = decoder
            .feed(&frame[7..])
            .expect("complete frame is decoded");
        assert_eq!(events[0].event_type, "assistantResponseEvent");
    }

    #[test]
    fn decoder_finish_rejects_leftover_fragment_after_split_prelude() {
        let frame = fixture_frame_hex("assistant_hello");
        let mut decoder = KiroEventStreamDecoder::default();
        assert!(decoder
            .feed(&frame[..7])
            .expect("split prelude is accepted")
            .is_empty());
        let error = decoder
            .finish()
            .expect_err("incomplete buffered frame must fail cleanup");
        assert!(matches!(error, KiroEventStreamError::IncompleteFrame(7)));
    }

    #[test]
    fn decoder_reads_fixture_assistant_hello_payload() {
        let events = KiroEventStreamDecoder::default()
            .feed(&fixture_frame_hex("assistant_hello"))
            .expect("fixture frame decodes");
        assert_eq!(events[0].event_type, "assistantResponseEvent");
        assert_eq!(
            events[0].payload.get("content").and_then(Value::as_str),
            Some("hello")
        );
    }

    #[test]
    fn decoder_rejects_corrupt_message_crc() {
        let mut frame = event_frame("assistantResponseEvent", r#"{"content":"hello"}"#);
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        let error = KiroEventStreamDecoder::default()
            .feed(&frame)
            .expect_err("corrupt CRC must fail");
        assert!(matches!(error, KiroEventStreamError::MessageCrcMismatch));
    }

    #[test]
    fn decoder_rejects_corrupt_prelude_crc() {
        let mut frame = event_frame("assistantResponseEvent", r#"{"content":"hello"}"#);
        frame[8] ^= 0xff;
        let error = KiroEventStreamDecoder::default()
            .feed(&frame)
            .expect_err("corrupt prelude CRC must fail");
        assert!(matches!(error, KiroEventStreamError::PreludeCrcMismatch));
    }

    #[test]
    fn pending_tool_uses_flush_completes_named_tool_without_stop() {
        let fragment =
            serde_json::from_str::<Map<String, Value>>(r#"{"name":"lookup","input":{"q":"x"}}"#)
                .expect("object input");
        let mut pending = KiroPendingToolUses::default();
        assert!(pending
            .accept_event(&fragment)
            .expect("pending fragment accepted")
            .is_empty());
        let tools = pending.flush().expect("stream-end cleanup emits the tool");
        assert_eq!(tools[0].name, "lookup");
        assert_eq!(tools[0].input.get("q").and_then(Value::as_str), Some("x"));
        assert!(pending.flush().expect("second flush is empty").is_empty());
    }

    #[test]
    fn pending_tool_uses_assemble_fixture_fragments() {
        let mut decoder = KiroEventStreamDecoder::default();
        let first = decoder
            .feed(&fixture_frame_hex("tool_use_fragment"))
            .expect("fragment frame");
        let second = decoder
            .feed(&fixture_frame_hex("tool_use_complete"))
            .expect("complete frame");
        decoder.finish().expect("no leftover EventStream bytes");
        let mut pending = KiroPendingToolUses::default();
        assert!(pending
            .accept_event(&first[0].payload)
            .expect("first fragment accepted")
            .is_empty());
        let tools = pending
            .accept_event(&second[0].payload)
            .expect("second fragment accepted");
        assert_eq!(tools[0].tool_use_id, "toolu_real");
        assert_eq!(tools[0].name, "lookup");
        assert_eq!(tools[0].input.get("q").and_then(Value::as_str), Some("x"));
    }

    #[test]
    fn pending_tool_uses_adopt_late_upstream_id() {
        let first =
            serde_json::from_str::<Map<String, Value>>(r#"{"name":"lookup","input":"{\"q\":"}"#)
                .expect("first fragment");
        let second = serde_json::from_str::<Map<String, Value>>(
            r#"{"toolUseId":"toolu_real","name":"lookup","input":"\"x\"}","stop":true}"#,
        )
        .expect("second fragment");
        let mut pending = KiroPendingToolUses::default();
        assert!(pending
            .accept_event(&first)
            .expect("first fragment accepted")
            .is_empty());
        let tools = pending
            .accept_event(&second)
            .expect("second fragment accepted");
        assert_eq!(tools[0].tool_use_id, "toolu_real");
        assert_eq!(tools[0].input.get("q").and_then(Value::as_str), Some("x"));
    }

    fn exception_frame(exception_type: &str, payload: &str) -> Vec<u8> {
        let mut headers = event_header(":message-type", "exception");
        headers.extend(event_header(":exception-type", exception_type));
        let total_length = 16 + headers.len() + payload.len();
        let mut frame = vec![0; total_length];
        frame[..4].copy_from_slice(&(total_length as u32).to_be_bytes());
        frame[4..8].copy_from_slice(&(headers.len() as u32).to_be_bytes());
        let prelude_crc = crc32_ieee(&frame[..8]);
        frame[8..12].copy_from_slice(&prelude_crc.to_be_bytes());
        frame[12..12 + headers.len()].copy_from_slice(&headers);
        frame[12 + headers.len()..total_length - 4].copy_from_slice(payload.as_bytes());
        let message_crc = crc32_ieee(&frame[..total_length - 4]);
        frame[total_length - 4..].copy_from_slice(&message_crc.to_be_bytes());
        frame
    }

    #[test]
    fn decoder_rejects_fixture_exception_and_error_frames() {
        let error = KiroEventStreamDecoder::default()
            .feed(&fixture_frame_hex("exception"))
            .expect_err("modeled exception must fail the stream");
        assert!(matches!(
            error,
            KiroEventStreamError::UpstreamStreamError(message) if message == "model unavailable"
        ));
        let error = KiroEventStreamDecoder::default()
            .feed(&fixture_frame_hex("error_without_event_type"))
            .expect_err("error frame must fail the stream");
        assert!(matches!(
            error,
            KiroEventStreamError::UpstreamStreamError(message) if message == "internal failure"
        ));
    }

    #[test]
    fn decoder_rejects_modeled_exception_frames() {
        let frame = exception_frame(
            "ValidationException",
            r#"{"message":"request body is invalid"}"#,
        );
        let error = KiroEventStreamDecoder::default()
            .feed(&frame)
            .expect_err("modeled exception must fail the stream");
        assert!(matches!(
            error,
            KiroEventStreamError::UpstreamStreamError(message) if message == "request body is invalid"
        ));
    }

    #[test]
    fn accumulator_omits_reasoning_and_merges_text_with_hidden_tokens() {
        let mut accumulator =
            ClaudeResponseAccumulator::new("claude-sonnet-4.5", HashMap::new(), 4);
        for event in [
            KiroEvent {
                event_type: "reasoningContentEvent".into(),
                payload: serde_json::from_str(r#"{"text":"Think first."}"#).expect("reasoning"),
            },
            KiroEvent {
                event_type: "assistantResponseEvent".into(),
                payload: serde_json::from_str(r#"{"content":"Hello"}"#).expect("hello"),
            },
            KiroEvent {
                event_type: "assistantResponseEvent".into(),
                payload: serde_json::from_str(r#"{"content":" world."}"#).expect("world"),
            },
        ] {
            accumulator.accept(&event).expect("event accepted");
        }
        accumulator.finish().expect("accumulator finished");
        assert_eq!(accumulator.blocks.len(), 1);
        assert_eq!(accumulator.blocks[0].text, "Hello world.");
        assert_eq!(accumulator.stop_reason, "end_turn");
        let visible = estimate_claude_output_tokens(&accumulator.blocks);
        assert!(accumulator.output_tokens > visible);
        assert_eq!(accumulator.response_json()["usage"]["input_tokens"], 4);
    }

    #[test]
    fn accumulator_prefers_context_usage_and_records_metering_credits() {
        let mut accumulator =
            ClaudeResponseAccumulator::new("claude-sonnet-4.5", HashMap::new(), 7);
        accumulator
            .accept(&KiroEvent {
                event_type: "contextUsageEvent".into(),
                payload: serde_json::from_str(r#"{"contextUsagePercentage":10.5}"#)
                    .expect("context"),
            })
            .expect("context accepted");
        accumulator
            .accept(&KiroEvent {
                event_type: "meteringEvent".into(),
                payload: serde_json::from_str(r#"{"usage":2.5}"#).expect("credits"),
            })
            .expect("metering accepted");
        accumulator
            .accept(&KiroEvent {
                event_type: "assistantResponseEvent".into(),
                payload: serde_json::from_str(r#"{"content":"ok"}"#).expect("text"),
            })
            .expect("text accepted");
        accumulator.finish().expect("accumulator finished");
        assert_eq!(accumulator.input_tokens, 21_000);
        assert_eq!(accumulator.credits, 2.5);
        let mut writer = ClaudeSseWriter::new();
        let start =
            String::from_utf8(writer.start(&accumulator).expect("start")[0].clone()).expect("utf8");
        assert!(start.contains("event: message_start"));
        assert!(start.contains("\"input_tokens\":21000"));
        let finish = writer.finish(&accumulator).expect("finish frames");
        let joined = finish
            .iter()
            .map(|frame| String::from_utf8_lossy(frame).into_owned())
            .collect::<String>();
        assert!(joined.contains("event: message_delta"));
        assert!(joined.contains("\"stop_reason\":\"end_turn\""));
        assert!(joined.contains("\"output_tokens\":"));
        assert!(joined.contains("event: message_stop"));
    }

    #[test]
    fn sse_writer_emits_stable_tool_use_block() {
        let mut accumulator =
            ClaudeResponseAccumulator::new("claude-sonnet-4.5", HashMap::new(), 1);
        accumulator
            .accept(&KiroEvent {
                event_type: "toolUseEvent".into(),
                payload: serde_json::from_str(
                    r#"{"toolUseId":"toolu_stable","name":"lookup","input":{"q":"x"},"stop":true}"#,
                )
                .expect("tool"),
            })
            .expect("tool accepted");
        accumulator.finish().expect("finished");
        let mut writer = ClaudeSseWriter::new();
        writer.start(&accumulator).expect("start");
        let frames = writer
            .blocks(&accumulator.blocks)
            .expect("tool frames")
            .into_iter()
            .map(|frame| String::from_utf8(frame).expect("utf8"))
            .collect::<String>();
        assert!(frames.contains(r#""id":"toolu_stable""#));
        assert!(frames.contains("input_json_delta"));
        assert_eq!(frames.matches("event: content_block_start").count(), 1);
        assert_eq!(frames.matches("event: content_block_stop").count(), 1);
        assert_eq!(accumulator.stop_reason, "tool_use");
    }
}
