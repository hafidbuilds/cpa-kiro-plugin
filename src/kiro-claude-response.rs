//! Kiro event accumulation and Claude response/SSE conversion.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::{KiroEvent, KiroEventStreamError, KiroToolUse};

use super::frame::first_string_field;

static KIRO_EVENT_UUID_COUNTER: AtomicU64 = AtomicU64::new(1);

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

pub(super) fn estimate_claude_output_tokens(blocks: &[ClaudeContentBlock]) -> i64 {
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
