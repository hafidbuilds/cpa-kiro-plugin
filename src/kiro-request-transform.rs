//! Typed conversion from Claude Messages requests to Kiro conversation payloads.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MAX_TOOL_DESCRIPTION_LENGTH: usize = 10_237;
const MAX_KIRO_PAYLOAD_BYTES: usize = 900 * 1024;
static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A Claude Messages request accepted by the Kiro request transformer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeRequest {
    /// Requested model identifier.
    #[serde(default)]
    pub model: String,
    /// Ordered Claude conversation messages.
    #[serde(default)]
    pub messages: Vec<ClaudeMessage>,
    /// Maximum number of generated tokens.
    #[serde(default)]
    pub max_tokens: usize,
    /// Optional sampling temperature, including an explicit zero.
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Optional nucleus sampling value, including an explicit zero.
    #[serde(default)]
    pub top_p: Option<f64>,
    /// Whether the caller requested streaming output.
    #[serde(default)]
    pub stream: bool,
    /// Claude system prompt, either text or an array of text blocks.
    #[serde(default)]
    pub system: Option<Value>,
    /// Claude stop sequences, which Kiro does not support.
    #[serde(default)]
    pub stop_sequences: Vec<String>,
    /// Claude tool-selection policy.
    #[serde(default)]
    pub tool_choice: Option<ClaudeToolChoice>,
    /// Optional extended-thinking settings.
    #[serde(default)]
    pub thinking: Option<ClaudeThinking>,
    /// Claude tool declarations.
    #[serde(default)]
    pub tools: Vec<ClaudeTool>,
}

/// A single Claude conversation message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeMessage {
    /// Message role, normally `user` or `assistant`.
    #[serde(default)]
    pub role: String,
    /// String content or an array of Claude content blocks.
    #[serde(default)]
    pub content: Value,
}

/// Claude tool-selection settings supported by the request format.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeToolChoice {
    /// Selection mode, which must be `auto` for Kiro.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// Explicit tool name, rejected by Kiro when present with `tool` mode.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether parallel tool use is disabled.
    #[serde(default)]
    pub disable_parallel_tool_use: bool,
}

/// Claude extended-thinking settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeThinking {
    /// Thinking mode, such as `enabled` or `adaptive`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// Maximum thinking budget in tokens.
    #[serde(default)]
    pub budget_tokens: usize,
}

/// A Claude tool declaration and its JSON input schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaudeTool {
    /// Optional Claude tool type, including web-search variants.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// Tool name supplied by the Claude caller.
    #[serde(default)]
    pub name: String,
    /// Human-readable tool description.
    #[serde(default)]
    pub description: String,
    /// JSON Schema accepted by the tool.
    #[serde(default)]
    pub input_schema: Value,
}

/// A Kiro request payload produced from a Claude request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroPayload {
    /// Conversation metadata, history, and current user message.
    #[serde(rename = "conversationState")]
    pub conversation_state: KiroConversationState,
    /// Optional generation controls.
    #[serde(rename = "inferenceConfig", skip_serializing_if = "Option::is_none")]
    pub inference_config: Option<KiroInferenceConfig>,
    /// OAuth profile ARN, omitted for API-key requests.
    #[serde(rename = "profileArn", skip_serializing_if = "Option::is_none")]
    pub profile_arn: Option<String>,
    /// Tool-name mapping used when translating Kiro tool events back to Claude.
    #[serde(skip)]
    pub tool_name_map: Option<HashMap<String, String>>,
    /// Approximate serialized input-token count, omitted from wire JSON.
    #[serde(skip)]
    pub estimated_input_tokens: usize,
}

/// Kiro conversation state containing the current message and prior turns.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KiroConversationState {
    /// Continuation identifier for this request.
    #[serde(
        rename = "agentContinuationId",
        skip_serializing_if = "String::is_empty"
    )]
    pub agent_continuation_id: String,
    /// Kiro task type, normally `vibe`.
    #[serde(rename = "agentTaskType", skip_serializing_if = "String::is_empty")]
    pub agent_task_type: String,
    /// Kiro chat trigger type, normally `MANUAL`.
    #[serde(rename = "chatTriggerType")]
    pub chat_trigger_type: String,
    /// Conversation identifier.
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    /// Current user input message.
    #[serde(rename = "currentMessage")]
    pub current_message: KiroCurrentMessage,
    /// Prior conversation turns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<KiroHistoryMessage>,
}

/// Wrapper around Kiro's current user input message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KiroCurrentMessage {
    /// Current user input.
    #[serde(rename = "userInputMessage")]
    pub user_input_message: KiroUserInputMessage,
}

/// A Kiro user message, including image bytes and tool context.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KiroUserInputMessage {
    /// User-visible text content.
    pub content: String,
    /// Normalized Kiro model identifier.
    #[serde(rename = "modelId", skip_serializing_if = "String::is_empty")]
    pub model_id: String,
    /// Message origin marker required by Kiro.
    pub origin: String,
    /// Base64 image sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<KiroImage>,
    /// Declared tools and tool results attached to this message.
    #[serde(
        rename = "userInputMessageContext",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_input_message_context: Option<KiroUserMessageContext>,
}

/// Tool declarations and results attached to one Kiro user message.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KiroUserMessageContext {
    /// Tools available to the model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<KiroToolWrapper>,
    /// Results corresponding to assistant tool uses.
    #[serde(rename = "toolResults", default, skip_serializing_if = "Vec::is_empty")]
    pub tool_results: Vec<KiroToolResult>,
}

/// Kiro wrapper around one tool specification.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroToolWrapper {
    /// Tool specification sent to Kiro.
    #[serde(rename = "toolSpecification")]
    pub tool_specification: KiroToolSpecification,
}

/// Kiro tool name, description, and input schema.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroToolSpecification {
    /// Sanitized Kiro tool name.
    pub name: String,
    /// Bounded tool description.
    pub description: String,
    /// JSON Schema wrapper expected by Kiro.
    #[serde(rename = "inputSchema")]
    pub input_schema: KiroInputSchema,
}

/// Kiro's JSON-schema wrapper.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroInputSchema {
    /// Tool JSON Schema value.
    pub json: Value,
}

/// A Kiro tool result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroToolResult {
    /// Claude tool-use identifier.
    #[serde(rename = "toolUseId")]
    pub tool_use_id: String,
    /// Text result content.
    pub content: Vec<KiroResultContent>,
    /// `success` or `error`.
    pub status: String,
}

/// Text content in a Kiro tool result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroResultContent {
    /// Result text.
    pub text: String,
}

/// A base64-encoded Kiro image.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroImage {
    /// Image format without the `image/` prefix.
    pub format: String,
    /// Image byte source.
    pub source: KiroImageSource,
}

/// Base64 image bytes consumed by Kiro.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroImageSource {
    /// Base64-encoded image data.
    pub bytes: String,
}

/// One historical Kiro message, either user input or assistant output.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroHistoryMessage {
    /// Historical user input, when this is a user turn.
    #[serde(rename = "userInputMessage", skip_serializing_if = "Option::is_none")]
    pub user_input_message: Option<KiroUserInputMessage>,
    /// Historical assistant response, when this is an assistant turn.
    #[serde(
        rename = "assistantResponseMessage",
        skip_serializing_if = "Option::is_none"
    )]
    pub assistant_response_message: Option<KiroAssistantResponseMessage>,
}

/// Historical assistant text and tool uses.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroAssistantResponseMessage {
    /// Assistant text content.
    pub content: String,
    /// Tool calls emitted by the assistant.
    #[serde(rename = "toolUses", default, skip_serializing_if = "Vec::is_empty")]
    pub tool_uses: Vec<KiroToolUse>,
}

/// A historical assistant tool call.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroToolUse {
    /// Claude tool-use identifier.
    #[serde(rename = "toolUseId")]
    pub tool_use_id: String,
    /// Sanitized Kiro tool name.
    pub name: String,
    /// Tool input object.
    pub input: Map<String, Value>,
}

/// Kiro generation controls.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KiroInferenceConfig {
    /// Maximum generated tokens.
    #[serde(rename = "maxTokens", skip_serializing_if = "is_zero")]
    pub max_tokens: usize,
    /// Optional sampling temperature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Optional nucleus sampling value.
    #[serde(rename = "topP", skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// Errors returned while converting a Claude request to a Kiro payload.
#[derive(Debug, Error)]
pub enum TransformError {
    /// Claude JSON could not be decoded.
    #[error("decode Claude request: {0}")]
    Decode(#[from] serde_json::Error),
    /// The request did not provide a model.
    #[error("model is required")]
    MissingModel,
    /// The request did not provide any messages.
    #[error("messages must not be empty")]
    EmptyMessages,
    /// Kiro cannot apply Claude stop sequences.
    #[error("Kiro provider does not support stop_sequences")]
    UnsupportedStopSequences,
    /// Kiro only permits automatic unrestricted tool choice.
    #[error(
        "Kiro provider supports only automatic tool choice without parallel-tool restrictions"
    )]
    UnsupportedToolChoice,
    /// Kiro cannot fetch images from URLs.
    #[error("Kiro provider does not support URL-backed image sources; use base64 image data")]
    UnsupportedImageSource,
    /// A serialized payload exceeded Kiro's request limit.
    #[error(
        "Kiro request payload is {bytes} bytes after truncating removable history; limit is {limit} bytes"
    )]
    PayloadTooLarge {
        /// Actual serialized payload size.
        bytes: usize,
        /// Maximum serialized payload size.
        limit: usize,
    },
}

/// Converts a Claude JSON request into a typed Kiro payload and decoded request.
///
/// The returned payload preserves system prompts, history, tools, tool results,
/// model normalization, thinking budgets, and supported base64 image bytes.
pub fn translate_claude_request_to_kiro(
    raw: &[u8],
    requested_model: &str,
) -> Result<(KiroPayload, ClaudeRequest), TransformError> {
    let request: ClaudeRequest = serde_json::from_slice(raw)?;
    let model = normalize_kiro_model(if requested_model.trim().is_empty() {
        &request.model
    } else {
        requested_model
    });
    if model.is_empty() {
        return Err(TransformError::MissingModel);
    }
    if request.messages.is_empty() {
        return Err(TransformError::EmptyMessages);
    }
    for message in &request.messages {
        validate_image_sources(&message.content)?;
    }
    if !request.stop_sequences.is_empty() {
        return Err(TransformError::UnsupportedStopSequences);
    }
    if let Some(choice) = &request.tool_choice {
        if !choice.kind.trim().eq_ignore_ascii_case("auto") || choice.disable_parallel_tool_use {
            return Err(TransformError::UnsupportedToolChoice);
        }
    }

    let mut system_prompt = extract_system_prompt(request.system.as_ref());
    if let Some(thinking) = &request.thinking {
        if thinking.kind.trim().eq_ignore_ascii_case("enabled")
            || thinking.kind.trim().eq_ignore_ascii_case("adaptive")
        {
            let budget = if thinking.budget_tokens > 0 {
                thinking.budget_tokens
            } else {
                200_000
            };
            system_prompt = format!(
                "<thinking_mode>enabled</thinking_mode>\n<max_thinking_length>{budget}</max_thinking_length>\n\n{}",
                system_prompt.trim()
            )
            .trim()
            .to_string();
        }
    }

    let (tools, name_map, request_name_map) = convert_claude_tools(&request.tools);
    let mut history = Vec::with_capacity(request.messages.len() + 2);
    if !system_prompt.is_empty() {
        history.push(KiroHistoryMessage {
            user_input_message: Some(KiroUserInputMessage {
                content: sanitize_surrogates(&system_prompt),
                model_id: model.clone(),
                origin: "KIRO_CLI".into(),
                ..Default::default()
            }),
            assistant_response_message: None,
        });
        history.push(KiroHistoryMessage {
            user_input_message: None,
            assistant_response_message: Some(KiroAssistantResponseMessage {
                content: "I will follow these instructions.".into(),
                tool_uses: Vec::new(),
            }),
        });
    }

    let mut current_text = String::new();
    let mut current_images = Vec::new();
    let mut current_tool_results = Vec::new();
    for (index, message) in request.messages.iter().enumerate() {
        let last = index + 1 == request.messages.len();
        match message.role.trim().to_ascii_lowercase().as_str() {
            "user" => {
                let (text, images, results) = extract_user_content(&message.content);
                if last {
                    current_text = text;
                    current_images = images;
                    current_tool_results = results;
                } else {
                    let mut user = KiroUserInputMessage {
                        content: sanitize_surrogates(&choose_fallback_content(
                            &text,
                            !images.is_empty(),
                        )),
                        model_id: model.clone(),
                        origin: "KIRO_CLI".into(),
                        images,
                        ..Default::default()
                    };
                    if !results.is_empty() {
                        user.user_input_message_context = Some(KiroUserMessageContext {
                            tools: Vec::new(),
                            tool_results: results,
                        });
                    }
                    history.push(KiroHistoryMessage {
                        user_input_message: Some(user),
                        assistant_response_message: None,
                    });
                }
            }
            "assistant" => {
                let (text, tool_uses) =
                    extract_assistant_content(&message.content, &request_name_map);
                history.push(KiroHistoryMessage {
                    user_input_message: None,
                    assistant_response_message: Some(KiroAssistantResponseMessage {
                        content: sanitize_surrogates(&text),
                        tool_uses,
                    }),
                });
            }
            _ => {}
        }
    }

    // Kiro carries tool results as structured context; unlike the legacy
    // Claude adapter, do not rewrite the user's text with narrated results.
    let mut current = KiroUserInputMessage {
        content: sanitize_surrogates(&choose_fallback_content(
            &current_text,
            !current_images.is_empty(),
        )),
        model_id: model.clone(),
        origin: "KIRO_CLI".into(),
        images: current_images,
        ..Default::default()
    };
    if !tools.is_empty() || !current_tool_results.is_empty() {
        current.user_input_message_context = Some(KiroUserMessageContext {
            tools,
            tool_results: current_tool_results,
        });
    }
    while history
        .first()
        .is_some_and(|entry| entry.assistant_response_message.is_some())
    {
        history.remove(0);
    }
    let mut payload = KiroPayload {
        conversation_state: KiroConversationState {
            agent_continuation_id: generate_kiro_uuid(),
            agent_task_type: "vibe".into(),
            chat_trigger_type: "MANUAL".into(),
            conversation_id: build_conversation_id(
                &model,
                &system_prompt,
                first_user_anchor(&request.messages),
            ),
            current_message: KiroCurrentMessage {
                user_input_message: current,
            },
            history,
        },
        inference_config: None,
        profile_arn: None,
        tool_name_map: name_map,
        estimated_input_tokens: 0,
    };
    if request.max_tokens > 0 || request.temperature.is_some() || request.top_p.is_some() {
        payload.inference_config = Some(KiroInferenceConfig {
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            top_p: request.top_p,
        });
    }
    truncate_kiro_payload(&mut payload, !system_prompt.is_empty())?;
    payload.estimated_input_tokens = serde_json::to_vec(&payload)?.len().div_ceil(4);
    Ok((payload, request))
}

/// Normalizes Claude model spellings to Kiro's dotted-version identifiers.
pub fn normalize_kiro_model(model: &str) -> String {
    let model = model
        .trim()
        .strip_suffix("-thinking")
        .unwrap_or(model.trim());
    if model == "claude-sonnet-4-20250514" {
        return "claude-sonnet-4".into();
    }
    let parts: Vec<&str> = model.splitn(5, '-').collect();
    if parts.len() >= 4
        && parts[0] == "claude"
        && matches!(parts[1], "opus" | "sonnet" | "haiku")
        && !parts[2].is_empty()
        && parts[2].chars().all(|character| character.is_ascii_digit())
        && !parts[3].is_empty()
        && parts[3].chars().all(|character| character.is_ascii_digit())
        && parts[3].len() <= 2
    {
        let suffix = parts.get(4).copied().unwrap_or_default();
        let suffix = if suffix.is_empty() {
            String::new()
        } else {
            format!("-{suffix}")
        };
        return format!("claude-{}-{}.{}{}", parts[1], parts[2], parts[3], suffix);
    }
    model.into()
}

/// Replaces unsupported Kiro tool-name characters and limits names to 64 bytes.
pub fn sanitize_kiro_tool_name(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    for character in name.trim().chars() {
        if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }
    let sanitized = sanitized
        .trim_matches('_')
        .chars()
        .take(64)
        .collect::<String>();
    if sanitized.is_empty() {
        "tool".into()
    } else {
        sanitized
    }
}
/// Removes unpaired UTF-16 surrogate code points from text fields.
fn sanitize_surrogates(text: &str) -> String {
    text.chars()
        .filter(|character| !(*character as u32 >= 0xd800 && *character as u32 <= 0xdfff))
        .collect()
}

const TOOL_RESULT_LIMIT: usize = 250_000;

fn truncate_tool_result(text: &str) -> String {
    if text.chars().count() <= TOOL_RESULT_LIMIT {
        return text.to_owned();
    }
    let half = TOOL_RESULT_LIMIT / 2;
    let start: String = text.chars().take(half).collect();
    let end: String = text
        .chars()
        .rev()
        .take(half)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}\n... [TRUNCATED] ...\n{end}")
}

fn to_kiro_tool_use_id(id: &str) -> String {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte));
    if valid {
        return id.to_owned();
    }
    use base64::Engine;
    let digest = Sha256::digest(id.as_bytes());
    format!(
        "pi_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(digest)
            .chars()
            .take(32)
            .collect::<String>()
    )
}

fn validate_image_sources(content: &Value) -> Result<(), TransformError> {
    for block in content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        let kind = block
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(kind, "image" | "input_image") {
            let source = block.get("source").and_then(Value::as_object);
            let source_type = source
                .and_then(|source| source.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let url = source
                .and_then(|source| source.get("url"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if source_type.trim().eq_ignore_ascii_case("url") || !url.trim().is_empty() {
                return Err(TransformError::UnsupportedImageSource);
            }
        } else if kind == "tool_result" {
            if let Some(nested) = block.get("content") {
                validate_image_sources(nested)?;
            }
        }
    }
    Ok(())
}

fn extract_system_prompt(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.trim().into(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .into(),
        _ => String::new(),
    }
}

fn extract_user_content(content: &Value) -> (String, Vec<KiroImage>, Vec<KiroToolResult>) {
    if let Some(text) = content.as_str() {
        return (text.into(), Vec::new(), Vec::new());
    }
    let mut texts = Vec::new();
    let mut images = Vec::new();
    let mut results = Vec::new();
    for block in content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        match block
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "text" | "input_text" => {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    texts.push(text);
                }
            }
            "image" | "input_image" => {
                if let Some(image) = extract_image(block) {
                    images.push(image);
                }
            }
            "tool_result" => {
                let (text, result_images) = extract_tool_result_content(block.get("content"));
                images.extend(result_images.iter().cloned());
                let status = if block
                    .get("is_error")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "error"
                } else {
                    "success"
                };
                results.push(KiroToolResult {
                    tool_use_id: to_kiro_tool_use_id(
                        block
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    ),
                    content: vec![KiroResultContent {
                        text: truncate_tool_result(&choose_fallback_content(
                            &text,
                            !result_images.is_empty(),
                        )),
                    }],
                    status: status.into(),
                });
            }
            _ => {}
        }
    }
    (texts.concat(), images, results)
}

fn extract_assistant_content(
    content: &Value,
    tool_names: &HashMap<String, String>,
) -> (String, Vec<KiroToolUse>) {
    if let Some(text) = content.as_str() {
        return (text.into(), Vec::new());
    }
    let mut texts = Vec::new();
    let mut tools = Vec::new();
    for block in content
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        match block
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "text" => {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    texts.push(text);
                }
            }
            "tool_use" => {
                let original_name = block
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let name = tool_names
                    .get(original_name)
                    .cloned()
                    .unwrap_or_else(|| sanitize_kiro_tool_name(original_name));
                let input = block
                    .get("input")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                tools.push(KiroToolUse {
                    tool_use_id: to_kiro_tool_use_id(
                        block.get("id").and_then(Value::as_str).unwrap_or_default(),
                    ),
                    name,
                    input,
                });
            }
            _ => {}
        }
    }
    (texts.concat(), tools)
}

fn extract_image(block: &Map<String, Value>) -> Option<KiroImage> {
    let source = block.get("source")?.as_object()?;
    let data = source.get("data")?.as_str()?;
    if data.is_empty() || !is_base64(data) {
        return None;
    }
    let mut format = source
        .get("media_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if let Some(stripped) = format.strip_prefix("image/") {
        format = stripped.into();
    }
    if format == "jpg" {
        format = "jpeg".into();
    }
    if !matches!(format.as_str(), "png" | "jpeg" | "gif" | "webp") {
        return None;
    }
    Some(KiroImage {
        format,
        source: KiroImageSource { bytes: data.into() },
    })
}

fn is_base64(data: &str) -> bool {
    let bytes = data.as_bytes();
    !bytes.is_empty()
        && bytes.len().is_multiple_of(4)
        && bytes.iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || *byte == b'+'
                || *byte == b'/'
                || (*byte == b'=' && index >= bytes.len().saturating_sub(2))
        })
}

fn extract_tool_result_content(content: Option<&Value>) -> (String, Vec<KiroImage>) {
    if let Some(text) = content.and_then(Value::as_str) {
        return (text.into(), Vec::new());
    }
    let mut texts = Vec::new();
    let mut images = Vec::new();
    if let Some(blocks) = content.and_then(Value::as_array) {
        for block in blocks.iter().filter_map(Value::as_object) {
            if let Some(text) = block.get("text").and_then(Value::as_str) {
                texts.push(text);
            }
            if let Some(image) = extract_image(block) {
                images.push(image);
            }
        }
    }
    (texts.concat(), images)
}

type ConvertedKiroTools = (
    Vec<KiroToolWrapper>,
    Option<HashMap<String, String>>,
    HashMap<String, String>,
);

fn convert_claude_tools(tools: &[ClaudeTool]) -> ConvertedKiroTools {
    let mut converted = Vec::with_capacity(tools.len());
    let mut response_names = HashMap::new();
    let mut request_names = HashMap::new();
    let mut used = HashSet::new();
    for tool in tools {
        if tool.kind.to_ascii_lowercase().starts_with("web_search") {
            continue;
        }
        let base = sanitize_kiro_tool_name(&tool.name);
        let name = allocate_unique_tool_name(&base, &mut used);
        request_names.insert(tool.name.clone(), name.clone());
        if name != tool.name {
            response_names.insert(name.clone(), tool.name.clone());
        }
        let mut description = tool.description.trim().to_string();
        if description.is_empty() {
            description = format!("Call {name}.");
        }
        description = description
            .chars()
            .take(MAX_TOOL_DESCRIPTION_LENGTH)
            .collect();
        let mut schema = match tool.input_schema.clone() {
            Value::Object(schema) => schema,
            _ => Map::new(),
        };
        schema
            .entry("type")
            .or_insert_with(|| Value::String("object".into()));
        converted.push(KiroToolWrapper {
            tool_specification: KiroToolSpecification {
                name,
                description,
                input_schema: KiroInputSchema {
                    json: Value::Object(schema),
                },
            },
        });
    }
    (
        converted,
        (!response_names.is_empty()).then_some(response_names),
        request_names,
    )
}

fn allocate_unique_tool_name(base: &str, used: &mut HashSet<String>) -> String {
    let base = base.to_owned();
    if used.insert(base.clone()) {
        return base;
    }
    for index in 2.. {
        let suffix = format!("_{index}");
        let prefix: String = base
            .chars()
            .take(64usize.saturating_sub(suffix.len()))
            .collect();
        let candidate = format!("{prefix}{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!()
}

fn choose_fallback_content(content: &str, has_image: bool) -> String {
    if !content.trim().is_empty() {
        content.into()
    } else if has_image {
        "Please analyze the attached image.".into()
    } else {
        ".".into()
    }
}

fn first_user_anchor(messages: &[ClaudeMessage]) -> String {
    messages
        .iter()
        .find(|message| message.role.eq_ignore_ascii_case("user"))
        .map(|message| extract_user_content(&message.content).0)
        .filter(|text| !text.trim().is_empty() && text.trim() != ".")
        .unwrap_or_default()
}

fn build_conversation_id(model: &str, system_prompt: &str, anchor: String) -> String {
    if anchor.trim().is_empty() {
        return generate_kiro_uuid();
    }
    let seed = format!("{model}\n{}\n{}", system_prompt.trim(), anchor.trim());
    let mut hasher = Sha1::new();
    hasher.update(b"6ba7b8119dad11d180b400c04fd430c8");
    hasher.update(seed.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_kiro_uuid(bytes)
}

fn generate_kiro_uuid() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64);
    let counter = UUID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&now.to_be_bytes());
    bytes[8..].copy_from_slice(&(counter ^ now.rotate_left(17)).to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_kiro_uuid(bytes)
}

fn format_kiro_uuid(bytes: [u8; 16]) -> String {
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

fn truncate_kiro_payload(
    payload: &mut KiroPayload,
    preserve_system_pair: bool,
) -> Result<(), TransformError> {
    let protected = if preserve_system_pair { 2 } else { 0 };
    loop {
        let bytes = serde_json::to_vec(payload)?.len();
        if bytes <= MAX_KIRO_PAYLOAD_BYTES {
            return Ok(());
        }
        if payload.conversation_state.history.len() <= protected {
            return Err(TransformError::PayloadTooLarge {
                bytes,
                limit: MAX_KIRO_PAYLOAD_BYTES,
            });
        }
        let remove_count = if protected + 1 < payload.conversation_state.history.len()
            && payload.conversation_state.history[protected]
                .user_input_message
                .is_some()
            && payload.conversation_state.history[protected + 1]
                .assistant_response_message
                .is_some()
        {
            2
        } else {
            1
        };
        payload
            .conversation_state
            .history
            .drain(protected..protected + remove_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_model_converts_dash_minor_version() {
        assert_eq!(
            normalize_kiro_model(" claude-sonnet-4-5-thinking "),
            "claude-sonnet-4.5"
        );
        assert_eq!(
            normalize_kiro_model("claude-sonnet-4-20250514"),
            "claude-sonnet-4"
        );
    }

    #[test]
    fn sanitize_tool_name_replaces_invalid_characters_and_bounds_length() {
        assert_eq!(
            sanitize_kiro_tool_name(" math.add/unsafe "),
            "math_add_unsafe"
        );
        assert_eq!(sanitize_kiro_tool_name("___"), "tool");
        assert_eq!(sanitize_kiro_tool_name(&"x".repeat(70)).len(), 64);
    }

    #[test]
    fn conversion_preserves_system_tools_history_and_results() {
        let raw = br#"{"model":"claude-sonnet-4-5","max_tokens":128,"system":"Be concise.","tools":[{"name":"math.add/unsafe","description":"Add values","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"Add 2 and 3"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"math.add/unsafe","input":{"a":2}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"5"}]}]}"#;
        let (payload, request) =
            translate_claude_request_to_kiro(raw, "").expect("conversion succeeds");
        assert_eq!(request.max_tokens, 128);
        assert_eq!(
            payload
                .conversation_state
                .current_message
                .user_input_message
                .model_id,
            "claude-sonnet-4.5"
        );
        assert_eq!(
            payload
                .conversation_state
                .current_message
                .user_input_message
                .user_input_message_context
                .as_ref()
                .expect("context")
                .tool_results[0]
                .status,
            "success"
        );
        assert_eq!(
            payload.tool_name_map.as_ref().expect("name map")["math_add_unsafe"],
            "math.add/unsafe"
        );
        assert!(payload.conversation_state.history[0]
            .user_input_message
            .as_ref()
            .expect("system")
            .content
            .contains("Be concise."));
    }

    #[test]
    fn tool_ids_preserve_native_and_remap_invalid_ids_deterministically() {
        assert_eq!(to_kiro_tool_use_id("call_1"), "call_1");
        let first = to_kiro_tool_use_id(&"call_".repeat(20));
        assert!(first.starts_with("pi_"));
        assert_eq!(first, to_kiro_tool_use_id(&"call_".repeat(20)));
        assert!(first.len() <= 35);
    }

    #[test]
    fn tool_result_truncation_keeps_both_ends() {
        let text = format!("START{}END", "x".repeat(TOOL_RESULT_LIMIT));
        let truncated = truncate_tool_result(&text);
        assert!(truncated.starts_with("START"));
        assert!(truncated.ends_with("END"));
        assert!(truncated.contains("[TRUNCATED]"));
    }

    #[test]
    fn surrogate_sanitization_preserves_valid_unicode() {
        assert_eq!(sanitize_surrogates("ok 🙈"), "ok 🙈");
    }
}
