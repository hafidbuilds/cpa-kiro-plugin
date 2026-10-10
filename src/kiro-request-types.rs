//! Claude and Kiro wire-model definitions used by the request transformer.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use thiserror::Error;

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
