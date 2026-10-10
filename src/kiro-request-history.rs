//! Claude content extraction and image/tool-result conversion for Kiro history.

use serde_json::{Map, Value};
use std::collections::HashMap;

use super::{
    choose_fallback_content, sanitize_kiro_tool_name, to_kiro_tool_use_id, truncate_tool_result,
    KiroImage, KiroImageSource, KiroResultContent, KiroToolResult, KiroToolUse, TransformError,
};

pub(super) fn validate_image_sources(content: &Value) -> Result<(), TransformError> {
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

pub(super) fn extract_system_prompt(value: Option<&Value>) -> String {
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

pub(super) fn extract_user_content(
    content: &Value,
) -> (String, Vec<KiroImage>, Vec<KiroToolResult>) {
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

pub(super) fn extract_assistant_content(
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
