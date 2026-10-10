//! AWS EventStream framing and low-level Kiro event decoding.

//! AWS EventStream framing and Kiro response-event decoding.

use std::collections::HashMap;

use serde_json::{Map, Value};
use thiserror::Error;

const MAX_EVENT_STREAM_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

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

pub(super) fn crc32_ieee(data: &[u8]) -> u32 {
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
pub(super) fn nonempty_header(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    headers.get(name).filter(|value| !value.is_empty()).cloned()
}

pub(super) fn first_string_field(values: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        values
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}
