//! Kiro event-stream facade combining EventStream decoding and Claude response conversion.

#[path = "kiro-claude-response.rs"]
mod claude_response;
#[path = "kiro-event-frame.rs"]
mod frame;

pub(crate) use claude_response::{ClaudeResponseAccumulator, ClaudeSseWriter};
pub(crate) use frame::{KiroEvent, KiroEventStreamDecoder, KiroEventStreamError, KiroToolUse};

#[cfg(test)]
mod tests {
    use super::claude_response::{estimate_claude_output_tokens, KiroPendingToolUses};
    use super::frame::crc32_ieee;
    use super::*;
    use serde_json::Map;
    use serde_json::Value;
    use std::collections::HashMap;

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
