//! Incremental Server-Sent Events decoding for provider streams.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Stateful SSE frame decoder. Feed it raw bytes; it returns complete frames.
#[derive(Debug, Default)]
pub struct SseDecoder {
    buffer: String,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        self.drain(false)
    }

    pub fn finish(&mut self) -> Vec<SseEvent> {
        self.drain(true)
    }

    fn drain(&mut self, flush: bool) -> Vec<SseEvent> {
        let mut events = Vec::new();
        while let Some(index) = self
            .buffer
            .find("\n\n")
            .or_else(|| self.buffer.find("\r\n\r\n"))
        {
            let separator = if self.buffer[index..].starts_with("\r\n\r\n") {
                4
            } else {
                2
            };
            let frame: String = self.buffer.drain(..index + separator).collect();
            if let Some(event) = parse_frame(&frame) {
                events.push(event);
            }
        }
        if flush && !self.buffer.is_empty() {
            let frame = std::mem::take(&mut self.buffer);
            if let Some(event) = parse_frame(&frame) {
                events.push(event);
            }
        }
        events
    }
}

fn parse_frame(frame: &str) -> Option<SseEvent> {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<&str> = Vec::new();
    for line in frame.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(name) = line.strip_prefix("event:") {
            event_name = Some(name.trim().to_owned());
        } else if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.strip_prefix(' ').unwrap_or(data));
        }
    }
    if event_name.is_none() && data_lines.is_empty() {
        return None;
    }
    Some(SseEvent {
        event: event_name,
        data: data_lines.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_named_and_data_only_frames_across_chunks() {
        let mut decoder = SseDecoder::new();
        assert!(decoder.push(b"event: message\nda").is_empty());
        let events = decoder.push(b"ta: {\"a\":1}\n\ndata: [DONE]\n\n");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert_eq!(events[0].data, "{\"a\":1}");
        assert_eq!(events[1].event, None);
        assert_eq!(events[1].data, "[DONE]");
    }

    #[test]
    fn joins_multiline_data_and_flushes_at_eof() {
        let mut decoder = SseDecoder::new();
        decoder.push(b"data: one\ndata: two\n\n");
        let events = decoder.push(b"data: tail");
        assert!(events.is_empty());
        let events = decoder.finish();
        assert_eq!(events[0].data, "tail");
    }
}
