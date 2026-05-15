//! Minimal SSE (`text/event-stream`) parser for Streamable-HTTP MCP responses.
//!
//! Overslash uses the lowest-common-denominator subset of SSE: each event is a
//! single `data: <json>` line followed by a blank line. KeepAlive comments
//! (`: keep-alive\n\n`) appear between data events. We don't need event ids,
//! event names, retry directives, or multi-line concatenation — the server
//! never emits them. If that ever changes, extend `parse_event`.

use bytes::Bytes;
use futures_util::stream::{Stream, StreamExt};
use serde_json::Value;
use std::pin::Pin;

use crate::error::{Error, Result};

/// A typed stream of parsed SSE events, each one the JSON payload of a
/// `data:` block. Comment-only events (KeepAlive) are skipped silently.
pub struct SseEventStream {
    inner: Pin<Box<dyn Stream<Item = std::result::Result<Bytes, reqwest::Error>> + Send>>,
    buf: Vec<u8>,
}

impl SseEventStream {
    pub fn from_reqwest(resp: reqwest::Response) -> Self {
        Self {
            inner: Box::pin(resp.bytes_stream()),
            buf: Vec::new(),
        }
    }

    pub async fn next_event(&mut self) -> Result<Option<Value>> {
        loop {
            match drain_one(&mut self.buf)? {
                Some(DrainOutcome::Event(v)) => return Ok(Some(v)),
                Some(DrainOutcome::SkipComment) => continue, // try buffer again
                None => {}                                   // need more bytes
            }
            match self.inner.next().await {
                Some(Ok(chunk)) => self.buf.extend_from_slice(&chunk),
                Some(Err(e)) => return Err(Error::Http(e)),
                None => return Ok(None),
            }
        }
    }
}

enum DrainOutcome {
    Event(Value),
    SkipComment,
}

fn drain_one(buf: &mut Vec<u8>) -> Result<Option<DrainOutcome>> {
    let Some((end, term_len)) = find_terminator(buf) else {
        return Ok(None);
    };
    let raw: Vec<u8> = buf.drain(..end).collect();
    buf.drain(..term_len);
    match parse_event(&raw)? {
        Some(v) => Ok(Some(DrainOutcome::Event(v))),
        None => Ok(Some(DrainOutcome::SkipComment)),
    }
}

fn find_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some((i, 2));
        }
        if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
        }
        i += 1;
    }
    None
}

fn parse_event(raw: &[u8]) -> Result<Option<Value>> {
    let text = std::str::from_utf8(raw).map_err(|e| Error::SseParse(format!("utf8: {e}")))?;
    let mut data = String::new();
    let mut had_data = false;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(':') {
            continue; // comment / keepalive
        }
        if let Some(rest) = line.strip_prefix("data:") {
            had_data = true;
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest);
        }
        // event:, id:, retry: ignored — Overslash doesn't emit them.
    }
    if !had_data {
        return Ok(None);
    }
    let value: Value =
        serde_json::from_str(&data).map_err(|e| Error::SseParse(format!("json: {e}")))?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stream(chunks: Vec<&'static [u8]>) -> SseEventStream {
        let inner = futures_util::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<Bytes, reqwest::Error>(Bytes::from_static(c))),
        );
        SseEventStream {
            inner: Box::pin(inner),
            buf: Vec::new(),
        }
    }

    #[tokio::test]
    async fn parses_two_events_split_across_chunks() {
        let mut s = make_stream(vec![b"data: {\"a\":1}\n", b"\ndata: {\"b\":2}\n\n"]);
        let e1 = s.next_event().await.unwrap().unwrap();
        let e2 = s.next_event().await.unwrap().unwrap();
        assert_eq!(e1, serde_json::json!({"a":1}));
        assert_eq!(e2, serde_json::json!({"b":2}));
        assert!(s.next_event().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn skips_keepalive_comment_event_then_yields_data() {
        let mut s = make_stream(vec![b": keep-alive\n\ndata: {\"ok\":true}\n\n"]);
        let v = s.next_event().await.unwrap().unwrap();
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    #[tokio::test]
    async fn handles_crlf_terminators() {
        let mut s = make_stream(vec![b"data: {\"x\":42}\r\n\r\n"]);
        let v = s.next_event().await.unwrap().unwrap();
        assert_eq!(v, serde_json::json!({"x": 42}));
    }

    #[tokio::test]
    async fn data_split_across_chunks_byte_by_byte() {
        let mut s = make_stream(vec![
            b"data:",
            b" ",
            b"{\"hel",
            b"lo\":",
            b"\"world\"}",
            b"\n\n",
        ]);
        let v = s.next_event().await.unwrap().unwrap();
        assert_eq!(v, serde_json::json!({"hello":"world"}));
    }
}
