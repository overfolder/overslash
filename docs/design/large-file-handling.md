# Large File Handling — Streaming Proxy

**Status**: Implemented
**Date**: 2026-03-28
**Related**: `SPEC.md` (execution modes), `http_executor.rs`, `actions.rs`

## Overview

Overslash buffers all HTTP responses in memory as `String`. This breaks for file-oriented APIs (Google Drive download, S3 GetObject, Dropbox) — binary data corrupts as UTF-8, and large files cause OOM. This design adds a response size limit safety net and a streaming proxy mode that pipes upstream bytes through Overslash with minimal memory usage.

## Key Constraint

**Secrets never leave the vault.** An earlier design considered returning authenticated URLs + tokens to callers ("prefer_url"). This was rejected — it would leak OAuth tokens and API keys to the caller, undermining Overslash's core security model. Instead, all auth stays server-side: Overslash injects credentials, executes the upstream request, and streams the response bytes through.

## Problem

```
POST /v1/actions/execute
  → http_executor::execute()
      → response.text().await?        ← buffers entire response as String
      → ActionResult { body: String }  ← returned inline in JSON
```

- **OOM**: 2GB Google Drive file download crashes the process
- **Corruption**: Binary → UTF-8 `String` silently corrupts data
- **No awareness**: No `Content-Length` check, no max body size

## Design: Two Strategies

### Strategy A: Buffered (default + size limit)

Current behavior with a safety net. Configurable via `MAX_RESPONSE_BODY_BYTES` (default 5 MB). If exceeded, returns a structured error:

```json
{
  "error": "response_too_large",
  "content_length": 2147483648,
  "content_type": "application/octet-stream",
  "limit_bytes": 5242880,
  "hint": "retry with prefer_stream: true to stream large responses"
}
```

### Strategy C: Streaming Proxy (`prefer_stream: true`)

Caller adds `"prefer_stream": true` to the execute request. Overslash:
1. Resolves auth (OAuth tokens, secrets) — same as always, server-side
2. Checks permissions — same as always
3. Executes the upstream request
4. Pipes the response bytes directly to the caller without buffering

The response is the raw upstream HTTP response (status + selected headers + streamed body), not a `Json<ExecuteResponse>`. This works because the handler returns `impl IntoResponse`.

**Headers forwarded**: `content-type`, `content-length`, `content-disposition`, `etag`, `last-modified`, `cache-control`. Auth headers are NOT forwarded.

**Audit**: Logs `action.streamed` with method, url, status_code, content_length.

## Implementation

### Files Changed

| File | Change |
|------|--------|
| `Cargo.toml` | Added `stream` feature to reqwest |
| `crates/overslash-api/Cargo.toml` | Added `futures-util` |
| `crates/overslash-api/src/config.rs` | `max_response_body_bytes` field |
| `crates/overslash-api/src/error.rs` | `ResponseTooLarge` variant |
| `crates/overslash-api/src/services/http_executor.rs` | Size-limited `execute()`, new `execute_streaming()` |
| `crates/overslash-api/src/routes/actions.rs` | `prefer_stream` field, streaming response path |
| `crates/overslash-core/src/types/service.rs` | `response_type` on `ServiceAction` |
| `crates/overslash-api/tests/common/mod.rs` | `/large-file`, `/drive/files/download` mock endpoints |
| `crates/overslash-api/tests/large_file.rs` | 4 integration tests |

### http_executor changes

- `execute()` now takes `max_body_bytes`. Checks `Content-Length` first; if absent, streams chunks up to limit. Returns `ExecuteError::ResponseTooLarge` if exceeded.
- `execute_streaming()` returns the raw `reqwest::Response` unconsumed — caller streams from it.
- Shared `build_request()` helper to avoid duplication.

### Google Drive redirect handling

Google Drive downloads return `302 Found` → redirect to `googleusercontent.com` CDN. reqwest follows redirects by default. In streaming mode this works transparently — reqwest follows the redirect internally, and we stream the final response.

The mock server simulates this:
- `GET /drive/files/download` → 302 to `/drive/files/content`
- `GET /drive/files/content` → binary response body

### Service action metadata

`ServiceAction` now has an optional `response_type` field (`"json"` or `"binary"`). Services can mark file-download actions as `binary` to signal that callers should use `prefer_stream: true`.

## Tests

| Test | What it proves |
|------|---------------|
| `test_response_too_large` | 10KB vs 1KB limit → 502 with structured error |
| `test_prefer_stream_large_file` | 100KB streamed through 1KB-limited gateway → 200, correct bytes |
| `test_prefer_stream_with_auth` | Streaming with secret injection, secrets don't leak |
| `test_google_drive_redirect_stream` | 302 redirect followed, bytes streamed from redirect target |

## Security

- Secrets never leave the vault — they're injected into the upstream request, not exposed to the caller
- Streamed response only forwards safe headers (content-type, content-length, etc.)
- Auth headers (Authorization, X-Token, etc.) are NOT forwarded to the caller
- Audit captures that a streaming action was executed, with method, URL, and status code
