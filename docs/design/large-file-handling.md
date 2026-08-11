# Large File Handling — Streaming Proxy

**Status**: Implemented
**Date**: 2026-03-28
**Related**: `SPEC.md` (execution modes), `http_executor.rs`, `actions.rs`

## Overview

Overslash buffers all HTTP responses in memory as `String`. This breaks for file-oriented APIs (Google Drive download, S3 GetObject, Dropbox) — binary data corrupts as UTF-8, and large files cause OOM. This design adds a response size limit safety net and a streaming proxy mode that pipes upstream bytes through Overslash with minimal memory usage.

## Key Constraint

**Secrets never leave the vault.** An earlier design considered returning authenticated URLs + tokens to callers ("prefer_url"). That *shape* was rejected — handing the caller a URL plus the credential to use it would leak OAuth tokens and API keys, undermining the core security model.

> **Updated (D51).** Capability URLs came back, in a form that keeps the constraint. `deliver: "url"` mints an Overslash-owned, **credential-free** token: the row stores the request, not a credential, and Overslash resolves the secret from the vault at fetch time. Nothing authenticating leaves the vault, so the objection above does not apply. See D51 for the descriptor shape and TTL, and D57 for the token now being minted automatically on an oversized response.

Either way, all auth stays server-side: Overslash injects credentials, calls the upstream request, and streams or serves the response bytes through.

## Problem

```
POST /v1/actions/call
  → http_caller::call()
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
  "download_url": "https://…/v1/downloads/AbC…",
  "expires_at": "2026-08-11T12:15:00Z",
  "hint": "the response exceeded the cap; fetch the full body at download_url, or narrow the call with the action's own paging parameters or a filter. The URL returns the unfiltered body."
}
```

`download_url` / `expires_at` are D57: since `deliver: "url"` never needs the
body on this runtime, the token for the same request is minted at the point of
failure so the retry is already in hand. It is best-effort — OAuth-injected
services and raw HTTP carrying inline credential headers are refused, as are
any other mint failures. The status stays 502 either way.

The `hint` therefore has **three** forms, and the rule behind them is the same
one throughout: never name a recovery the caller cannot use.

| Case | Wording |
|---|---|
| Minted | Fetch `download_url`, or narrow the call. Neither flag is named — there is nothing left to retry. |
| Not minted, REST caller | `deliver: "url"` **and** `prefer_stream: true`. |
| Not minted, MCP caller | `deliver: "url"` only. |

`deliver: "url"` (D51) leads whenever a flag is named at all — it works from
every surface. `prefer_stream` is appended only for callers who can act on it,
which today means direct REST callers; it is absent from the `overslash_read`
/ `overslash_call` input schemas (which are `additionalProperties: false`).
`routes::mcp::forward` stamps `X-Overslash-Transport` on its loopback request
and `extractors::CallerTransport` reads it back.

The approval-replay path renders no hint at all: it surfaces the error through
`AppError`'s `Display` impl (`"response too large"`) rather than
`IntoResponse`, so the JSON body — `hint` included — is never built. Neither
recovery is reachable there anyway; replay forces `prefer_stream: false` and
`POST /v1/approvals/{id}/call` takes no request body to carry `deliver`, and
for the same reason it mints no `download_url`.

Note what does **not** help here: a jq `filter` runs on an already-buffered
body, so an oversized response fails before it ever executes. The remedies are
the action's own paging parameters (now visible on `/v1/search` action rows),
the download URL, or `prefer_stream`.

### Strategy C: Streaming Proxy (`prefer_stream: true`)

Caller adds `"prefer_stream": true` to the call request. Overslash:
1. Resolves auth (OAuth tokens, secrets) — same as always, server-side
2. Checks permissions — same as always
3. Calls the upstream request
4. Pipes the response bytes directly to the caller without buffering

The response is the raw upstream HTTP response (status + selected headers + streamed body), not a `Json<CallResponse>`. This works because the handler returns `impl IntoResponse`.

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
| `crates/overslash-api/src/services/http_caller.rs` | Size-limited `call()`, new `call_streaming()` |
| `crates/overslash-api/src/routes/actions.rs` | `prefer_stream` field, streaming response path |
| `crates/overslash-core/src/types/service.rs` | `response_type` on `ServiceAction` |
| `crates/overslash-api/tests/common/mod.rs` | `/large-file`, `/drive/files/download` mock endpoints |
| `crates/overslash-api/tests/large_file.rs` | 4 integration tests |

### http_executor changes

- `call()` now takes `max_body_bytes`. Checks `Content-Length` first; if absent, streams chunks up to limit. Returns `CallError::ResponseTooLarge` if exceeded.
- `call_streaming()` returns the raw `reqwest::Response` unconsumed — caller streams from it.
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
- Audit captures that a streaming action was called, with method, URL, and status code
