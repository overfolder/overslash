# Audit Log Design

**Status**: Implemented (PR #7)
**Date**: 2026-03-27

## Problem

Overslash had an audit_log table and basic infrastructure (migration 007) but only 5 out of ~16 mutable operations were logged. The IP address column existed but was never populated, and the query API only supported limit/offset pagination with no filtering.

## Goals

1. Every mutable API operation produces an audit log entry
2. Client IP addresses are captured for forensic traceability
3. The query API supports filtering by action, resource type, identity, and date range
4. Zero new migrations required

## Non-goals

- Real-time webhook dispatch for audit events (deferred)
- Audit log retention/archival policies
- Dashboard UI for browsing audit entries
- Composite indexes for filtered queries (premature; add when needed)

## Design

### Action naming convention

All actions follow `resource.verb` with lowercase snake_case resource and past-tense verb:

```
org.created          identity.created       api_key.created
secret.put           secret.deleted         permission_rule.created
permission_rule.deleted  approval.created   approval.resolved
action.executed      connection.created     connection.deleted
byoc_credential.created  byoc_credential.deleted
webhook.created      webhook.deleted
```

16 total action types.

### IP address capture

A `ClientIp` extractor resolves the client IP from (in order):
1. `X-Forwarded-For` header (first IP in comma-separated list)
2. `X-Real-IP` header
3. `ConnectInfo<SocketAddr>` fallback (direct connection)

The extractor never fails -- it returns `Option<String>`. This is a separate extractor from `AuthContext` because IP is a request-level concern, and some handlers (org creation, API key creation) are unauthenticated.

`main.rs` uses `into_make_service_with_connect_info::<SocketAddr>()` to make the socket address available.

### Audit entry struct

The `audit::log()` function accepts an `AuditEntry` struct instead of 8 positional arguments:

```rust
pub struct AuditEntry<'a> {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub action: &'a str,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub ip_address: Option<&'a str>,
}
```

This avoids the clippy `too_many_arguments` warning and makes call sites self-documenting.

### Logging pattern

All audit calls follow fire-and-forget: `let _ = audit::log(...).await;`

- Audit is written **after** the successful operation, never before
- Failures in audit logging do not fail the handler
- Delete operations only log when `deleted == true`
- Secret values and webhook signing secrets are never included in detail

### Filtered query API

`GET /v1/audit` now accepts optional query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | i64 | Max results (default 50) |
| `offset` | i64 | Pagination offset |
| `action` | string | Exact match (e.g. `secret.put`) |
| `resource_type` | string | Exact match (e.g. `secret`) |
| `identity_id` | UUID | Filter by actor |
| `since` | RFC3339 datetime | `created_at >= since` |
| `until` | RFC3339 datetime | `created_at <= until` |

The query uses optional parameter matching (`$N::type IS NULL OR column = $N`) to avoid dynamic SQL construction. The existing `(org_id, created_at DESC)` index covers the base case.

Response now includes `ip_address`.

## Future: Human-readable audit descriptions (Mode C)

Currently, Mode C audit entries store the static action description from the service YAML (e.g. `"Delete a calendar event (Google Calendar)"`). This is useful but doesn't tell you *which* event was deleted — you'd need to cross-reference the URL's UUID with an external system.

### Goal

Audit entries like `Deleted event "Team Standup" (Google Calendar)` instead of `Delete a calendar event (Google Calendar)`.

### Proposed approach

Add two optional fields to each action in the service YAML:

```yaml
delete_event:
  description: Delete a calendar event
  audit_template: 'Deleted event "{summary}"'
  audit_resolve:
    summary:
      from: params       # "params" or "response"
      path: summary      # dot-path into the source object
```

**Resolution sources:**

| Source | When to use | Example |
|--------|-------------|---------|
| `params` | Value is in the request params (create/update actions) | `summary` from create_event params |
| `response` | Value is in the API response body (read/delete actions) | `summary` from get_event response before deletion |

**For delete actions**, the response body is often empty (204 No Content). Two options:
1. **Pre-fetch**: Before executing the delete, do a GET to retrieve the resource name. Adds latency but gives the best description.
2. **Params only**: Only resolve from request params. For deletes that only take an ID, fall back to the static description.

**Recommendation**: Start with `params`-only resolution (zero extra API calls). Add `response` resolution as a second pass. Skip pre-fetch for deletes initially — the static description + URL is enough context.

### Implementation sketch

1. Add `audit_template` and `audit_resolve` to `ActionDefinition` in `overslash-core/types.rs`
2. After `resolve_request()` builds the `ActionRequest`, check if the action has `audit_resolve`
3. For `from: params`, substitute values from `req.params` into the template
4. For `from: response`, parse `result.body` as JSON and extract the value
5. Store the resolved string as `detail.description` in the audit entry
6. Fall back to the static `action.description` if resolution fails

### Service YAML examples

```yaml
# Google Calendar — create uses params
create_event:
  audit_template: 'Created event "{summary}"'
  audit_resolve:
    summary: { from: params, path: summary }

# Google Calendar — list uses response (count)
list_events:
  audit_template: 'Listed {count} events'
  audit_resolve:
    count: { from: response, path: items.length }

# Resend — send uses params
send_email:
  audit_template: 'Sent email to {to}'
  audit_resolve:
    to: { from: params, path: to }

# GitHub — create PR uses response
create_pull:
  audit_template: 'Created PR #{number} "{title}"'
  audit_resolve:
    number: { from: response, path: number }
    title: { from: response, path: title }
```

## Alternatives considered

**Middleware-based logging**: An Axum middleware could intercept all requests and log automatically. Rejected because it can't capture resource-specific context (resource_type, resource_id, semantic action names, detail payloads). The per-handler pattern gives precise control over what's logged.

**Dynamic SQL for filtering**: Building WHERE clauses dynamically would be more efficient for the query planner when parameters are absent. Rejected for simplicity -- the optional parameter matching approach is straightforward and the existing index covers performance needs at current scale.

**Webhook integration**: Publishing audit events as webhooks for real-time monitoring. Deferred because it couples audit writes to HTTP dispatch, increasing blast radius. Better to add as a separate `audit.*` event category after audit coverage is complete.

## Files changed

| File | Change |
|------|--------|
| `crates/overslash-db/src/repos/audit.rs` | `AuditEntry` struct, `ip_address` in `log()`, `AuditFilter` + `query_filtered()` |
| `crates/overslash-api/src/extractors.rs` | `ClientIp` extractor |
| `crates/overslash-api/src/main.rs` | `into_make_service_with_connect_info` |
| `crates/overslash-api/src/routes/audit.rs` | Filter params, `ip_address` in response |
| 10 route files | Added `ClientIp` extractor + audit calls |
