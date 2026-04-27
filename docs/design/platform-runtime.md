# Platform Runtime

**Status:** Implemented (first slice — templates surface)
**Author:** Factory

## Motivation

`services/overslash.yaml` declares permission anchors (`manage_templates`,
`manage_secrets`, …) that previously had no HTTP method or path. The template
validator marked them non-executable, and agents could only reach the
corresponding REST routes via raw HTTP (Mode A) — outside the permission graph,
with no approval bubbling and no risk-based gates.

`Runtime::Platform` fixes this: it routes Mode-C calls to registered in-process
Rust handlers using the same approval chain and permission-key walk as HTTP and
MCP actions.

## Design Space

Three options were considered:

**A — Proxy to localhost.** Re-route calls to the API's own REST endpoints.
Simple, but adds an HTTP round-trip and forces every platform action to look
like an HTTP action from the permission system's perspective. Discarded.

**B — Shared kernel functions called from both HTTP and Platform paths.**
Extract the business logic from route handlers into standalone `async fn` kernels
that neither path owns. Both the HTTP handler and the platform dispatch call the
same kernel. Chosen: it keeps HTTP and Platform surfaces in sync automatically,
and avoids the proxy overhead.

**C — Store-procedure model.** Pre-compile platform actions into a dedicated
executor process. Rejected as over-engineering for the current scale.

## Architecture

```
POST /v1/actions/call
  { service: "overslash", action: "list_templates" }
        │
        ▼
   resolve_request()
     finds Runtime::Platform
     ─► returns PlatformTarget { action_key: "list_templates" }
        ServiceScope { action_key: "manage_templates" }   ← permission anchor
        │
        ▼
   permission_chain::walk()
     checks "overslash:manage_templates:*"
     ─► Allowed  ─────────────────────────────────────────────┐
     ─► Gap      → 202 PendingApproval (same as HTTP/MCP)     │
     ─► Denied   → 403                                         │
        │                                                      │
        ▼ (Allowed)                                            │
   Platform dispatch fork ◄─────────────────────────────────────┘
     state.platform_registry.get("list_templates")
     handler.call(PlatformCallContext { org_id, identity_id, db, registry }, params)
        │
        ▼
   kernel_list_templates(ctx)
     queries DB + in-memory registry
        │
        ▼
   audit row  →  200 CallResponse::Called { result }
```

## Handler Contract

```rust
pub trait PlatformHandler: Send + Sync {
    fn call(
        &self,
        ctx: PlatformCallContext,
        params: HashMap<String, Value>,
    ) -> BoxFuture<'_, Result<Value, AppError>>;
}
```

`PlatformCallContext` carries only what a handler needs:
- `org_id` / `identity_id` — for multi-tenancy and audit
- `db: PgPool` — direct DB access
- `registry: Arc<ServiceRegistry>` — read the in-memory global template list

Handlers return `Value` (serialised to the `result.body` string).
The `ActionResult.status_code` is always 200 for successful platform calls.
`ip_address` in the audit row is `None` — the caller's identity is recorded;
the IP is the server's own loopback.

## Permission Field

`ServiceAction` carries an optional `permission: Option<String>` field.
When set, `resolve_request` uses it as the `service_scope.action_key` instead
of the raw action key:

```
list_templates  →  action.permission = "manage_templates"
get_template    →  action.permission = "manage_templates"
create_template →  action.permission = "manage_templates"
```

`PermissionKey::from_service_action` produces `overslash:manage_templates:*`
for all three. An existing grant on that anchor covers all template actions
without any migration.

## Privilege Escalation Mitigations

The permission-chain walk (`permission_chain::walk`) is identical to HTTP and
MCP paths — there is no bypass. Platform handlers never receive more context
than what is derivable from `org_id` + `identity_id`. The `PlatformCallContext`
does not carry decryption keys, config secrets, or the full `AppState`.

`create_template` is atomic: it either succeeds (template immediately active) or
returns `400 TemplateValidationFailed` with structured errors. No draft state is
persisted on failure, so there is no partial-create attack surface.

Platform handlers run in-process on the same Tokio runtime as the HTTP server.
A panicking handler will surface as an `AppError::Internal` at the
`call_action` layer rather than crashing the process (Rust's `catch_unwind`
at the boundary of `tokio::spawn` does not apply here, but panics propagate
up as task failures which Axum turns into 500s).

## Extension Guide

To add a new platform action:

1. **Kernel function** (`services/platform_templates.rs` or a new file):
   ```rust
   pub async fn kernel_my_action(ctx: PlatformCallContext, ...) -> Result<Value, AppError> { ... }
   ```

2. **Handler wrapper** (`services/platform_registry.rs`):
   ```rust
   struct MyActionHandler;
   impl PlatformHandler for MyActionHandler {
       fn call(&self, ctx: PlatformCallContext, params: HashMap<String, Value>)
           -> BoxFuture<'_, Result<Value, AppError>>
       {
           Box::pin(async move { kernel_my_action(ctx, ...).await })
       }
   }
   ```

3. **Register** in `build_registry()`:
   ```rust
   m.insert("my_action".into(), Box::new(MyActionHandler));
   ```

4. **YAML** (`services/overslash.yaml`):
   ```yaml
   my_action:
     description: "..."
     risk: read
     permission: manage_something  # optional — maps to existing anchor
   ```

5. **Test** in `tests/platform_dispatch.rs`.

## Agent Story: Template Authoring Loop

This shows the full self-management loop that `Runtime::Platform` enables.

```
Agent: "I need a weather service. What templates exist?"

→ overslash_call(service: overslash, action: list_templates)
← [{"key":"github","tier":"global"}, {"key":"google-calendar","tier":"global"}, ...]
  No weather template.

Agent: "I'll create one."

→ overslash_call(service: overslash, action: create_template, params: {
    openapi: "openapi: 3.1.0\ninfo:\n  title: Weather\n  key: weather\n...\n
              paths:\n  /forecast:\n    get:\n      operationId: get_forecast\n
              ...{missing required path param declaration}...",
    user_level: false
  })
← 400 TemplateValidationFailed
  errors: [{"code":"unknown_path_param","detail":"path uses {city} but no param named city is declared"}]

Agent: "Fixing the city param..."

→ overslash_call(service: overslash, action: create_template, params: {
    openapi: "...(corrected YAML)...",
    user_level: false
  })
← 200 { "id": "...", "key": "weather", "tier": "org" }

Agent: "Template live. Now I need an API key."
  (future PR: create_secret)

→ overslash_call(service: weather, action: get_forecast, params: {city: "London"})
← 200 { "temp_c": 14, "condition": "Cloudy" }
```

**Key properties of this loop:**
- Validation errors are synchronous 400s — no polling, no draft state to clean up
- The agent retries with corrected YAML; nothing was persisted on failure
- The template is immediately usable in Mode C after a successful `create_template`
- `list_templates` and `get_template` only return `status='active'` rows —
  the draft system is a dashboard-only concern; agents never see drafts

## Audit Log Invariants

Every platform dispatch writes an audit row:
- `action`: `"action.executed"`
- `resource_type`: the service key (`"overslash"`)
- `detail.runtime`: `"platform"`
- `detail.action`: the invoked action key
- `ip_address`: `null` (platform calls have no ClientIp)

## What Ships Next

- `create_secret` / `get_secret_version` — complete the template → secret → call loop
- `resolve_approval` — agents resolving their own sub-agent approvals
- `create_agent` / `create_service` — full identity self-provisioning
