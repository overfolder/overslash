# External MCP Services (Runtime: `mcp`)

**Status:** Shipped
**Date:** 2026-04-23

---

## Context

Third-party tool providers ship their APIs as MCP servers (Linear, Sentry, DeepWiki, Anthropic, Cloudflare docs, etc.). Overslash's goal is to keep being the single gateway agents talk to for permissioned, audited access — whether the upstream is a REST API or an MCP server.

The prior `feat/mcp-hosting` branch tried to bundle this with *hosting* (subprocess runtime, Cloud Run deployment, admin wizard) and grew to 91 commits. This feature is strictly **external** MCP — Overslash as a client of MCP servers the user already trusts and can reach over HTTPS.

## Scope

- A service template can declare `x-overslash-runtime: mcp` with an `x-overslash-mcp` block.
- Agents invoke its tools through `/v1/actions/call` exactly as they would an HTTP action.
- Permission chain, approval bubbling, and audit semantics are unchanged.
- Auth supported: `none`, `bearer` (via the org secret vault), `oauth` (via a provider connection — HubSpot/Slack remote MCP; see below).
- Streamable HTTP transport only (MCP 2025-06-18). No stdio, no subprocess, no hosting.

## Template shape

```yaml
openapi: 3.1.0
info:
  title: Linear
  key: linear_mcp
x-overslash-runtime: mcp
servers: []
paths: {}
x-overslash-mcp:
  url: https://mcp.linear.app/mcp
  auth:
    kind: bearer                     # or: none
    secret_name: linear_api_token    # resolved from org vault
  autodiscover: true                 # default true — enables /mcp/resync
  tools:                             # overrides on top of discovered_tools
    - name: search_issues
      risk: read
      scope_param: team
  # discovered_tools: [ … ]          # populated by /mcp/resync; do not hand-edit
```

### OAuth auth kind

```yaml
x-overslash-mcp:
  url: https://mcp.slack.com/mcp     # or https://mcp.hubspot.com
  auth:
    kind: oauth
    provider: slack                  # an oauth_providers row
    scopes: [chat:write, channels:read, ...]   # superset requested at connect
```

`kind: oauth` authenticates to the upstream MCP server with a live token from a
provider **connection**, not a static vault secret. At call time
`mcp_auth::resolve_headers` resolves the caller's owner connection (D22) for
`provider`, refreshes it if expired (org/BYOC OAuth client), and injects
`Authorization: Bearer <token>` — mirroring HTTP-runtime `ServiceAuth::OAuth`.
This is distinct from the DCR-based resource-server flow in the non-goals below:
it reuses a **pre-configured** provider client, so it works with MCP auth
servers that don't support Dynamic Client Registration (e.g. Slack, HubSpot).
`services/hubspot.yaml` and `services/slack.yaml` are the shipped examples.

- `tools[]` is the admin-authored overlay (risk, scope_param, disabled, description/schema overrides).
- A template's `discovered_tools[]` may ship in-repo (globals) or be authored; it compiles into the template's action set.
- Per-**instance** `discovered_tools` are populated by `POST /v1/services/:id/mcp/resync` (see Resync lifecycle) and stored on `service_instances`; they are overlaid onto the compiled template def at every read path that has an instance in scope (actions listing, the call/validate resolver, and visibility-scoped search).
- Compile merges authored `tools[]` over template `discovered_tools[]` (authored wins per-field) and emits one `ServiceAction` per merged tool; the instance overlay then adds any instance-discovered tool the template doesn't already declare (authored/existing wins). Tools present in YAML but not in `discovered_tools` emit a `mcp_tool_not_discovered` warning (admins can pre-annotate).
- `autodiscover: false` pins the tool set to YAML; every tool must declare `input_schema`.

## Dispatch

```
/v1/actions/call
  → resolve_request  ── svc.runtime == Mcp? ──► ResolvedMeta.mcp_target
                       │                        (skip HTTP URL, secrets, streaming)
                       └── Mode A / Mode C HTTP (unchanged)

  → Layer 1 group ceiling (unchanged)
  → Layer 2 approval chain (force-gated for MCP; no empty-auth bypass)

  → meta.mcp_target.is_some()
       ├── mcp_executor::invoke
       │     ├── mcp_auth::resolve_headers   (secret vault)
       │     └── McpClient.tools_call        (POST JSON-RPC)
       │         → { content, structuredContent, isError }
       └── audit "action.executed" with detail.runtime = "mcp"
```

Response envelope on `ActionResult.body`:

```json
{
  "runtime": "mcp",
  "tool": "search_issues",
  "structured": <structuredContent or null>,
  "content": [ …MCP content blocks, or null ],
  "is_error": false
}
```

Tool-level errors (`isError: true`) return HTTP 200 with `is_error: true` in the envelope — MCP treats tool errors as in-band. Transport/protocol failures map to `AppError::BadGateway` and short-circuit the audit row.

## Resync lifecycle

`POST /v1/services/:id/mcp/resync` — resync is **instance-scoped**. A template
like `telegram` ships no `url`/`secret_name` (one fast-mcp container per
end-user); the instance carries the config needed to reach the server, so
resync must run against an instance, not the template.

- Write-ACL gated, org-scoped by instance id.
- Resolves the effective MCP target with `mcp_resolve::resolve_effective_mcp`
  (shared with the exec path): URL and bearer `secret_name` are instance-wins-
  template-fallback; OAuth mints a live bearer from the instance's connection
  (explicit `connection_id` → `use_default_connection` → owner default), and
  when none exists yet returns `needs_authentication` (the dashboard drives the
  connect popup and retries).
- Calls `tools/list` and writes the response into the **instance's**
  `discovered_tools` + `discovered_at` (RFC 3339) — last write wins per
  instance, so sibling instances don't clobber each other.
- Audited as `service.mcp_resync` (`resource_type: service_instance`).
- On network/auth failure returns `502` with a descriptive message; the
  instance row is left unchanged.

Rejected with `400` when the template is not MCP-runtime or `autodiscover:
false`. (The template-scoped `POST /v1/templates/:key/mcp/resync` route was
retired in favour of this one.)

No discovery runs on `/v1/actions/call` — the resync is the only code path that contacts the upstream for metadata.

## Dashboard

Service detail page, Actions tab:

- When `template.runtime === 'mcp'`: show `Tool | Description | Risk | (pill)` columns; disabled tools render with a muted "hidden" pill.
- A strip above the table shows the MCP URL, the instance's last resync timestamp, and a "Resync tools" button. The button is shown whenever `autodiscover` is on and an effective URL exists (`svc.url || template.mcp.url`) — including global-template instances and OAuth servers, since resync is instance-scoped. For an OAuth instance with no connection the resync returns `needs_authentication`, and the page drives the same connect popup the reconnect button uses, then retries.

No separate "Add MCP server" wizard — admins paste the YAML in the template editor.

## Non-goals / deferred

- Custom-header auth (`kind: header` / `headers`) — schema slot reserved, not implemented.
- MCP OAuth 2.1 **resource-server** support (RFC 9728 discovery, DCR, PKCE, per-upstream connections) — the DCR-based nested-upstream-OAuth path. Note: the `oauth` auth kind above (provider-connection bearer) is implemented and covers OAuth MCP servers that don't support DCR; the discovery/DCR variant remains deferred.
- Stateful sessions + out-of-band enrollment (WhatsApp-style QR pairing, Signal, etc.). Credential persistence stays server-side; Overslash only tracks paired/not-paired when that's added.
- stdio/subprocess MCP servers.
- Hosted MCP runtime.
- SSE streaming of partial tool results (the client accepts SSE frames but only decodes the first data event).
- Dynamic discovery at call time.

## Example

`services/deepwiki.yaml` ships a `kind: none` template pointing at `https://mcp.deepwiki.com/mcp` (DeepWiki's public MCP server, `ask_question` tool). It's the smallest end-to-end example: no auth, three tools, works out of the box.
