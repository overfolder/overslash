# External MCP Services (Runtime: `mcp`)

**Status:** Shipped
**Date:** 2026-04-23

---

## Context

Third-party tool providers ship their APIs as MCP servers (Linear, Sentry, DeepWiki, Anthropic, Cloudflare docs, etc.). Overslash's goal is to keep being the single gateway agents talk to for permissioned, audited access — whether the upstream is a REST API or an MCP server.

The prior `feat/mcp-hosting` branch tried to bundle this with *hosting* (subprocess runtime, Cloud Run deployment, admin wizard) and grew to 91 commits. This feature is strictly **external** MCP — Overslash as a client of MCP servers the user already trusts and can reach over HTTPS.

## Scope

- A service template can declare `x-overslash-runtime: mcp` with an `x-overslash-mcp` block.
- Agents invoke its tools through `/v1/actions/execute` exactly as they would an HTTP action.
- Permission chain, approval bubbling, and audit semantics are unchanged.
- Auth supported: `none`, `bearer` (via the org secret vault).
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

- `tools[]` is the admin-authored overlay (risk, scope_param, disabled, description/schema overrides).
- `discovered_tools[]` is populated by `POST /v1/templates/:key/mcp/resync` from a live `tools/list` call.
- Compile merges the two (YAML wins per-field) and emits one `ServiceAction` per merged tool. Tools present in YAML but not in `discovered_tools` emit a `mcp_tool_not_discovered` warning (admins can pre-annotate).
- `autodiscover: false` pins the tool set to YAML; every tool must declare `input_schema`.

## Dispatch

```
/v1/actions/execute
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

`POST /v1/templates/:key/mcp/resync`

- Write-ACL gated. User-tier rows reachable by their owner; org-tier rows require admin; globals ship their tool list in-repo and cannot be resynced.
- Calls `tools/list` against `mcp.url` with the template's configured auth.
- Writes the response into `x-overslash-mcp.discovered_tools` and stamps `discovered_at` (RFC 3339).
- Audited as `template.mcp_resync`.
- On network/auth failure returns `502` with a descriptive message; the template row is left unchanged.

No discovery runs on `/v1/actions/execute` — the resync is the only code path that contacts the upstream for metadata.

## Dashboard

Service detail page, Actions tab:

- When `template.runtime === 'mcp'`: show `Tool | Description | Risk | (pill)` columns; disabled tools render with a muted "hidden" pill.
- A strip above the table shows the MCP URL, last resync timestamp, and a "Resync tools" button (hidden for `autodiscover: false` or global tier).

No separate "Add MCP server" wizard — admins paste the YAML in the template editor.

## Non-goals / deferred

- Custom-header auth (`kind: header` / `headers`) — schema slot reserved, not implemented.
- MCP OAuth 2.1 resource server support (discovery, DCR, PKCE, per-user connections).
- Stateful sessions + out-of-band enrollment (WhatsApp-style QR pairing, Signal, etc.). Credential persistence stays server-side; Overslash only tracks paired/not-paired when that's added.
- stdio/subprocess MCP servers.
- Hosted MCP runtime.
- SSE streaming of partial tool results (the client accepts SSE frames but only decodes the first data event).
- Dynamic discovery at execute time.

## Example

`services/deepwiki.yaml` ships a `kind: none` template pointing at `https://mcp.deepwiki.com/mcp` (DeepWiki's public MCP server, `ask_question` tool). It's the smallest end-to-end example: no auth, three tools, works out of the box.
