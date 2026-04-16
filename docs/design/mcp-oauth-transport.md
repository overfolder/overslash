# MCP OAuth Transport

**Status:** Approved
**Date:** 2026-04-16
**Supersedes:** the dual-key sections of [`mcp-integration.md`](mcp-integration.md). The stdio surface is kept (see [Surfaces](#surfaces)) but its role is now compatibility, not primary.

---

## Context

Today the MCP server in Overslash is **stdio JSON-RPC** with a **dual-key static config** (`~/.config/overslash/mcp.json`: agent key + user access token + refresh token). The `overslash mcp setup` helper is supposed to mint those credentials but has never worked end-to-end — its `browser_oauth` step (`crates/overslash-mcp/src/setup.rs:114-123`) is a placeholder that asks the user to paste tokens out of a `/settings/mcp` dashboard page that does not exist (`STATUS.md:138`). Worse, the API doesn't even accept the kind of token that helper would produce: `extractors::AuthContext` (lines 87-99) requires Bearer values to start with `osk_`; the JWTs minted by IdP login are only accepted as the `oss_session` cookie. The user-token half of the dual-key model has therefore never been authenticated by the API in any environment.

Meanwhile, the MCP ecosystem has standardised an **Authorization** profile (introduced March 2025, formalised in the 2025-06-18 revision of the MCP spec) layered on **Streamable HTTP** transport. Clients (Claude Code, Cursor, Windsurf, …) handle the entire auth lifecycle themselves: when an MCP server returns `401 Unauthorized` with a `WWW-Authenticate: Bearer resource_metadata="…"` header, the client discovers the Authorization Server, dynamically registers itself ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)), opens a browser for user consent (OAuth 2.1 Authorization Code + PKCE), and uses the resulting access token on every subsequent JSON-RPC request. The "needs authentication" message visible inside Claude Code is exactly this challenge.

We adopt the HTTP+OAuth profile as the **primary** transport, and keep `overslash mcp` as a thin **stdio compat shim** for editors that haven't shipped HTTP MCP yet (modelled after [executor's pattern](https://github.com/RhysSullivan/executor) — a single-purpose stdio-to-HTTP pipe).

## Decision

1. **MCP-over-Streamable-HTTP at `POST /mcp`** in the existing Axum app, behind OAuth 2.1.
2. **Overslash IS the Authorization Server.** JWTs are minted from the existing IdP login flow (SPEC §4); the OAuth endpoints below wrap that flow so MCP clients can drive it without touching the dashboard.
3. **`overslash mcp` is kept as a stdio-to-HTTP shim** for editors that drive MCP via stdio. It holds **one** credential in `~/.config/overslash/mcp.json` (server URL + bearer token, optionally a refresh token) and proxies every JSON-RPC frame to `POST <server>/mcp`. No business logic, no dual credentials.
4. **`overslash mcp login`** replaces `overslash mcp setup`. It runs the standard OAuth Authorization Code + PKCE flow against `/oauth/authorize` (opens a browser, captures the callback on `127.0.0.1`), persists the resulting token, and exits. End-to-end, no paste-tokens.
5. **Identity model: two single-credential modes.** OAuth → user identity (Layer 2 skipped per SPEC §5 *User Identities Skip Layer 2*). Static `osk_…` agent key configured directly on the MCP client (or in the shim) → agent identity (Layer 2 active; approvals via standard webhook/SSE/URL fallback). The previous dual-key co-location problem is dissolved by removing the user-token half from the agent path.
6. **`overslash_approve` stays in the catalog** but is no longer "MCP only". In OAuth/user mode there's no Layer 2 approval to resolve in-band; the tool exists for the inverse case — a user surface resolving approvals raised by an agent identity elsewhere in the org.

## Surfaces

After this change, an MCP-aware editor reaches Overslash through **one** of:

| Path | Editor speaks | Auth | What runs in the editor's MCP config |
|---|---|---|---|
| **HTTP-direct** | MCP Streamable HTTP | OAuth (editor handles it) | `{"url": "https://acme.overslash.dev/mcp"}` (or whatever shape the editor uses for HTTP MCP servers) |
| **Stdio shim** | MCP stdio only | `overslash mcp login` once, then the shim forwards | `{"command": "overslash", "args": ["mcp"]}` |

Both paths terminate at the same `POST /mcp` handler. The shim is a 1:1 frame pipe — it never speaks MCP semantics itself.

## Endpoints

All endpoints live in the existing Axum router. No new crate, no new process.

| Endpoint | Spec | Purpose |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | AS metadata document — `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, supported scopes / response types / PKCE methods. Static JSON keyed off `state.config.public_url`. |
| `GET /.well-known/oauth-protected-resource` | [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | Protected-resource metadata — points clients at the AS metadata above. Returned via `WWW-Authenticate` from `/mcp` on 401. |
| `POST /oauth/register` | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) | Dynamic Client Registration. Open by default (anyone can register a client); UA + IP recorded for audit; admin-revocable. Public clients only — no `client_secret` issued. |
| `GET /oauth/authorize` | OAuth 2.1 §4.1 + PKCE | Authorization endpoint. Validates the client + redirect_uri + PKCE challenge; if the user has no `oss_session` cookie, redirects through the existing IdP login flow first; on success issues an authorization code (single-use, 60s TTL, bound to client_id + PKCE challenge). |
| `POST /oauth/token` | OAuth 2.1 §4.1.3, §4.6 | Token endpoint. Supports `authorization_code` and `refresh_token` grants. Issues an access token (JWT) and a refresh token (opaque, single-use rotation). |
| `POST /oauth/revoke` | [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | Revoke a refresh token (or an access token, treated as best-effort). |
| `POST /mcp` | MCP Streamable HTTP | JSON-RPC body. Requires `Authorization: Bearer …`. Returns `401 + WWW-Authenticate` on missing / invalid token. |
| `GET /mcp` | MCP Streamable HTTP | Optional SSE channel for server-initiated notifications, when the MCP spec requires it for a given capability. Same auth. |

## Token model

**Access token** — JWT, signed with the existing `signing_key`, 1h TTL.

```
{
  "iss":   "<public_url>",
  "sub":   "<identity_id>",
  "aud":   "mcp",
  "org":   "<org_id>",
  "scope": "mcp",
  "iat":   …,
  "exp":   …
}
```

Reuses `services::jwt::Claims` with the `aud` field added. Distinct from the dashboard `oss_session` JWT (which has `aud=session` and a 7-day TTL) so an MCP token cannot be replayed against the dashboard cookie path and vice versa.

**Refresh token** — opaque 32-byte random, base64url-encoded. Stored hashed in a new `mcp_refresh_tokens` table (`id`, `client_id`, `identity_id`, `org_id`, `hash`, `created_at`, `expires_at`, `revoked_at`, `replaced_by_id`). Single-use rotation per OAuth 2.1 BCP — every refresh issues a new refresh token and marks the old one as `replaced_by`; reuse of a rotated refresh token revokes the entire chain (replay-attack mitigation).

**Bearer acceptance.** `extractors::AuthContext` currently rejects any Bearer that does not start with `osk_`. It is extended to **also** accept JWTs whose `aud=mcp` and which validate against `signing_key`. The cookie path is unchanged. The `osk_` path is unchanged.

## Identity model

| Mode | How the MCP client (or shim) authenticates | Identity established | Layer 2 / approvals |
|---|---|---|---|
| **OAuth (default)** | Browser flow at `/oauth/authorize` → access token → `Authorization: Bearer <jwt>` on `/mcp`. | The IdP-authenticated **user**. | Skipped (SPEC §5 *User Identities Skip Layer 2*). |
| **Agent key** | Static `Authorization: Bearer osk_…` on `/mcp`. No OAuth involved. | The **agent identity** the key is bound to. | Active; approvals fire and surface via the standard webhook / SSE / approval-URL path. |

The MCP client (or shim) UX picks the mode by what's configured. Claude Code / Cursor users get OAuth out of the box (zero config beyond entering the server URL or running `overslash mcp login`). Production agents that want gated execution use the agent-key mode.

## `overslash mcp` (stdio shim)

Lifecycle:

1. Read `~/.config/overslash/mcp.json` (`{ server_url, token, refresh_token? }`). Bail with a clear error pointing to `overslash mcp login` if missing.
2. Open `POST <server_url>/mcp` lazily on the first frame; reuse the connection for the rest of the session.
3. Pump frames: stdin line → HTTP body → response → stdout line. Same for SSE notifications when the server pushes them on `GET /mcp`.
4. On `401`: if a refresh token is present, hit `/oauth/token` to refresh and retry once. Otherwise surface the error to the editor (which will typically prompt the user to re-run `overslash mcp login`).

The shim crate (`overslash-mcp`) is reduced to:
- `client.rs` — slimmed: only `mcp_call`, `oauth_refresh`. The previous `Cred` enum and dual-credential plumbing go away.
- `config.rs` — slimmed: one credential, no dual-key.
- `server.rs` — moved into `overslash-api` as the body of the `POST /mcp` handler.

## `overslash mcp login`

A small interactive helper that performs the standard OAuth Authorization Code + PKCE flow against the configured server:

1. Prompt for server URL (or accept it as `--server`); default to whatever's already in `~/.config/overslash/mcp.json`.
2. Hit `GET /.well-known/oauth-authorization-server` to discover endpoints.
3. (First run only) `POST /oauth/register` to obtain a `client_id`. Persist it under `~/.config/overslash/mcp.json` for re-use.
4. Generate a PKCE pair, start a one-shot `127.0.0.1:0` listener, open the user's browser to `/oauth/authorize?response_type=code&client_id=…&redirect_uri=http://127.0.0.1:<port>/callback&code_challenge=…&code_challenge_method=S256&scope=mcp`.
5. On callback, `POST /oauth/token` with the code + verifier. Persist the access + refresh tokens.
6. Print the snippet to drop into the editor's MCP config.

This is what `overslash mcp setup` was always supposed to be. The previous helper's "create-an-agent-while-you're-here" branch (`setup.rs::create_agent_identity`) is dropped — agent enrollment is its own flow (SPEC §4 *Agent Enrollment*) and doesn't need to be co-loaded into MCP onboarding.

## Dynamic Client Registration

`POST /oauth/register` accepts the standard RFC 7591 body (`redirect_uris`, `client_name`, `client_uri`, `software_id`, `software_version`, …) and returns a `client_id` (no `client_secret` — public clients with PKCE only). Persisted in `oauth_mcp_clients` (new table), with `created_at`, `last_seen_at`, `created_ip`, `created_user_agent`, and an `is_revoked` flag for admin cleanup.

**Open registration** is intentional: gating it would defeat the seamless "paste server URL → consent → done" flow that MCP clients implement. The blast radius is bounded — a malicious client still has to get a real user to consent in a real browser, and the AS metadata advertises only PKCE-protected public clients. Registered clients are visible to org-admins in the dashboard (new `Settings → MCP Clients` view, replacing the never-built `/settings/mcp` page) and revocable individually.

## Approval model

- **OAuth/user mode** → no approval surface. The user is their own approver.
- **Agent-key mode** → existing flow: `POST /v1/actions/execute` returns `pending_approval` with an approval URL; the agent surfaces the URL in its response; the user resolves via dashboard / webhook handler / direct REST call. SSE / webhooks / polling all work as documented in SPEC §10 *Async Event Delivery*.

`overslash_approve` (previously "MCP only") becomes a regular user operation in §10. It is callable from any surface where the caller is authenticated as a user identity; the agent-key MCP path cannot use it (an agent cannot approve its own requests, by design).

## Removal list

Surfaces deleted as part of this work:

- `overslash mcp setup` clap subcommand and all of its branches (paste-tokens prompt, `create_agent_identity`, the dashboard URL placeholder).
- The dual-key fields in `~/.config/overslash/mcp.json` (`agent_key`, `user_token`, `user_refresh_token`). Replaced by `{ server_url, token, refresh_token?, client_id? }`.
- `crates/overslash-mcp/src/setup.rs::browser_oauth` placeholder.
- `crates/overslash-mcp/src/setup.rs::create_agent_identity` (replaced by the existing REST `POST /v1/identities` + `POST /v1/api-keys` flow, which the dashboard and any user-mode CLI can drive directly).
- `Cred::User` / `Cred::Agent` distinction in `crates/overslash-mcp/src/client.rs` — only one credential per session now.
- Stale `STATUS.md:138` "Gap — `overslash mcp setup`" item (closed by this work).

Surfaces kept:

- `overslash mcp` subcommand (rebuilt as a stdio↔HTTP shim).
- `crates/overslash-mcp/src/server.rs` — the JSON-RPC dispatcher and tool implementations. Moved behind the `POST /mcp` handler in `overslash-api`.
- `overslash_search`, `overslash_execute`, `overslash_auth` — unchanged.
- `overslash_approve` — kept, no longer "MCP only".

## Migration / compatibility

The dual-key + paste-tokens flow is not in production (`STATUS.md:141` — "Nothing yet. Running locally via Docker Compose"). Nothing to migrate. The new `overslash mcp` shim accepts the same MCP client config snippet (`{"command":"overslash","args":["mcp"]}`) so editor configs need no changes — only the contents of `~/.config/overslash/mcp.json` are different (re-run `overslash mcp login` once).

## Open questions

1. **Scope granularity.** Initially a single scope `mcp` granting full Layer-1 access on the user's behalf. Future: per-service scopes (`mcp:github`, `mcp:read`, …) for "give Claude Code read-only access to my secrets" use cases. Out of scope here.
2. **Multi-tenant AS metadata.** Single AS per Overslash deployment for v1. If/when org-specific issuer URLs become a requirement (e.g. enterprise SSO branding), revisit. The org context is established at IdP login time, not in the AS metadata.
3. **Resource Indicators ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)).** Single audience (`mcp`) for v1 — clients do not need to specify a `resource` parameter. If/when Overslash exposes additional protected resources (e.g. a separate event-stream API surface), per-resource audiences become useful.
4. **Token introspection ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)).** Not exposed. JWT self-validation in `AuthContext` is sufficient; introspection is only useful when the resource server can't verify the AS's signing key, which doesn't apply (same process, same key).
5. **Long-lived "personal access tokens" for headless agents** (e.g. CI). For v1, headless agents continue to use `osk_…` API keys directly — this avoids needing a separate AS flow for non-interactive callers. If demand materialises, OAuth 2.0 Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) is the natural follow-up.

## Implementation order

1. **Schema** — `oauth_mcp_clients` and `mcp_refresh_tokens` migrations.
2. **AuthContext extension** — accept `aud=mcp` JWTs as Bearer.
3. **AS endpoints** — `/.well-known/*` metadata, `/oauth/authorize`, `/oauth/token`, `/oauth/register`, `/oauth/revoke`. Each gets its own integration test.
4. **`POST /mcp`** route delegating to the moved `server.rs` dispatcher. `WWW-Authenticate` challenge on missing / bad token.
5. **Shim rewrite** — strip `Cred::User`, simplify `McpConfig`, implement the stdio↔HTTP pump and refresh-on-401.
6. **`overslash mcp login`** — PKCE + browser + 127.0.0.1 callback listener.
7. **Removal pass** — delete `setup.rs`, the dual-key plumbing, the `/settings/mcp` placeholder.
8. **Docs** — SPEC §3 + §5 + §10 updated in this PR; README + dashboard "MCP Clients" admin view follow.
