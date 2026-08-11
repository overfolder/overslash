# Agent Self-Management via MCP

**Status:** Draft — future work
**Date:** 2026-04-22

---

## Context

Today the Overslash MCP surface exposes four tools: `overslash_search`, `overslash_call`, `overslash_auth` (a multiplexer over six sub-actions), and `overslash_approve`. In practice only the "use a configured service" path is safe and useful to an agent: discovery + execution + identity introspection. The rest of the surface — creating subagents, creating service instances, requesting secrets, resolving approvals — is self-management, and a self-managing agent combined with Claude Code's auto mode opens real privilege-escalation paths that we don't yet have the gates for.

This document captures the long-term vision for agent self-management without committing to an implementation. It is the follow-up bucket for everything that was pulled out of the MCP surface in the cleanup PR ("MCP call-only"). Short-term the MCP tool list is trimmed to `overslash_search`, `overslash_call`, and a reduced `overslash_auth` (`whoami` + `service_status` only). Self-management happens in the dashboard until this document's pieces land.

---

## Goals

1. Let an agent **create and configure services** for itself within bounds set by Overslash permissions.
2. Let an agent **resolve approvals safely**, distinguishing "I'm approving my own request" (dangerous) from "I'm approving my subagent's request" (delegation, usually fine).
3. Let an agent **introspect the credentials and services it can see**, without being able to inventory the whole org.
4. Compose cleanly with Claude Code's permission-rule engine so auto mode is the right default for low-risk work and always-ask is the right default for high-risk work — without either side having to implement the other's gate.

Non-goal: arbitrary admin actions from an agent. The `overslash` metaservice declares many `platform_actions` (`manage_members`, `manage_api_keys`, `manage_permissions`, etc.) that should remain dashboard-only indefinitely.

---

## Design

### 1. Platform-action bridge on the metaservice

The `overslash` service template declares `platform_actions` but the call route doesn't route them — they exist only as permission labels on REST endpoints. Bridge a subset through `overslash_call` so an agent with the right permission can do e.g.:

```
overslash_call(service="overslash", action="create_service_instance", params={...})
```

Candidate actions to bridge (in rough order of safety):

| Platform action | Bridged? | Notes |
|---|---|---|
| `manage_services_own` | yes | create/update instances the caller owns |
| `manage_services_share` | no (dashboard) | grant an instance to groups — social action |
| `manage_templates_own` | yes | author a template under the caller's scope |
| `manage_templates_publish` | no (dashboard) | promote a template to global/org-wide |
| `create_agents` / `create_subagent` | yes | subagent creation is already a delegated act |
| `manage_members` / `manage_api_keys` / `manage_permissions` | no | identity-and-access plumbing |

The split around `_own` vs `_share`/`_publish` is the important piece: the dangerous half of each permission is the socialisation step, not the creation step. Splitting them at the permission level lets an agent build tooling for itself without being able to publish tooling to humans.

Implementation shape:
- Extend `routes/actions.rs` to recognize `service=overslash` and route to a small internal dispatch table that calls the existing REST handlers with the caller's auth context intact (no re-auth, no credential elevation).
- Each bridged action maps to one existing endpoint. No new endpoints.

### 2. Approval split: self vs downstream

Approvals today have one `overslash_approve` MCP tool and one `POST /v1/approvals/{id}/resolve` endpoint. The resolver is legitimate for downstream approvals and dangerous for self-approvals. Split at **both** layers:

**MCP tools** (tool-name granularity lets Claude Code permission-rule each separately):

- `overslash_approve` — resolves an approval whose requester is a *proper descendant* of the caller's identity. Safe to allow in auto mode. Ancestor approving descendant is the delegation model working.
- `overslash_approve_self` — resolves an approval whose requester is the caller itself. Always ask in Claude Code. May also be outright denied by an admin setting.

**Server classifier** (enforcement — tool dispatch is UX, the security must be server-side):

- Compare `caller.identity_id` with `approval.requester_identity_id`.
- Caller == requester → **self** — accept only through `overslash_approve_self`; even then, caller must hold an explicit `self_approve` permission (dashboard-granted, rare).
- Caller is ancestor of requester → **downstream** — accept through `overslash_approve`.
- Caller is sibling / unrelated → **not_in_your_chain** — reject with structured error.

**Tool-selection ergonomics**: the `PendingApproval` response from `overslash_call` already carries `approval_id`. Extend it to also carry `relationship: "self" | "downstream"` (from the classifier above, evaluated at creation time) so the agent knows which tool to call without trial-and-error. This avoids fatigue approvals where the human is prompted once per mis-chosen tool.

### 3. Identity-scoped secret visibility *(shipped)*

`GET /v1/secrets` now accepts session, MCP bearer, and `osk_` API key
auth uniformly via the `AuthContext` extractor. To make per-identity
visibility well-defined the data model was extended: `secrets` gained
an `owner_identity_id` column (NULL = legacy/org-wide / admin-only),
written on first insert and preserved across versions via COALESCE.

Visibility for a non-admin caller is "the secret's owner is the caller
or any descendant of the caller via `identities.parent_id`" — the same
recursive subtree pattern used by approvals and the identity hierarchy.
Admins (`is_org_admin` flag, or `overslash` ceiling Admin grant) see
every row. The same predicate gates session, bearer, and the
detail/reveal/restore checks.

Two response shapes branch on the calling identity's kind: user-kind
callers see the full `SecretMetadata` (name, current_version,
owner_identity_id, timestamps); agent and sub-agent callers see a
narrow `SecretNameRow` (name, version_count, last_rotated_at) — no
value, no owner identity, no creation timestamp.

The MCP dispatch map's `list_secrets` arm was *not* added — agents
already hold a bearer and can call `GET /v1/secrets` directly. The
broken-promise advertisement was removed at the dispatch layer.

Detail (`GET /v1/secrets/:name`) and reveal/restore stay session-only
in this iteration: detail surfaces `versions[].provisioned_by_user_id`,
which leaks human identities outside the agent's view. Extending the
detail surface with a parallel narrowed shape is a follow-up.

### 4. Claude Code permission-rule recommendations

Claude Code's permission engine matches on tool name and argument patterns, not on server-side risk. Users who want auto mode to Just Work need a recommended config. The Overslash docs should ship an example `settings.json` snippet:

```json
{
  "permissions": {
    "allow": [
      "mcp__overslash__overslash_search",
      "mcp__overslash__overslash_auth(action:whoami)",
      "mcp__overslash__overslash_auth(action:service_status)",
      "mcp__overslash__overslash_approve"
    ],
    "ask": [
      "mcp__overslash__overslash_call(service:overslash)",
      "mcp__overslash__overslash_approve_self"
    ]
  }
}
```

This relies on Claude Code matching argument patterns in permission rules; if the pattern isn't expressive enough (`action:whoami` vs `action:service_status`), the `overslash_auth` multiplexer should be split into one tool per sub-action at the MCP layer. That's a small ergonomic choice, not a design constraint.

### 5. Structured errors from `overslash_call` *(shipped)*

`overslash_call` (and the search/read/auth siblings) surface every recoverable failure as a typed envelope alongside `PendingApproval`:

- `needs_authentication { service, service_instance_id?, connection_id?, auth_url?, missing_credentials?, hint_url? }` — the service has no live credentials yet. Two shapes under one code (D60). **OAuth-backed**: `auth_url` is a gated consent link the agent hands to the user. **Secret-backed** (a template authenticating with vault secrets — `email`, `stripe`, any org template declaring an apiKey scheme — whose instance was never configured): there is no consent page, so no `auth_url`/`provider`; instead `missing_credentials` names the slot keys and `required` config vars that resolved to nothing, and `hint_url` deep-links the dashboard form that fixes it (`/services/{id}?tab=credentials`, or `/services/new?template={key}` when no instance exists). Agents should treat `auth_url` as optional and fall back to `hint_url`. Headless orgs get neither URL but still get `missing_credentials`.
- `reauth_required { connection_id, auth_url, reason }` — refresh token is dead; `auth_url` runs an in-place upgrade against the same connection.
- `missing_scopes { connection_id, missing, upgrade_url, auth_url? }` — connection exists but the action's `required_scopes` aren't all granted; `auth_url` runs incremental-scope OAuth.
- `credential_missing { service?, secret_name, hint_url? }` — a non-OAuth secret the action needs is absent.
- `not_in_your_chain { identity_id, action, reason }` — caller is asking to act on an identity outside their reachable chain. Distinct from `Forbidden` (explicit deny). Wire shape shipped now; emit sites land with the cross-identity ACL work.

**Transport.** Typed envelopes travel as MCP tool **success results with `isError: true`** — not as JSON-RPC errors. Per the MCP spec, JSON-RPC errors are reserved for protocol-level failures (malformed request, unknown method); tool-execution failures use `result: { content, isError: true }` so the model still sees the body. Claude.ai, Claude Code, and Openclaw all forward `result.content` to the model but treat JSON-RPC `error.data` as client-private — using JSON-RPC errors would lose the typed envelope at the model boundary in two of three clients. The existing `pending_approval` flow already used this idiom; typed errors extend the convention by setting `isError: true`.

The pipeline has two halves: the REST layer renders typed envelopes via `AppError::IntoResponse` (`crates/overslash-api/src/error.rs`); the MCP `forward()` helper detects them on non-2xx responses by matching the top-level `error` field against an allow-list of the five spec codes above, then routes the envelope through `rpc_tool_error_response` so the JSON-RPC wrapper carries `result.isError = true` and `result.content[0].text` is the stringified envelope. Every other AppError shape — generic `Forbidden`, `NotFound`, `BadRequest`, etc. — still falls through to JSON-RPC `INTERNAL_ERROR (-32603)`. Adding a new typed envelope is a deliberate two-step move: ship the `AppError` variant, then add the code to the `forward()` allow-list.

Locked in by `crates/overslash-api/tests/mcp_typed_errors.rs` (`needs_authentication` + `reauth_required` over the JSON-RPC `tools/call` surface) and `crates/overslash-api/tests/actions_reauth.rs` (REST `needs_authentication` shape; `reauth_required` REST coverage is at unit-test level via `routes::actions::tests::classify_oauth_*`). The secret-backed `needs_authentication` shape is locked in by `crates/overslash-api/tests/instance_credentials_envelope.rs`, which also pins that the OAuth shape is unchanged and that a template needing no credential still sends unauthenticated.

---

## Trust boundaries

The cumulative effect of this design is two independent gates the agent must cross:

1. **Overslash permissions** — the agent's identity must hold the relevant `manage_services_own`, `self_approve`, etc. scope. Granted by a human in the dashboard.
2. **Claude Code permission rules** — the tool call must pass the session's allow/ask/deny config.

An agent that has the Overslash permission still gets Claude Code's always-ask on dangerous tools. An agent with permissive Claude Code rules still hits Overslash's server-side classifiers. Neither side is a single point of failure — the two gates are meant to disagree, and the stricter one wins.

---

## Out of scope

- Automated permission-grant flows (an agent requesting a new Overslash permission for itself). The human stays in the loop for all permission minting.
- Cross-tenant self-management. Everything above is scoped within a single org.
- Service template *marketplaces* (publishing templates to a public registry). The `manage_templates_publish` permission is dashboard-only precisely to keep this a human act.
