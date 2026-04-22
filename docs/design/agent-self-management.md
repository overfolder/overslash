# Agent Self-Management via MCP

**Status:** Draft — future work
**Date:** 2026-04-22

---

## Context

Today the Overslash MCP surface exposes four tools: `overslash_search`, `overslash_execute`, `overslash_auth` (a multiplexer over six sub-actions), and `overslash_approve`. In practice only the "use a configured service" path is safe and useful to an agent: discovery + execution + identity introspection. The rest of the surface — creating subagents, creating service instances, requesting secrets, resolving approvals — is self-management, and a self-managing agent combined with Claude Code's auto mode opens real privilege-escalation paths that we don't yet have the gates for.

This document captures the long-term vision for agent self-management without committing to an implementation. It is the follow-up bucket for everything that was pulled out of the MCP surface in the cleanup PR ("MCP execute-only"). Short-term the MCP tool list is trimmed to `overslash_search`, `overslash_execute`, and a reduced `overslash_auth` (`whoami` + `service_status` only). Self-management happens in the dashboard until this document's pieces land.

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

The `overslash` service template declares `platform_actions` but the execute route doesn't route them — they exist only as permission labels on REST endpoints. Bridge a subset through `overslash_execute` so an agent with the right permission can do e.g.:

```
overslash_execute(service="overslash", action="create_service_instance", params={...})
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

- `overslash_approve_downstream` — resolves an approval whose requester is a *proper descendant* of the caller's identity. Safe to allow in auto mode. Ancestor approving descendant is the delegation model working.
- `overslash_approve_self` — resolves an approval whose requester is the caller itself. Always ask in Claude Code. May also be outright denied by an admin setting.

**Server classifier** (enforcement — tool dispatch is UX, the security must be server-side):

- Compare `caller.identity_id` with `approval.requester_identity_id`.
- Caller == requester → **self** — accept only through `overslash_approve_self`; even then, caller must hold an explicit `self_approve` permission (dashboard-granted, rare).
- Caller is ancestor of requester → **downstream** — accept through `overslash_approve_downstream`.
- Caller is sibling / unrelated → **not_in_your_chain** — reject with structured error.

**Tool-selection ergonomics**: the `PendingApproval` response from `overslash_execute` already carries `approval_id`. Extend it to also carry `relationship: "self" | "downstream"` (from the classifier above, evaluated at creation time) so the agent knows which tool to call without trial-and-error. This avoids fatigue approvals where the human is prompted once per mis-chosen tool.

### 3. Identity-scoped secret visibility

Today `GET /v1/secrets` uses the dashboard `SessionAuth` extractor and the MCP dispatch map advertises `list_secrets` but the call 401s — a broken promise. The right shape is not to remove the feature but to scope it:

- Accept bearer on `GET /v1/secrets` in addition to session.
- When called with a bearer, return only secret *names* visible to the calling identity — i.e. the intersection of the org's secrets with the permission rules in the caller's identity chain.
- Never return values, regardless of auth.

The visibility query is non-trivial because Overslash secrets today are org-wide rows; "which identity can see which" is derived from permission rules at execution time. The filtering logic should reuse whatever `get_current_secret_value` uses to decide access, not reimplement it. Prior work on this codepath is the baseline.

### 4. Claude Code permission-rule recommendations

Claude Code's permission engine matches on tool name and argument patterns, not on server-side risk. Users who want auto mode to Just Work need a recommended config. The Overslash docs should ship an example `settings.json` snippet:

```json
{
  "permissions": {
    "allow": [
      "mcp__overslash__overslash_search",
      "mcp__overslash__overslash_auth(action:whoami)",
      "mcp__overslash__overslash_auth(action:service_status)",
      "mcp__overslash__overslash_approve_downstream"
    ],
    "ask": [
      "mcp__overslash__overslash_execute(service:overslash)",
      "mcp__overslash__overslash_approve_self"
    ]
  }
}
```

This relies on Claude Code matching argument patterns in permission rules; if the pattern isn't expressive enough (`action:whoami` vs `action:service_status`), the `overslash_auth` multiplexer should be split into one tool per sub-action at the MCP layer. That's a small ergonomic choice, not a design constraint.

### 5. Structured errors from `overslash_execute`

Related but separate from self-management: today when an OAuth connection needs reauth, the MCP `forward` returns a string-wrapped 400 that ends up as "secret not found". For agents to self-serve recovery, `overslash_execute` needs to surface structured error types alongside `PendingApproval`:

- `reauth_required { connection_id, reauth_url, reason }`
- `missing_scopes { connection_id, missing, upgrade_url }` *(already structured)*
- `credential_missing { service, hint_url }`
- `not_in_your_chain`

This work predates self-management but unblocks much of it: an agent that can distinguish "I don't have this permission" from "the connection is dead" knows whether to ask for a permission grant vs nudge the user to reconnect.

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
