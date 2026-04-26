# MCP Integration Design

**Status:** WIP  
**Date:** 2026-04-05

---

## Context

Overslash exposes a REST API as its canonical interface. To maximize adoption across the AI agent ecosystem, we want to support three integration surfaces:

1. **REST API** — production systems, platform integrations (already built)
2. **CLI (`ovs`)** — developer tooling, shell-capable agents
3. **MCP server** — native integration with MCP clients (Claude Code, Cursor, Windsurf, etc.)

All three are thin wrappers over the same backend. This doc focuses on the MCP server design, specifically the **approval flow problem** — how users approve agent actions inline without leaving their editor/terminal.

---

## The Approval Problem in MCP

Overslash's trust model: **agents cannot approve their own requests.** Approvals must come from a credential with authority over the requesting identity (a user, or an ancestor agent with sufficient permissions).

In the MCP context:
1. Claude Code calls `overslash_call` via MCP server
2. MCP server calls Overslash REST API with the **agent's API key**
3. Overslash returns `{ "status": "pending_approval", "approval_id": "apr_abc123" }`
4. ...the agent cannot resolve this with its own key

### Options Considered

#### Option A: Web redirect

Return the approval URL in the tool result. User opens browser, logs in, approves.

```
⚠️ Approval required: "Create pull request on overfolder/backend"
Approve here: https://acme.overslash.dev/approvals/apr_abc123
```

MCP server polls until resolved, then retries the action.

- **Pros:** Trust model intact. Works with zero additional design.
- **Cons:** Breaks flow. Context switch to browser. Poor DX.
- **Verdict:** Fallback path, not primary flow.

#### Option B: Dual-key MCP server (recommended)

The MCP server holds **two credentials**:
- **Agent API key** — for executing actions as the agent identity
- **User token** — for resolving approvals on the user's behalf

The user IS sitting at the terminal. The MCP server runs on their machine. Having user credentials there is natural and doesn't violate the trust model — the agent key calls, the user key approves. Two separate identities.

- **Pros:** Inline approval. Trust model intact. Best DX.
- **Cons:** Requires two-credential setup. User token needs refresh logic.
- **Verdict:** Primary flow.

#### Option C: MCP server runs as user identity directly

Skip agent identity — MCP server authenticates as the user.

- **Verdict:** Rejected. Defeats the purpose of the identity hierarchy. No audit distinction between "Claude Code on my laptop" and "Henry the production agent."

---

## Recommended Design: Dual-Key MCP Server

### Setup Flow

```
ovs mcp setup
  → Opens browser for user login (one-time OAuth, stores refresh token)
  → Prompts for agent API key (or creates a new agent identity)
  → Writes MCP server config with both credentials
```

Config stored at `~/.config/overslash/mcp.json`:
```json
{
  "server_url": "https://acme.overslash.dev",
  "agent_key": "ovs_acme_claude-code_...",
  "user_token": "ovs_user_alice_...",
  "user_refresh_token": "ovs_refresh_..."
}
```

### MCP Tools

| Tool | Credential Used | Purpose |
|------|----------------|---------|
| `overslash_search` | agent key | Discover available services and actions |
| `overslash_call` | agent key | Call an action (may return `pending_approval`) |
| `overslash_auth` | agent key | Initiate OAuth connection or manage secrets |
| `overslash_approve` | **user token** | Resolve a pending approval inline |

The fourth tool (`overslash_approve`) only exists in the MCP context. REST callers handle approvals their own way (webhooks, dashboard, platform UX).

### Inline Approval Flow

```
1. LLM calls overslash_call({service: "github", action: "create_pull_request", ...})

2. MCP server → POST /v1/actions/call (agent key) → 202 pending_approval

3. MCP server returns tool result:
   {
     "status": "pending_approval",
     "approval_id": "apr_abc123",
     "description": "Create pull request on overfolder/backend",
     "suggested_tiers": [
       { "tier": "exact",  "description": "Create PR on overfolder/backend" },
       { "tier": "action", "description": "Create PR on any repo" },
       { "tier": "service","description": "Any GitHub action" }
     ],
     "web_url": "https://acme.overslash.dev/approvals/apr_abc123"
   }

4. LLM sees this, asks user:
   "Overslash needs approval: Create pull request on overfolder/backend.
    Allow once, allow & remember for this repo, or allow all GitHub actions?"

5. User responds: "allow & remember for all repos"

6. LLM calls overslash_approve({
     approval_id: "apr_abc123",
     resolution: "allow_remember",
     remember_keys: ["github:create_pull_request:*"],
     ttl: null
   })

7. MCP server → POST /v1/approvals/apr_abc123/resolve (user token) → 200 OK

8. MCP server retries original call → 200 OK → returns result to LLM
```

### Why This Works Well

- **Trust model intact**: Agent key calls, user key approves. Two identities, proper separation.
- **No context switch**: Approval happens inline in the conversation. No browser.
- **Natural language specificity**: The user says "allow for all repos" and the LLM maps it to the right suggested tier. Better than clicking radio buttons.
- **"Allow & Remember" reduces friction over time**: First call to a new service needs approval. Subsequent calls auto-approve. The MCP experience improves the more you use it.
- **Web URL as fallback**: If the user prefers, they can always open the web approval page instead.

---

## Integration Priority

| Surface | Priority | Rationale |
|---------|----------|-----------|
| REST API | ✅ Done | Canonical interface. Everything else wraps this. |
| CLI (`ovs`) | **Next** | Developer tooling. Shell-capable agents. Fastest path to "trivial to use." The CLI client library becomes the MCP server's backend. |
| MCP server | **After CLI** | Three tools + `overslash_approve`, thin wrapper. Once CLI/client lib exists, this is a small project. Distribution channel for Claude Code, Cursor, etc. |

---

## White-Label Considerations

For platforms like Overfolder that white-label Overslash, the MCP server is **not used** — the platform's controlplane calls the REST API directly and handles approvals in its own UX (Telegram buttons, web dashboard, etc.).

The MCP server is for **direct Overslash users**: developers using Claude Code, Cursor, or other MCP clients who want to connect to overslash.dev (or a self-hosted instance) without going through a platform.

Two modes:
- **Branded mode** (direct users): Tools show as `overslash_search`, `overslash_call`, etc.
- **White-label mode** (platform-embedded): The platform wraps Overslash's REST API behind its own tool names and UX. MCP server not involved.

---

## Open Questions

- **Token refresh in MCP server**: The user token will expire. Should the MCP server silently refresh using the stored refresh token, or prompt the user to re-authenticate? (Likely: silent refresh, with fallback to browser re-auth if refresh fails.)
- **Multi-org support**: If a user belongs to multiple orgs, should `ovs mcp setup` support profiles? (Likely: yes, `ovs mcp setup --profile work` → separate config.)
- **Approval timeout**: If the user ignores the approval in Claude Code, Overslash's approval has its own TTL/expiry. The MCP server should communicate this. ("This approval expires in 10 minutes.")
- **Batched approvals**: If an agent needs multiple approvals in sequence (e.g., read calendar + send email), should the MCP server batch them into a single user prompt? (Likely: yes, better DX.)
