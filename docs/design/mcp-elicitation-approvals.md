# MCP Elicitation as Approval Surface

**Status:** Draft
**Date:** 2026-04-24
**Related:** [`overslash.md`](overslash.md), [`mcp-integration.md`](mcp-integration.md), [`mcp-oauth-transport.md`](mcp-oauth-transport.md), [`agent-self-management.md`](agent-self-management.md)

---

## Context

Overslash approvals today are out-of-band: a tool call lands on the API, a permission gap creates an Approval row, and the Approval is resolved through the dashboard, the `overslash_approve` tool, a Telegram callback, or some other caller-side surface. The MCP-side feedback to the agent is "execution failed, approval `xyz` pending" — the model either polls or moves on, with no protocol-level hook that wakes it up when the approval resolves.

The MCP spec has shipped two primitives in late 2025 that map almost 1:1 onto this problem:

- **Elicitation** (`2025-06-18`, `form` mode; `2025-11-25`, `url` mode added) — a server-initiated request that pauses a tool call until the *client* collects structured input from the *user*.
- **Tasks** (`2025-11-25`, experimental) — `tools/call` becomes call-now-fetch-later: the server returns `CreateTaskResult { status: "working" }`, the model can keep going via an `io.modelcontextprotocol/model-immediate-response` placeholder, and the client polls `tasks/get` / `tasks/result` to resume.

This doc captures (a) what the spec actually says, (b) which clients ship it today, and (c) how Overslash approvals could ride on top.

## Spec answers

### Who provides the elicitation answer — agent or user?

**The user.** The spec is unambiguous: clients **MUST** "provide UI that makes it clear which server is requesting information", **MUST** "respect user privacy and provide clear decline and cancel options", and **MUST** "for form mode, allow users to review and modify their responses before sending". There is no protocol field by which a server can demand "this must be the human, not the model" — but there is also no provision for the agent to silently auto-answer; the spec models elicitation as a UI prompt by default.

In practice, *clients* may add hooks that auto-answer (Claude Code ships `Elicitation` and `ElicitationResult` hooks for exactly this — sysadmins or the user-side config can short-circuit the dialog). That decision lives entirely on the client side; the server cannot prevent it and cannot detect it. For Overslash's threat model this is acceptable — auto-answering an approval is a *client-side* policy choice, equivalent to the user editing `permissions.json`. (See *Trust boundary* below.)

The schema for the request supports flat objects with primitive properties only — `string`, `number`, `integer`, `boolean`, plus enum-via-`enum` (no titles) or enum-via-`oneOf` with `{const, title}` pairs (titled radio choices). Arrays are only allowed as a multi-select wrapper around a primitive `enum`/`anyOf`. Three response actions are returned: `accept` (with `content` matching the schema), `decline`, `cancel`.

### Does elicitation combine with tasks for async answers?

**Yes, two ways.**

1. **`tasks.requests.elicitation.create`.** A client that declares this capability lets the server task-augment the elicitation itself: the elicitation request comes back with `CreateTaskResult { status: "working" }` and the *server* polls `tasks/get` / `tasks/result` for the user's eventual answer. This is the exotic direction; it presupposes a client willing to defer its own elicitation UI. Useful if Overslash is the *requestor* (server) and wants to fire-and-forget into a queued user inbox.

2. **`tasks.requests.tools.call` + nested elicitation (the ergonomic path).** The *client* task-augments the `tools/call`. The server immediately returns `CreateTaskResult { status: "working" }` plus an optional `_meta["io.modelcontextprotocol/model-immediate-response"]` string ("Approval pending — I'll continue when it resolves"). Claude/Codex passes that string back to the model as the tool result and **keeps working on other things**. Behind the scenes the server transitions the task to `input_required`; when the client opens the `tasks/result` SSE stream it sees the elicitation request, presents the dialog (or fires its hook, or routes the user to the dashboard via URL mode), and the answer flows back tagged with `_meta["io.modelcontextprotocol/related-task"] = { taskId }`. The server completes the task and the result becomes retrievable via `tasks/result`.

This second pattern is exactly the flow the user sketched: tool call → "approval pending" placeholder → model keeps working → user resolves out-of-band → model receives the real result later. Critically, the *tool call* is what's task-augmented, not the elicitation — the elicitation is just the resume signal.

3. **`URLElicitationRequiredError` (-32042) + URL mode + `notifications/elicitation/complete`.** A degraded but useful fallback for clients that *don't* support tasks: the tool call returns the `-32042` error pointing at a dashboard URL; the client renders a "click to authorize" prompt, returns `accept` immediately when the user opens the URL, and waits for `notifications/elicitation/complete` before retrying the original `tools/call`. The model still sees a synchronous failure on the first call, but the retry is automated.

### Does Claude Code support this?

Per Anthropic's [`CHANGELOG.md`](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md):

- **2.1.76** — added MCP elicitation support ("form fields or browser URL"), plus `Elicitation` and `ElicitationResult` hooks.
- **2.1.117** — fixed a regression where `elicitation/create` requests auto-cancelled in print/SDK mode when the server finished connecting mid-turn.

Probed empirically against the locally installed **Claude Code 2.1.119** by sniffing `initialize` from the mock server (see Mock implementation below). Capabilities declared:

```
client = claude-code 2.1.119
protocolVersion = 2025-11-25
capabilities = { "elicitation": {}, "roots": {} }
```

| Feature | Status in Claude Code 2.1.119 | Notes |
|---|---|---|
| Protocol version | `2025-11-25` (latest) | Negotiated automatically |
| `elicitation/create` form mode | **Yes** | Empty `elicitation: {}` is spec-equivalent to `{ form: {} }` |
| URL mode (`elicitation: { url: {} }`) | **No, not announced** | Despite shipping protocol 2025-11-25, the URL-mode capability bit is not advertised. Empirically confirmed by forcing the server to send `mode: "url"` anyway: client rejected with `-32602 "Client does not support URL-mode elicitation requests"` — the exact spec-prescribed error. So `URLElicitationRequiredError` and the dashboard-redirect approval pattern are both unreachable today. |
| `Elicitation` / `ElicitationResult` hooks | **Yes** | Per docs; can auto-answer the dialog |
| `notifications/elicitation/complete` retry | **Untestable until URL mode lands** | Server-side calls to `send_elicit_complete` succeed but the client never observes them (we never get past the `-32602`) |
| `tasks.requests.tools.call` augmentation | **No** | Capability not declared. Flow B is not reachable today. Empirically, when a server forces a `CreateTaskResult` reply to `tools/call` anyway, Claude Code 2.1.119 **silently swallows it as if it were an empty `CallToolResult`** — no error returned, no `tasks/get` / `tasks/result` polling, the model sees "tool completed with no output". The task continues to run on the server and eventually completes, but the agent has already moved on. **This is the worst failure mode of the three** — URL mode at least returns a clean `-32602`. |
| `tasks.requests.elicitation.create` | **No** | Same. |
| Behaviour in `--print` (headless) mode | Returns `action: "cancel"` automatically (≤5 ms) | No UI to render the dialog, so the elicitation is dismissed. The 2.1.117 fix only addressed a connect-mid-turn race; the broader "no UI in headless" auto-cancel is intentional. **Critical**: any agent reaching Overslash through headless Claude Code will cancel-by-default unless the user installs an `Elicitation` hook that auto-answers. |

So **Flow A works in interactive Claude Code today** (assuming a human is present to answer); **Flow B and URL mode are blocked** on Claude Code adopting the relevant capabilities. Headless usage is a hard fail unless the user pre-loads an `Elicitation` hook that auto-answers — which is a deliberate per-server policy decision the user must make.

### Does Codex support this?

| Feature | Status in Codex | Source |
|---|---|---|
| `elicitation/create` form mode | **Yes (recent)** — [PR #13425](https://github.com/openai/codex/pull/13425) merged 2026-03-05, makes elicitation a first-class `mcpServer/elicitation/request` in the v2 app-server (previously elicitations were silently auto-declined) | issue #6992, PR #13425 |
| URL mode | Not explicitly confirmed; PR scope is the request/response plumbing | same |
| Boolean approval pattern for modify-tools | **Yes** — Codex itself wraps modify-tools in a boolean elicitation as its approval primitive | `developers.openai.com/codex/mcp` |
| Tasks augmentation | **Not mentioned** | – |

Both major coding agents now do elicitation; neither has publicly committed to client-side tasks support. **Tasks-augmented async is the right end-state, but not the safe assumption today.**

### What about OpenClaw / `mcp2cli`-style bridges?

The relevant question is **OpenClaw as an MCP client** (consuming Overslash's MCP server), *not* OpenClaw exposed-via-MCP. The two roles have opposite plumbing requirements:

| Role | What's needed | Relevant to this doc? |
|---|---|---|
| OpenClaw exposed *via* MCP | OpenClaw runs an MCP server; outsiders call its tools. Server-side spec compliance. | No |
| OpenClaw *as* MCP client (direct, or wrapped via `mcp2cli` / similar stdio bridges) | OpenClaw must speak MCP back at Overslash, which means handling server-initiated requests like `elicitation/create` and `sampling/createMessage`, plus tasks notifications | **Yes** |

OpenClaw today consumes Overslash through the REST meta-tools, not as an MCP client (see story 1 in [`user-stories.md`](user-stories.md)). When/if it grows MCP-client capability — natively or by wrapping the Overslash MCP server through a tool like `mcp2cli` that surfaces tool calls as CLI invocations — its support matrix needs to be evaluated independently:

| Feature | Status in OpenClaw-as-MCP-client | Notes |
|---|---|---|
| `tools/call` over stdio/HTTP | Implementable trivially; this is what `mcp2cli`-style bridges already cover | – |
| `elicitation/create` round-trip | **Depends on the bridge.** A naive `mcp2cli` bridge that only forwards `tools/call` and pipes results back will silently drop server-initiated requests, leaving Overslash hanging until the request times out | If OpenClaw goes this path, the bridge must declare `elicitation` capability *and* relay the request back to OpenClaw's prompt loop |
| URL mode | Trivial if the bridge can print a URL to OpenClaw's chat | – |
| `tasks` augmentation | Same as above — bridge must implement it | – |

**Implication for Overslash:** the elicitation flow described in this doc is gated on the *client* speaking full MCP. For OpenClaw and any other agent reached only through a `tools/call`-only bridge, Overslash must continue to fall back to the existing out-of-band approval surfaces (URL printed in chat, `overslash_approve`, dashboard). The mock server below should also exercise this case — connecting it through a stdio-bridge that only forwards `tools/call` should produce a deterministic "client doesn't declare `elicitation`" failure that Overslash can detect at `initialize` time and switch flows.

## Proposed Overslash flow

Two flows, depending on what the client supports. The *server* implementation is the same; the *behaviour observed by the model* differs based on the client's declared capabilities at `initialize`.

### Flow A — Synchronous elicitation (works today)

Available on Claude Code 2.1.76+, Codex v2 post-merge.

```
1. Claude → POST /mcp  tools/call  service_x.action_y(args)
2. Overslash determines a permission gap. Instead of returning "approval pending",
   it sends elicitation/create back to the client with mode="form":

   {
     "message": "Allow agent <name> to call <service.action> on <resource>?",
     "requestedSchema": {
       "type": "object",
       "properties": {
         "decision": {
           "type": "string",
           "title": "Decision",
           "oneOf": [
             { "const": "allow_once",        "title": "Allow once" },
             { "const": "allow_remember_1h", "title": "Allow for 1 hour" },
             { "const": "allow_remember_perm","title": "Allow & remember (this resource)" },
             { "const": "deny" ,             "title": "Deny" }
           ],
           "default": "allow_once"
         }
       },
       "required": ["decision"]
     }
   }

3. Claude Code shows a dialog. User picks one of the four options.
4. Client returns { action: "accept", content: { decision: "allow_remember_1h" } }.
5. Overslash:
     - "allow_once"        → execute the call, do not modify rules
     - "allow_remember_*"  → upsert a permission rule scoped to the chosen TTL,
                             then execute
     - "deny"              → return tool error, log denial
6. Tool result flows back to the model, Claude continues.

action == "decline"  → tool error "denied by user", same as decision="deny"
action == "cancel"   → tool error "no decision", model can retry or move on
```

Sensitive flows (provider OAuth, credential entry) take URL mode instead — return `URLElicitationRequiredError` pointing at `/dashboard/approvals/<id>`. The dashboard handles the approval, then sends `notifications/elicitation/complete` back to the client and Claude Code retries the original tool call.

### Flow B — Asynchronous via task-augmented `tools/call` (when client opts in)

Triggered when the client's `initialize` declares `capabilities.tasks.requests.tools.call`.

```
1. Claude Code (with tasks capability) → POST /mcp
   tools/call ... params.task = { ttl: 600000 }

2. Overslash detects task-augmented request. Returns immediately:
   {
     "task": {
       "taskId": "approval-<uuid>",
       "status": "working",
       "ttl": 600000,
       "pollInterval": 2000
     },
     "_meta": {
       "io.modelcontextprotocol/model-immediate-response":
         "Approval pending for <service.action>. The user will resolve it; \
          continue with other work and check back."
     }
   }

3. Model gets the immediate-response string as the tool result, keeps working.

4. Overslash creates the Approval row and (optionally) pushes notifications
   through existing channels (Telegram, dashboard, email).

5. Client polls tasks/get every 2s. Once Overslash needs the actual decision
   (default: immediately) it transitions task → input_required.

6. Client opens tasks/result SSE; Overslash sends elicitation/create over that
   stream (form or URL mode, same shapes as Flow A) tagged with
   _meta["io.modelcontextprotocol/related-task"] = { taskId }.

7. User answers (in dialog, hook, or dashboard). Client returns elicitation
   response, also tagged with related-task.

8. Overslash applies the decision, executes the underlying action, transitions
   task → completed (or failed on deny / error).

9. Client's tasks/result completes, real CallToolResult flows back, model
   resumes the original line of reasoning.
```

The two flows share the *same elicitation schema and the same Overslash decision logic*. The branch is entirely on whether the client task-augmented the call. No protocol fork, no separate `overslash_approve_async` tool.

### Trust boundary

The agent can never silently bypass an approval by answering the elicitation itself, because:

1. **The elicitation request is sent to the client process, not back into the model's tool-call loop.** The model never sees the request as a tool call it can answer.
2. **Auto-answer hooks are user-side configuration.** A hook that always returns `decision: "allow_once"` is functionally equivalent to a user-side `permissions.json` rule that pre-authorizes the action — and Overslash already trusts user-side permission configuration. The mitigation is that hooks live in the user's editor config, not in any agent-controllable surface.
3. **Server-side rule reuse stays gated by Overslash's identity model.** "Allow & remember" creates an org/user-scoped permission rule via the existing rule machinery; the rule subsequently applies without re-prompting. This is identical to today's "approve then add rule" UX.

## Open questions / what to verify

1. **Does Claude Code 2.1.76 actually advertise `tasks` capability?** Inspect `initialize` from the mock server. If yes, Flow B works today.
2. **Codex URL-mode support and notifications/elicitation/complete handling.** Probably yes, not confirmed.
3. **`overslash_approve` semantics under Flow A.** Probably becomes redundant for the in-band case but remains useful for cross-identity approvals (a user resolving an approval raised by an agent in a different session).
4. **Rate-limiting on elicitation prompts.** Spec says clients SHOULD; Overslash should also dedupe identical (subject, action, resource) prompts within a short window to avoid prompt-spam if an agent retries a forbidden call.
5. **Hook-based auto-answer policy disclosure.** Should Overslash audit-log when an elicitation is answered without a visible user dialog? The client doesn't tell the server, so this is fundamentally invisible — document the limitation rather than try to detect it.

## Mock implementation

[`test-mcp-elicitation/`](../../test-mcp-elicitation/) at the repo root contains a minimal Python `mcp`-SDK server with a single `show_message(message)` tool that prompts the user via `elicitation/create` (titled `oneOf` choices: Allow once / Allow & remember session / Allow & remember forever / Deny) before logging the message. The companion `handshake_test.py` drives it through stdio as a stand-in MCP client and exercises the accept / decline / cancel / remember / no-capability scenarios.

Empirical findings from the mock (run 2026-04-24, `mcp` SDK 1.27.0, Claude Code 2.1.119):

- **Form-mode elicitation works end-to-end** with `oneOf` + `const` + `title` schemas: the SDK forwards them verbatim, accept/decline/cancel all behave per spec, and `_meta` plumbing for related-task IDs is present.
- **The Python `mcp` SDK does not gate `elicitation/create` on the client's declared capability.** A server calling `session.elicit_form(...)` will send the request even when the client's `initialize` did not declare `elicitation`. The spec says servers **MUST NOT** do this. *Implication for Overslash:* the application layer must inspect the negotiated client capabilities at `initialize` and short-circuit to the existing out-of-band approval surface when elicitation isn't on offer. We cannot rely on the SDK to refuse.
- **URL-mode elicitation rejected with `-32602` by Claude Code 2.1.119**, with the message "Client does not support URL-mode elicitation requests". Tested by running the mock with `--elicit-mode url --force --url https://example.com/overslash-approve`. This is the spec-prescribed rejection — clean and detectable. URL mode (and therefore the dashboard-redirect approval flow + `notifications/elicitation/complete` retry pattern) remains gated on Claude Code adopting `elicitation: { url: {} }`.
- **`CreateTaskResult` silently swallowed by Claude Code 2.1.119** when the server returns one without the client task-augmenting the request. Tested with `--use-tasks --force --task-resolve-after-ms 500`: server declares full `tasks.requests.tools.call` capability, returns a `CreateTaskResult { task: { taskId, status: "working" } }` plus an `io.modelcontextprotocol/model-immediate-response` placeholder, spawns a background resolver that fires elicitation and completes the task. **Claude Code reports "tool completed with no output" to the model and never polls `tasks/get` or `tasks/result`.** No error is surfaced; the call is effectively dropped on the floor. This is *worse* than the URL-mode rejection, because it gives no signal Overslash could detect to fall back. Until Claude Code declares `tasks` support, Flow B must not be attempted.
- **Tasks server-side support in the `mcp` SDK is sufficient.** `CreateTaskResult` can be returned from `@server.call_tool()`; `request_handlers[GetTaskRequest]` etc. accept hand-registered handlers. The mock implements the full lifecycle (working → completed) and a basic `tasks/cancel`. So the *server* side of Flow B is implementable today; what's missing is a client that participates.

See the test directory's README for run instructions and the exact `claude mcp add` / `.mcp.json` setup to wire it into Claude Code.
