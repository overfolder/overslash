# External execution — services Overslash gates but doesn't proxy

**Status:** Draft — exploratory
**Date:** 2026-05-08

---

## Context

After D14 (kill Mode B, PR #261) and D15 (collapse Mode A into the synthetic `http` service, PR #265), Overslash has a single action-execution pipeline. SPEC §8 names two callable shapes — *Service + defined action* and *Service + HTTP verb* — and the `http` instance is just another service from the ceiling's point of view. There is no longer a separate "raw HTTP" code path or a "connection-based" code path; everything goes through one resolver, one ceiling check, one approval flow, one executor.

This unified pipeline currently has one fixed assumption baked into its tail: **Overslash executes the upstream HTTP request itself.** That assumption is what makes the gateway model possible — secret injection, host bounding, response filters, replay, audit-with-result — and it's the right default for the services we ship today (GitHub, Gmail, Slack, Stripe, etc.).

There's a second shape of integration where the assumption is wrong. Overslash should still own identity, ceilings, permission keys, approvals, bubbling, suggested tiers, and audit — but the *execution* belongs somewhere else:

1. **Agent harness with a computer-use MCP.** The harness already drives the browser/desktop. It wants Overslash to gate each click/type/screenshot — "is this agent allowed to click 'Send' on this page?" — but routing the desktop through Overslash is absurd. The harness performs the action; Overslash decides.
2. **A SaaS service with its own API and its own users.** They want Overslash as the central permissions and approvals plane across their product (delegation hierarchy, "Allow & Remember", human-in-the-loop bubbling, audit) but their API stays in their own stack — Overslash never holds their bearer tokens or proxies their traffic.
3. **High-throughput / latency-sensitive paths.** Some calls (an in-process function call, a local tool, a privileged DB write) shouldn't traverse a public gateway just to ask "may I?". A sub-millisecond local decision cache plus an Overslash policy lookup on miss is the right shape.

The proposal: extend `service_templates` with an `execution` property. The default — `gateway` — is what every shipped template does today. A new value — `external` — declares that this template's actions are **gated by Overslash but executed by the caller**. The action-execution pipeline grows one fork at the end: external templates skip the upstream HTTP step and return a decision verdict; everything before the fork is shared.

This is intentionally framed as a property of the template, not a parallel mode. The upcoming SPEC rewrite in CLAUDE.md (replacing the stale "Three execution modes: Mode A/B/C" line) reflects that direction: there are not modes; there are templates with different execution properties.

---

## Goals

1. Let a caller submit an abstract action — `(service, action, args, context)` — and receive a decision (`allow` / `deny` / `pending_approval`) without Overslash executing anything.
2. Reuse the existing identity, group, permission-key, approval, bubbling, suggested-tiers, webhook/SSE, and audit machinery unchanged.
3. Make it possible for a caller to **report the execution outcome** afterwards, so the audit trail still tells the truth ("agent X did Y at time T, succeeded with code Z").
4. Add this surface as a **natural extension** of `POST /v1/actions/call`, not as a parallel endpoint or a new "mode." The shape is: gateway templates return an executed result, external templates return a decision verdict, both go through the same pipeline.

### Non-goals

- Reimplementing a generic OPA/Rego policy language. Overslash's policy is the existing two-layer model (group ceiling + permission keys); external execution is an entry shape, not a new policy engine.
- Holding caller-side secrets. If Overslash doesn't execute, it doesn't need or want the secret. Secret governance for external-execution services lives on the caller side.
- A push channel that sends decisions to the caller. Decisions are pulled (synchronous `actions/call`) or notified (existing webhook/SSE on approval lifecycle). No new transport.

---

## Two motivating scenarios

### Scenario 1 — Computer-use MCP gating

```
Agent (claude code) ──► Harness ──► Computer-use MCP ──► Browser
                          │
                          │  before each tool call
                          ▼
                       Overslash
                       /v1/actions/call
                       { service: "computer-acme",
                         action:  "click",
                         params:  { target: "button[name=Send]" },
                         context: { url: "https://app.example.com/checkout",
                                    description: "Click 'Send' on checkout page",
                                    screenshot_url: "..." } }
                       → { status: "decided", … } | { status: "pending_approval", … }
```

The first time this agent tries to click `Send` on a checkout page, Overslash files an approval. The user sees the description and screenshot, approves with `Allow & Remember` scoped to `computer-acme:click:button[name=Send]`. Next time, `actions/call` returns `decided` synchronously and the harness clicks. Overslash never holds a screenshot, a DOM, or browser credentials.

### Scenario 2 — External SaaS using Overslash as its perms plane

A SaaS product (call it "Inkwell") has its own API. They want delegation, approvals, "Allow & Remember", audit, and human-in-the-loop bubbling for a handful of high-risk operations — without rebuilding any of it.

```
Inkwell client ──► Inkwell API ──┬──► Overslash /v1/actions/call
                                  │     { service: "inkwell",
                                  │       action:  "publish_post",
                                  │       params:  { workspace_id: "ws_42" },
                                  │       context: { post_title: "...",
                                  │                  audience_size: 18000 } }
                                  │     → decided | pending_approval
                                  │
                                  └──► (on decided) execute the publish in Inkwell's stack
                                  └──► (optional) /v1/actions/decisions/{id}/attest
                                         { outcome: "ok",
                                           detail:  { post_id: "p_xyz" } }
```

Inkwell holds the user → token mapping. Overslash holds identity hierarchy, ceilings, approval state, and audit. The two sides communicate only through `actions/call` and the attestation endpoint.

---

## How well does Overslash already support this?

Surprisingly well in the abstract pieces, weakly in the wiring at the tail.

### Already in place

| Concept | Why it works for external execution unchanged |
|---|---|
| **Permission key format `{service}:{action}:{arg}`** | Already protocol-agnostic. Nothing about it presumes HTTP. `computer-acme:click:button[name=Send]` is a perfectly valid key today. Since D40 the arg may also be labelled (`{label}={value}`), which an external executor gets for free — the label comes from the template's `scope_param`, not from the transport. |
| **Two-layer model (group ceiling + permission keys)** | Both layers operate on keys, not on HTTP shape. |
| **Approval lifecycle** | Create → bubble → resolve → store rule on `Allow & Remember`. None of these steps look at the HTTP request. |
| **Suggested tiers + `derived_keys`** | Already structured strings; the dashboard / platform renders them without seeing the upstream call. |
| **Webhooks / SSE for `approval.created` / `approval.resolved` / `approval.executed`** | Same envelope works; only the `executed` event needs an external-execution variant where the caller — not Overslash — provides the result. |
| **Identity hierarchy + bubbling + auto-bubble timeout** | Pure identity-graph logic, independent of execution. |
| **Risk enum (`read` / `write` / `delete`) + auto-approve-reads** | Already a property of the action, not the HTTP method. Templates can declare it explicitly. |
| **Platform-namespace actions** | Templates with empty `hosts` and actions that omit `method`/`path` are explicitly supported (§9 *Template Validation*). The `overslash` metaservice already uses this. External-execution templates slot into the same shape. |
| **Audit log** | Schema already records `action.executed` independently of the runtime that produced it; external rows just have a different `executor` field. |
| **Single action-execution pipeline (post-D14/D15)** | The resolver, ceiling check, and approval branch are now shared by every callable shape. Adding an "external" tail is one fork at the executor, not a parallel pipeline. |

### Partially in place

| Concept | What needs to change |
|---|---|
| **`POST /v1/actions/call` executor tail** | After ceiling + permission-key check, the executor today always builds and dispatches an outbound HTTP request. The fork is: *if* `template.execution = "external"`, return a `decided` verdict instead of executing. The gating code above the fork is shared 1:1. |
| **`x-overslash-disclose` jq filters** | The projection today is HTTP-shaped: `{ method, url, params, body, resolved }`. For external templates the projection becomes `{ action, params, context }` where `context` is whatever JSON the caller passes. The jq engine itself doesn't care; the projection builder needs an external-execution path. |
| **Replay / `executions` table** | Coupled to "Overslash re-runs the HTTP request 15 minutes after resolve." For external execution, "replay" is the wrong word — there's nothing to replay. The right shape is a **one-shot consume token** that the caller redeems by calling `actions/call` again with `approval_id`. |
| **Secret-injection keys (`secret:{name}:{host}`)** | These exist to gate Overslash's own secret vault. For external execution, Overslash holds no secret for the call, so these keys don't apply. External templates should not generate them. |

### Not in place

- Template marker + validator rules for external execution.
- The `decided` response variant on `actions/call`.
- A consume-token resume model (vs `/call` replay).
- An attestation endpoint for caller-reported outcomes.
- A non-HTTP disclosure projection.
- A way to tag a service template as external-execution so the dashboard doesn't render Connect-credentials UX for it.
- Integration tests for the path.

None of these are deep architectural changes; they're all small, well-scoped additions that lean on existing primitives.

---

## Proposed API

The API surface stays **`POST /v1/actions/call`**. The response carries an additional `status` variant (`decided`) for external-execution services, alongside the existing `executed` and `pending_approval`. There is no `/v1/policy/*` parallel surface.

### `POST /v1/actions/call` against an external-execution template

```jsonc
// Request — same shape as today, plus an optional context block
{
  "service": "computer-acme",            // service instance name
  "action":  "click",                    // action key from the template
  "params":  { "target": "button[name=Send]" },

  // optional — surfaced to humans on approval, fed to disclose filters
  "context": {
    "description":     "Click 'Send' on checkout page",
    "url":             "https://app.example.com/checkout",
    "screenshot_url":  "https://...",
    "extra":           { /* arbitrary caller-supplied JSON */ }
  },

  // optional — caller pre-derives the keys it expects, so Overslash can validate
  // the caller and Overslash agree on what's being authorized
  "expected_keys":  ["computer-acme:click:button[name=Send]"],

  // optional — consume a previously-issued one-shot grant from a resolved approval
  "approval_id":    "apr_..."
}
```

```jsonc
// Response — decided (template.execution = "external" and gating passed)
{
  "status":        "decided",
  "decision_id":   "dec_abc123",         // for attestation
  "derived_keys":  ["computer-acme:click:button[name=Send]"],
  "expires_at":    "2026-05-08T12:35:00Z"  // short, e.g. 60s — caller must act promptly
}

// Response — denied (not approvable, gating failed at ceiling)
{
  "status":        "denied",
  "reason":        "exceeds_ceiling",
  "derived_keys":  ["computer-acme:click:button[name=Send]"]
}

// Response — pending approval (existing variant; identity_id and execution_mode added below)
{
  "status":         "pending_approval",
  "approval_id":    "apr_xyz789",
  "approval_url":   "https://acme.app.overslash.com/approvals/apr_xyz789",
  "derived_keys":   ["computer-acme:click:button[name=Send]"],
  "suggested_tiers": [ /* same shape as today */ ]
}
```

The caller waits for resolution via the existing webhook / SSE / polling channels (§10 *Async Event Delivery*). On resolution, the caller calls `actions/call` again with `approval_id` to redeem the one-shot grant — Overslash returns `decided` with a fresh `decision_id` and burns the one-shot. For `Allow & Remember`, no `approval_id` is needed: the next bare `actions/call` already auto-passes via the stored rule.

For gateway-execution templates, `actions/call` returns `executed` with a `result` field exactly as today. Both variants are status-discriminated: clients sniff `status` to know whether to consume a result, attest a decision, or wait on an approval.

### `POST /v1/actions/decisions/{decision_id}/attest`  *(optional)*

```jsonc
{
  "outcome":  "ok" | "error" | "skipped",
  "summary":  "Sent confirmation email to alice@example.com",
  "detail":   { "post_id": "p_xyz" },
  "error":    { "code": "upstream_5xx", "message": "..." }   // when outcome=error
}
```

Writes the `action.executed` audit row with `executor = "external"` and the caller-supplied result. Idempotent on `decision_id`. Optional — a caller that doesn't attest still gets an `action.decided` audit row from the `actions/call` itself, but the audit timeline won't know whether the action actually ran.

The endpoint lives under `actions/`, not under a separate `policy/` or `decisions/` namespace, because it's the closing event of an `actions/call` lifecycle — same as `approvals/{id}/call` is the closing event of an approval lifecycle today.

---

## Service definition: declaring an external-execution service

External-execution services are templates that explicitly opt out of upstream execution. Overslash needs to know about them — for permission-key derivation, for the approval payload, for discovery — but must reject any attempt to proxy them. The mechanism is a **template-level marker** that the validator, runtime, dashboard, and `overslash_search` all read from one place.

### Template-level flag

`x-overslash-execution: external` on `info` (alias `execution: external`):

```yaml
openapi: 3.1.0
info:
  title: Computer (Acme)
  key:   computer-acme
  description: "Browser/desktop control gated by Overslash, executed by the harness."
  x-overslash-execution: external        # alias: execution: external
# servers, components.securitySchemes, paths — all forbidden when execution: external
x-overslash-platform_actions:
  click:
    description: "Click {target}"
    risk:        write
    scope_param: target
    disclose:
      - label:  Target
        filter: '.params.target'
      - label:  Page
        filter: '.context.url'
  type:
    description: "Type {value} into {target}"
    risk:        write
    scope_param: target
  capture_screenshot:
    description: "Capture a screenshot of the current page"
    risk:        read
```

The default — `x-overslash-execution: gateway` (implicit) — is what every shipped template does today. The marker drives five behaviours when set to `external`:

1. **Validator** rejects `servers`, `components.securitySchemes`, and any `paths.<route>.<method>` block — they're mutually incompatible with `execution: external`. The validator also forbids `secret:` injection metadata on actions (`token_injection`, `default_secret_name`, etc.) since Overslash holds no secret for the call.
2. **Runtime gating**: the action-execution pipeline forks at the executor. Gating, ceiling, approval, audit, bubbling all run identically; the gateway tail (build-and-dispatch HTTP) is replaced by "return `status: decided` with a `decision_id`."
3. **Dashboard**: the template detail page hides every Connect-credentials affordance (OAuth flow, API-key page, secret slots, scope picker). Service creation is a single-step form (name + scope).
4. **Discovery** (`overslash_search`): rows include `execution: "external"` and `auth: { type: "none", connected: true }`. Group ceilings and tier visibility (global / org / user) apply identically.
5. **Audit** rows for actions on these instances carry `execution_mode = "external"`, distinguishing decisions from gateway calls.

The five points piggyback on the existing `platform_actions` mechanism — that path already supports actions with no `method`/`path`, used today by the `overslash` metaservice (§9 *Template Validation*). `execution: external` makes the same shape user-authorable, gives it a runtime identity, and ties it to the validator so a malformed external template fails at promote-time rather than silently behaving like a gateway template with empty hosts.

### Instantiation flow

The lifecycle short-circuits — no credentials means no `pending_credentials` state:

```
gateway service:    create → pending_credentials ──(15-min TTL)──► active | error
external service:   create ─────────────────────────────────────► active
```

`POST /v1/services/from-template` against an external template returns:

```jsonc
{
  "id":            "svc_abc",
  "name":          "computer-acme",
  "template":      "computer-acme",
  "execution":     "external",
  "state":         "active",      // never pending — there's nothing to provision
  "owner_identity_id": "ide_alice",
  "exposed_to_agents": true
}
```

`overslash_auth.create_service_from_template` follows the same shape — no `flow_url` is returned because there's no flow to drive.

Per-instance state holds:

- `id`, `name`, `owner_identity_id`, `exposed_to_agents`, group memberships — same as today.
- **No** OAuth connection, **no** secret slots, **no** `connections.account_email` / `connections.scopes`.
- An optional `metadata` JSON column for display-only annotations (e.g., `{ "workspace_id": "ws_42" }`). Not used for routing or auth — the caller passes any dynamic context as `params`/`context` on each `actions/call`. The metadata is purely so an external-service dashboard row reads as something other than a bare name.

The naming/shadowing model from §9 (*Services (Instances)*) carries over unchanged: `inkwell` resolves to the user's instance if present, falling back to the org's; `org/inkwell` pins to the org instance. Mixing gateway and external services in the same shadow chain is allowed — resolution doesn't care about execution mode.

### Discovery and visibility

`overslash_search` returns external services in the same list as gateway services:

```jsonc
{
  "service": "computer-acme",
  "template": "computer-acme",
  "service_display_name": "Computer (Acme)",
  "execution": "external",
  "action": "click",
  "description": "Click {target}",
  "risk": "write",
  "tier": "global",
  "auth": { "type": "none", "connected": true },
  "score": 0.71
}
```

LLM agents calling these via `overslash_call` (the MCP tool that wraps `actions/call`) see `status: "decided"` exactly like any caller of `actions/call`. The MCP tool description for `overslash_call` documents the `decided` variant alongside `executed` and `pending_approval` — it's not a failure mode, it's the natural answer for actions whose execution is external.

Group ceilings apply unchanged — an external service still requires a group grant on the owner-user, the same way a gateway service does. `auto_approve_level` works on external actions identically, rung for rung.

### Validation rules — explicit list

The template validator (§9 *Template Validation*) gains an execution-aware ruleset. When `info.x-overslash-execution: external`:

| Rule | Severity | Catches |
|---|---|---|
| `external_servers_forbidden` | error | top-level `servers` is non-empty |
| `external_security_schemes_forbidden` | error | `components.securitySchemes` is defined |
| `external_paths_forbidden` | error | any `paths.<route>` is defined |
| `external_action_method_forbidden` | error | a platform action declares `method` or `path` |
| `external_secret_injection_forbidden` | error | a platform action declares `token_injection` / `default_secret_name` / any other secret-vault field |
| `external_disclose_projection` | warning | a `disclose` filter references `.body` or `.url` (the projection only carries `action`, `params`, `context`) |
| `external_no_actions` | warning | the template has no `platform_actions` (instantiable but pointless) |

The marker is template-level only, not per-action. (See "Mixed-execution templates" below for why.)

### Mixed-execution templates *(deferred)*

A single template marking *some* actions external and others gateway is technically expressible (a per-action `execution` field on each platform action). It would let, e.g., a SaaS proxy reads through Overslash and gate writes externally with one template. The validator surface, dashboard UX, search row shape, and `actions/call` response disambiguation all double in complexity. **Recommendation: not in V1.** A caller that wants both behaviours for one upstream defines two templates (`inkwell-read` gateway, `inkwell-write` external) and creates two instances. Revisit if real callers ask.

### Registration handshake *(deferred)*

An external instance arguably wants to advertise *who is going to execute* — e.g., the computer-use harness POSTs `/v1/services/{id}/register { webhook_url, hostname }` so Overslash knows where to send `approval.resolved` events for that instance. **Recommendation: not in V1.** The existing per-identity webhook subscription (§10 *Async Event Delivery*) already routes events to the right caller, and per-service routing isn't well-justified — many harnesses share one identity. If a real need emerges, add `metadata.executor_webhook_url` as an optional instance attribute and let the webhook dispatcher prefer it over the identity-level subscription.

### End-to-end authoring flow

1. Author writes a YAML template with `info.x-overslash-execution: external` and a list of `platform_actions`. No servers, no auth, no paths.
2. `POST /v1/templates` (or the dashboard editor) runs the validator. The external-execution ruleset catches everything malformed before the row is persisted.
3. Promote → `service_templates.status = 'active'`. The template appears in the dashboard's templates list with an "External execution" badge.
4. A user (or an agent acting `on_behalf_of` the user) creates an instance via `POST /v1/services/from-template`. The response is `state: active` immediately.
5. The harness — whatever's actually going to execute — gates each operation through `POST /v1/actions/call`. A `decided` response means proceed; a `pending_approval` means wait.

---

## Approval payload differences

The existing approval payload (§5 *Specificity Tiers*) is already mostly external-execution-ready. Two additions:

```jsonc
{
  "id": "apr_xyz789",
  "execution_mode": "external",          // distinguishes external from gateway
  "context":        { /* whatever the caller passed in actions/call.context */ },
  "disclosed_fields": [
    { "label": "Target", "value": "button[name=Send]" },
    { "label": "Page",   "value": "https://app.example.com/checkout" }
  ],
  /* derived_keys, suggested_tiers, identity, etc. — unchanged */
}
```

`context` is opaque JSON the dashboard surfaces verbatim under a "Context" pane (with the same 1 MB projection cap as `action_detail`). The `disclose` filters from the template run against `{ action, params, context }` and produce the same `disclosed_fields` shape rendered above the Context pane, identical to today.

---

## Resume / consume model

Today the gateway-execution flow is:

```
actions/call → pending_approval → resolve(allow) → executions row (15-min)
            → /approvals/{id}/call → run upstream → result
```

The external-execution equivalent:

```
actions/call → pending_approval → resolve(allow) → consume token (15-min)
            → actions/call(approval_id) → decided → caller runs
                                       └──► actions/decisions/{id}/attest
```

The `executions` table can host both: add an `execution_mode` column with values `gateway` (existing) and `external`. The atomic `pending → executing` transition guards both — for external, `executing → executed` is driven by the redemption call rather than by Overslash dispatching the upstream HTTP.

`Allow & Remember` is identical in both cases — the rule is stored only on a successful execution. For external, "successful execution" means either (a) attest succeeded, or (b) the consume token was redeemed and the caller did not attest within 15 minutes (best-effort fallback — the alternative is requiring attest, which is worse for adoption). This is a knob worth discussing.

---

## Secrets in external execution

By construction, Overslash does not see, hold, or inject secrets for external services. Two consequences:

1. **`secret:{name}:{host}` keys are not derived for external services.** Templates that use the secret pseudo-service can't be `execution: external` — that's a validation rule.
2. **`overslash_auth.request_secret` doesn't apply to external services.** Asking the user for an Inkwell API key only makes sense if Overslash will use the key. For external execution, the caller (Inkwell) handles its own user-credential flow; Overslash is downstream of that.

If an external caller *also* wants Overslash to manage some secrets (e.g., a shared notification webhook URL), they create a separate gateway service for it. Execution boundary is per-service-instance, not per-call.

---

## Identity & auth on the call

`POST /v1/actions/call` accepts the same credentials regardless of the target template's execution mode: an `osk_…` agent key, a user JWT, or an MCP-issued token. The identity drives ceiling resolution and approval routing exactly like today.

For external-SaaS callers (Scenario 2), the SaaS holds an Overslash API key per end user (or per agent the SaaS represents). Mapping `SaaS user → Overslash identity` is the SaaS's job — Overslash sees only the Overslash identity. This is identical to how Overfolder / OpenClaw integrate today, just with `decided`-status responses for the external-execution call paths.

---

## Audit semantics

| Event | When written | Source of truth for "did it happen?" |
|---|---|---|
| `action.decided` | every `actions/call` against an external template | yes — proves Overslash gave a verdict |
| `approval.created` / `resolved` / `executed` | unchanged | unchanged |
| `action.executed` | gateway: when Overslash runs upstream call. external: when caller posts attest. | only on attest for external execution |

A caller against an external template that never calls attest is observable in the audit log as a stream of `action.decided` rows with no matching `action.executed` — this is intentional and visible (a dashboard column "outcome reported?" can surface attestation gaps).

---

## What this changes for existing concepts

- **Webhooks**: `approval.executed` payload gains `execution_mode: "gateway" | "external"`. For external, `result` is whatever the caller attested, or `null` if no attestation.
- **Auto-fired executions**: gateway-mode auto-call (`auto_call_on_approve = true`, §5 *Approval Bubbling*) doesn't apply to external services — there's nothing to auto-fire. Resolved approvals on external services produce a consume token; the caller is responsible for redeeming it.
- **Replay timeouts**: the 15-minute `executions` lifetime applies to the consume token. Past the lifetime, the caller must re-request approval.
- **Specificity tiers**: unchanged. Tiers are derived from keys, which are protocol-agnostic.
- **`overslash_call` MCP tool**: unchanged. The tool returns the `actions/call` response verbatim; agents handle `decided` like they handle `executed`.

---

## Open questions

1. **Is `decided` the right `status` value?** Alternatives: `permitted`, `allowed`, `verdict`. `decided` reads naturally next to `executed`/`pending_approval`/`denied` as "Overslash made a decision and this is it"; the others either conflict with allow/deny semantics or feel jargony. Lean `decided`.

2. **Allow & Remember without attestation.** Is "stored rule on caller redemption, regardless of attest" right? Strict alternative: require attest for the rule to be stored. Strict is safer (a remembered rule reflects a known-successful outcome) but adds friction for callers who can't attest.

3. **One-shot grant vs explicit redeem.** Today's `/approvals/{id}/call` is the redemption for gateway services. For external services, options: (a) implicit redemption inside `actions/call(approval_id)` (proposed above), (b) explicit `POST /v1/actions/decisions/{decision_id}/redeem` followed by execution. (a) is fewer round-trips; (b) makes the lifecycle audit-complete without attestation. Lean toward (a).

4. **Quota / rate-limit accounting.** A `decided` response is cheaper than an `executed` response but still costs Overslash a DB round trip and possibly an approval write. Reuse the existing two-tier rate limit (User bucket + identity cap) without a new bucket, and tag external-execution calls in audit so an org admin can see the mix.

5. **Computer-use UX.** For approvals on a click/type/screenshot, the resolver wants to see *what's on the screen now*, not what the agent is asking to do in the abstract. The right primitive is probably a `context.screenshot_url` field that the dashboard renders inline (we already pass screenshots between agents in other contexts). Decision out of scope of this doc — it's a dashboard/disclosure question, not an execution question.

6. **Closed-loop "nudge" channel.** If a caller is mid-action and the user resolves an approval out-of-band, the caller wants to know now, not on the next poll. The existing SSE stream covers this; document the pattern in agent-facing docs alongside external execution.

---

## Phasing

A reasonable build order:

1. **Template flag + validation** — `x-overslash-execution: external`, validator rules excluding `secret:` keys, dashboard hides Connect UX.
2. **`actions/call` returns `decided` for external templates (no approvals yet)** — happy path: ceiling check + permission-key check, returns `decided` / `denied`. Reuses the same gate code; adds a fork at the executor.
3. **Approval flow on external services** — wire up `pending_approval` response, approval row creation with `execution_mode = external`, dashboard renders external approvals.
4. **Consume token + redeem** — `actions/call(approval_id)` redemption, `executions` row with `execution_mode = external`.
5. **Attestation endpoint** — `POST /v1/actions/decisions/{decision_id}/attest`, audit `action.executed` with `executor = external`.
6. **Disclose filter projection for non-HTTP** — `{ action, params, context }` shape, validator updates.
7. **Documentation** — agent-harness recipe (Scenario 1), SaaS integration recipe (Scenario 2), `SKILL.md` companion section.

Each phase delivers something usable on its own. (1) + (2) is enough for a callback-free read-only policy lookup. (3) + (4) unlocks the approval flow. (5) + (6) closes the audit loop.

---

## Alternatives considered

- **External OPA/Rego sidecar.** Out: duplicates the policy plane Overslash already owns (groups, permission keys, hierarchical bubbling). Doesn't get us the approval UX.
- **Embed Overslash as a library.** Out: defeats the multi-tenant story and the human-in-the-loop dashboard. External execution is the network-protocol equivalent of embedding without giving up centralisation.
- **Reverse model — Overslash calls back into the caller to execute.** Out: requires every caller to expose an inbound webhook target with auth, doubles the failure modes, and inverts the desirable trust direction (caller trusts Overslash, not the reverse).
- **Separate `/v1/policy/decide` endpoint.** Out: introduces a parallel surface for what is one fork at the executor in a single pipeline. Status-discriminated responses on `actions/call` keep the surface unified and the mental model simple — there is one way to call an action, and the response tells you what kind of action it was.
- **Skip the attestation step entirely.** Possible MVP. Audit log just shows decisions, not outcomes. Acceptable for low-stakes deployments; meaningful audit trails want it eventually.

---

## Summary

External execution is a **template property** (`x-overslash-execution: external`), not a parallel mode. The action-execution pipeline gains one fork at the executor: gateway templates dispatch upstream HTTP and return `executed`; external templates skip dispatch and return `decided` with a `decision_id` the caller can attest against. Everything before the fork — identity, ceiling, permission keys, approval, bubbling, suggested tiers, disclosure, audit — is shared. The product surface (computer-use gating, external-SaaS perms plane, local privileged-call gating) is meaningful and difficult to serve any other way, and the implementation cost is small because the policy half of `actions/call` is already protocol-agnostic and is now the only resolver after D14/D15.
