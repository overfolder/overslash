# RESTy / scoped / monotype tools over MCP-wrapped services

**Status:** Draft — proposed
**Date:** 2026-07-09
**Draft spec:** [hubspot-resty-draft.yaml](hubspot-resty-draft.yaml)
**Related:** [external-mcp-services.md](external-mcp-services.md) (Shipped), [DECISIONS.md](../../DECISIONS.md) D27

---

## Context

HubSpot's remote MCP (`services/hubspot.yaml`, `x-overslash-runtime: mcp`) exposes a
small, heavily-overloaded tool surface. A single tool, `get_crm_objects`, reads **any**
of ~20 object types (`objectType` discriminator); `search_crm_objects` and
`manage_crm_objects` are the same shape for search and write. This is ergonomic for a
frontier model but works against Overslash's grain:

- **Permissions are coarse.** One action key covers reading contacts, deals, invoices,
  and everything else. `scope_param: objectType` narrows the permission key by object
  type, but there's still no way to grant "read contacts, not deals" as distinct actions.
- **Availability is invisible.** The live hub reports per-type, per-verb availability
  (`get_user_details`): contacts/companies/deals/tickets are full CRUD; quotes / invoices
  / subscriptions are **read-only**; `payment_links` is **write-only**. The overloaded
  tools can't express "you may create a payment link but never read one."
- **Shapes leak.** Callers must know `objectIds` is an array, that writes nest under a
  `createRequest`/`updateRequest` envelope, and that `search_crm_objects` carries a
  semantically-required `chatInsights` telemetry object that has nothing to do with the
  query.

We want a second, higher-level surface: **one small single-purpose tool per
(object-type × operation)** — `get_contact(id)`, `search_deals(query)`,
`update_deal_stage(id, dealstage)` — layered over the same MCP server, without giving up
the raw tools as an escape hatch. This note documents how, and what (if anything) the
runtime needs.

The pattern is not HubSpot-specific: any overloaded MCP-wrapped service (a `list_objects`
with a `type` param, a `graphql` catch-all) can be given scoped tools the same way.

## What the runtime does today

An MCP action resolves to an upstream `tools/call` in
`crates/overslash-api/src/routes/actions/resolve.rs` with two degrees of freedom:

```rust
let tool      = action.mcp_tool.clone().unwrap_or_else(|| action_key.clone()); // name may differ
let arguments = serde_json::to_value(&req.params).unwrap_or(Null);             // args are VERBATIM
```

1. **Name aliasing exists.** `mcp_tool` (authored in `x-overslash-mcp.tools[].mcp_tool`,
   lowered at `openapi/extract.rs:842`) lets the Overslash action key differ from the
   upstream tool name. So `get_contact` can target upstream `get_crm_objects`.
2. **Param defaults are injected.** `apply_defaults` runs at `call.rs:107` (and
   `validate.rs:80`) before resolve, so an `input_schema` property with `default:` is
   filled when the caller omits it — for **every** runtime, MCP included.
3. **But arguments are forwarded verbatim.** There is no rename, restructure, wrap, or
   constant-injection step. Whatever the (defaulted) params map contains is what goes
   upstream.

This splits the goal into two tiers.

## Tier 1 — scoped monotype tools (works today, no runtime change)

Alias the action to a raw tool via `mcp_tool` and pin the discriminator with a param
`default`:

```yaml
- name: search_contacts
  mcp_tool: search_crm_objects
  x-overslash-risk: read
  description: "Search contacts by free text or property filters"
  input_schema:
    type: object
    properties:
      objectType: { type: string, default: "contacts", description: "Locked to contacts — leave unset." }
      query: { type: string }
      # …remaining search_crm_objects params, verbatim…
    required: []
```

This yields a real, per-resource tool with its own name, risk class, permission key, and
disclosure — immediately useful, zero runtime work.

**Limits (why Tier 1 isn't enough on its own):**

- The discriminator stays **visible and agent-overridable** — it's a default, not a lock.
  There is no `const`/`hidden` param flag, and dropping `objectType` from the schema
  entirely means no `ActionParam` carries the default, so nothing is injected.
- Param **names and shapes must stay identical to the upstream tool** (args forward
  verbatim): `objectIds` is still an array, writes still use the `createRequest` envelope,
  and `chatInsights` must still be supplied by the caller or omitted-and-hoped.

So Tier 1 buys scoping and discoverability, not clean REST ergonomics.

## Tier 2 — `x-overslash-transform` (proposed extension)

Add one optional per-action field, **`x-overslash-transform`**: a jq program that rewrites
the agent's (defaulted) params into the upstream tool's `arguments` immediately before
`tools/call`.

> **Naming.** Single word, no underscores, matching the single-word `x-overslash-*`
> extensions (`risk`, `disclose`, `redact`, `runtime`, `mcp`). Chosen over `x-overslash-map`
> and the working-title `x-overslash-arg_map` (which mixed a hyphen and an underscore).

```yaml
- name: get_contact
  mcp_tool: get_crm_objects
  x-overslash-risk: read
  description: "Fetch a single contact by id"
  input_schema:
    type: object
    properties:
      id: { type: string, description: "Contact record id (hs_object_id)." }
      properties: { type: array, items: { type: string } }
    required: [id]
  x-overslash-transform: |
    { objectType: "contacts", objectIds: [ .id ], properties: ( .properties // [] ) }
```

`{id:"123"}` → `{objectType:"contacts", objectIds:["123"], properties:[]}`. The agent
sees a clean scalar `id`; the discriminator is locked (not in the input schema at all);
the array-wrapping is invisible.

### What the transform unlocks

| RESTy tool (agent sees) | Upstream tool | Transform does |
|---|---|---|
| `get_contact(id)` | `get_crm_objects` | scalar `id` → `objectIds:[id]`; inject locked `objectType` |
| `update_deal_stage(id, dealstage)` | `manage_crm_objects` | flat args → nested `updateRequest.objects[0]` envelope; `id \| tonumber` |
| `create_contact(properties)` | `manage_crm_objects` | flat map → `createRequest` envelope; pin `confirmationStatus:CONFIRMED` |
| `create_ticket_from_email(subject, emailId, contactId)` | `manage_crm_objects` | set `source_type:"EMAIL"`; fan optional ids into `associations[]` |
| *(any search)* | `search_crm_objects` | inject `chatInsights` so agents never see HubSpot's telemetry param |

### Runtime seam

One localized change: in `resolve.rs`, replace

```rust
let arguments = serde_json::to_value(&req.params).unwrap_or(Null);
```

with `apply_transform(action, &req.params)` that, when the action carries a transform,
runs it through the **jq engine already used by `x-overslash-disclose`** (input = the
defaulted params object, output = the `arguments` object). Absent a transform → verbatim,
so there is **zero regression** for the raw tools and every other MCP service.

Disclosure/audit already project `{runtime, tool, arguments, service, action}`, so they
naturally observe the **post-transform** arguments — i.e. exactly what is sent upstream,
which is what a reviewer wants to see. The draft's write tools set `x-overslash-disclose`
filters against the transformed `.arguments.createRequest…` accordingly.

## Availability gates the verb set

Per-type/per-verb availability (from `get_user_details`) determines which tools each
resource gets — something the overloaded tools cannot encode:

| Family | Types | Tools to expose |
|---|---|---|
| Full CRUD | contacts, companies, deals, tickets, tasks, notes, calls, emails, meetings, products, line_items | search, get, create, update |
| Read-only | quotes, quote_templates, invoices, subscriptions, carts, users, lists, marketing_events, blog_posts, site_pages | search, get only |
| Write-only | payment_links | create only |
| Gated (`REQUIRES_ACCOUNT_MODIFICATION`) | campaigns, partner_client | none (until account enables) |

## Non-goals

The MCP surface is a **subset** of Breeze's in-app capabilities. These are out of scope
because no MCP tool backs them: **report building**, **workflow authoring**, and
**quote/invoice/subscription creation** (those objects are read-only). The spec should
state these as non-goals so callers calibrate expectations.

## Open question / caveat

`lower_input_schema` (`openapi/extract.rs:880`) "silently ignores nested object
properties," so a Tier-2 flat-envelope input like `properties: {type: object}` is **not**
lowered into a typed `ActionParam` and thus **not arg-validated** — only forwarded. With
`x-overslash-transform`, validation looseness on the pre-transform input is more
noticeable. Decision needed: rely on upstream (HubSpot) validation, or extend
`lower_input_schema` to descend one level for transform-backed actions.

## Rollout

1. **Tier 1 now** — land the `search_*` scoped tools into `services/hubspot.yaml`
   (no runtime work).
2. **Tier 2** — implement `x-overslash-transform` (extractor field in `extract.rs` +
   `apply_transform` at the `resolve.rs` seam + a `template_validation` test), then land
   the `get_*` / `create_*` / `update_*` tools from the draft.
3. Generalize the pattern to other overloaded MCP services as they're wrapped.
