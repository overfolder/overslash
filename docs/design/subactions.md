# Subactions: content-classified variants of one action

**Status:** Implemented
**Date:** 2026-10-27
**Supersedes:** [hubspot-resty-tools.md](hubspot-resty-tools.md) (Tier 2 `x-overslash-transform`)
**Related:** SPEC §9 *Template Definition*, D42 (dynamic SQL risk, the other call-time classifier)

## Problem

HubSpot's remote MCP exposes `manage_crm_objects`, which creates or updates *any*
CRM object, up to ten per call. Before this change, every approval for it read:

> Create or update CRM records (HubSpot)

It said nothing about which record was written, or what type it was. One permission
key, `hubspot:manage_crm_objects:*`, covered contacts, deals and tickets alike. The
gateway never looked inside the arguments, and its description grammar couldn't
index arrays, so it couldn't name anything in `createRequest.objects[0]`.

## Shape

```yaml
- name: manage_crm_objects
  risk: write
  description: "Create or update CRM records"
  subactions:
    each: >-                                   # jq: one item per unit of work (default `.`)
      (.createRequest.objects[]? | . + {op: "create"}),
      (.updateRequest.objects[]? | . + {op: "update"})
    variants:
      - name: create_contact
        match: '.op == "create" and .objectType == "contacts"'   # jq predicate on one item
        description: "Create a HubSpot contact from a flat property map."
        verb: create
        phrase: "contact[ '{item.label}']"
        vars: { label: '.properties.email' }   # jq on the item → {item.label}
        disclose:                              # filters see `.items`
          - { label: Contacts, filter: '[.items[].label] | join(", ")', primary: true }
        # risk / scope_param / redact / timeout_ms / required_scopes as on an action
        input_schema: { … }                    # opt-in: callable as `create_contact`
        transform: '{createRequest: {objects: [{objectType: "contacts", properties: .properties}]}}'
```

## Semantics

- **Items.**
  - `each` decides what an item is. The author tags each item with any context
    `match` needs that the object doesn't carry itself, such as `op` above.
  - Without `each`, the whole call is one item. That is right for tools with a
    top-level discriminator. A `match` that iterates arrays with no `each`
    raises a lint warning (`subactions_match_without_each`).
- **One jq evaluation.**
  - `each`, every `match` and every `vars` expression compile into a single
    program (`SubactionSpec::classifier_program`).
  - A predicate counts as matched if any of its outputs is truthy. One that
    emits nothing is a non-match, never an item that drops out of the array.
  - An error or a timeout in that program gates the whole call as the parent.
- **Keys.**
  - A matched item mints `{service}:{parent}/{variant}:{arg}`, with the arg
    taken from the variant's `scope_param` resolved against the item.
  - The call needs every key. Any unclaimed item adds the parent's key.
  - `match_forms` also yields the parent form, so `hubspot:manage_crm_objects:*`
    covers every variant and existing grants keep working.
  - The approval ladder widens a variant to its parent before the whole
    service.
- **Risk.** A call's risk is the highest risk among its matched variants, plus
  the parent's risk when any item is unclaimed. A layer's risk clamp on the
  parent raises every variant. A clamp on a callable variant raises its entry
  in the spec.
- **Descriptions.** The first applicable rule wins:
  1. the block's `summary`, which can `enumerate` over all items, with
     `{item.verb}`, `{item.phrase}` and `{item.subaction}`;
  2. a variant's `summary`, when every item fell into that variant;
  3. the default composition: items grouped by `verb`, written as
     `<Verb> <English list of phrases>`, with clauses joined by `; `.

  The grammar adds `{item.<path>}`, `{count}` and `{enumerate(<template>)}` to the
  existing `{param}` / `[optional]` grammar. Rendered lists are parked behind
  private-use markers while the outer template is interpolated, so caller data
  is never re-read as grammar.
- **Disclosure.**
  - Each variant's filters are appended to the parent's. The variant's items are
    bound in as `.items` through a jq literal, not added to the shared
    projection.
  - The projection is what gets persisted, and a copy of the arguments there
    would sit unredacted beside the redacted original.
- **Callable variants.**
  - Compile emits an action under the variant's name, carrying the parent's
    routing fields and the variant's lowered params.
  - At call time the variant's own arguments are validated first. Then
    `transform` rewrites them into the parent's params, and they are validated
    again as the parent.
  - The rewritten call must classify entirely as that variant, so its keys,
    description and disclosure are identical to the equivalent raw call.
  - A collision with any other action key is a compile error.
- **Not on `risk: dynamic`.** That action is already classified per call by the
  SQL policy, and two classifiers would give two answers to "what risk is this".

## Where it runs

- **Classification.** `routes/actions/subactions.rs`, called in the same place
  from `/call` (after `resolve_request`, so display resolvers have run) and from
  `/validate`. Both share `prepare_args`, so the two cannot drift.
- **Pure rendering and matching.** `overslash_core::subactions` holds the
  renderer, and `permissions::matching` the matching.
- **Parsing and emission.** `openapi/extract/subactions.rs`.
- **Template checks.** `template_validation/core/subactions.rs` lints the
  labels. `routes/templates` syntax-checks every jq fragment and the composed
  program.

## Not done

- Classifier jq is compiled per call, like every other template jq. Caching
  compiled programs is a general follow-up, not one specific to subactions.
- `get_crm_objects` and `search_crm_objects` already scope by `objectType`
  through `scope_param` and are left alone. Splitting them would need the
  variants to keep that `scope_param` so existing `objectType=` grants keep
  matching.
