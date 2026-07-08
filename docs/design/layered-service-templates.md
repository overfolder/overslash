# Layered service templates — one primitive for forks and catalog overlays

**Status:** Draft — proposed (buildable spec). Supersedes the earlier "org catalog overlay" draft.
**Date:** 2026-07-08
**Related:** [Feedback 2026-07-08 — refocus/adapt-to-corporate](../feedback/2026-07-08-refocus-adapt-to-corporate.md), SPEC §9 (Service Templates and Services), PR #435 (curated catalogs + hard instantiation gate), PR #431/#432 (`use_default_connection`), #100 (three-tier template registry), #418/#416/#428 (remote-MCP autodiscovered services)

> **Handover note.** This document is written to be built by an implementer with no prior context. It settles the model; §"Implementation map" points at the code that changes. Decisions were fixed in a design interview — where a plausible alternative was rejected, the rejection is stated so it isn't relitigated.

## Glossary (canonical vocabulary)

The words below are load-bearing; a reader with none of the design conversation depends on them being crisp.

| Term | Meaning |
|---|---|
| **template** | The **effective, resolved** blueprint an agent instantiates. Public / API concept, unchanged. `template = resolve(base, layer)`. |
| **layer** | One stored `service_templates` row — the unit an admin/user edits. |
| **`extends`** | The field on a layer. `NULL` → a **standalone layer** (holds a full OpenAPI doc; this is today's org/user "fork"). Set to a base template key → a **derived layer** (holds a *delta*). Single-inheritance: 0 or 1 base, never many. |
| **standalone layer** | A layer that `extends` nothing. Full OpenAPI doc. Retires the informal word "fork". |
| **derived layer** | A layer that `extends` a base template. Stores a *delta*, not a full doc. Retires the informal word "overlay". |
| **delta** | A derived layer's stored content. Two halves: **masks** (restrictive — hide/clamp/relabel over the base's own actions) and **extensions** (expansive — add new actions/hosts). |
| **the fold** | The resolution function `resolve(layer) = apply(layer.delta, resolve(layer.extends))`, base case `resolve(standalone) = openapi`. The centerpiece of the model. |

---

## 1. Why

Two of the corporate-refocus asks are the same missing primitive:

1. *"Orgs override/whitelist tools in their catalog while still receiving upstream Overslash updates; must work with autodiscover too."*
2. *"Share prefilled services without sharing an instance+connection — each user does their own OAuth."*

Today an org has two levers over a shipped **global** template, and neither fits:

- **Catalog gate** (`orgs.enabled_global_templates`, #435): template-granularity allow-list, enforced at discovery + instantiation. Cannot express "GitHub, but only these 4 actions."
- **Fork to an org template** (SPEC §9 org tier): a full copy with per-action control — but a **copy**, so it stops tracking upstream, duplicates maintenance, and drifts. Every fork is also an unreviewed capability grant.

The design collapses fork and overlay into a **single layered primitive**. A fork becomes a *standalone layer*; an overlay becomes a *derived layer* holding a sparse *delta* over a live base. The delta both curates (restrictive masks) and, for those who own the API, extends (expansive additions) — so one mechanism spans "trim what Overslash ships us" through "author our own API," with a clean line between them.

**The point of the whole exercise is that `extends` is a live pointer, not a copy** — a derived layer keeps tracking its base as upstream evolves. That is the property forks cannot have.

---

## 2. The primitive & data model

A **layer** is a `service_templates` row. Its `extends` field decides its nature:

- **standalone** (`extends IS NULL`) — holds a full OpenAPI doc in `openapi`. (Today's org/user template.)
- **derived** (`extends` set) — holds a `delta` over the base named by `extends`.

Global (Overslash-shipped) templates remain an **in-memory registry loaded from `services/*.yaml`** — they are *not* rows (that's why `extends` holds a base **key**, resolved against the registry, and is **not an FK**). Org and user layers are `service_templates` rows as today.

### Migration 095 (`095_layered_service_templates`)

```sql
ALTER TABLE service_templates ADD COLUMN extends text;          -- base template key; NULL = standalone
ALTER TABLE service_templates ADD COLUMN delta   jsonb;         -- derived-layer content; NULL = standalone

-- A row is a base doc XOR a delta over a base.
ALTER TABLE service_templates
  ADD CONSTRAINT service_templates_layer_shape
  CHECK ((delta IS NULL) = (extends IS NULL));
```

- **Absorb the existing tier now.** Every existing `service_templates` row is already a valid **standalone layer** — `extends`/`delta` backfill to `NULL`, `openapi` stays authoritative. No data transform, because we are pre-GA with essentially zero production forks. This is the cheap moment; post-launch it would not be.
- **`openapi` on a derived layer** is `NULL` today, but the `CHECK` deliberately does **not** forbid it: it is **reserved as an optional denormalized cache** of the resolved template (future materialization). If ever written, it is produced by the fold and invalidated whenever the delta *or* the base changes.

> **Rejected — a separate `service_template_overlays` table (the original draft).** That keeps fork ≠ overlay, i.e. rejects the unification. One table with `extends`/`delta` is the whole point.
> **Rejected — reusing the `openapi` column to hold the delta (flip meaning on `extends`).** Distinct columns make the JSON self-describing (a delta is structurally not an OpenAPI doc) so nothing downstream branches on `extends` to know how to read the blob.

---

## 3. Resolution — the fold (centerpiece)

```
resolve(layer):
    if layer.extends is NULL:              # standalone
        return layer.openapi
    base = resolve(lookup(layer.extends))  # recursive; global key → registry, else another layer
    return apply(layer.delta, base)
```

Every mask op in `apply()` operates on the **base's already-resolved effective surface**, never the raw root. This yields the load-bearing invariant:

> **Containment:** for the restrictive (mask) half of any delta, `resolve(child) ⊆ resolve(base)`. A derived layer can never widen past its base.

### Chains

`extends` may target a layer at the **same tier or higher** in `global > org > user` — you extend "up", toward global. `global → org → user` chains are allowed; a layer never extends downward. The recursive fold handles arbitrary depth unchanged.

**Payoff:** a user layer extending an org layer inherits the org's curation as a **hard ceiling for free** — an employee's personal customization can never re-expose what the org hid.

Guardrails on `extends` writes:
- **cycle detection** — same-tier extends make `A → B → A` possible; walk the chain and reject cycles.
- **target validation** — target must exist, be same-or-higher tier, and be visible/owned by the extender: a user may extend a global, an org-namespace layer, or **their own** user layers — never another user's private layer; an org may extend a global or another org-namespace layer.

### Live pointer

**`extends` is a live pointer, not a snapshot.** Editing a base (or Overslash shipping a new global version) propagates immediately to every descendant's effective template. This is the entire reason for layers over forks, and it matches existing precedent (`inherit_permissions` is a live pointer). Cost: **cache invalidation cascades** — invalidating a layer must invalidate the resolved-template cache of every layer that transitively extends it (the same cascade the reserved `openapi` materialization would need).

> **Rejected — merge-then-apply** (combine all deltas field-wise, apply once). Counterexample: org sets an allowlist of 5 actions; a child sets a broader visibility → field-wise merge lets the child's choice win and re-expose everything, breaching containment. The fold (apply each layer to the previous layer's *output*) is what makes containment structural. You **may** materialize/flatten as an optimization, but the flattened result must equal the fold — never a field-wise merge.
> **Rejected — snapshot `extends`.** Recreates fork drift: a layer frozen against last quarter's base misses upstream security tightening.

---

## 4. Delta vocabulary

A delta has a **mask** half (restrictive) and an **extension** half (expansive). A single layer may carry both.

```jsonc
delta = {
  // ---- template-level masks ----
  "hidden": false,                     // drop the whole template from the org catalog
  "display_name": "GitHub (Acme)",     // relabel
  "description": "…",

  // ---- action masks (restrictive; monotonic; order-independent) ----
  "allowlist": ["create_pull_request", "list_pull_requests"],  // ∩ keep only these
  "denylist":  ["delete_repo"],                                 // \ drop these
  "action_patch": {
    "merge_pull_request": {
      "risk": "delete",                // clamp UP only (write→delete ok; delete→write rejected)
      "disclose": [ /* additive disclose specs */ ],
      "display_name": "Merge PR (requires approval)",
      "description": "…"
    }
  },

  // ---- extensions (expansive; capability-adding) ----
  "extensions": {
    "actions": { "archive_repo": { /* full OpenAPI action fragment */ } },
    "hosts":   ["ghe.acme.internal"]
  }
}
```

### Masks — restrictive, provably safe in chains

- **Visibility** = monotonic set-ops on the base's effective surface: **`allowlist`** (∩) and/or **`denylist`** (\). `resolve = base ∩ allowlist \ denylist`. There is **no scalar default-visibility field** — it was the only widening lever and the only order-sensitive field, so it was removed. Consequences:
  - **Always restrictive** — ∩ and \ only shrink, so a child can never re-expose what a parent hid; the (deferred) classifier never has to police visibility.
  - **Order-independent** — `S ∩ A₁ \ D₁ ∩ A₂ \ D₂ = S ∩ (A₁∩A₂) \ (D₁∪D₂)`; layer order never changes the result.
  - **No one-flip kill-switch** — "expose nothing" is an explicit empty `allowlist: []`, which the toggle UI shows as *every toggle visibly off*, not a hidden scalar.
  - **Autodiscover-safe by construction** — an `allowlist` excludes any un-listed action, *including new tools an upstream remote-MCP server adds* (the #428 hazard). So "use an allowlist for MCP-based layers" is the safety story, with no special field.
- `action_patch.<key>.risk` clamps **upward only** (adds approvals; never removes them); `disclose` is additive; `display_name`/`description` relabel. All monotonic-restrictive.
- A **hidden** action (via `denylist`, or absent from an `allowlist`) is **excluded from the effective template entirely** — not just from discovery but from execution, which returns `unknown_action`. This is the hard gate, and it comes for free because execution resolves actions through the effective template.

### Extensions — expansive, bounded

- May **add new action keys** and **additional hosts** (union).
- **No auth extensions.** A derived layer inherits the base's auth mechanism and cannot add or override auth schemes — this keeps derived layers entirely out of credential resolution (the egress boundary). "Different auth" ⇒ a standalone layer.
- **No rebinding.** An extension cannot change an existing base action's method/path/host. A mask changes an action's *metadata* (risk/disclose/labels/visibility); nothing in a delta changes where an authed call lands. "Different binding" ⇒ a standalone layer.
- **Collision:**
  - *write-time:* reject an extension key that collides with **any** base action key — **visible or hidden** (checking hidden keys closes the hide-then-re-add hijack: `denylist: [delete_repo]` then `extensions.actions.delete_repo` → rejected).
  - *runtime (future upstream collision):* the **base action wins** (a well-known key can never be hijacked by a layer), the extension is **shadowed but not deleted**, and the layer raises a `shadowed_extension` warning (§6) so the admin can rename.

---

## 5. Authority & governance

**No restrictive/expansive classifier in v1.** Authority is **namespace-based** — the axis that already carries the security semantics (blast radius):

- **Org-namespace layer** (`owner_identity_id IS NULL`, standalone or derived) → **org-admin only**. Affects everyone in the org; matches existing org-template + #435 curation authority.
- **User-namespace layer** (`owner_identity_id` set) → governed by org policy (below). Affects only that user and their agents.

### `user_template_policy` (replaces `allow_user_templates`)

Generalize the existing boolean to a three-valued org enum, migrated in place (`false → none`, `true → full`):

| Value | Meaning | v1 |
|---|---|---|
| `none` | Users may not create any layers. | **honored** |
| `restrictive` | Users may create user-namespace layers whose delta is **mask-only** (no extensions). | **reserved** (lights up with the classifier) |
| `full` | Users may create any user-namespace layer, incl. expansive. (= today's `allow_user_templates = true`.) | **honored** |

- Define all three enum values in the schema **now** so the classifier is a pure-compute add later with **no migration**.
- **Rationale for gating user templating at all:** an *expansive* user-namespace layer adds a host/auth = a new egress channel through the org's gateway. Orgs must be able to forbid (`none`) or, later, restrict (`restrictive`) that.
- **Policy downgrade is forward-only.** Flipping `full → none` blocks *new* user-layer creation, leaves existing user layers working, and surfaces them in the admin compliance view for deliberate pruning. It never yanks live layers out from under agents.

> **Rejected — a classifier in v1.** Its only job is to enforce the `restrictive` tier (non-admins creating org-safe curation). No corporate ask needs that yet, and because deltas are stored structurally, adding the classifier later classifies existing deltas by pure computation — no migration. Deferring costs nothing.

---

## 6. Validation & health

Two validation moments, both reusing the existing `POST /v1/templates/validate` `{errors, warnings}` report shape:

- **Write-time delta validation — blocking errors.** Valid action keys; `risk` enum; `disclose`/label shapes; extension fragments compile as OpenAPI; extension keys don't collide with the base's full keyset; `extends` valid + same-or-higher tier + owned/visible; no cycle. A bad delta is rejected.
- **Resolution-time `resolution_report.warnings[]` — non-blocking.** Computed during the fold and attached to the effective template. Because `extends` is live, it **recomputes exactly when a base changes** (same cascade invalidation), so drift warnings appear the moment upstream shifts. Codes:
  - `shadowed_extension` — an extension key now collides with a base key (the collision runtime rule fired).
  - `dead_allowlist_entry` / `dead_denylist_entry` / `dead_action_patch_target` — a delta entry references an action key no longer in the live base.
  - `unreviewed_new_actions` — for an allowlist layer over an autodiscovered base, N new upstream tools exist but aren't allowlisted (the lightweight form of the deferred review queue).
  - Surfaced inline in the layer editor and as a badge in the catalog / compliance view.
- **Deleted base — referential guard.** Block deleting a base layer that has live dependents (offer reparent/detach first). A global unshipped from `services/` is an operator action; dependents degrade to a loud error badge until repointed.

---

## 7. Feedback asks → mechanism

| Ask | Mechanism |
|---|---|
| Curate / per-action whitelist / works with autodiscover | Mask `allowlist`/`denylist` over global **and** remote-MCP bases. |
| Override while tracking upstream | Derived layer + **live** `extends`. |
| Share prefilled service, each user own OAuth (point 2) | A **curated catalog template users self-instantiate** via the existing `create_service_from_template` flow → their own instance + own OAuth connection. **No new mechanism** — "shared org instance" vs "user self-instantiates" is which existing action is taken, not stored state. Scopes come from the OAuth consent screen. |

---

## 8. v1 scope vs deferred

**In v1:**
- Layer model (`extends` + `delta`) + absorption of the existing org/user tier (migration 095).
- The fold, with live-pointer `extends` and `global → org → user` chains (cycle + target guards, cascade invalidation).
- Masks: action `allowlist`/`denylist`, `risk` clamp-up, `disclose` add, relabel, template `hidden`.
- Extensions: new actions + hosts (no auth, no rebinding); collision handling.
- Write-time validation + resolution warnings.
- `user_template_policy` enum honoring `none`/`full`.
- Catalog/editor UI: the #435 admin curation grid becomes a per-template **layer editor** (action toggle list + risk/disclose/label fields + "advanced/OpenAPI" escalation for extensions).

**Deferred (reserved; no future migration required):**
- Restrictive/expansive **classifier** + `user_template_policy = restrictive`.
- **Scope** default-request preset (`x-overslash-default-scopes`) — OAuth consent handles per-user scope choice; requesting the superset is fine for v1.
- **Scope-constraint** fold op (a scope ceiling) — enforcement depends on per-action `required_scopes` (SPEC §9 "planned"). It is the *same monotonic fold op* as an action allowlist, so it drops in with no model change when per-action scopes ship.
- Materialized `openapi` cache on derived layers.
- Proactive "new tools" review queue (present in v1 only as the `unreviewed_new_actions` warning).

---

## 9. Implementation map

- **Schema/repo:** migration 095; `crates/overslash-db/src/repos/` template repo gains `extends`/`delta` read/write + cycle/target validation. `user_template_policy` migration off `allow_user_templates`.
- **Registry + resolver:** the in-memory global loader (`services/*.yaml`) is unchanged as the base source; add a pure **`resolve(layer)` fold** (new module in `overslash-core`, no I/O — testable in isolation) and a resolved-template **cache with cascade invalidation** keyed on `(org, layer, base-version)`.
- **Discovery/execution read effective templates:** `platform_templates.rs` / `platform_services.rs` (`GET /v1/templates`, `overslash_search`) and `kernel_create_service` + the action resolver in `routes/actions/call.rs` all resolve through the fold — hidden actions vanish everywhere, including execution (`unknown_action`), for free.
- **Validation:** extend `overslash-core::template_validation` with delta validation; add the resolution-warning pass (reuses the report shape).
- **Authority:** org-namespace writes → admin; user-namespace writes → `user_template_policy` gate; forward-only downgrade.
- **Catalog gate coexistence:** the #435 `enabled_global_templates` allow-list still decides *which globals appear at all*; layers customize the ones that do. (Fold the gate into layers in a later pass.)
- **Dashboard:** evolve `TemplateCatalog.svelte`'s admin grid into the layer editor (toggle list primary; OpenAPI editor as the extension escape hatch); surface resolution-warning badges.
- **API:** layer CRUD extends the existing template endpoints (`extends`/`delta` in the body; `resolution_report` in responses). No new resource type.

---

## 10. Assumptions (flag if wrong)

- The existing **#435 catalog gate** coexists with layers in v1 (which globals appear vs how they're shaped); folding the gate into layers is a later pass.
- Existing **user-shadows-org resolution** (SPEC §9) applies to layers unchanged.
- This document covers **layered templates only**; MCP-enrollment org-scoping is a separate deliverable ([mcp-enrollment-org-scoping.md](mcp-enrollment-org-scoping.md)).
