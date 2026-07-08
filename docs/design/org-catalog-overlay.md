# Org catalog overlay — curate and pre-fill service templates without forking

**Status:** Draft — proposed
**Date:** 2026-07-08
**Related:** [Feedback 2026-07-08 — refocus/adapt-to-corporate](../feedback/2026-07-08-refocus-adapt-to-corporate.md), SPEC §9 (Service Templates and Services), PR #435 (curated catalogs + hard instantiation gate), PR #431/#432 (`use_default_connection`), #418/#416/#428 (remote-MCP autodiscovered services)

---

## Context

Two of the corporate-refocus asks are the same missing primitive:

1. *"Orgs/users can override things when publishing in their catalog, while still supporting upstream Overslash updates. Allow whitelisting tools; must work with autodiscover too."*
2. *"Share prefilled services in org, without sharing a full instance with a connection — each user establishes his own OAuth. Ideally solved by the same primitive as before."*

Today an org has exactly two levers over a **global** (shipped) template:

- **Catalog gate** (`orgs.global_templates_enabled` + `enabled_global_templates`, #435): a template-granularity allow-list. Hide `stripe` from the org, or curate down to a chosen set. Enforced on discovery *and* instantiation (the #435 hard gate). But it is all-or-nothing per template — you cannot say "GitHub, but only `create_pull_request` / `list_pull_requests`."
- **Fork to an org template** (SPEC §9 Org tier): copy the global into a full org-tier `service_templates` row and edit it. This gives per-action control, but it is a **copy** — it stops tracking upstream. When Overslash ships a `github.yaml` fix or a new action, the fork never sees it. It also duplicates maintenance and drifts silently.

Neither lever expresses *"take the shipped template, keep receiving upstream updates, but hide these three actions, tighten the risk on this one, relabel it for our staff, and pre-fill the OAuth scopes we want our users to request."* That is the **overlay**.

The same gap bites **autodiscovered remote-MCP services** (HubSpot #418, Slack #416). Their action set is discovered from the upstream MCP server at runtime, not authored in YAML. #428 is the cautionary tale: HubSpot silently replaced its tool catalog and we had to re-sync. An org needs to curate *that* dynamic list too — and needs a safe default when upstream adds a tool nobody has reviewed.

---

## What the overlay is (and is not)

An **overlay** is a **sparse, org-owned patch** keyed on `(org_id, base_template_key)` that layers restrictions and cosmetics on top of a base template. The effective template an org sees is a pure merge:

```
effective_template = resolve(base, overlay)
```

- **base** = a shipped global template (identified by its stable `key`, not a version) **or** the live autodiscovered action set of a remote-MCP service.
- **overlay** = the org's patch. Absent overlay ⇒ `effective == base` (today's behavior).

### It is a *restriction + cosmetic* layer, never a capability grant

This is the load-bearing security property. An overlay can only:

- **hide** the template or **hide/allow-list/deny-list** individual actions,
- **tighten** an action's risk (clamp *upward* only: `write → delete` is allowed; `delete → write` or `write → read` is rejected),
- **add** `disclose` declarations (force disclosure of params),
- **relabel** (`display_name`, `description`) the template or an action,
- **pre-fill instantiation defaults** (scopes, connection policy) — see [Pre-filled services](#pre-filled-services-the-second-ask).

An overlay **cannot** add HTTP actions, change `hosts`, add or alter auth schemes, change `scope_param` (that would rewrite permission-key derivation), or lower risk. Adding capability is exactly what the **org template tier** (full CRUD fork) is for. Keeping the overlay incapable of escalation means an admin editing an overlay can never smuggle in a dangerous action or silently widen the blast radius — the worst an overlay can do is over-hide.

### Why this answers "still supporting upstream updates"

Because the overlay stores only the *delta*, upstream ships freely. When `github.yaml` gains `create_issue` next release, every org's overlay still applies on top of the new base. The org sees the new action governed by its `new_action_posture` (default: hidden until an admin opts in). No fork, no drift, no re-sync chore.

---

## Storage: DB (JSONB), authored as YAML

**Canonical storage is the database, not a file.** This is forced by the deployment model:

- Global templates are read-only repo YAML (`services/*.yaml`); an org cannot edit repo files.
- The overlay is per-tenant state in a multi-tenant cloud — it *has* to be per-org rows.
- It must survive upstream version bumps — a sparse DB delta does; a file copy does not.
- Autodiscovered bases are not YAML at all — they are a runtime action list. A patch keyed on action id works for both YAML and discovered bases.

This mirrors how the template tiers already work: global is shipped YAML, but **org/user templates are DB rows** with JSON `auth`/`actions`. The overlay is the same story, one level more granular.

**Authoring surface.** Admins edit the overlay in Org Settings / the catalog editor. For point-and-click curation (toggle actions on/off, pick a risk, add a disclose) the dashboard writes structured JSON directly. For power users we render the overlay as a **YAML patch fragment** in the existing template editor, validated by the same `overslash-core::template_validation` linter (already WASM-gated for client-side use). So the honest answer to *"YAML or DB?"* is: **stored as DB JSONB, optionally authored and diffed as a YAML fragment** — never a standalone file.

### Schema

```sql
CREATE TABLE service_template_overlays (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    base_template_key   text NOT NULL,          -- stable key of the global/remote base
    base_tier           text NOT NULL DEFAULT 'global',   -- 'global' | 'remote_mcp'

    -- template-level
    hidden              boolean NOT NULL DEFAULT false,
    display_name        text,                    -- NULL = inherit base
    description         text,

    -- action curation
    action_mode         text NOT NULL DEFAULT 'all',      -- 'all' | 'allowlist' | 'denylist'
    new_action_posture  text NOT NULL DEFAULT 'hidden',   -- 'hidden' | 'visible'
    action_patches      jsonb NOT NULL DEFAULT '{}',      -- { <action_key>: ActionPatch }

    -- instantiation defaults (pre-filled services)
    instantiation       jsonb,                   -- InstantiationDefaults | NULL

    created_by          uuid REFERENCES identities(id),
    updated_by          uuid REFERENCES identities(id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, base_template_key)
);
```

```
ActionPatch = {
  visible?:      bool,                 // for denylist/allowlist explicit toggle
  risk?:         "read"|"write"|"delete",   // clamp-upward-only vs base
  disclose?:     [ ...disclose specs ],     // additive
  display_name?: string,
  description?:  string
}

InstantiationDefaults = {
  publish_mode?:           "shared_instance" | "user_instantiated",
  preset_scopes?:          [ string ],       // OAuth scopes to request on instantiate
  use_default_connection?: bool,             // seeds the #431 per-instance flag
  default_secret_name?:    string
}
```

`action_mode` semantics:
- `all` — every base action is visible; `action_patches` refines individual ones.
- `allowlist` — only actions named in `action_patches` with `visible=true` survive; everything else hidden.
- `denylist` — every base action survives except those with `visible=false`.

`new_action_posture` governs actions that appear in the base but are absent from `action_patches` (the autodiscover / upstream-update case). Default `hidden` means *"a tool nobody reviewed does not reach agents"* — the #428 failure mode becomes a no-op instead of a silent exposure.

---

## Resolution and enforcement

`resolve(base, overlay) -> EffectiveTemplate` is a **pure function** that runs at the same seam where alias normalization already happens (on template load / before persist). Merge order:

1. If `overlay.hidden` ⇒ template is dropped from all org surfaces. Done.
2. Template-level `display_name`/`description` overlay wins if present.
3. For each base action, decide visibility from `action_mode` + `action_patches[key].visible` + `new_action_posture`.
4. For surviving actions, apply `risk` (clamp-upward-only; reject-at-write-time if the overlay tries to lower it), additive `disclose`, and label overrides.
5. Attach `instantiation` defaults to the template envelope.

The result is cached per `(org_id, base_template_key, base_version)` and invalidated when the overlay row changes or the base template/version changes.

### One resolution point ⇒ enforced everywhere for free

The key design win: **discovery, instantiation, and execution all read the effective template**, because the action resolver in `call_action` resolves through the same registry the catalog does. A denied or hidden action simply *does not exist* in the effective template, so:

- `overslash_search` / `GET /v1/services` never list it,
- `create_service_from_template` sees the curated surface,
- `POST /v1/actions/call` returns `unknown_action` for it — the **hard gate, automatically**, with no separate enforcement path to drift out of sync.

This is the #435 lesson generalized: #435 had to add an instantiation check because discovery-only enforcement left a hole. Routing execution through the effective template closes the equivalent hole at action granularity by construction.

### Relationship to the existing catalog gate (#435)

The overlay **composes with** the existing `enabled_global_templates` allow-list rather than replacing it in v1:

- The catalog gate still answers *"which templates appear at all"* (coarse, template-granularity).
- The overlay refines *within* an enabled template (per-action, risk, labels, presets).
- `overlay.hidden = true` is equivalent to curating the template out; a later migration can fold the allow-list into overlay rows and expose the gate as a derived view. Kept separate in v1 to avoid a disruptive data migration.

---

## Pre-filled services (the second ask)

The `instantiation` block is the whole of feedback point 2. Two publish modes:

- **`shared_instance`** (today's org-OAuth service, unchanged): admin creates one org-namespaced instance; users in the granted groups each attach their own token to that single instance (SPEC §9 "org services with OAuth (per-user tokens)").
- **`user_instantiated`** (new): the admin publishes a **preset**, not an instance. Nothing is shared except the blueprint. In the member catalog the template shows a "Connect your own" affordance; each user runs `create_service_from_template`, which pre-fills `preset_scopes` / `use_default_connection` / `default_secret_name` from the overlay and produces **that user's own instance** in their Myself namespace with **their own** OAuth connection.

So the admin curates the blueprint (which scopes, which connection policy, relabeled and trimmed to the actions staff should have), and every user owns their credentials. No shared instance, no shared connection — exactly *"share prefilled services without sharing a full instance with a connection."* It reuses `use_default_connection` (#431) as the connection-binding primitive and the overlay as the curation primitive: one mechanism, both asks.

---

## Ownership, visibility, authority

| Question | Answer |
|---|---|
| **Who owns an overlay?** | The **org** (`org_id`). Exactly one overlay per `(org_id, base_template_key)`. Not user-scoped — users get personal customization via the user template tier, not overlays. |
| **Who can create/edit/delete?** | **Org admins only** (`is_org_admin`, i.e. the system **Admins** group / `overslash:admin`). Same authority that curates the catalog today. |
| **Who sees the overlay (the patch)?** | Org admins, in Org Settings / the catalog editor, rendered as a **base-vs-effective diff**. Non-admin members never see the patch. |
| **Who sees the effect?** | Every org member sees only the **effective** template in discovery / search / catalog / execution. They cannot see the raw base behind an overlay that hides or relabels it. |
| **Can admins inspect the base?** | Yes — read-only, for security/compliance (SPEC §9 "org-admins can see all templates"). The diff view shows exactly what upstream ships vs. what the org exposes. |
| **Cross-org visibility?** | None. Strictly per-`org_id`. |
| **Audited?** | Yes. Overlay upsert/delete emits `template_overlay.updated` / `template_overlay.deleted` audit rows — an admin changing what agents may do is security-relevant and must be forensically visible. |

---

## API surface

All admin-gated, org-subdomain-scoped:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/orgs/{id}/template-overlays` | List overlays for the org. |
| `GET` | `/v1/orgs/{id}/template-overlays/{base_key}` | Fetch `{ base, overlay, effective, diff }` for review. |
| `PUT` | `/v1/orgs/{id}/template-overlays/{base_key}` | Upsert. Body is structured JSON **or** a YAML patch fragment; validated by the shared linter. Rejects escalations (risk-lowering, unknown action keys, capability additions) with a `validation_failed` report. |
| `DELETE` | `/v1/orgs/{id}/template-overlays/{base_key}` | Remove overlay → revert to base. |

Effective templates continue to flow through the **existing** `GET /v1/templates`, `GET /v1/services`, `overslash_search`, and the action resolver — those endpoints gain no new shape; they just resolve `base ⊕ overlay` internally.

Dashboard: the Services → Catalog admin grid (added in #435) grows from a per-template on/off toggle into a per-template **overlay editor** — an action checklist (allow/deny), a risk selector, a disclose editor, label fields, and an "instantiation defaults / publish mode" panel.

---

## Alternatives considered

- **YAML file per org in the repo / a config volume.** Rejected: not multi-tenant, admins can't edit repo files, doesn't reach autodiscovered bases, and version control of per-tenant state in the product repo is wrong.
- **Full fork to the org template tier (status quo).** Works for per-action control but is a copy — loses upstream updates, duplicates maintenance, drifts. The overlay exists precisely to avoid the fork.
- **A capable overlay (can add actions / change hosts / lower risk).** Rejected: turns a curation layer into a capability-granting layer, breaking the "admin can't smuggle capability via a patch" property. Capability additions stay in the CRUD-able org template tier where they are reviewed as first-class templates.
- **Store curation in group grants.** Rejected: grants gate by *risk level* per service instance, not by specific action, and are per-group not per-template-definition. Action-granular catalog shaping is a property of the template surface, not of who-can-reach-it.

---

## Open questions

- **Precedence between the #435 allow-list and `overlay.hidden`** during the v1 coexistence window — proposed: allow-list is checked first (template appears at all), overlay second (refine). Fold into one model in a follow-up migration.
- **User-tier overlays.** v1 is org-only. If individual users later want to trim their own view of a template, the same row shape with an `owner_identity_id` could extend it — deferred until there's demand.
- **Remote-MCP re-sync cadence.** `new_action_posture: hidden` makes upstream additions safe, but we still need a signal ("3 new HubSpot tools are hidden pending review") surfaced to admins. Proposed: a catalog badge + audit event on re-sync when the discovered set diverges from the overlay's known actions.
