# MCP enrollment org-scoping — a corp subdomain onboards agents only into that org

**Status:** Draft — proposed
**Date:** 2026-07-08
**Related:** [Feedback 2026-07-08 — refocus/adapt-to-corporate](../feedback/2026-07-08-refocus-adapt-to-corporate.md), [mcp-oauth-transport.md](mcp-oauth-transport.md), SPEC §3 (Multi-Org Deployment Model), §4 (Agent Enrollment), DECISIONS D12 (trust-domain isolation on corp subdomains)

---

## The requirement

> Ensure `<org>.app.overslash.com/mcp` (and `<org>.api.overslash.com/mcp`) only allow onboarding into `<org>`, so a corporation can point its corporate Claude / MCP clients at its own subdomain and be **guaranteed** every enrolled agent is a member of that cloud org — under that org's IdP, ceiling, and catalog.

The corporate story this unlocks: IT ships an MDM-managed MCP client config —

```json
{ "mcpServers": { "overslash": { "type": "http", "url": "https://acme.api.overslash.com/mcp" } } }
```

— and can trust that any agent enrolled through it is an **Acme** agent, signed in through **Acme's** Okta, bounded by **Acme's** group ceiling and [catalog overlay](org-catalog-overlay.md). An employee's personal Overslash account must be unreachable from that client, by construction.

---

## What already holds

- **Per-subdomain discovery.** `oauth_as::issuer_for` returns a per-subdomain issuer, so `.well-known/oauth-authorization-server`, `.well-known/oauth-protected-resource`, and the `WWW-Authenticate` challenge on `/mcp` all name `acme.api.overslash.com`. RFC 8414 discovery is correctly org-scoped.
- **Unauthenticated authorize bounces through the org IdP.** On `RequestOrgContext::Org`, `/oauth/authorize` with no session redirects through the org's default IdP (or the picker), per D12. A cold client is forced into the org's trust domain.
- **Trust-domain isolation (D12).** `resolve_auth_credentials` does not fall through to env-var creds when an org is in scope — only that org's `org_idp_configs` grant admission.

## What does not hold (the gap)

Read `authorize()` in `crates/overslash-api/src/routes/oauth.rs`:

1. **Enrollment org is taken from the *session*, not the subdomain.** The parked authorize request is built with `org_id: session_claims.org` (the `oss_session` cookie's org), and the subdomain `ctx` is consulted **only** for the unauthenticated IdP bounce. When a session is already present, `ctx` is never compared to `session_claims.org`. So an employee who happens to hold a **personal-org** session and hits `acme.api.overslash.com/oauth/authorize` while authenticated parks `pending.org_id = <personal org>` — and the agent is created in their personal org, even though the client connected via Acme's subdomain. The subdomain governed discovery but not the final binding.

2. **DCR clients are org-global.** `oauth_mcp_clients` has no `org_id` column. A `client_id` minted once is usable against any subdomain's authorize endpoint; the only org binding is downstream, at `mcp_client_agent_bindings` (which *does* carry `org_id`) and at `pending.org_id`.

3. **The fast-path binding lookup is not subdomain-scoped.** The `(user, client_id) → agent` fast path in `authorize` resolves the agent by `session_claims.org`, so a binding formed under org A could short-circuit an authorize arriving on org B's subdomain if a cross-org session is present.

Net: the subdomain is a strong signal for *discovery and cold login* but not an enforced boundary on *where the agent lands*. The requirement is to make the subdomain the boundary.

---

## Design

### Invariant

> On a corp subdomain (`RequestOrgContext::Org { org_id }`), the enrolled agent's org **is** `org_id`. Full stop. The session org, any pre-existing binding, and the client's registration are all subordinate to the subdomain.

The subdomain *is* the lock — this is unconditional for corp subdomains, not a per-org toggle. But note precisely what it constrains: **the enrollment endpoint on that subdomain**, and nothing else. It is *not* a claim that an org is reachable only via its subdomain. The root apex (`RequestOrgContext::Root`) remains the **multi-org hub**: a user with a valid session for any org they belong to — personal *or corp* — continues to see and use that org from `app.overslash.com` (org switcher, dashboard, and enrollment into their own session org), exactly as today. See *Root and multi-org access* below.

### Changes to `authorize()`

1. **Derive the enrollment org from `ctx`, not the session.** On `Org { org_id }`, set `pending.org_id = org_id`.

2. **Reconcile the session against the subdomain before proceeding.** With a session present:
   - `session_claims.org == ctx.org` → proceed; the user is already in the right org.
   - `session_claims.org != ctx.org` → **do not** enroll into the session org. Treat as not-authenticated-for-this-org and bounce through the org's default IdP with `next=` preserved (the same mechanism the dashboard uses for `org_mismatch` → `/auth/switch-org`). The corporate user signs into the corp org; the agent lands there. Never silently fall back to the session org.

3. **Scope the fast-path binding lookup by `ctx.org`.** Resolve `(user, client_id, ctx.org) → agent`. A binding from another org cannot satisfy an authorize on this subdomain.

4. **Root unchanged — and deliberately permissive.** On `Root`, enrollment continues to use the session's org, which **may be a corp org the user belongs to**, not only a personal/created org. There is no subdomain claim to honor at root, and the session already proves membership, so a member legitimately enrolls into and uses `<org>` from `app.overslash.com`. This is existing behavior and must be preserved (next subsection).

### Root and multi-org access (unchanged — the clarification)

The subdomain lock must not be read as "an org is only usable at its subdomain." It isn't, and today's code already reflects that: `check_subdomain_matches_jwt` (`extractors.rs`) enforces `jwt.org == ctx.org` **only when the context is `Org { … }`** — at `Root` the check is a **no-op**, so a corp-org session is fully accepted on `app.overslash.com`. A member switches to and uses `<org>` from root via the org switcher exactly as for a personal org.

This change is therefore **additive on the subdomain path only**. Two rules keep root intact:

- **Enrollment org follows the *resolved* org**, defined as: the subdomain org on `Org` ctx, the **session org** on `Root` ctx. So the org-derivation and the fast-path binding scoping (item 3) are keyed on that resolved org — on root they degrade to today's session-org behavior, not to any subdomain constraint.
- **The re-auth-on-mismatch (item 2) fires only on `Org` ctx.** At root there is no subdomain to mismatch against, so a valid session — corp or personal — is never bounced.

Net: the corporate subdomain is a *lock you opt into by pointing a client at it*; root is the *unlocked multi-org hub*. A user who wants the multi-org experience uses root; a corporation that wants its Claude pinned points it at `acme.api.overslash.com`. The two coexist without one restricting the other.

### Hardening: org-scope the DCR client (recommended)

Rather than rely solely on the authorize-time check, close the gap structurally:

- Add nullable `org_id` to `oauth_mcp_clients`, stamped from `ctx` at `POST /oauth/register`: a **subdomain** registration stamps that org (locked); a **root** (or pre-migration back-compat) registration stamps `NULL` — intentionally, so a root-registered client works across whichever of the user's orgs their session is on. `NULL` is the multi-org path, not a gap.
- On a corp subdomain, `authorize` accepts a `client_id` if its `org_id` is **`NULL` or equals `ctx.org`**, and rejects one stamped for a *different* org. A `NULL` client is safe here precisely because items 1+2 force the agent into `ctx.org` regardless of the client; the stamp only adds cross-subdomain *replay* protection (an Acme-locked client can't be used on Beta's subdomain) and correctly scopes the admin's MCP-Clients list.
- **Root does not gate on the client's `org_id`** — it's the multi-org hub, so the session org governs and any of the user's orgs is reachable.

In practice standards-compliant clients (Claude Code, Cursor, …) register per issuer and store credentials per server URL, so each `(client, subdomain)` is already a distinct registration — the `org_id` stamp simply makes that structural instead of behavioral, and it makes the admin's **Org Settings → MCP Clients** list correctly scoped to their own org.

### Composability with client admission

Org-scoping answers *"which org does an agent land in"*. It does **not** by itself answer *"which client software may enroll at all"* (the separate "only approve Claude/ChatGPT" ask). The two compose: once enrollment is pinned to the subdomain, an org-level **client admission gate** (allow-list or admin-approval on new DCR registrations, keyed on `client_name` / `software_id` / a signed software statement) layers cleanly on top, because every registration and authorize is now unambiguously scoped to one org. That gate is out of scope for this doc but is the natural next step for full corporate control; noted here so the two are designed to fit.

---

## Security properties after this change

- **No cross-org leak via a stale session.** A personal (or other-org) session on a corp subdomain forces a re-auth into the corp org; it can never divert the agent.
- **No cross-org replay of a client.** A `client_id` stamped for one subdomain org can't authorize on another org's subdomain.
- **The corporate guarantee is structural.** Point a client at `acme.api.overslash.com/mcp` and every path — discovery, cold login, warm re-auth, fast-path rebind — resolves to the Acme org, Acme's IdP, Acme's ceiling. That is the "force Overslash and their cloud org" outcome the feedback asks for.
- **Root multi-org access is preserved (the clarification).** A member with a valid `<org>` session sees and uses `<org>` from `app.overslash.com` — dashboard *and* enrollment into their session org — exactly as today. The subdomain lock is an opt-in corporate control (you get it by pointing a client at the subdomain), not a restriction on the root hub.

Root behavior (personal orgs, org creation, **and corp-org access/enrollment via the session**) is untouched.

---

## Test plan

- Authenticated with a **personal** session, hit `acme.*/oauth/authorize` → bounced through Acme's IdP; agent ends up in Acme, not personal.
- Authenticated with an **Acme** session on `acme.*` → proceeds to consent/fast-path; agent in Acme.
- A binding made on `beta.*` does not short-circuit authorize on `acme.*`.
- A `client_id` registered on `acme.*` is rejected on `beta.*/oauth/authorize`.
- Apex enrollment (personal org, org-creator) unchanged — regression guard.
- **Root multi-org (the clarification):** authenticated with an **Acme** session on **`app.overslash.com`** → dashboard access to Acme works (no `org_mismatch`), and MCP enrollment at root lands the agent in **Acme** (the session org), not forced elsewhere.
- A `NULL`/root-registered `client_id` is accepted on a corp subdomain and still lands the agent in that subdomain's org (items 1+2), i.e. back-compat holds without a leak.

## Open questions

- **`org_mismatch` UX for MCP clients.** Dashboard users get `/auth/switch-org`; an MCP browser handoff should transparently re-auth through the org IdP. Confirm the bounce preserves `next=` cleanly through the IdP round-trip on the corp subdomain (the return-host preservation machinery from the subdomain work should cover this — verify).
- **Back-compat for NULL-`org_id` clients** registered before the migration — treat NULL as "any subdomain" (today's behavior) and let them re-register per subdomain over time, or backfill from existing bindings.
