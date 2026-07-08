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

The subdomain *is* the lock — this is unconditional for corp subdomains, not a per-org toggle. The apex (`RequestOrgContext::Root`) remains the only place personal-org and org-creator enrollment happens, exactly as today.

### Changes to `authorize()`

1. **Derive the enrollment org from `ctx`, not the session.** On `Org { org_id }`, set `pending.org_id = org_id`.

2. **Reconcile the session against the subdomain before proceeding.** With a session present:
   - `session_claims.org == ctx.org` → proceed; the user is already in the right org.
   - `session_claims.org != ctx.org` → **do not** enroll into the session org. Treat as not-authenticated-for-this-org and bounce through the org's default IdP with `next=` preserved (the same mechanism the dashboard uses for `org_mismatch` → `/auth/switch-org`). The corporate user signs into the corp org; the agent lands there. Never silently fall back to the session org.

3. **Scope the fast-path binding lookup by `ctx.org`.** Resolve `(user, client_id, ctx.org) → agent`. A binding from another org cannot satisfy an authorize on this subdomain.

4. **Apex unchanged.** On `Root`, enrollment continues to use the session's (personal or created) org.

### Hardening: org-scope the DCR client (recommended)

Rather than rely solely on the authorize-time check, close the gap structurally:

- Add nullable `org_id` to `oauth_mcp_clients`, stamped from `ctx` at `POST /oauth/register` time (NULL for apex/back-compat registrations).
- On a corp subdomain, `authorize` accepts a `client_id` only if its `org_id` is NULL **or** equals `ctx.org`. A client registered against Acme's AS cannot be replayed against Beta's subdomain.

In practice standards-compliant clients (Claude Code, Cursor, …) register per issuer and store credentials per server URL, so each `(client, subdomain)` is already a distinct registration — the `org_id` stamp simply makes that structural instead of behavioral, and it makes the admin's **Org Settings → MCP Clients** list correctly scoped to their own org.

### Composability with client admission

Org-scoping answers *"which org does an agent land in"*. It does **not** by itself answer *"which client software may enroll at all"* (the separate "only approve Claude/ChatGPT" ask). The two compose: once enrollment is pinned to the subdomain, an org-level **client admission gate** (allow-list or admin-approval on new DCR registrations, keyed on `client_name` / `software_id` / a signed software statement) layers cleanly on top, because every registration and authorize is now unambiguously scoped to one org. That gate is out of scope for this doc but is the natural next step for full corporate control; noted here so the two are designed to fit.

---

## Security properties after this change

- **No cross-org leak via a stale session.** A personal (or other-org) session on a corp subdomain forces a re-auth into the corp org; it can never divert the agent.
- **No cross-org replay of a client.** A `client_id` is pinned to the subdomain it registered against.
- **The corporate guarantee is structural.** Point a client at `acme.api.overslash.com/mcp` and every path — discovery, cold login, warm re-auth, fast-path rebind — resolves to the Acme org, Acme's IdP, Acme's ceiling. That is the "force Overslash and their cloud org" outcome the feedback asks for.

Apex behavior (personal orgs, org creation) is untouched.

---

## Test plan

- Authenticated with a **personal** session, hit `acme.*/oauth/authorize` → bounced through Acme's IdP; agent ends up in Acme, not personal.
- Authenticated with an **Acme** session on `acme.*` → proceeds to consent/fast-path; agent in Acme.
- A binding made on `beta.*` does not short-circuit authorize on `acme.*`.
- A `client_id` registered on `acme.*` is rejected on `beta.*/oauth/authorize`.
- Apex enrollment (personal org, org-creator) unchanged — regression guard.

## Open questions

- **`org_mismatch` UX for MCP clients.** Dashboard users get `/auth/switch-org`; an MCP browser handoff should transparently re-auth through the org IdP. Confirm the bounce preserves `next=` cleanly through the IdP round-trip on the corp subdomain (the return-host preservation machinery from the subdomain work should cover this — verify).
- **Back-compat for NULL-`org_id` clients** registered before the migration — treat NULL as "any subdomain" (today's behavior) and let them re-register per subdomain over time, or backfill from existing bindings.
