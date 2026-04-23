# Multi-Org Auth

**Status**: Draft
**Date**: 2026-04-23
**Related**: `SPEC.md` §3 (deployment), §4 (identity/auth), `DECISIONS.md` (multi-org trust model), migrations `021`, `032`, `org_idp_configs`

## Overview

Today every user is provisioned into exactly one org on first login, `identities` are the only user-facing table, and the session JWT embeds a single `org: Uuid` claim. This document introduces (a) a global `users` table, (b) org memberships, (c) subdomain-based org routing, (d) an explicit `/auth/switch-org` endpoint, and (e) self-hosted mode toggles.

Cloud root domain is `app.overslash.com`. Corp orgs live at `<slug>.app.overslash.com`. Personal orgs are always 1-member, always authenticate via Overslash-level IDPs, and have no subdomain — they live under the root domain.

## Key Constraints

- **Personal org isolation.** A personal org is non-configurable: no per-org IDP, no members, no billing seats. It exists solely as a scope for the user's own agents/secrets/services.
- **Org IDP sovereignty.** Per-org IDPs (already implemented via `org_idp_configs`) are only valid within that org's subdomain — they cannot authenticate a user at the Overslash level.
- **Overslash IDP ↔ org membership.** A user signed in via Overslash-level IDP can access any org they are a member of. Membership is the permission, regardless of how they proved identity.
- **Two user classes.** A `users` row is either **Overslash-backed** (`overslash_idp_provider + overslash_idp_subject` set, has a `personal_org_id`, can log into root) or **org-only** (both IDP columns NULL, `personal_org_id` NULL, can only log into the subdomain of orgs they are a member of).
- **Users are keyed by IDP subject, never by email.** The primary lookup at auth time is `(provider, subject)` — Overslash-level for root logins (on `users.overslash_idp_*`), and `(org_id, external_id)` for org-subdomain logins (on `identities`). `users.email` is informational (last value the IDP returned) and is NOT unique. Two different Google accounts that both claim the same email create two different `users` rows.
- **Email alone never grants membership or merges users.** This is the threat-model load-bearing rule. Google (or any Overslash-level IDP) saying "the email is `amartcan@acme.org`" does not grant membership to Acme and does not attach to an existing Acme-provisioned `users` row, because Google is not Acme's IDP. Membership into a corp org is granted *only* by signing in via that org's own IDP — covered by `org_idp_configs.allowed_email_domains`. There are no invites and no cross-IDP account linking.
- **Corp orgs require an IDP to have members.** Before any IDP is enabled on a corp org, only the bootstrap creator can access it (see "Corp Org Creation Bootstrap"). Once an IDP is configured and enabled, membership is gated entirely by that IDP.
- **Email claim still required from IDPs.** Without an email we have no display/invite matching. Missing email → `idp_missing_email` and the login is rejected.
- **Cookies never leave the hierarchy.** Session cookies are scoped to `.app.overslash.com` so the same `oss_session` is sent to all subdomains, but the JWT's `org` claim and subdomain resolution must agree — mismatch triggers re-mint.

## Data Model

```
users
  id                      UUID PK
  email                   TEXT          -- informational; NOT unique; last value the IDP returned
  display_name            TEXT
  overslash_idp_provider  TEXT          -- e.g. 'google', 'github'; NULL if org-only user
  overslash_idp_subject   TEXT          -- provider's stable subject
  personal_org_id         UUID FK → orgs(id)  -- set when Overslash-backed; NULL for org-only
  created_at, updated_at
  UNIQUE (overslash_idp_provider, overslash_idp_subject)  -- enforced where both set

user_org_memberships
  user_id             UUID FK → users(id)
  org_id              UUID FK → orgs(id)
  role                TEXT NOT NULL  -- 'admin' | 'member' (room to grow)
  created_at
  PRIMARY KEY (user_id, org_id)

orgs  (additive)
  is_personal         BOOLEAN NOT NULL DEFAULT false
  -- existing slug column becomes the subdomain label for non-personal orgs

identities  (additive)
  user_id             UUID NULL FK → users(id)   -- NULL for pure machine identities
  UNIQUE (org_id, user_id) WHERE user_id IS NOT NULL AND kind = 'user'
```

**Why `users.email` is not unique:** since we key on `(provider, subject)` at auth time, two different Google accounts that happen to report the same email must produce distinct `users` rows. Uniqueness on email would block that — and opening a UNIQUE collision on login would reveal account existence to an attacker.

**Why a global `users` table:** decouples identity-of-the-human from identity-of-the-actor-in-an-org. Billing, profile, account deletion all need a stable "human" record. The existing `identities` table continues to be the unit of permission in an org; we just link each user-kind identity back to a `user_id`.

**Note on `identities`:** the table already has `external_id TEXT` (IDP subject) and `email TEXT`, scoped to `org_id`. These stay — they describe *how this org sees the user*. The new `user_id` column describes *who the human actually is*. One human can have one `identities` row per org they're a member of, each with its own `external_id` matching whichever IDP that org used to authenticate them.

### Worked example: `amartcan@acme.org` via Okta with no Overslash account

User navigates to `acme.app.overslash.com`, clicks "Continue with Okta". They have never signed in at `app.overslash.com`.

Okta callback returns `{ sub: "00u123abc", email: "amartcan@acme.org", name: "Arturo" }`.

Tables after login:

```
users
  id = U1
  email = 'amartcan@acme.org'
  display_name = 'Arturo'
  overslash_idp_provider = NULL           ← org-only user
  overslash_idp_subject  = NULL
  personal_org_id        = NULL           ← no personal org

user_org_memberships
  (user_id=U1, org_id=ACME, role='member')

identities
  id = I1
  org_id = ACME
  user_id = U1
  kind = 'user'
  email = 'amartcan@acme.org'
  external_id = '00u123abc'               ← Okta subject for this org
```

JWT: `{ user_id: U1, org_id: ACME }`. User can log into `acme.app.overslash.com`. Hitting `app.overslash.com/login` shows only Overslash-level IDPs; there is no Okta button there, and Okta can't authenticate a user at the Overslash level anyway, so this user cannot enter root. That is the correct product behavior: org-only users exist *within* their org.

**Later Google sign-in (stays separate, forever).** Suppose the same person later visits `app.overslash.com` and signs in with Google using the same email `amartcan@acme.org`. Google returns `(sub=G1, email=amartcan@acme.org)`.

- Lookup on `users.(overslash_idp_provider='google', overslash_idp_subject=G1)` → not found.
- **No email fallback.** Create a fresh users row U2 (Overslash-backed), auto-create personal org P1, membership `(U2, P1, 'admin')`.
- U2 has **no membership to Acme**. The Google-signed user cannot access Acme's data.
- U1 (Acme / Okta) and U2 (personal / Google) coexist indefinitely and are never merged. This is by design: to use Acme, sign in through Acme's Okta at `acme.app.overslash.com`; to use the personal scope, sign in with Google at `app.overslash.com`. One human, two accounts, one per trust domain.

**Why this is safe:** the system never lets an IDP grant access to resources belonging to another IDP's trust domain. Google's claim about the email is only relevant within Google's own trust domain (Overslash-level root). Acme's Okta is the only authority on Acme memberships, and it already grants membership via its own `allowed_email_domains` when the user signs in through Okta.

**The impostor case.** If the Google sign-in isn't Alice but Bob with a Google account claiming `amartcan@acme.org`, Bob gets his own U_bob row with only his own personal org. He cannot access Acme through any path: Acme's membership table doesn't name him, and the root-domain JWT can't satisfy a subdomain auth check for Acme.

**What if the IDP returns no email claim?** Reject with `{ error: "idp_missing_email", hint: "Configure your IDP to include 'email' in the OIDC claims." }`.

### Corp Org Creation

An Overslash-backed user creates a corp org from their root-domain dashboard. This is the only path by which an Overslash-level IdP admits someone into a non-personal org.

1. User (e.g., U2 with personal org P1) calls `POST /v1/orgs { name, slug }`.
2. Org is created with `is_personal=false`.
3. An admin `identities` row is created in the new org for the caller, linked to U2 via `user_id`.
4. A plain `user_org_memberships(U2, ACME, 'admin')` row is inserted — **no special flag**. The creator is simply an admin.
5. Dashboard hard-reloads onto `acme.app.overslash.com/`, where the creator lands inside their new org.

Two legitimate paths from here:

- **Stay on the Overslash-level IdP indefinitely.** The org never configures its own IdP. It remains a single-admin org reachable only via the creator's Overslash-level login. This is valid and supported — an org is free to ride the Overslash instance's IdP forever.
- **Configure a corp IdP later.** The creator adds an `org_idp_config` (Okta / generic OIDC) on the Settings page. Additional humans can now sign in via the corp IdP on the subdomain and auto-provision memberships (gated by `allowed_email_domains`). The creator's original admin membership is unchanged and continues to work — their Overslash-level login remains valid for the corp subdomain because the membership row still grants access.

No `is_bootstrap` flag. No "breakglass" labeling. Removing it was a deliberate simplification: the creator is just the org's admin, identical to any other admin they may later promote from within. The fact that they authenticate via the Overslash-level IdP is derivable from `users.overslash_idp_*` and is not a special state on the membership itself.

### Migration/backfill

Migration `033_multi_org_users.sql`:

1. Create `users`, `user_org_memberships`, add `orgs.is_personal`, add `identities.user_id`.
2. For each existing `kind='user'` identity, upsert a `users` row. Dedup strategy: current code already enforces unique email across orgs via `find_user_identity_by_email`, so email is safe as the dedup key for the backfill specifically (we are not using it for new logins). Populate `overslash_idp_provider`/`overslash_idp_subject` where discoverable from existing metadata; otherwise leave NULL (the row becomes org-only post-migration, which is correct for users who only existed inside one org). Backfill `identities.user_id` and `user_org_memberships(user_id, org_id, 'admin')`.
3. For each backfilled user with `overslash_idp_*` set (i.e., would be Overslash-backed going forward), create a personal org (`is_personal=true`, slug `personal-<short-random>`) and set `users.personal_org_id`. Users with no Overslash IDP binding stay org-only and get no personal org.

## Subdomain Routing (cloud)

DNS: wildcard `*.app.overslash.com` pointing at the same Cloud Run service as `app.overslash.com`, sharing a managed wildcard cert.

New middleware in `crates/overslash-api/src/middleware/subdomain.rs` runs before auth:

- Parse `Host` header.
- If host == root (`app.overslash.com`) → `RequestOrgContext::Root`.
- If host matches `<slug>.app.overslash.com` → look up `orgs` by slug; if `is_personal=true` or not found, return 404. Else → `RequestOrgContext::Org { org_id, slug }`.
- Attach the context to the request extensions.

Self-hosted deployments bypass this middleware when `SINGLE_ORG_MODE=<slug>` is set; then every request is treated as `RequestOrgContext::Org` for the configured slug regardless of host.

## Authentication Flows

### Flow 1 — Root login (`app.overslash.com/login`)

- `GET /auth/providers` (no `?org=` param) returns the Overslash-level IDPs only (those configured via env).
- `GET /auth/login/{provider}` initiates OAuth without org context. Cookie `oss_auth_org` is **not** set.
- Callback handler:
  1. Exchange code → `{ provider, subject, email, name }`. If email missing → reject (`idp_missing_email`).
  2. Look up `users` by `(overslash_idp_provider, overslash_idp_subject)`. **No email fallback** — this is the rule that prevents Google from vouching its way into an org-only row.
  3. If not found → create a new users row with the IDP binding set, create a personal org (`is_personal=true`), membership `(user_id, personal_org_id, 'admin')`, link `users.personal_org_id`, create the identity row in the personal org.
  4. If found → refresh `users.email` and `display_name` opportunistically.
  5. Mint session JWT with `{ user_id, org_id: personal_org_id }` by default. If the user has exactly one non-personal membership (typical for a creator who just bootstrapped one corp org), land there instead.
  6. Set `oss_session` cookie with `Domain=.app.overslash.com`.
  7. Redirect to dashboard, which shows the org switcher.

### Flow 2 — Org subdomain login (`acme.app.overslash.com/login`)

- Subdomain middleware resolves `org_id` for `acme`.
- `GET /auth/providers` returns only the org's enabled IDPs from `org_idp_configs`. There is no "Continue with Overslash" fallback — an Overslash-level IDP cannot grant membership to a corp org under this design, so offering it would be misleading.
  - Exception: the org's creator (and any other Overslash-backed user who already has a membership in the org) reaches it via `/auth/switch-org` from the root dashboard, not via the org's `/login` page.
- Provisioning on callback — lookups key on `(org_id, external_id)`, never on email:
  1. Exchange code → `{ subject, email, name }` from IDP. If email missing → reject (`idp_missing_email`).
  2. Look up `identities` by `(org_id, kind='user', external_id=<IDP subject>)`.
     - **If found** → use `identities.user_id` as the target `users` row. Refresh `identities.email` and `users.display_name` opportunistically.
     - **If not found** → first-time sign-in for this IDP subject. Create a fresh `users` row (org-only: `overslash_idp_*` NULL, `personal_org_id` NULL). Create the `identities` row in this org with `external_id=<subject>`, `email=<IDP email>`, `user_id=<new users row>`. Never match against existing `users` rows by email.
  3. Ensure `user_org_memberships(user_id, org_id, role)` exists. Role comes from the org's `allowed_email_domains` auto-provision rules (default `'member'`). If the IDP email does not match any allowed domain, reject with `not_permitted_by_org_idp` — the org admin controls who gets in through their allowed-domains list. Empty `allowed_email_domains` = trust the IdP (any email admitted by it provisions); non-empty = strict whitelist.
  4. Mint JWT `{ user_id, org_id }`, redirect into the org.

### Flow 3 — Org switch in-app

- `POST /auth/switch-org { org_id }`:
  - Requires valid session (any org).
  - Verifies `user_id` has a membership to `org_id` (or that `org_id` is the user's personal org).
  - Mints a new JWT `{ user_id, org_id }`, sets `oss_session` on `.app.overslash.com`.
  - Response body: `{ redirect_to: "<subdomain-or-root-url>" }`. Dashboard hard-reloads to the returned URL.

### Session middleware update

Current: reads JWT, extracts `org_id` from claims. New: reads JWT → extracts `user_id` and JWT `org_id`; if `RequestOrgContext::Org { org_id: subdomain_org }` is present, require `jwt.org_id == subdomain_org` (else 401 with `reason=org_mismatch`, dashboard forwards to `/auth/switch-org`). If `RequestOrgContext::Root`, the JWT's `org_id` wins (used by account-level routes that still need scope).

## Dashboard Changes

- **Login page** (`dashboard/src/routes/login/+page.svelte`):
  - On root domain: render only Overslash-level providers; no org field.
  - On org subdomain: render only the org's enabled IDPs. No Overslash fallback button.
  - If the subdomain has no enabled IDPs yet, show an explanatory page: "This org has no sign-in configured. Contact the org admin." The admin (= creator) reaches the org via root → org switcher.
- **`+layout.ts`**: `MeIdentity` gains `user_id`, `memberships: [{ org_id, slug, name, role, is_personal }]`, `personal_org_id`.
- **`OrgSwitcher.svelte`** (new) — sidebar-top component. Dropdown listing memberships grouped as Personal / Orgs; calls `/auth/switch-org` then hard-reloads to returned URL. No per-row badges — every row is just an org name.
- **`/account`** (new) — top-level page outside any org scope; shows profile, linked Overslash IDP, org memberships, "Create org" CTA (gated by `ALLOW_ORG_CREATION`). Lets the user drop a bootstrap membership.
- **`/org`** (existing) — hide IDP + OAuth credential cards when current org `is_personal=true`. For corp orgs, surface a warning banner when no IDP is enabled: "Configure an IDP to let your team sign in."

## Self-Hosted Configuration

Two new env flags parsed once at startup:

- `ALLOW_ORG_CREATION` (default `true`). When `false`: `POST /v1/orgs` returns `403 org_creation_disabled`; dashboard hides "Create org" CTAs.
- `SINGLE_ORG_MODE=<slug>` (default unset). When set: subdomain middleware disabled; every request scoped to the named org; root login lands directly in that org (no personal org auto-creation); org switcher hidden.

Documented in `SPEC.md §3` and a future `docs/self-hosting.md`.

## Open Questions (deferred)

- Per-user profile settings (name, avatar) surface in `/account` — scoped for a later PR once `users` table exists.
- SAML — already out of scope per SPEC; unchanged.
- Slug squatting on corp orgs — deferred; add domain verification or admin approval later if abuse materializes.
- Auditing bootstrap-admin removal — should likely emit an audit event; straightforward follow-up.
