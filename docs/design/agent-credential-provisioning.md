# Agent-Driven Credential Provisioning

**Status:** Draft
**Date:** 2026-06-03 (§6 token-vault addendum added 2026-07-10)

---

## Context

An agent (over MCP) or a white-label PAI (over REST — e.g. Overfolder) can already
*discover* and *call* services. What it cannot do is bring a service to life when the
platform lacks the credentials that service needs. Two failure shapes dominate:

1. **Non-OAuth secret missing.** An action needs `RESEND_API_KEY`; no value exists for
   the caller. The action layer already emits the typed `credential_missing` envelope
   (`error.rs:205`), and `request_secret` already lets the agent mint a human-fill URL
   (`platform_secrets.rs:51`, bridged at `mcp.rs:1214`). **This half is solved.**

2. **OAuth client app missing.** A `google_calendar` connect tries to mint an OAuth flow,
   but the org has no Google OAuth *client* registered. `client_credentials::resolve()`
   exhausts its cascade (pinned BYOC → connection BYOC → identity BYOC → org
   `OAUTH_GOOGLE_CLIENT_*` secrets → env) and returns a plain
   `AppError::BadRequest("no OAuth client credentials configured for provider 'google'…")`
   (`client_credentials.rs:120`). Auto-connect catches it best-effort and drops the connect
   bundle (`platform_services.rs:655`). The agent has **no structured signal and no
   provisioning path.** This half is the subject of this doc.

> **Note on prior art.** `agent-self-management.md` described the platform-action bridge and
> `request_secret` as future work. Those have since landed (`platform_registry.rs:312`,
> `platform-runtime.md`). This doc extends that machinery to OAuth client credentials; it
> does not re-litigate the bridge.

### Why the agent can't just pass the secret

The naive fix — bridge `POST /v1/byoc-credentials` to MCP and let the agent pass
`client_secret` as a tool parameter — violates **"secrets never leave the vault"** (CLAUDE.md
rule 3). A tool parameter lands in the model's context window, gets logged, and may be
cached by the client. The whole point of `request_secret`'s capability-URL pattern is that
the agent *initiates* provisioning but the secret material flows out-of-band, human → vault.
OAuth client secrets get the same treatment.

---

## Goals

1. Give an agent / PAI a **structured trigger**: a typed error that says "this provider has
   no OAuth client app registered" — distinct from `needs_authentication` ("the user hasn't
   authorized yet").
2. Let an agent / PAI **initiate** OAuth-client provisioning without ever handling the secret,
   reusing the capability-URL pattern that `request_secret` established.
3. Make provisioning **white-label-able**: a PAI with its own trusted backend (Overfolder)
   collects the credential in its own UI and writes it server-to-server, so the value never
   crosses the agent/model boundary at all.
4. Keep the human in the loop for the act that matters — registering an OAuth app and
   pasting its client secret — while removing the dead-end where the agent can only say
   "ask an admin."

**Non-goals (this iteration):**

- **Org-level OAuth credential provisioning.** Requesting org-wide `OAUTH_<PROVIDER>_CLIENT_*`
  (the `PUT /v1/org-oauth-credentials/{provider}` / AdminAcl path) stays a pure dashboard/admin
  act. This doc scopes to **per-identity BYOC** (Write-level, self-or-admin). Org-level is a
  natural follow-up once the BYOC request flow is proven — the request primitive below already
  leaves room for a `scope: "org"` variant.
- Automated **permission** minting (an agent granting itself an Overslash scope). Unchanged from
  `agent-self-management.md`: humans grant permissions.
- Registering the OAuth app itself in the upstream console (Google Cloud, etc.). That is
  inherently out-of-band; we make it *easy and guided*, not automatic.

---

## Design

### 1. Generalize `secret_requests` → `credential_requests`

Today `secret_requests` mints a single-use, TTL-bounded, hashed-JWT capability URL where a
human supplies a value the agent never sees (`routes/secret_requests.rs`,
`platform_secrets.rs:kernel_request_secret`). Generalize the table and the mint/fulfill
machinery around a `kind` discriminator:

| `kind` | Human supplies | Lands in | Fulfillment ACL |
|---|---|---|---|
| `secret` | one value | `secrets` (versioned) | Write + on-behalf rules (today) |
| `oauth_client` | `client_id` + `client_secret` | `byoc_credentials` for `(provider, identity)` | Write + self-or-admin (matches `POST /v1/byoc-credentials`) |

**Migration.** Rename `secret_requests` → `credential_requests`, add `kind` (default
`'secret'` for existing rows), `provider_key` (NULL for `secret`), and `target_identity_id`
(already present as the request's identity). All existing secret-request behavior is the
`kind = 'secret'` path, byte-for-byte. The public provide route generalizes:
`/public/credential-requests/{id}` with kind-specific render/submit, and the old
`/public/secrets/provide/{id}` path 308-redirects for one release for any links in flight.

**Why generalize rather than add a parallel table.** Both kinds share the entire
mint/sign/hash/TTL/single-use/fulfill lifecycle, the permission-chain checks, the audit
shape, and the dashboard "pending requests" surface. A second table duplicates all of it and
forces every consumer (MCP bridge, dashboard, audit, cleanup job) to special-case two shapes.
One discriminated table keeps a single lifecycle with kind-specific *leaves* (the provide
form, the storage target).

### 2. The trigger — a new typed error `oauth_client_missing`

Add a sixth typed envelope to `AppError` (alongside the five in `error.rs:43-226`) and to the
`forward()` allow-list (`mcp.rs:1443`):

```rust
OauthClientMissing {
    provider: String,            // "google"
    scope: OauthClientScope,     // Byoc | Org — this iteration only emits Byoc
    provision_url: Option<String>, // best-effort pre-minted capability URL (cf. needs_authentication.auth_url)
    hint_url: Option<String>,    // dashboard deep-link to BYOC settings
}
```

Rendered shape (parallel to `needs_authentication`):

```json
{ "error": "oauth_client_missing", "provider": "google", "scope": "byoc",
  "provision_url": "https://…/public/credential-requests/…?token=…",
  "hint_url": "https://app.…/settings/byoc?provider=google" }
```

**Emit sites.**

- `client_credentials::resolve()` (`client_credentials.rs:120`) returns `OauthClientMissing`
  instead of the plain `BadRequest`. This is the single source of truth; every caller
  (connection mint, action call, auto-connect) inherits the typed signal.
- The best-effort auto-connect in `kernel_create_service` (`platform_services.rs:655`) stops
  silently dropping the connect bundle. When the inner failure is `OauthClientMissing`, it
  surfaces the envelope so `POST /v1/services` callers (Overfolder) get a structured reason
  instead of an empty `connect`.

**Pre-minting `provision_url`.** Like `needs_authentication.auth_url`, the field is
best-effort: if the caller is identity-bound and holds `request_credentials_own`, the emit
site mints a `kind = oauth_client` request for `(provider, caller-identity)` and embeds its
URL. If minting fails or isn't permitted, the field is omitted and the agent falls back to the
explicit action (§3) or the dashboard `hint_url`. Minting is idempotent per
`(identity, provider)` within the TTL window so a retry loop doesn't spawn duplicate requests.

This makes the whole loop uniform with the OAuth-authorization loop that already works:
**call → typed error carrying a link → hand link to a human → human provisions → retry.**

### 3. MCP surface — `request_oauth_client`

Add one bridged platform action, sibling to `request_secret`:

```
overslash_call(service="overslash", action="request_oauth_client",
               params={ provider, identity_id?, return_url? })
  → { request_id, provide_url, expires_at }
```

- Implemented as a `RequestOauthClientHandler` in `platform_registry.rs`, reusing
  `kernel_request_secret`'s identity-chain and permission machinery under a shared
  `kernel_request_credential(kind, …)`.
- Permission gate: `request_credentials_own` / `request_credentials_share` (rename/superset of
  the existing `request_secrets_*` anchors so one permission covers both kinds; existing grants
  migrate forward).
- Declared in `services/overslash.yaml` with `risk: write`, and added to the `mcp.rs:1214`
  bridge allow-list.
- Recommended client config: `ask` default (it surfaces a URL to a human; low blast radius but
  worth a confirm), added to the `settings.json` snippet in `agent-self-management.md §4`.

The agent's job is unchanged in spirit from `request_secret`: it receives a URL and hands it to
the user. It never sees `client_id` or `client_secret`.

### 4. White-label PAI surface (Overfolder) — delegated backend is primary

Overfolder calls Overslash over REST with an org service key + `X-Overslash-As` impersonation
(`agent-runner/src/overslash/client.rs`), not over MCP. The **recommended** integration is the
*delegated-backend* mode, because it keeps the credential inside the PAI's own trust boundary:

**Mode 1 — delegated collection (recommended).**

1. agent-runner's `configure_external_service` connect receives `oauth_client_missing`
   (§2) from `POST /v1/services` and maps it to a first-class tool result — replacing today's
   opaque `no_oauth_flow` string (`configure_external_service.rs:471`).
2. agent-runner surfaces a native Overfolder prompt: "Google needs an OAuth app. Register one
   (here's the redirect URI to whitelist) and paste the client ID + secret."
3. The user fills Overfolder's **own** trusted form. Overfolder's backend writes
   server-to-server to `POST /v1/byoc-credentials` (org key + `X-Overslash-As` = the user's
   linked Overslash identity from `overslash_user_links`).
4. agent-runner retries the connect; the cascade now resolves the BYOC client and mints the
   OAuth flow.

The value path is **Overfolder-UI → Overfolder-backend → Overslash vault**. It never touches
the agent, the model context, or a third-party-hosted page. This needs **no new Overslash
endpoint** — `POST /v1/byoc-credentials` already accepts this exact call. The work is two
agent-runner pieces (map the typed error; add the collect-and-forward tool) plus surfacing the
redirect URI (next paragraph).

**Redirect URI discovery.** To register a working OAuth app, the human must whitelist
Overslash's per-provider callback URL. Expose it so the PAI can display it:
`oauth_client_missing` carries enough to derive it, and a read endpoint
`GET /v1/oauth/providers/{provider}/redirect-uri` (Read ACL) returns the exact URI(s). Without
this the human registers a client that can't complete the flow — it is the single most common
self-service BYOC failure and the design treats it as load-bearing, not a footnote.

**Mode 2 — hosted capability URL (fallback).** For a PAI without a trusted backend collection
form, `provision_credential` in agent-runner mints a `kind = oauth_client` request via REST and
deep-links the user to Overslash's hosted provide page with `return_url` back into the PAI. The
provide-page metadata is also available as JSON (`GET /public/credential-requests/{id}`) so a
PAI can render its own form against the hosted request rather than iframing Overslash chrome.
Documented as the secondary option; Mode 1 is the recommendation.

### 5. Storage, fulfillment, and the provide page

- `kind = oauth_client` fulfillment writes through the **existing** `POST /v1/byoc-credentials`
  semantics: encrypt `client_id`/`client_secret` with the org keyring, upsert into
  `byoc_credentials` keyed `(org_id, identity_id, provider_key)`. No new storage model.
- Fulfillment ACL is **Write + self-or-admin**, identical to the direct endpoint — minting the
  request at Write does not relax who may *complete* it.
- The provide page (`kind = oauth_client`) shows: the provider, the **redirect URI(s) to
  whitelist**, and `client_id` / `client_secret` inputs. It reuses the secret-provide page's
  single-use-token, expiry, and optional require-session enforcement.
- Dashboard (vertical-integration rule): a "Provide OAuth client" page and a "Pending
  credential requests" list so a human can see and fulfill what agents/PAIs have asked for.

### 6. Token-vault partners (2026-07 addendum)

`white-label-token-vault.md` shipped after this draft and changes the picture for white-label
partners on the import path (Overfolder). Reconciliation:

**The trigger moves partner-side.** A token-vault partner runs the OAuth dance with its *own*
client and only touches Overslash at `POST /v1/byoc-credentials` + `POST /v1/connections/import`.
Overslash never mints a flow for these orgs, so `oauth_client_missing` (§2) is not the signal
they see — the "no OAuth client for provider X" condition is detected in the partner's own
connect path (Overfolder: `docs/design/structured-secret-requests.md`, which resolves it with a
branded structured secret request and then pushes the user's client here). §2/§3 remain the
track for MCP-native agents and orchestrated-OAuth orgs; nothing in this addendum replaces them.

**The redirect URI is the partner's, not ours.** Mode 1 (§4) says the human whitelists
*Overslash's* callback. For token-vault partners that is wrong: the OAuth dance terminates at
the partner's callback (e.g. `api.overfolder.com/auth/oauth/google/callback`), so the
redirect-URI read endpoint is unnecessary on this path and any provide-page / guide copy must
treat the redirect URI as a parameter, not a constant. The docs-site provider guides
(e.g. the Google OAuth-app how-to, still unchecked in `TODO.md`) double as shared collateral
partners link to — write them redirect-URI-parametrized.

**What the partner UX needs from Overslash (new, small, and ahead of §§1–3 in priority):**

1. **BYOC replace/upsert.** Today a same-`(identity, provider)` re-registration 409s and the
   only rotation path is DELETE + POST, which silently strands connections pinned to the old
   credential id (`TECH_DEBT.md` "no BYOC replacement UX"). Add `PUT /v1/byoc-credentials/{id}`
   (or an upsert flag on POST): update the encrypted pair in place so the credential id — and
   every pin on it — survives. Tokens minted under the old client will stop refreshing; mark
   affected connections `reauth_required` at replace time instead of letting refresh fail later.
2. **Partner metadata on BYOC credentials (generic tagging).** List/create responses expose
   only ids and provider keys, so a partner cannot tell whether the registered credential
   matches its vault copy — and the `(org, identity, provider)` slot may already hold a
   different client (e.g. the partner's org client from an earlier connect). Add
   `metadata jsonb DEFAULT '{}'` to `byoc_credentials`, writable by the creating caller and
   echoed verbatim on create/list/get. The partner stamps provenance at push time — e.g.
   `{"source": "overfolder", "vault_secret_id": "<uuid>", "vault_updated_at": "<ts>"}` — and
   reconciliation becomes a stateless read-and-compare against its own vault row; no shadow
   link table on the partner side. Two caveats: (a) metadata is a *claim*, not content — any
   dashboard/API path that replaces the encrypted pair must clear or rewrite it so a stale
   claim never masks a foreign credential; (b) it is opaque to Overslash — no semantics, no
   indexing promises beyond echo. The same column generalizes naturally to `secrets` (org +
   optional `owner_identity_id`) for the future partner secrets-bridging track. A
   `client_id_hint` echo (client_id is not secret) remains a cheap optional complement when
   content-level verification is wanted, but the metadata tag is the primary mechanism.

Re-scoped ordering: these two ship first as standalone PRs against the existing routes; the
original sketch below (typed error → `credential_requests` → `request_oauth_client` → provide
page) is unchanged and remains the MCP-agent track.

---

## Trust boundaries

The two-gate model from `agent-self-management.md` holds, with a third invariant for secret
material:

1. **Overslash permission** — the initiating identity needs `request_credentials_own`
   (mint) and the *fulfilling* human/backend needs Write + self-or-admin on
   `byoc_credentials`. Minting never implies fulfillment.
2. **Client permission rule** — `request_oauth_client` defaults to `ask`.
3. **Secret material never crosses the model boundary.** Provisioning is capability-URL
   (human → vault) or trusted-backend server-to-server (PAI backend → vault). Value-in-param
   BYOC (`POST /v1/byoc-credentials` with a body) stays REST-only for trusted callers and is
   **never** bridged to MCP.

---

## Implementation sketch (rough PR ordering)

1. **PR 1 — typed error.** Add `AppError::OauthClientMissing`, render it, add to `forward()`
   allow-list, emit from `client_credentials::resolve()`. Surface from auto-connect in
   `kernel_create_service`. Tests parallel `mcp_typed_errors.rs` / `actions_reauth.rs`.
2. **PR 2 — data model.** Migrate `secret_requests` → `credential_requests` (+ `kind`,
   `provider_key`); fold `request_secret` onto `kernel_request_credential`; 308-redirect the old
   provide path. No behavior change for `kind = secret`.
3. **PR 3 — `request_oauth_client`.** New platform handler + bridge entry +
   `services/overslash.yaml` + `request_credentials_*` permission rename/migration.
4. **PR 4 — provide page + dashboard.** `oauth_client` provide page with redirect-URI display;
   pending-credential-requests list; redirect-URI read endpoint.
5. **PR 5 — Overfolder.** Map `oauth_client_missing` in `configure_external_service`; add the
   delegated-collection tool that forwards to `POST /v1/byoc-credentials`. Update the
   `no_oauth_flow` dead-end to the new structured path.

---

## Out of scope

- Org-level OAuth credential provisioning (admin-scoped) — follow-up; the `scope: "org"` field
  is reserved but not emitted.
- Automated OAuth app registration in upstream consoles.
- Cross-tenant / cross-org provisioning. Everything is scoped within one org.
- Permission-grant automation (unchanged from `agent-self-management.md`).
