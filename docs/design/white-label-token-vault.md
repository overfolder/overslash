# White-label OAuth as a token vault

**Status**: Approved — implemented (migration `082_connection_token_vault`, `POST /v1/connections/import`)
**Supersedes**: the per-request `redirect_uri` override + `oauth_callback_allowed_hosts` allow-list (#388/#392) and the per-org `oauth_redirect_url` + `use_org_redirect` switch (#398). Both are reverted by this design.

## Context

Overslash currently *orchestrates* the OAuth dance for white-label partners: it builds the authorize URL (client_id, `redirect_uri`, scopes, state, PKCE), the partner shows it, the provider redirects back to a `redirect_uri`, and the partner forwards `{code, state}` to `POST /v1/oauth/exchange` where overslash exchanges the code for tokens and stores them.

That coupling is the root of a recurring problem: the `redirect_uri` must be registered on *the provider's OAuth client*, and OAuth clients are **per-provider**. A single per-org callback URL (#398) forces every provider to share one URL; the older per-request override (#388/#392) handled multi-provider but at the cost of an allow-list and per-call URL plumbing. Either way overslash stays in the OAuth loop for a partner — like Overfolder — that **already owns its own OAuth** (its own Google client, its own `/auth/google/integrations/callback`). Overslash orchestrating it is redundant work that exists only to fight the redirect coupling.

This doc flips the model: **the partner runs the OAuth dance; overslash is a token vault.** Overslash stores the resulting tokens, refreshes them, and uses them for authenticated execution — and never sends a `redirect_uri` to any provider.

## The model

```
Partner (Overfolder)                         Overslash
────────────────────                         ─────────
build authorize URL (their client)
user consents (partner branding)
provider → partner callback (code+state)
exchange code → {access, refresh, expiry}
                                POST /v1/connections/import ──▶ encrypt + store connection
                                                                (identity-bound, byoc-linked)
agent calls action ───────────────────────▶ inject access token; refresh as needed
```

The partner owns everything user-facing (consent screen, branding, domain, the code→token exchange). Overslash receives `{provider, access_token, refresh_token?, expires_at?, scopes?, account_email?, byoc_credential_id?}` and persists a connection **byte-identical to what an orchestrated callback produces** — same `connections` row, same encryption, same single-default semantics — so refresh, execution, permissions, and approvals all work unchanged downstream.

Per-provider redirect URIs become a non-issue: overslash issues no redirect URI, so there is nothing to configure per provider.

## API: `POST /v1/connections/import`

Auth: org API key, identity-bound (`WriteAcl`), `on_behalf_of` supported (same as `POST /v1/connections`).

Body:
| field | req | notes |
|---|---|---|
| `provider` | ✓ | provider key (`google`, `github`, …) |
| `access_token` | ✓ | the bearer token to vault + inject |
| `refresh_token` | – | enables overslash-managed refresh (with a client) |
| `expires_at` *or* `expires_in` | – | `expires_at` = absolute Unix timestamp (seconds); `expires_in` = seconds from now (the raw OAuth value). `expires_at` wins; omitting both ⇒ treated as long-lived/opaque |
| `scopes` | – | granted scopes (labeling + scope-gate); default `[]` |
| `account_email` | – | label; if omitted overslash best-effort fetches via `userinfo_endpoint` |
| `byoc_credential_id` | – | the partner's registered client (see [agent-credential-provisioning](agent-credential-provisioning.md)); **present ⇒ overslash self-refreshes, null ⇒ integration-managed (the integration refreshes and re-imports)**. No inline client_id/secret — refresh creds always come from a stored BYOC row. |
| `on_behalf_of` | – | owner-user binding, same semantics as connect |

Behavior (`kernel_import_connection` in `services/platform_connections.rs`): validate `provider` exists and (if given) `byoc_credential_id` resolves for this org/provider (Tier-1 hard pin — a missing id 400s here, not at first refresh); resolve `expires_at`; best-effort `account_email` via the provider userinfo endpoint when not supplied; encrypt tokens (`crypto::encrypt`); upsert via the connection repo (`find_for_import` → `update_tokens_and_scopes`, else `create`); compute `is_default` (first per identity+provider); fire the `connection.created` / `connection.updated` audit + webhook. Returns the connection summary (`connection_id`, `provider`, `account_email`, `scopes`, `is_default`, `integration_managed`) — never the tokens.

Re-import is idempotent and keyed on `(identity, provider, account_email)` (or the identity's default connection for the provider when no email is given): it updates the existing row's tokens/scopes in place rather than accreting a duplicate — essential because an integration-managed connection is re-imported on every refresh cycle. A *different* `account_email` creates a distinct connection (multi-account vaulting). The refresh mode (`integration_managed` / pinned BYOC) is fixed at first import, and the match is mode-aware so an import never overwrites a connection it doesn't own:

- **Email-keyed match** (the caller named the account): an in-place update is intended, so a mode/client *change* (integration-managed ↔ self-refresh, or a different pinned client) is **rejected with 400** rather than silently validated-and-discarded — delete and re-import to change.
- **Emailless match** (the `(identity, provider)` default-connection fallback): the row is reused **only when it is the same kind of vault connection** (same mode, same pinned client). This stops an emailless import from overwriting an *orchestrated* connection that the fallback happens to match (e.g. one whose userinfo fetch left `account_email` NULL) — on a mismatch the import creates a fresh row instead.

A token-only re-import that carries no fresh `expires_at`/`expires_in` **preserves** the existing `token_expires_at` rather than nulling it — otherwise an integration-managed connection would look perpetually valid and never surface reauth (it would keep injecting a token that has actually expired upstream). Supplying a fresh expiry overrides it.

## Q2 — What happens when we need refresh?

Access tokens are short-lived (Google ≈ 1 h); agents execute at arbitrary times, so overslash must obtain fresh tokens. The refresh-token grant (`grant_type=refresh_token`) needs **client_id + client_secret + refresh_token** — and crucially **no `redirect_uri`**. So refresh is independent of the whole redirect problem. **Overslash refreshes only when it holds the OAuth client for that connection.** Two modes, fixed per connection at import:

**Self-refresh.** Import carries a `refresh_token` and a `byoc_credential_id` (the *same* client the partner used to mint the token). Overslash refreshes autonomously via the existing path (`oauth::resolve_access_token` → `refresh_token`), using **that BYOC credential only — a hard pin, not the cascade.** A refresh token is valid only against the client that issued it, so an imported connection must **never** fall back to an org-level `OAUTH_*_CLIENT` secret or the env/system client — a *different* client would mismatch or silently fail. If the pinned BYOC row is later deleted, the connection degrades to integration-managed rather than refreshing against the wrong client. This is the path that supports unattended agent execution past the first hour.

**Integration-managed.** Import carries a **null** `byoc_credential_id` — overslash holds no client for it and **does not fall back to env/org OAuth clients** (this is the explicit exception to the §7 credential cascade: imported connections never borrow another client to refresh). The connection is flagged `connections.integration_managed = true`. Overslash never calls the refresh grant; it injects the access token until expiry, and when the token is stale (or upstream returns 401) it surfaces `reauth_required` on the action call — **marked integration-managed and with no overslash reconnect link** — and emits a `connection.refresh_required` webhook. The integration refreshes on its side (it owns the client) and re-imports. Availability is bounded by the partner's refresh loop.

Signaling detail: the `reauth_required` envelope today carries an overslash auth URL (`AuthRecoveryUrls`) for the user to reconnect through overslash. For an integration-managed connection that link is *wrong* — overslash has no client to mint it — so the envelope instead carries `integration_managed: true` (plus `connection_id` + `provider`) and **omits the auth URL**, telling the partner backend "*you* refresh this," not "send the user to overslash." Both signals fire: the `reauth_required` field on the failing action call **and** a `connection.refresh_required` webhook so the partner can refresh proactively before a call fails.

Implementation: one new column `connections.integration_managed boolean NOT NULL DEFAULT false` (migration `082_connection_token_vault`), set true at import exactly when `byoc_credential_id` is null. The action-handler auth resolvers (`resolve_service_auth`, `resolve_instance_auth` in `routes/actions/auth.rs`) branch on it **before** the credential cascade: `oauth::resolve_integration_managed_token` decrypts + injects the token while valid and returns `IntegrationManagedStale` once expired — no client resolution, no grant, no org/env fallback. The reauth arm then builds the envelope via `integration_managed_reauth_envelope` (no auth-URL mint, `integration_managed: true`) and fires the `connection.refresh_required` webhook. `GET /v1/connections/{id}` reports `credential_source: integration_managed` and `integration_managed: true`. The same migration drops `orgs.oauth_redirect_url` (082, ex-081) and `oauth_connection_flows.redirect_uri` (ex-079).

## Q1 — Can we vault providers without their client id/secret? Should we?

**Can we?** Yes — for *store* and *execute*. Overslash can hold and inject a bearer access token (and even a refresh_token it won't itself use) with no knowledge of the client credentials. This is exactly the integration-managed mode above, and it generalizes cleanly to credentials that have **no client/secret concept at all** — long-lived PATs, opaque API bearer tokens — which overslash already injects elsewhere.

**Should we?** Yes, as an explicit, documented capability, because:
1. Some partners won't share an OAuth client secret with overslash (trust boundary) and want to keep the OAuth client fully in-house.
2. Some credentials simply have no refresh/secret (PATs, machine tokens).
3. It keeps overslash a *generic* vault, consistent with Rule 4 ("no platform-specific logic") and its stated identity (secret management + authenticated execution).

…with one honest caveat in the contract: **without a client, overslash cannot refresh**, so the connection lives only as long as the imported token and the partner's willingness to re-import. For overslash's core value — autonomous agent execution — **self-refresh via BYOC is the recommended path**, and the docs/dashboard should nudge partners toward registering a client. We support secretless; we recommend BYOC.

## What stays vs. what's removed

**Stays** — orchestrated OAuth for everyone who is *not* a white-label partner (normal orgs, the dashboard's own "Try it"/Connect/reconnect): overslash builds the authorize URL, the browser completes at `GET /v1/oauth/callback`, the popup+poll resolves it. These flows always use the default `{public_url}/v1/oauth/callback` — there is no longer any redirect override to choose. BYOC, the credential cascade, refresh, and connection storage are unchanged.

**Removed** (white-label-via-orchestration, now obsolete):
- `POST /v1/oauth/exchange` + the `oauth_callback` guard that split white-label vs. browser completion.
- `include_raw` / the raw authorize URL surface on `POST /v1/connections`, `/upgrade_scopes`, MCP `create_service`, and the `raw` response fields + MCP strip — partners build their own authorize URLs now.
- `oauth_connection_flows.redirect_uri` (migration 079) — every orchestrated flow uses the default callback, so the column is always NULL.
- All of #398: `orgs.oauth_redirect_url` (migration 081), `use_org_redirect`, the `/v1/orgs/{id}/oauth-redirect-settings` endpoints, and the dashboard "OAuth redirect URL" section.

The `return_url` reactive-redirect machinery (DECISIONS D16) is *orthogonal* and left in place for now; it is a candidate for later cleanup once we confirm no orchestrated flow relies on the 303-back.

## Migration / breaking changes

Breaking for the one white-label consumer (Overfolder), which is acceptable (owner-confirmed) and already mid-migration: #398 removed the per-request `redirect_uri` it depended on, so Overfolder must change regardless. Token-vault means Overfolder migrates *once* (to `import`) rather than twice (to `use_org_redirect`, then to `import`). Overfolder-side work (run its own exchange, call `POST /v1/connections/import`, stop calling `/v1/oauth/exchange` and dropping `connect_redirect_uri`/`include_raw`) is tracked separately — this design is overslash-only.

## Security considerations

- Tokens arrive in a request body — same threat model as secret-provide: TLS + org API key + AES-256-GCM at rest; tokens never returned via API.
- Overslash trusts the partner's consent (scopes, the account identity) — appropriate for a first-party partner; the permission-chain + approval gates still apply at **execution** time regardless of token provenance.
- Imports are identity-bound and `on_behalf_of`-validated, so an imported connection lands on exactly the agent/user the caller is authorized to write.

## Resolved decisions

1. **Field name** — `connections.integration_managed` (boolean). Marks a connection whose refresh/re-auth is the integration's responsibility.
2. **Signaling** — build **both** now: the `integration_managed` field on the `reauth_required` action-call envelope (replacing the reconnect link for these connections) **and** the `connection.refresh_required` webhook.
3. **Refresh client** — `byoc_credential_id` is the only way to supply a client and it is **nullable**. Non-null ⇒ overslash self-refreshes, hard-pinned to that client. Null ⇒ `integration_managed = true`; overslash refreshes only when it knows the client, and **does not fall back to the env/org `OAUTH_*_CLIENT` cascade** for imported connections. No inline client_id/secret on `import`.
