# White-label OAuth as a token vault

**Status**: Approved — implemented (`POST /v1/connections/import`). Updated by migrations `084_orgs_headless` + `085_drop_connection_integration_managed`: the `integration_managed` flag from `082_connection_token_vault` is **removed** — its two conflated axes are split into (a) structural refreshability (a pinned `byoc_credential_id` self-refreshes; no stored boolean) and (b) a per-org `headless` capability that drives URL-less auth-recovery. Imports now **require** a `byoc_credential_id`.
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

The partner owns everything user-facing (consent screen, branding, domain, the code→token exchange). Overslash receives `{provider, access_token, refresh_token?, expires_at?, scopes?, account_email?, byoc_credential_id}` (the BYOC pin is required) and persists a connection **byte-identical to what an orchestrated callback produces** — same `connections` row, same encryption, same single-default semantics — so refresh, execution, permissions, and approvals all work unchanged downstream.

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
| `scopes` | – | granted scopes (labeling + scope-gate). Omitted ⇒ `null` = *unknown* (not `[]`): the action scope-gate gives the connection the **benefit of the doubt** (doesn't pre-emptively 403) since Overslash can't know what the imported token covers. Pass the granted set to opt into precise scope checking. |
| `account_email` | – | label; if omitted overslash best-effort fetches via `userinfo_endpoint` |
| `byoc_credential_id` | ✓ | the partner's registered client (see [agent-credential-provisioning](agent-credential-provisioning.md)); **required** — overslash self-refreshes hard-pinned to this client. A null value is **rejected with 400**. No inline client_id/secret — refresh creds always come from a stored BYOC row. |
| `on_behalf_of` | – | owner-user binding, same semantics as connect |

Behavior (`kernel_import_connection` in `services/platform_connections.rs`): validate `provider` exists and `byoc_credential_id` resolves for this org/provider (Tier-1 hard pin — a missing/null id 400s here, not at first refresh); resolve `expires_at`; best-effort `account_email` via the provider userinfo endpoint when not supplied; encrypt tokens (`crypto::encrypt`); upsert via the connection repo (`find_for_import` → `update_tokens_and_scopes`, else `create`); compute `is_default` (first per identity+provider); fire the `connection.created` / `connection.updated` audit + webhook. Returns the connection summary (`connection_id`, `provider`, `account_email`, `scopes`, `is_default`) — never the tokens.

Re-import is idempotent and keyed on `(identity, provider, account_email)` (or the identity's default connection for the provider when no email is given): it updates the existing row's tokens/scopes in place rather than accreting a duplicate — the partner's refresh loop re-imports rather than minting duplicates. A *different* `account_email` creates a distinct connection (multi-account vaulting). The pinned client is fixed at first import, and the match is pin-aware so an import never overwrites a connection it doesn't own:

- **Email-keyed match** (the caller named the account): an in-place update is intended, so a pinned-client *change* is **rejected with 400** rather than silently validated-and-discarded — delete and re-import to change.
- **Emailless match** (the `(identity, provider)` default-connection fallback): the row is reused **only when it pins the same client**. This stops an emailless import from overwriting a differently-pinned (or orchestrated, unpinned) connection that the fallback happens to match (e.g. one whose userinfo fetch left `account_email` NULL) — on a mismatch the import creates a fresh row instead.

A token-only re-import preserves fields it doesn't carry rather than wiping them: omitting `expires_at`/`expires_in` keeps the existing `token_expires_at` (otherwise the connection would look perpetually valid and never surface reauth), and omitting `scopes` keeps the existing granted scopes (otherwise every subsequent scope-gated call would 403). Supplying a fresh expiry or a non-empty scope set overrides the respective field.

## Q2 — What happens when we need refresh?

Access tokens are short-lived (Google ≈ 1 h); agents execute at arbitrary times, so overslash must obtain fresh tokens. The refresh-token grant (`grant_type=refresh_token`) needs **client_id + client_secret + refresh_token** — and crucially **no `redirect_uri`**. So refresh is independent of the whole redirect problem. Because every import pins a `byoc_credential_id`, **overslash always self-refreshes** an imported connection.

**Self-refresh (the only import mode).** Import carries a `refresh_token` and a **required** `byoc_credential_id` (the *same* client the partner used to mint the token). Overslash refreshes autonomously via the existing path (`oauth::resolve_access_token` → `refresh_token`), using **that BYOC credential only — a hard pin, not the cascade.** A refresh token is valid only against the client that issued it, so an imported connection must **never** fall back to an org-level `OAUTH_*_CLIENT` secret or the env/system client — a *different* client would mismatch or silently fail. This is the path that supports unattended agent execution past the first hour. (The earlier "integration-managed" no-client mode — inject-until-expiry, never refresh — is **removed**: a null pin is now a 400 at import.)

**Scope knowledge.** `connections.scopes` is nullable (migration `083_connection_scopes_nullable`): `NULL` = *unknown* (an import that didn't declare scopes), `{}`/array = the known granted set (orchestrated flows always record it from the token response). The action scope-gate (`check_required_scopes`) and the dashboard credential-health badge both treat `NULL` as **benefit of the doubt** — covering everything — so an imported token isn't falsely 403'd when the partner simply didn't declare scopes; a genuine shortfall still surfaces as the upstream's own error. The `missing_scopes` envelope reports both `required` (the action's full set) and `missing` (the delta to obtain).

## Headless orgs & URL-less auth-recovery

Self-refresh keeps a connection live as long as its refresh token works. When it *dies* (revoked, expired Google testing-client refresh) — or a scope is missing, or no connection exists yet — the action call must surface an auth gap. For a normal dashboard org overslash mints a **gated** `{public_url}/connect-authorize?id=<flow>` link the user opens to reconnect. **A white-label org's end users have no Overslash session**, so that link is a dead end and handing it to them is a white-label violation.

The fix is a per-org capability, `orgs.headless` (migration `084_orgs_headless`, admin-only via `GET`/`PATCH /v1/orgs/{id}/headless`). For a headless org, all three auth-recovery envelopes become **URL-less**:

| envelope | status | URL-less shape (headless) |
|---|---|---|
| `reauth_required` | 401 | omits `auth_url`/`short`; `headless: true`, `connection_id`, `provider`, `account_email`, `required_scopes` |
| `needs_authentication` | 401 | omits `auth_url`/`short`; `headless: true`, `provider`, `required_scopes` |
| `missing_scopes` | 403 | omits `auth_url`/`short` **and** `upgrade_url`; `headless: true`, `provider`, `account_email`, `required`/`missing` |

The `headless: true` discriminator appears **only** on the URL-less variant, so the gated envelopes agents normally see are unchanged. Crucially, **no `oauth_connection_flows` row is minted** — the recovery arms return before the URL-mint. The integration reads the envelope, re-runs its own OAuth dance against its own client, and re-imports (idempotent on identity+provider+account_email). No `connection.refresh_required` webhook is emitted — the signal is inline on the failing call.

This is orthogonal to refreshability: `headless` answers *who runs the user-facing flow*, `byoc_credential_id` answers *who refreshes*. The old `integration_managed` flag conflated the two.

Implementation: the auth resolvers (`resolve_service_auth`, `resolve_instance_auth`, `check_required_scopes`, `needs_authentication_for_service` in `routes/actions/auth.rs`) consult `org_is_headless()` at each recovery arm and return the URL-less envelope before minting; otherwise the gated path runs unchanged. `POST /v1/connections/{id}/upgrade_scopes` is rejected for headless orgs (they re-import with wider scopes). Every connection now flows through the normal `client_credentials::resolve` (pinned BYOC) + `resolve_access_token`. Migration `085_drop_connection_integration_managed` drops the column; `GET /v1/connections/{id}` reports `credential_source` as the pinned-BYOC/cascade source like any connection (no `integration_managed` field).

## Q1 — Can we vault providers without their client id/secret?

The original design supported a **secretless / no-client** import (inject a bearer token until expiry, never refresh). That mode is **no longer supported**: `import` now requires a `byoc_credential_id` so every imported connection self-refreshes. The trade-off it carried — a connection that lived only as long as the imported token and the partner's re-import loop — is exactly what made it weak for overslash's core value (autonomous agent execution past the first hour). Partners that previously relied on it register a BYOC client and import against it; the partner-side OAuth flow and re-import path are unchanged, only the pin is now mandatory.

Opaque credentials that genuinely have **no client/secret concept** (long-lived PATs, machine tokens) are still injected via the ordinary secret-bag surfaces; they are not OAuth connections and don't go through `import`.

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

1. **Two axes, not one** — the original `connections.integration_managed` flag conflated *who refreshes* with *who runs the user flow*. It is **removed** (migration `085`). Refreshability is now structural (a pinned `byoc_credential_id` self-refreshes); flow-ownership is the per-org `orgs.headless` capability (migration `084`).
2. **Import requires BYOC** — `byoc_credential_id` is **required**; a null pin is a 400. Overslash self-refreshes hard-pinned to that client, never the env/org `OAUTH_*_CLIENT` cascade. No inline client_id/secret on `import`. The secretless/no-client import mode is removed.
3. **Headless auth-recovery** — for a headless org, `reauth_required` / `needs_authentication` / `missing_scopes` return **URL-less** envelopes carrying `headless: true` + `provider`/`required_scopes`/`account_email`, mint **no** gated link and **no** `oauth_connection_flows` row, and emit **no** `connection.refresh_required` webhook (the old per-connection signal is dropped — the integration re-runs its dance and re-imports off the inline envelope). The gate is unchanged for non-headless orgs.
