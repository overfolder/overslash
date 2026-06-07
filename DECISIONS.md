# Overslash — Decisions

Settled architectural decisions. Don't re-litigate without new information.

---

## D1: Standalone service, not a library

**Date**: 2026-03
**Decision**: Overslash is a standalone REST API service, not embedded in Overfolder's agent-runner.
**Rationale**: Auth, secrets, approvals, and action execution are general-purpose. Any agent platform should be able to use Overslash. Decoupling also simplifies agent-runner.

## D2: Replace Nango with native OAuth

**Date**: 2026-03
**Decision**: Overslash owns OAuth flows natively instead of using Nango.
**Rationale**: Nango adds a dependency and limits control over the token lifecycle. Overslash needs tight integration between OAuth tokens, permission rules, and approval workflows. See `docs/design/nango-integration.md` for the evaluation that led to this decision.

## D3: Rust + Axum (same stack as Overfolder)

**Date**: 2026-03
**Decision**: Use Rust/Axum, matching the Overfolder stack.
**Rationale**: Shared expertise, proven stack, consistent tooling. AES-256-GCM for secrets at rest.

## D4: Valkey over Redis

**Date**: 2026-03
**Decision**: Use Valkey (not Redis) for caching and pub/sub.
**Rationale**: Valkey is the open-source fork of Redis, maintained by the Linux Foundation. License-compatible, drop-in replacement, actively developed. No reason to use Redis's restrictive SSPL license.

## D5: Cloud SQL Auth Proxy by default (no VPC)

**Date**: 2026-03
**Decision**: Default to Cloud SQL Auth Proxy mode instead of VPC private networking.
**Rationale**: VPC connector costs ~$7/month even idle. Auth Proxy is free, secure (IAM-authenticated), and sufficient for pre-GA. VPC mode is available via `use_private_vpc = true` for production hardening later.

## D6: Podman-first container tooling

**Date**: 2026-03
**Decision**: Prefer Podman / podman-compose over Docker where available.
**Rationale**: Rootless by default, daemonless, OCI-compliant. Docker is supported as fallback. Makefile auto-detects `podman-compose` first.

## D7: Identity hierarchy with live inheritance

**Date**: 2026-03
**Decision**: `inherit_permissions` is a live pointer, not a copy. Child dynamically has parent's current + future rules.
**Rationale**: Static copies create drift. Live pointers mean granting a user a new permission automatically flows to their agents. See SPEC.md for full design.

## D8: Two-tier rate limiting (User bucket + identity caps)

**Date**: 2026-04
**Decision**: Rate limits use two counters per request: a User-level bucket (shared by all agents under that user) and optional per-identity caps. Not per-agent buckets alone.
**Rationale**: Per-agent-only limits are easily circumvented by spawning sub-agents. The User bucket ensures a hard ceiling regardless of agent topology. Identity caps are a convenience for isolating misconfigured agents from consuming the entire User budget. See SPEC.md §13.

## D9: Merge queue on `dev`, merge-commits on `master`

**Date**: 2026-04
**Decision**: PRs target `dev` and merge through GitHub's merge queue (squash, ALLGREEN, required check `ci-ok`, strict-up-to-date off — the queue handles rebasing). `dev` flows to `master` via **merge commits only** (`master` ruleset disallows squash/rebase) so feature history is preserved on `master`. Repo was made public to unlock merge queue without an Enterprise upgrade. The Stop hook arms `gh pr merge --auto --squash` once its three gates pass, but **only when the PR's base branch is `dev`** — never on PRs targeting `master`.
**Rationale**: Keeping branches up-to-date with base was a recurring source of agent churn. The merge queue serializes PRs and rebases them in-place, eliminating that responsibility. Squash on `dev` keeps feature PRs as single commits; merge-commits on `master` retain the full feature history at release-cut time. See `.claude/hooks/pr-mergeability-gate.sh` and rulesets `dev` (id 14770759) / `master` (id 14707284).

## D10: MCP over Streamable HTTP + OAuth 2.1

**Date**: 2026-04
**Decision**: MCP clients connect via `POST /mcp` on the API, gated by `Authorization: Bearer`. Two single-credential modes: user JWT (aud=mcp, minted via `/oauth/authorize` → `/oauth/token` on the same Axum process) or static `osk_…` agent API key. The dual-credential model and stdio-only transport are retired. `overslash mcp` becomes a thin stdio↔HTTP compat shim for editors whose MCP transport is stdio-only; `overslash mcp login` runs the standard OAuth Authorization Code + PKCE flow and writes `~/.config/overslash/mcp.json`.
**Rationale**: OAuth 2.1 is the standard auth flow in the MCP spec, and Streamable HTTP is the reference transport for remote MCP. Hosting the Authorization Server (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`) next to the API means DCR, consent, refresh, and revocation share infra and reuse the existing IdP login flow. Editors speaking stdio get the compat shim so Overslash doesn't break their setup. Implementation landed in PR #121 (single binary) and PR #123 (HTTP transport + AS). Full design at `docs/design/mcp-oauth-transport.md`.

## D11: Semantic search uses local pgvector + fastembed, not an API

**Date**: 2026-04
**Decision**: `GET /v1/search` (§10) ranks candidates with a hybrid of keyword + Jaro-Winkler fuzzy and pgvector cosine similarity, where the embeddings come from **locally hosted** `BAAI/bge-small-en-v1.5` (384-dim) via the `fastembed` crate. Dev, CI, and the shipped compose images run `pgvector/pgvector:pg16`; vanilla Postgres is supported — both the extension migration and the table migration are wrapped in `DO $$` blocks that probe `pg_available_extensions` and no-op cleanly. A boot-time preflight (`SELECT … FROM pg_extension`) plus the env kill-switch `OVERSLASH_EMBEDDINGS=off` force-disable embeddings at runtime; search then falls back to keyword + fuzzy transparently.
**Rationale**: The service/action catalog is tiny (~9 global templates × ~20 actions plus DB-tier templates) — an external embedding API would add a per-query cost, a new secret, and network latency for a corpus that fits trivially in CPU-embedded memory. The local model is a one-time ~130 MB download cached under `OVERSLASH_EMBED_CACHE_DIR`; ONNX runtime adds ~40 MB to the binary, which is acceptable for a single-binary server distribution (the `embeddings` Cargo feature lets library consumers opt out). Keyword + fuzzy alone handles exact matches and typos well but misses paraphrased intent — the embedding signal covers that gap, and the hybrid weighting (0.4 keyword + 0.6 embedding) keeps exact service / action names dominant when they match literally. The pgvector no-op path means a self-hosted deploy on vanilla Postgres still boots and serves search, just without the embedding signal.

## D12: Multi-org trust model — each IdP is its own trust domain

**Date**: 2026-04 (amended 2026-05)
**Decision**: Overslash treats each IdP as its own trust domain. An IdP can only admit members into resources it controls: Overslash-level IdPs admit into personal orgs and into corp orgs the user themselves created (the creator becomes a regular admin of the new org); per-org IdPs admit into that org only. Users are keyed at auth time by `(provider, subject)`, never by email. There is no cross-IdP account linking — a human who uses Google for their personal Overslash account and Okta for Acme simply has two distinct `users` rows.
**Rationale**: If email alone could attach a login to an existing membership, a user who registers a Google account claiming `amartcan@acme.org` would inherit whatever Acme provisioned for its real employee via Okta. By restricting each IdP to its own trust domain, an external IdP (Google) cannot vouch its way into resources controlled by an internal one (Acme's Okta).

**2026-05 amendment — opt-in invite-gated admission**: a corp org may opt in (via `orgs.allow_overslash_managed_signin`, default `true` for new orgs) to invite-gated membership. Two things change when the flag is on:

1. Authentication via Overslash's shared OAuth apps (`GOOGLE_AUTH_*`, `GITHUB_AUTH_*`, future env-var providers) becomes available — until now D12 forbade env-var creds on corp subdomains.
2. **Every** sign-in into the org — including authentications through a dedicated `org_idp_configs` row — must match a pending `org_invites(email, role)` allowlist entry. The `allowed_email_domains` whitelist is bypassed when the flag is on.

The trust boundary moves from "the IdP's domain claim" to "the admin's curated invite list." The email-spoofing concern the original D12 raised against invites does not apply: there is no second-source IdP to phish (no Okta-backed phantom employee to inherit from); the admin's invite list is the only path in, and each invite is for a specific email the admin chose. Existing orgs stay opted out until an admin flips the toggle. Full design at `docs/design/multi_org_auth.md`.

## D13: Auto-call-on-approve is a per-Identity setting (default on)

**Date**: 2026-05
**Decision**: `auto_call_on_approve` lives on the agent identity itself (`identities.auto_call_on_approve`, default `true`) and applies uniformly to MCP, REST, and white-label agents — there is no separate per-MCP-binding column anymore. Org admins can flip `orgs.default_deferred_execution` to seed *new* agents with auto-call OFF (existing agents keep their value). When auto-call is ON, the `approval.executed` webhook payload includes the full execution `result` (only when `triggered_by="auto"` and the call succeeded); manual `/call` paths omit it because the caller already received the result inline. The toggle also governs cascade-resolved approvals (`resolved_by='cascade'`): each cascaded approval is auto-called per its *own* requesting identity's setting; because cascade executions are created with `remember=false`, a cascade-triggered replay never writes rules or re-cascades.
**Rationale**: Pre-migration the toggle was on `mcp_client_agent_bindings`, so REST API agents and white-label embeddings (Overfolder, etc.) silently fell through to manual-only `POST /v1/approvals/{id}/call`. White-label platforms are explicitly first-class consumers per SPEC.md §1, and the bound-to-MCP gate forced every white-label integration to do an extra round-trip on every approval. Moving the toggle to the identity makes the policy uniform across surfaces; the org-level default lets a tenant flip the policy without touching individual agents; and including the result in the webhook lets a white-label UI render the outcome from a single delivery instead of a follow-up `GET /v1/approvals/{id}/execution`. Manual-call paths are unchanged because the caller already has the response.

## D14: `connection: <uuid>` action calls removed; free-form authed calls go through Service + HTTP verb

**Date**: 2026-05
**Decision**: `POST /v1/actions/call` no longer accepts a top-level `connection: <uuid>` field. Callers that previously used it (raw URL + stored OAuth connection) must instead use SPEC §8 "Service + HTTP verb" — naming a service instance plus `method` + `path` (or `url`). The instance binding provides auth; the template's `hosts[]` bounds where the bearer can land. The `CallRequest` parser uses `deny_unknown_fields`, so stale callers get a parse-time 400 naming the removed field.
**Rationale**: The connection-based shape was an implementation deviation from SPEC §8 and carried a host-binding gap — `host(req.url)` was never validated against the connection's `provider_key`, so an agent with a managed OAuth connection could direct the bearer at any URL and exfiltrate the token. Implementing SPEC §8 "Service + HTTP verb" subsumes the legitimate use case (free-form authed calls) while inheriting the host bound from `svc.hosts`. Removing the deviated shape is a straight code-and-surface reduction; nothing in-tree depended on it that wasn't trivially rewritable to the verb shape.

## D15: Mode A is the `http` service instance, not a separate code path

**Date**: 2026-05
**Decision**: Mode A (raw HTTP) is implemented as the **synthetic `http` service**: a global template (`hosts: []`, `auth: []`, `runtime: Http`) shipped in the registry and a system-managed org-level service instance (`is_system = true`, no owner, no credentials) created for every org at bootstrap. Callers send `service: "http"` with `method` + `url` (the no-`service` legacy shape is rejected with a 400 carrying a migration hint). The `groups.allow_raw_http` boolean was dropped in migration 063 — group access to raw HTTP flows through the standard `group_grants` mechanism on the `http` instance, with the same access-level → verb-risk mapping as any other service. Permission keys derive identically to the legacy form (`http:{METHOD}:{host}{path}`) so existing rules continue to match.
**Rationale**: Pre-migration, raw HTTP carried two parallel code paths (a separate Mode A branch in `actions.rs::resolve_request` and `resolve_action_metadata`, a `service_name == "http"` special case in `check_group_ceiling`, and a dedicated `PermissionKey::from_http` builder) plus a special-purpose `allow_raw_http` boolean. Treating `http` as just another service collapses all four into the standard verb-shape path: `actions.rs` loses ~60 lines of branch duplication, `permissions.rs` loses the http special case + `from_http`, the column is gone, the dashboard's standalone "Allow raw HTTP" toggle disappears (raw HTTP is granted via the same UI as `github` or `slack`), and access-level granularity gains read/write/admin instead of a binary flag. Owner experience is unchanged — Everyone+Admins keep an admin grant on the `http` instance from the migration backfill, mirroring the prior `allow_raw_http = true` default. Org admins can now downgrade or revoke raw HTTP per-group like any other service.

## D16: Reactive auth flows carry the caller's `return_url`

**Date**: 2026-05
**Decision**: `POST /v1/actions/call` accepts an optional `return_url` body field. When a call reactively mints an OAuth flow — `reauth_required` (refresh-token failed / no refresh token), `missing_scopes` (incremental scope upgrade), or `needs_authentication` (no connection yet) — that `return_url` is stamped onto the minted flow row, so the `/v1/oauth/callback` handler 303-redirects the user back to the partner once consent completes, identical to the first-connect path. The hint is format-validated once at the request boundary (`parse_return_url` → 400 on malformed input); the host is re-checked against `OVERSLASH_CONNECTION_RETURN_URL_HOSTS` at callback time, and an off-list host silently falls back to the historical JSON response.
**Rationale**: First-time connects already pass `connect_return_url` → flow row → callback 303. But reactive reauth/upgrade flows are minted server-side during a *failed* action call, where the partner had no first-class place to supply a return URL, so they hardcoded `return_url: None` and the user landed on raw callback JSON. A body-field hint on the action call (mirroring `return_url` on the connect endpoint) closes the gap with no new transport surface and reuses the existing boundary validator and callback-side allow-list gate unchanged. The org-config alternative (a per-org configured callback URL) was rejected as heavier schema for no extra safety — the allow-list already bounds where the callback will redirect.

## D17: Builtin GitHub service uses GitHub App user-to-server OAuth

**Date**: 2026-06
**Decision**: The shipped `services/github.yaml` template targets **GitHub App user-to-server tokens**: the OAuth flow declares no scopes (GitHub Apps ignore the `scope` parameter — access is the intersection of the app's fine-grained permissions and its installations), and the org's configured GitHub client credentials (`OAUTH_GITHUB_CLIENT_ID`/`SECRET` or BYOC) must belong to a GitHub App. The previous classic-OAuth-App template is retained verbatim as `services/github_legacy_oauth.yaml` (key `github_legacy_oauth`, title "GitHub (Legacy OAuth)") for orgs whose configured client is still an OAuth App; it is pre-annotated `x-overslash-hidden: true` in its info block so it drops out of the catalog once hidden-template support lands. Both templates keep `provider: github` — same provider row, credentials cascade, and connections pool, so existing connections and permission rules (`github:<action>:{repo}`) work unchanged. Installation (server-to-server) tokens are out of scope — they need RS256 JWT signing with an app private key, which doesn't exist in the gateway yet.
**Rationale**: GitHub recommends GitHub Apps over OAuth Apps: fine-grained per-repo permissions instead of broad `repo` scope, and short-lived (~8h) tokens with refresh. The user-to-server flow is endpoint-compatible with the OAuth App flow (same authorize/token URLs, same code-exchange and refresh grants), so the migration is template-only: the existing refresh machinery handles expiring tokens (`oauth_providers.supports_refresh` defaults true), the scope gate passes because github actions declare no `required_scopes`, and the `default_identity_scopes` sent on the authorize URL are harmlessly ignored by GitHub Apps. Keeping the legacy template as a separate hidden key (instead of mutating `github` in place per-org) gives OAuth-App orgs a zero-breakage path while new setups land on the recommended model.

## D18: Audit response-body capture is org-opt-in, inline, and truncated; transport failures always audit

**Date**: 2026-06
**Decision**: Upstream response bodies can be persisted on `action.executed` audit rows under `detail.response` (`{body, truncated, content_type}`), governed by a new org setting `orgs.audit_response_body_mode` (`off` default / `errors_only` / `all`, managed via `GET/PATCH /v1/orgs/{id}/audit-settings`). "Error" reuses the normalized `detail.is_error` semantics (upstream HTTP ≥ 400, MCP in-band error). Bodies are stored inline in the existing `detail` JSONB as strings — truncated at a char boundary to `AUDIT_RESPONSE_BODY_MAX_BYTES` (64 KB default) and NUL-sanitized (Postgres rejects ` ` in jsonb and `log_audit` swallows errors, so an unsanitized body would silently drop the row). Streamed executions record `response: {skipped: "streamed"}` instead — their bodies never pass through a buffer. Platform-runtime calls are excluded (in-process, no upstream). Independently of the setting, transport-level failures (DNS/connect/timeout, response-too-large, MCP transport/JSON-RPC errors) now always write an `action.executed` row with `is_error: true` and a fixed-string `detail.error` `{kind, message}` — never the raw reqwest/MCP error text, whose Display can carry the resolved URL with injected secrets.
**Rationale**: The response body is the most useful artifact when debugging a failed agent action, but storing every body is a privacy and storage liability — so capture is admin-gated, defaults off, and offers an errors-only middle mode (error payloads are small and the debugging gold; success bodies are the volume). Inline JSONB avoids a migration and a lazy-fetch endpoint at 64 KB scale; a string (not parsed JSON) keeps one predictable shape since truncated bodies rarely parse. The transport-failure rows fix an audit blind spot: before this, a DNS failure or timeout was visible in metrics (#368) but wrote no audit row at all — `is_error` only covered responses that arrived.
