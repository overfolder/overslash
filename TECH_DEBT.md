# Overslash — Tech Debt

Known workarounds and deferred improvements.

---

## MCP OAuth authorization codes are in-process

`POST /oauth/authorize` stashes one-shot authorization codes (60 s TTL, single-use) in a process-local store (`crates/overslash-api/src/services/oauth_as.rs`). This is fine today because codes expire fast and Overslash runs as a single replica. Moving to multi-replica serving either requires sticky-routing the `authorize` / `token` pair to the same instance or promoting the store to Redis. The `AuthCodeStore` facade is deliberately narrow so a Redis-backed implementation can drop in behind the same interface.

---

## `serde_yaml` is deprecated upstream

`overslash-core` uses `serde_yaml = "0.9"` for the registry loader and the template validator's YAML entry point. The crate was archived by dtolnay in 2024 and is no longer receiving updates. Current behavior is stable and well-tested, but we should migrate to `saphyr` / `yaml-rust2` eventually. The validator's duplicate-action-key detection parses a serde_yaml error string to extract the offending key — a drop-in replacement will need to re-derive that from whatever API the replacement exposes (probably easier, since `yaml-rust2`'s event API surfaces every key emission directly).

Scoped feature gate (`overslash-core/yaml`) already isolates the dependency so swapping it out shouldn't touch the rest of the crate.

---

## Dashboard: Identity Providers have no edit UI

The Org Settings → Identity Providers table only exposes toggle (enable/disable) and delete actions. The backend `PUT /v1/org-idp-configs/{id}` fully supports updating client_id/secret and flipping between dedicated credentials and `use_org_credentials` mode (see `CredentialsUpdate` in `crates/overslash-db/src/repos/org_idp_config.rs`), but the dashboard currently has no Edit action on existing rows — admins must delete and recreate. Add a full edit flow when we touch this page next.

---

## IdP env-var naming differs from service-OAuth env-var naming

IdP credentials fall back to `GOOGLE_AUTH_CLIENT_ID` / `GITHUB_AUTH_CLIENT_ID` (see `crates/overslash-api/src/config.rs` `env_auth_credentials`), while service OAuth (tier 3 of the SPEC §7 cascade) falls back to `OAUTH_{PROVIDER}_CLIENT_ID` / `OAUTH_{PROVIDER}_CLIENT_SECRET` (see `crates/overslash-api/src/services/client_credentials.rs`). The UI mirrors the service-OAuth naming for the new Org Settings → OAuth App Credentials section. Unifying the two env-var schemes is out of scope for the three-tier cascade PR but should happen together with a deprecation window.

---

## Dashboard: Org Groups page

- **Auto-approve toggle uses DELETE + POST.** `/v1/groups/{id}/grants` has no PATCH endpoint, so toggling `auto_approve_reads` removes the grant and re-adds it with the new value. Add a PATCH route and switch the dashboard to use it.
- **Member and grant counts derived client-side.** The list view fetches per-group grants/members in parallel to compute counts. Add aggregated counts to `GroupResponse` (or a `/v1/groups?include=counts` query) once group volume grows.
- **"Everyone" group not implemented.** UI_SPEC §Groups specifies an always-present "Everyone" group containing all users. Backend has no concept of it yet — the dashboard does not synthesize one.

---

## Dashboard: no BYOC replacement UX

The Create Service form surfaces user-level BYOC state via `has_user_byoc_credential` (from `/v1/oauth-providers`) and `ByocSection` renders a read-only "✓ Your {provider} OAuth app is configured" card when present. There is no in-place replace action: silently swapping the BYOC would invalidate every existing `connections` row authorized against the old client_id (tokens minted by one OAuth app are not redeemable by another). A proper replace flow needs (a) a settings page listing BYOC credentials with explicit delete, (b) a warning that lists impacted connections, and ideally (c) re-auth prompts or a dual-creds overlap window. Until then, users have to delete + recreate via `DELETE /v1/byoc-credentials/{id}` from profile/settings.
