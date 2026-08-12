# Overslash — Tech Debt

Known workarounds and deferred improvements.

---

## CI seeds ort-sys binaries from a release asset (cdn.pyke.io outage)

Since 2026-07-03, `cdn.pyke.io` answers HTTP 403 (Cloudflare bot challenge) to non-browser clients, so any CI job compiling `ort-sys` 2.0.0-rc.12 (pulled in via `fastembed` for semantic search) from a cold cache fails at the build script's binary download. Workaround: `.github/actions/seed-ort-cache` pre-populates `~/.cache/ort.pyke.io` in the `lint`, `coverage`, and `e2e` jobs from the `ort-sys-cache-ms-1.24.2` release asset (the build script's own hash-verified extraction, re-hosted), which makes the build script skip the download entirely. Remove the action and the release once the CDN is reliable again, and refresh the asset + dist hash whenever `ort-sys` is bumped (`build/download/dist.txt` in the crate lists the current hashes). `release.yml` is not covered — it builds non-Linux targets too and needs per-target assets if the outage persists into a release.

---

## Display-param resolver GETs: query-param credentials and the SSRF guard

`services::param_resolver::resolve_display_params` fires an authenticated GET
per `x-overslash-resolve` declaration so approvals can name an object instead
of its id. Two gaps remain in how those GETs are made
(`routes/actions/resolve.rs`, at the `resolver_headers` construction):

1. **`in: query` credentials do not reach them.** Header-injected credentials
   now do: OAuth arrives pre-materialized as `auth_header`, and secret-backed
   apiKey schemes (Metabase's `x-api-key`) go through the same
   `resolve_credential_values` + `inject_secrets` the executor runs. But
   `inject_secrets` appends query-param credentials to the request URL, and
   the resolver builds its own URL *inside* `resolve_display_params` — so the
   injection lands on a throwaway URL and is discarded. No shipped template
   pairs a query-param credential with a resolver; the day one does, the
   resolver URL has to be built before injection rather than inside the
   resolver. Symptom if it happens: the provider 401s, resolution silently
   fails, and the disclosure shows the raw id — never an error.

2. **They bypass the SSRF guard.** Resolver GETs go out on
   `state.http_client` directly, while the executor's own call goes through
   `services::ssrf_guard`. Same host either way (the resolver reuses the
   action's resolved base), so this is not a new reachable target — but it is
   an un-guarded egress on an operator-supplied URL, and it predates any
   particular template.

---

## Domain admission does not verify Google's `hd` claim, and two domain lists coexist

Migration 092 added org-wide domain admission for managed sign-in
(`orgs.managed_signin_allowed_domains`, consulted when
`require_invite_admission = false`). Two follow-ups:

1. **`hd` not honored.** Domain match splits the verified email on `@`
   (case-insensitive) in `provision_org_subdomain`
   (`crates/overslash-api/src/routes/auth.rs`). It does NOT consult Google's
   `hd`/hosted-domain claim — `OidcUserInfo` doesn't even parse it. A user
   with a personal Gmail whose *address* ends in an allowlisted domain (e.g.
   a `@reveni.io` alias not backed by Workspace) would match. Trust boundary:
   the verified-email domain, not cryptographic Workspace membership. To
   tighten, parse `hd` from the Google userinfo/ID token and require
   `hd == domain` on the managed path.

2. **Two allowlists.** The legacy per-org-IdP path still uses
   `org_idp_configs.allowed_email_domains` (per provider); the managed path
   uses the new org-wide list. The unwired cross-tenant primitive
   `OrgIdpConfigRepo::find_by_email_domain` /
   `find_idp_configs_by_email_domain`
   (`crates/overslash-db/src/repos/org_idp_config.rs`,
   `scopes/system_idp_config.rs`) only sees the per-provider list, so it is
   NOT a router for managed-signin domain admission. If we ever build generic
   domain→org routing, decide whether it should union both lists (or migrate
   the per-provider list onto `orgs`).

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

- **Member and grant counts derived client-side.** The list view fetches per-group grants/members in parallel to compute counts. Add aggregated counts to `GroupResponse` (or a `/v1/groups?include=counts` query) once group volume grows.
- **"Everyone" group not implemented.** UI_SPEC §Groups specifies an always-present "Everyone" group containing all users. Backend has no concept of it yet — the dashboard does not synthesize one.

---

## Dashboard: no BYOC replacement UX — RESOLVED

~~The Create Service form surfaces user-level BYOC state via `has_user_byoc_credential`…~~

Resolved by the §6 token-vault work (`docs/design/agent-credential-provisioning.md`):
`PUT /v1/byoc-credentials/{id}` replaces the encrypted client pair **in place** so the
credential id — and every `connections` row pinned to it — survives the rotation. Because
tokens minted under the old OAuth app can't be redeemed by the new one, the replace path
proactively sets the persisted `connections.reauth_required` flag on every pinned connection;
the action auth path short-circuits a flagged connection to the existing `reauth_required`
recovery envelope, and a fresh reconnect clears the flag. The dashboard exposes this as a
**Replace** action on each app in the profile's "My OAuth apps" list, and connections render a
"Reauth required" badge. (A dual-creds overlap window remains a possible future refinement, but
is not needed for correctness.)

---

## Pending Approvals date renders as "Requested Invalid Date"

The dashboard's approvals list shows the timestamp as `Requested Invalid Date`. Backend emits approval timestamps in a serialization format the frontend parser does not accept (likely a chrono default that skips the trailing `Z` or uses space-separated date/time). Fix: pick one ISO-8601 shape at the API boundary (probably `DateTime<Utc>` → RFC 3339 with `Z`) and update dashboard parsers to match. Tracked under card `2e268`.

---

## Reusing existing Google OAuth connections fails

Choosing a previously-authorized Google connection on a newly-created Google service does not bind the service to the existing token; the connection stays unlinked and the service remains in `pending_credentials`. Suspected cause: the service-instance → connection mapping does not match by `(provider, subject)` — probably by `connection_id` only — so the dashboard's "reuse existing" picker writes a binding the backend doesn't honor. Relates to the broader 2026-04-20 review ask to support reusing connections across services sharing a provider. Tracked under card `c2575`.

---

## Manual `cargo update` is not covered by the 7-day dependency cooldown

D30 gates automated dependency bumps behind Dependabot's 7-day `cooldown`, but a manual `cargo update` on the stable toolchain can still pull a version published minutes ago. Cargo's client-side gate (`min-publish-age`, RFC 3923) is nightly-only as of 2026-07, and the forward-compatible `.cargo/config.toml` staging used in overfolder isn't possible here because `.cargo/` is gitignored (reserved for developers' local mold-linker config). When `min-publish-age` stabilizes, either commit a tracked `.cargo/config.toml` (migrating the mold convention to e.g. `.cargo/config.local.toml` isn't a thing — cargo reads a fixed filename — so this means un-ignoring the path and folding mold config in, or documenting `CARGO_*` env vars instead) or set `CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE` in CI. Low urgency: updates normally flow through Dependabot, which does enforce the window.

---

## Two SHA-pinned actions track branches, so Dependabot won't bump them

D31 pins every third-party action in `.github/workflows/*.yml` to a commit SHA so D30's `cooldown` applies. Two of those pins freeze a *moving pointer* rather than a release tag, and Dependabot's version-update logic tracks tags/releases — so it will not reliably propose bumps for either:

- `dtolnay/rust-toolchain@4be7066` — its ref is the `stable` **branch**, not a semver tag; the branch tip is what we froze. (Overfolder carries the same debt.) Note the branch name no longer selects the toolchain: every step now passes an explicit `toolchain: "1.97"` matching `rust-toolchain.toml`, so only the *action code* rides the branch.
- `rui314/setup-mold@9c9c13b` — the repo publishes no semver releases at all, only a mutable `v1` tag that moves.

Both still behave correctly at runtime — rustup installs the toolchain the step asks for; mold installs normally. Only the *action code* is frozen, so upstream fixes won't be picked up automatically and the pins can drift stale silently with no PR. Low risk (both actions are small and stable), but they're untracked pins. Ideal fix: re-pin each to its current tip by hand periodically (e.g. quarterly), or switch to a version-tagged equivalent with the same ergonomics if one appears, so Dependabot can manage it.

---

## `SecretRef::encode` is deserialized and ignored for one release

D35 replaced `x-overslash-encode` with a jq credential template, but
`ActionRequest`s persisted on approvals created *before* that deploy still
carry `encode` on their `secrets[]`. `SecretRef` keeps the field as
`#[serde(default, skip_serializing)]` — accepted on read, never written, never
applied — purely so such an approval still *deserialises* rather than failing
to parse.

It is not replayable, though, and deliberately so: applying the surviving
prefix without the dropped base64 would send `Basic user:pass` upstream, which
reads as a wrong password rather than as our bug. `resolve_credential_values`
therefore rejects any `SecretRef` still carrying `encode` with "re-issue the
call". In practice this is the one `email`/`mailbox` shape, whose instances
must be rebound to two slots anyway (see D35 rollout). Drop the field once no
pending approval predates the deploy.

## Non-JSON `requestBody` media types are parsed but never sent

`ServiceAction::request_body` records whatever media type a template declares
under `requestBody.content` (`crates/overslash-core/src/openapi/extract.rs`,
`parse_request_body`), but two places still only understand JSON:

- `collect_body_parameters` reads the schema from `content["application/json"]`
  only, so a form-encoded or multipart body extracts **zero** params — the
  action shows no body fields to agents, and validation has nothing to check.
- Routing (`crates/overslash-api/src/routes/actions/resolve.rs`) sends a body
  only when `RequestBodySpec::is_json()`, so a declared non-JSON body results in
  no body and no `Content-Type` at all.

This is latent: every shipped template in `services/` declares
`application/json`. Before, such a body would have been silently re-serialised
*as JSON* under a `Content-Type: application/json` the template never asked for;
recording the real media type at least makes the mismatch legible rather than
wrong-on-the-wire. To actually support one (a multipart attachment upload is the
likely first caller), teach `collect_body_parameters` to pick the schema for the
declared media type and give routing an encoder per type, keyed off
`RequestBodySpec::content_type`.

## An unresolvable instance credential sends an unauthenticated request

When a service instance cannot resolve its credentials — an unbound secret slot,
or (since D38) a `required` config var with no value — `resolve_instance_auth`
sets `instance_secret_missing` and deliberately declines to return a partial
credential set. It then falls through to `resolve_service_auth`, which only
knows about OAuth and env-backed secrets. For a template like `email` that has
neither, resolution ends with *no* credentials and the call is sent upstream
**unauthenticated**, returning whatever the upstream says (a 401 from a real
overfwd) rather than a `needs_authentication` prompt naming what to configure.

Verified on `email`: both an unbound `mailbox_pass` and a missing `mailbox_user`
produce an outbound request carrying neither `X-Mailbox-Auth` nor the org
`Authorization` — correct in that nothing partial or truncated is ever sent, but
the caller gets a confusing upstream error instead of "go set this field".

The safety property is covered (`email_unbound_mailbox_never_injects_gateway_key_alone`,
`email_missing_required_config_never_sends_a_truncated_credential`); the UX is
not. Fixing it means short-circuiting to `needs_authentication` when the template
declares no OAuth and no env fallback, which changes behaviour for every
secret-backed template — deliberately out of scope for D38, which only had to
match the existing unbound-slot contract.

---

## Object-array recipients can't be scoped — `scope_param` names params, not values inside them

`scope_param` now accepts a list with per-entry labels
(`[to:recipient, cc:recipient, bcc:recipient]` on `services/email.yaml`), which
gates a send on every address regardless of header. That works because
`email`'s recipient params are arrays of plain strings.

The other mail/calendar templates cannot use it:

- `outlook.yaml` — `toRecipients`/`ccRecipients`/`bccRecipients` are arrays of
  `{emailAddress: {address, name}}` objects.
- `google_calendar.yaml` — `create_event.attendees` is an array of `{email}`.
- `gmail.yaml` — `send_message` takes one base64url RFC 2822 `raw` blob; there
  is no recipient param at all (it scopes on `userId`).

Pointing `scope_param` at an object array would derive keys whose value is the
JSON literal of the object — nothing a rule can match and nothing a human can
read — so those templates keep their existing service/mailbox-level scoping
(`outlook` has no `scope_param` on `send_mail`; the others scope on the
mailbox/calendar id).

Closing it needs a value *extractor* on a scope entry (a jq filter, in the
shape `disclose` already uses) so a template can say "the scope values are
`.toRecipients[].emailAddress.address`". That is a bigger change than the
label syntax: it puts a filter on the permission-derivation path, which today
is pure string handling and runs before any approval exists.

## SQL policy: Windows release binary ships without the parser

`sql_policy` (D42/D43) builds vendored libpg_query — a C build verified on
the Linux/macOS release runners but not on `windows-latest` (pg_query.rs uses
bindgen, and libpg_query only gained MSVC support recently). The release
matrix therefore enables the feature everywhere **except**
`x86_64-pc-windows-msvc`, where the binary fails closed: every
`risk: dynamic` action classifies write-on-unknown-tables and routes to
approval. Correct but read-path-less. To close: try
`features: embed-dashboard,sql_policy` on the Windows matrix row (LLVM is
preinstalled on the runner), and delete this entry if the build passes.

Windows is now the *only* build without the parser. The Cloud Run image
(`crates/overslash-api/Dockerfile`, which serves both dev and prod via
`infra/modules/cloud-build`) shipped without it for the whole 0.7 line — its
`cargo build` carried no `--features`, so every SQL call on the hosted
deployments classified `sql_reason:unavailable` and bubbled to approval with
no table analysis at all, while the release-binary matrix above made it look
handled. Both `cargo build` lines in that Dockerfile now pass
`--features sql_policy`, and `GET /v1/version` / `/health` report a
`sql_policy` boolean so the question is answerable without reading a build
recipe. Keep the two Dockerfile invocations identical — the first is
`cargo chef cook`, which exists only to warm the dependency layer, and a
feature mismatch between it and the real `cargo build` silently wastes it.

Two adjacent small items:

- **Metabase `{{template_vars}}` don't parse** → classify write. If agents
  want Metabase-variable queries approval-free, add a pre-parse substitution
  step (bind `native_parameters` values before classification).
- **`EXPLAIN` (without `ANALYZE`) classifies write** — a deliberate
  fail-closed simplification (`EXPLAIN ANALYZE` executes DML, so
  whitelisting bare EXPLAIN means recursing into the option list). Relax in
  `sql_policy/analyze.rs` if the prompt-noise ever matters.

## Deferred downloads don't carry the D56 timeout cascade

`GET /v1/downloads/{token}` re-dials the upstream at fetch time
(`services/deferred_download.rs`), and that request is bounded by the bare
deployment default (`CALL_TIMEOUT_MS`) rather than by the layered timeout the
original call resolved. There is no caller-supplied `timeout_ms` on a token
redemption and no action key to read the template rungs from — the request was
resolved when the token was minted, possibly under different org policy — so
the cascade has nowhere to come from without persisting the resolved budget
alongside the stored request.

Bounding the header phase at the default is already a strict improvement on
the unbounded wait it replaced, so this is a fidelity gap rather than a hole.
The fix is to store the resolved timeout on the `download_tokens` row at mint
and re-clamp it at redemption, exactly as replay does with
`StoredCallRequest::timeout_ms`.

Related: the proxied fetch is itself a request through the same 120s cap the
synchronous ceiling is sized against, so a genuinely multi-minute export is not
deliverable through this path regardless of what timeout it carries.

## `Config` has no `Default`, so every new field touches ~17 test literals

`crates/overslash-api/src/config/mod.rs` defines `Config` with no `Default`
impl, and every construction site — one in-crate (`empty_test_config`) plus
sixteen across `tests/` — is an exhaustive struct literal with no
`..Default::default()` spread. Adding a single field is therefore a
seventeen-file mechanical diff before any of it can compile.

`ServiceAction` had the same problem and D56 fixed it there by deriving
`Default` and spreading at the two real construction sites. `Config` wants the
same treatment, but it is a bigger decision than it looks: the tests are a
separate binary, so a `#[cfg(test)]` helper cannot reach them, and a public
`Config::for_tests()` is a surface worth agreeing on rather than adding in
passing.
