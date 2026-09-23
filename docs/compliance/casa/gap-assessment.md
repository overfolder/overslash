# CASA gap assessment

Assessed against **CASA Specification v2.1.1 (2026-06-03)** and its Test Guide.
Planning for **AL2** (lab assessment) — see [README.md](README.md).

Assessed on 2026-09-22 against `origin/dev`. Every `pass` row cites a file and line;
re-verify citations at revalidation, because line numbers drift.

Rows about infrastructure were written from the Terraform in `infra/` and have since been
**measured against both live projects** — `overslash` and `overslash-dev`. Where a row
links to [gcp-posture.md](gcp-posture.md), the finding is confirmed in production, not
inferred. That document also carries three findings the IaC could not show, because they
are GCP defaults Terraform never created.

**Verdicts**

| | |
|---|---|
| `pass` | The control exists and the evidence is already in the repo |
| `statement` | The control exists but only holds with a written explanation; the lab will ask, and we need a prepared answer |
| `gap` | Would be raised as a finding today |
| `scan` | Only an authenticated DAST run can answer it; not assessable from source |
| `n/a` | Genuinely out of scope, with a reason |

**Severity** is *assessment* severity — how likely a lab is to raise it and how hard it is
to argue. It is deliberately separate from security severity: the rows below that are live
vulnerabilities carry both.

---

## Read this first: live vulnerabilities

These were found while assessing and are **not** compliance gaps. They were exploitable on
the `dev` head this document was written against, and were decided on their own timeline
rather than waiting for a CASA engagement. **Both are now fixed** — V2 first, then V1.
Each block below is kept as the record of what was wrong.

### V1 — Unrestricted SSRF on the action-execution path — **fixed**

*Fixed in the PR that carries this edit; the description below is kept as the record of
what was wrong, with the remedy and the residual at the end.*

Any authenticated org member could make Overslash issue an arbitrary HTTP request to an
internal address and read the response body.

- Mode A URL validation stops at "parses, scheme is `http`/`https`, has a host" —
  `crates/overslash-api/src/routes/actions/service_resolve.rs:311`. No IP resolution, no
  private/loopback/link-local check.
- Execution uses `state.http_client`, a bare `reqwest::Client::new()` —
  `crates/overslash-api/src/lib.rs:189`. That carries reqwest's **default redirect policy
  (follows up to 10)** and no DNS pinning, so even a host allowlist added at the URL layer
  would be defeated by a redirect or a rebind.
- Org bootstrap grants the `Everyone` group **`admin` on the `http` pseudo-service** —
  `crates/overslash-db/src/repos/org_bootstrap.rs:143-153` ("preserves the prior
  `allow_raw_http=true` default").
- Layer-2 approval is skipped for `kind == "user"` identities —
  `crates/overslash-api/src/routes/actions/permission_gate.rs:79` ("Users are gated by
  groups only — they are their own approvers").

So `POST /v1/actions/call {"service":"http","method":"GET","url":"http://169.254.169.254/…"}`
reached the metadata endpoint, and `http://localhost:*` reached anything the container
could. The same gap existed on webhook delivery — see 7.3.1.

**The remedy.** The fix was wiring, not design:
`crates/overslash-api/src/services/ssrf_guard.rs` was already correct — it denies loopback
/ private / link-local / CGNAT / broadcast / multicast / unspecified / documentation IPv4
and loopback / ULA / link-local / multicast IPv6, recurses into IPv4-mapped *and*
IPv4-compatible v6 addresses, pins the validated IP via `.resolve()` to close DNS
rebinding, and sets `Policy::none()` so a redirect cannot walk it inward. It was simply
not on this path.

It is now. `services/http_caller.rs` — the transport all five action-execution call sites
share — no longer *accepts* a `reqwest::Client`; it builds one per request from the URL
through `ssrf_guard::outbound_client`, so a new call site cannot reach the wire without
the guard. `services/webhook_dispatcher.rs::deliver` does the same for the registrant's
URL. A refusal is `CallError::Blocked`, which maps to a 400 and writes an
`action.executed` audit row with `detail.error.kind = "blocked"`. Coverage is
`crates/overslash-api/tests/ssrf_guard.rs`: the metadata endpoint, RFC1918, CGNAT, ULA
and v4-mapped addresses are refused on both the buffered and the streamed fork, a 302
toward the metadata endpoint is handed back rather than followed, and two positive
controls keep the loopback fakes honest.

**Fixed — SSRF on OIDC issuer discovery.** `routes/org_idp_configs.rs` fetches an
admin-supplied `issuer_url` in two places: when creating a custom-OIDC IdP and in the
`/discover` preview. Both used to go through the shared `state.http_client`, behind a
hand-rolled string check that never resolved DNS, and the handler echoed the upstream
error and body. That check is gone. `services/oidc_discovery.rs` now follows redirects
by hand and runs every hop through `ssrf_guard::outbound_client_validated`, the same
resolve-check-pin as V1. It adds a scheme rule of its own: `https`, or plain `http` only
when the *resolved* address is loopback. HTTP to a private range is refused even when an
operator allow-lists that range. After the input check, every failure returns one
generic error, and the detail (guard refusal, status, a body snippet cut on a char
boundary) is logged server-side instead, so the endpoint is no longer an oracle. Tests:
`tests/ssrf_guard.rs` (private-IP issuer, redirect to metadata and RFC1918, redirect
that downgrades to http, upstream body not echoed).

**Self-hosted private networking.** The deny-list would otherwise make Overslash
unable to reach a service on the operator's own network, so a self-hosted deployment
declares the ranges it needs in `OVERSLASH_SSRF_ALLOWED_CIDRS`. Operator-only (process
environment; no org, user, template or request can reach it), checked against the
resolved address rather than the URL, specific about which ranges it opens, and still
pinned. The multi-tenant deployment sets nothing, so its egress is public-only. There is
no boolean bypass — the previous `OVERSLASH_SSRF_ALLOW_PRIVATE` is gone.

The allow-list explicitly **cannot** reach the instance-metadata ranges (`169.254.0.0/16`,
`fd00:ec2::/32`, and the v4-in-v6 spellings of both): they are denied before it is
consulted, so not even `0.0.0.0/0` opens them. A second variable,
`OVERSLASH_DANGER_ALLOW_METADATA_CIDR`, is the only gate past that, and it opens nothing
by itself — it merely lets the allow-list cover those ranges. This is the answer to the
one 5.1.5 finding a lab will not adjudicate: the metadata endpoint is unreachable on any
configuration short of two deliberate, separately-named acts.

**Still open — the default grant.** Whether `Everyone` should hold `admin` on `http` by
default is a behaviour change for new orgs, so it was deliberately left to a human. The
comment says it preserves a migrated default; it is now the difference between "raw HTTP
requires a deliberate grant" and "raw HTTP is available to every member on day one".
Removing it is also what [dast-readiness.md](dast-readiness.md) needs to be able to tell
a scanning lab: that the default-configured product has no unbounded egress at all.

### V2 — Cross-tenant API-key minting — **FIXED**

> **Resolved.** `POST /v1/api-keys` no longer reads an org from the request body, and no
> longer has an unauthenticated branch. Three layers, plus the root cause. Regression
> cover in `crates/overslash-api/tests/api_key_org_binding.rs`.

**What it was.** `crates/overslash-api/src/routes/api_keys.rs:96` built
`OrgScope::new(req.org_id, …)` from the **request body**, and `req.org_id` was never
compared to `acl.org_id`. The admin branch then honoured a caller-supplied
`req.identity_id`. `api_keys` had separate foreign keys on `org_id` and `identity_id` and
**no composite constraint**, so the pair was never cross-validated at the database either.
An admin of org A could mint a live `osk_` key bound to an identity in org B.

**Why the field was there at all.** The same handler carried an *unauthenticated*
bootstrap branch — "no keys, no identities yet, so mint the org's first admin" — and that
branch has no credential to derive an org from. One route was holding two authorization
models, and the field the credential-less branch needed became the field the authenticated
branch trusted. That is the root cause, not the missing comparison.

**The fix.**

1. **The org is never named by the caller.** `create_api_key` takes `AdminAcl` + the
   `OrgScope` extractor, like the other 91 handlers in the routes tree. `org_id` is gone
   from `CreateApiKeyRequest`. The scope is minted from the presented credential — a
   session JWT's currently *active* org, which `/auth/switch-org` re-mints, or an `osk_`
   key's own org. Deriving from the *user* would have reintroduced the bug in a subtler
   form, because a human can belong to several orgs: an org-A session would look valid for
   a request naming org B. A multi-org human mints into B by being switched to B.
2. **The identity resolves through that scope.** `scope.get_identity(identity_id)` binds
   the org as a `WHERE` clause on the lookup rather than a comparison a later edit can
   drop; an id from another tenant is indistinguishable from one that does not exist
   (404).
3. **The database refuses the pair.** Migration 121 adds
   `UNIQUE (org_id, id)` on `identities` and a composite
   `api_keys (org_id, identity_id) REFERENCES identities (org_id, id)` foreign key, so a
   mismatched pair is rejected regardless of what any future handler does. It replaces
   the single-column `api_keys_identity_id_fkey`, which it subsumes, and adds the index
   that cascade never had.

**The unauthenticated branch is gone, not relocated.** An org's first admin User and its
key are now minted by `POST /v1/orgs` itself and returned once in that response
(`routes/orgs/create.rs::provision_new_org_contents`). That inherits the org-creation
route's existing controls for free — `ALLOW_ORG_CREATION`, and a hard refusal under
`cloud_billing` — neither of which the old branch had. It was already dead in cloud:
signup provisioning (`routes/auth/provisioning.rs:254`) creates the org, the admin
identity and the membership together, so `count_identities() > 0` from the org's first
instant and the precondition never held.

**Was the old bootstrap branch exploitable?** In practice, no — but it was one control
deep. It authorised on a body-supplied `org_id` naming an org with zero keys *and* zero
identities. Reaching that window needed the org's UUIDv4, which is unguessable and is
returned only to the org's creator; and any org with a member has identities, so a leaked
id from a live tenant never qualified. The exposure was an org created via the no-session
`POST /v1/orgs` path and not yet claimed. Real, narrow, and now closed by construction.

---

## 1 Authentication

Overslash has **no passwords**. Users authenticate by IdP OAuth/OIDC (Google, GitHub,
per-org configured providers) or by passwordless magic link. Programmatic callers use
`osk_` API keys. This makes 1.1.3 non-applicable and reframes 1.1.1 and 1.3.x around the
magic link.

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 1.1.1 | Authentication resistant to brute force | `statement` | Google and GitHub are ADA-approved external authentication services. For the proprietary path (magic link), `routes/auth/magic_link.rs:16-19,76-113` enforces a per-IP bucket (30 / 600s) and a per-email bucket (5 / 900s) — comfortably inside the "no more than 100 failed attempts per account per hour" criterion. Needs a written policy + screenshots. **Caveat:** the *global* limiter (`middleware/rate_limit.rs:17-20,150-157`) only fires for `Bearer osk_…`, so session-cookie and MCP-bearer traffic is unthrottled — see 1.1.1's neighbour findings under §6 | Low |
| 1.1.2 | System-generated codes securely random, short expiry | `pass` | 32 CSPRNG bytes → URL-safe base64, 15-minute TTL (`services/magic_link_email.rs:24`), minted at `routes/auth/magic_link.rs:118-129` | — |
| 1.1.3 | Passwords resistant to offline attack | `n/a` | No passwords exist. The nearest analogue, API keys, is **Argon2id** over 256 bits of entropy with a 12-char prefix index (`routes/api_keys.rs:191-209`) — worth stating affirmatively | — |
| 1.2.1 | No default credentials on publicly exposed interfaces | `statement` | No default accounts ship. But `.env.example:4-5` carries a 64-zero `SECRETS_ENCRYPTION_KEY` and an all-ones `SIGNING_KEY`, and boot validation (`config/from_env.rs:303`) only checks non-emptiness — a copied `.env` boots silently with a publicly published vault key. Needs weak-key rejection at boot to make the statement clean | Med |
| 1.3.1 | OOB verifier expires in a reasonable timeframe | `pass` | 15 minutes — `services/magic_link_email.rs:24` | — |
| 1.3.2 | OOB verifier used only once | `pass` | `magic_link_token::consume` claims the row atomically — `routes/auth/magic_link.rs:178` | — |
| 1.3.3 | OOB verifier securely random | `pass` | `rand::rng().fill(&mut [u8; 32])` — `routes/auth/magic_link.rs:119-121` | — |
| 1.3.4 | OOB verifier resistant to brute force | `pass` | 256-bit token, **SHA-256 only** stored (`:122`), lookup by hash, plus the per-IP / per-email buckets above. Every outcome returns an identical `{"sent": true}` — no enumeration | — |

## 2 Session Management

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 2.1.1 | No passwords or session tokens in URL parameters | `statement` | No session token ever appears in a URL. Three *capability* tokens do: `GET /auth/magic-link/verify?token=…`, `/v1/downloads/{token}`, `/v1/uploads/{token}`. All are single-use or short-TTL, stored only as SHA-256, and the magic-link verifier redirects to a clean URL after setting the cookie. Defensible, but a Burp scan will surface it, so prepare the answer | Low |
| 2.2.1 | Logout invalidates all stateful session tokens incl. refresh | `gap` | Logout only emits a clearing `Set-Cookie` — `routes/auth/session.rs:5-17`. The JWT stays valid for its full 7 days. No denylist, no session table, no `session_version` claim. (The MCP side *does* have real refresh-token revocation with replay detection and chain revocation — `routes/oauth/token.rs:158-168` — so the pattern exists in-repo) | **High** |
| 2.2.2 | Option to terminate all other active sessions after credential change | `gap` | No mechanism. With no password there is no "password change", but magic-link login *is* account recovery, and the requirement covers reset/recovery explicitly. Falls out of the same fix as 2.2.1 | Med |
| 2.2.3 | Non-revocable stateless tokens expire within 24 hours | `gap` | `exp: now + 7 * 24 * 3600` in seven mint sites (`routes/auth/magic_link.rs:203`, `auth/providers.rs:375`, `auth/session.rs:261`, `auth/dev_token.rs:292`, `oauth/consent.rs:428`, `orgs/create.rs:188`, `connect_gate.rs:175`); cookie `Max-Age=604800` (`routes/auth/mod.rs:188`). The token carries no `jti` and there is no server-side state, so it is non-revocable by definition. **7 days > 24 hours — a literal fail** | **High** |
| 2.3.1 | Cookie session tokens have `Secure` | `pass` | Every cookie is built by one helper, `crates/overslash-api/src/cookies.rs:50-59` (`build`), which always emits `HttpOnly; SameSite=Lax; Secure` and a browser-enforced prefix: `__Secure-oss_session` (plus `__Secure-oss_auth_*`) when `SESSION_COOKIE_DOMAIN` is set, `__Host-…` with `Path=/` and no Domain when it is not; the Vercel preview handoff is always `__Host-oss_session`. The session, the IdP state cookies, their clears and the logout clear all go through it. The reader (`cookies.rs:138-144`) accepts only prefixed names, so a cookie planted over plaintext cannot be presented as a session; the unprefixed `oss_session` is rejected (`tests/auth_login.rs::unprefixed_session_cookie_is_rejected`) and actively cleared on login and logout. Attribute assertions: `tests/auth_login.rs`, `tests/oidc_auth.rs`, unit tests in `cookies.rs`. Plain `http://` works only on localhost / loopback, which browsers treat as a secure context | — |
| 2.3.2 | Cookie session tokens have `HttpOnly` | `pass` | `cookies.rs:50-59` — every cookie, no opt-out | — |
| 2.3.3 | Session tokens dynamically generated after authentication | `pass` | A fresh JWT is minted on every login and on org switch / OAuth consent (`routes/oauth/consent.rs:443`), so there is no session fixation. `osk_` API keys are the documented programmatic-access carve-out, not session tokens | — |
| 2.3.4 | Stateless tokens protected against tampering, replay, enveloping, key substitution | `statement` | HS256 with a fixed algorithm on decode, plus an `aud` split (`session` vs `mcp`) that stops a cookie JWT being replayed against `/mcp` and vice versa — `services/jwt.rs:6-11`, tests at `:215-237`. **Caveat to disclose:** `signing_key_bytes` falls back to the raw UTF-8 bytes of an arbitrary string when `SIGNING_KEY` is not hex (`services/jwt.rs:139-141`, duplicated at `extractors.rs:184-185,219-220,503-504`) with no length floor, so a short key is accepted | Med |
| 2.4.1 | Full login session or re-auth before sensitive transactions | `statement` | `GET /v1/secrets/{name}/versions/{v}/reveal` requires a **session cookie** — an API key cannot reach it — and writes a `secret.revealed` audit row (`routes/secrets.rs:334-379`). `InstanceAdminAuth` is likewise cookie-only and uncached, so revocation is immediate (`extractors.rs:722-742`). There is no step-up re-authentication, which is what a lab will probe; see 3.3.1 | Med |

## 3 Access Control

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 3.1.1 | Least-privilege access control on a trusted service layer | `pass` | Capability types in `crates/overslash-db/src/scopes/` (`SystemScope > OrgScope > UserScope > AgentScope`) inject `org_id` into every query. `/v1/actions/call` runs two layers: a default-deny group ceiling (`overslash-core/src/permissions/ceiling.rs`, enforced at `routes/actions/call.rs:346-356`) and an ancestor-chain walk with approval bubbling (`routes/actions/permission_gate.rs:48-90`). Enforcement is server-side only. **Infrastructure caveat from the live scan:** two GCP-default service accounts hold `roles/editor` on the production project — the default Compute Engine SA (flagged P2, **0 permissions used in 90 days**) and the cloudservices agent (P2, downgrade to `roles/compute.editor`) — both invisible to Terraform — [gcp-posture.md](gcp-posture.md) | — |
| 3.1.2 | Policy attributes not manipulable by end users | `pass` | **V2, fixed.** `POST /v1/api-keys` no longer accepts an `org_id`: `create_api_key` takes `AdminAcl` + the `OrgScope` extractor, so the org is the presented credential's currently-active org and the caller cannot name one (`routes/api_keys.rs`). `identity_id` is resolved through that scope. The unauthenticated bootstrap branch — the only reason a body `org_id` existed — is gone; the first admin key is minted by `POST /v1/orgs` (`routes/orgs/create.rs::provision_new_org_contents`) behind `ALLOW_ORG_CREATION`. Migration 121 backs it with a composite FK. Tests: `tests/api_key_org_binding.rs` | — |
| 3.1.3 | Access controls fail securely | `pass` | Default-deny ceiling; foreign ids 404 at the SQL boundary (`routes/approvals/resolve.rs:31-34`); org-configurable response capture is fail-closed (`services/audit_capture.rs:44-47`) | — |
| 3.1.4 | Protected against IDOR on create / read / update / delete | `pass` | The scope model holds across the surface — unscoped repo getters exist (`repos/service_template.rs:97`, `repos/mcp_upstream_connection.rs:79`, `repos/oauth_connection_flow.rs:119`) but every call site filters on the caller's org immediately. **V2 was the one exception — a create-path IDOR — and is fixed**: `routes/api_keys.rs` was the only handler in the routes tree taking its org from `req.*`, and it no longer does. Migration 121 adds the composite `api_keys (org_id, identity_id) -> identities (org_id, id)` FK so the pair cannot diverge even if a handler regresses | — |
| 3.1.5 | Anti-CSRF on authenticated functionality; anti-automation on unauthenticated | `statement` | `SameSite=Lax` on the session cookie, CORS with an explicit origin predicate and no `Any` (`lib.rs:709-756`), JSON-only endpoints, and no cookie-authenticated form posts. No synchronizer token. Anti-automation on unauthenticated surfaces is uneven — magic-link, downloads and uploads have buckets; `POST /oauth/register` has none. Needs a written answer and will also be probed by the scan | Med |
| 3.1.6 | Directory browsing disabled | `pass` | Nothing serves a filesystem directory. `/icons/{file}` reads a compiled-in table with a name allowlist, not the disk (`routes/icons.rs:68-79`) | — |
| 3.2.1 | Only secure OAuth flows (auth code / auth code + PKCE) | `pass` | Authorization Code throughout. The MCP Authorization Server mandates **PKCE S256** (`routes/oauth/authorize.rs:39-51`); upstream connections use PKCE where the provider supports it. No implicit, no ROPC anywhere | — |
| 3.2.2 | `redirect_uri` and `state` validated (open redirect / CSRF) | `pass` | Exact-match `redirect_uri` at authorize *and* re-checked at token exchange (`routes/oauth/authorize.rs:84-87`, `routes/oauth/token.rs:102-103`); IdP login carries PKCE + nonce state cookies (`routes/auth/providers.rs:207`); the `?next=` parameter is restricted to same-origin paths (`routes/auth/mod.rs:199-204`). **Fixed:** unauthenticated Dynamic Client Registration now parses `redirect_uris` into a typed value at the boundary (`services/oauth_redirect_uri.rs`, called from `routes/oauth/register.rs`): `https://` with a host, `http://` only on `127.0.0.1` / `[::1]` / `localhost` (RFC 8252 §7.3), or a private-use app scheme — reverse-DNS or the named `cursor` / `vscode` / `vscode-insiders` / `windsurf` (RFC 8252 §7.1). Everything else is refused with `invalid_redirect_uri`, including `javascript:`, `data:`, `file:` and `vbscript:`, as are fragments, userinfo, more than 10 URIs, and a URI over 2048 bytes. Tests: `tests/oauth_dcr_redirect_uris.rs` plus the parser's unit table. Residual: no per-IP registration cap — tracked as the anti-automation half of 3.1.5 | — |
| 3.3.1 | Administrative interfaces use MFA | `gap` | **No MFA of any kind exists** — no TOTP, WebAuthn, passkey or step-up, anywhere in `crates/` or `dashboard/`. Most exposed on `secret.reveal`, on minting a key with the `impersonate` scope, and on `InstanceAdminAuth` operations. Partial answer available: org admins who sign in through a Workspace or GitHub IdP inherit that IdP's MFA — but magic link bypasses it, so the answer is not complete until magic link is restricted for admin-class identities or a step-up is added | **High** |

## 4 Communications

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 4.1.1 | TLS enforced on all connections, default TLS 1.2+, secure ciphers | `gap` | Inbound is fine in practice — `api.overslash.com` and `app.overslash.com` both negotiate TLS 1.2/1.3 and reject 1.0/1.1 (verified externally 2026-09-22) — but it is *incidental*: no `google_compute_ssl_policy` is declared, so the GCLB runs GCP's permissive default profile (`infra/modules/api-lb/main.tf:183-192`). **Outbound action traffic is fixed:** `services/outbound_tls.rs` refuses plain `http` on every transport hop (redirects included) and on the MCP caller, checked against the address the SSRF guard pinned; Mode A is refused with or without secrets. Instance `url`, an org layer's `instance_defaults.url` and a template's `mcp.url` are refused at write time, and an endpoint stored earlier fails at resolve, before any approval. The only exception is an address inside the operator's `OVERSLASH_SSRF_ALLOWED_CIDRS`, which the multi-tenant deployment never sets — tests in `tests/outbound_tls.rs`. Webhook delivery is HTTPS-only too (7.1.1). Still open outbound: the MCP OAuth upstream endpoints (TODO §1.6). **Confirmed in production:** `overslash-prod-db` runs `sslMode=ALLOW_UNENCRYPTED_AND_ENCRYPTED`, and Google's own Cloud SQL Security Recommender raises `REQUIRE_SSL` at **P2** behind a **HIGH**-severity `SSL_NOT_REQUIRED` insight — [gcp-posture.md](gcp-posture.md) | **High** |
| 4.1.2 | Trusted TLS certificates; no blanket trust of self-signed | `pass` | `danger_accept_invalid_certs` appears **nowhere** in the repo; no custom certificate verifier, no `hostname_verification(false)`. reqwest defaults throughout | — |
| 4.1.3 | No weak cryptography affecting confidentiality or integrity | `pass` | AES-256-GCM for the vault with a per-encryption CSPRNG nonce (`overslash-core/src/crypto.rs:184-186`), SHA-256 for token hashing, Argon2id for API keys, HMAC-SHA256 for webhooks, HS256 for JWTs. All ≥ 112-bit security. `rsa 0.9.10` appears transitively (via `jsonwebtoken`'s `rust_crypto` backend) carrying RUSTSEC-2023-0071 at CVSS 5.9. That is below the 7.0 bar and on an unreached code path, since only HS256 keys are constructed. It is a documented exception in [dependency-vulnerability-policy.md](dependency-vulnerability-policy.md) | — |
| 4.1.4 | Cryptographic modules fail securely; no padding oracle | `pass` | AES-GCM is AEAD — no padding to oracle. Decrypt failures surface as `AppError::Crypto`, which returns a fixed generic string to the client and logs detail server-side only (`error/mod.rs:469-493`) | — |

## 5 Data Validation and Sanitization

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 5.1.1 | Protect against HTTP parameter pollution | `scan` | Not assessable from source. axum/serde reject duplicate JSON keys and take a deterministic first-wins on query params; the scan is the evidence | Low |
| 5.1.2 | Redirects and forwards allowlisted, or warned | `pass` | `sanitize_next` accepts only same-origin paths — must start `/`, must not start `//`, no CR/LF (`routes/auth/mod.rs:199-204`). OAuth `redirect_uri` is exact-match. The LB's catch-all 301 to `www` is static config (`infra/modules/api-lb/main.tf:154-181`) | — |
| 5.1.3 | Avoid `eval()` / dynamic code execution; sandbox where unavoidable | `statement` | Overslash *does* evaluate user-supplied jq filters — that is a product feature. It runs in-process with syntax validation and a timeout, over JSON only, with no filesystem, network or shell reach (`services/response_filter.rs:145-199`). No `Command::new` exists in any server crate. Needs a written description of the sandbox | Med |
| 5.1.4 | Protect against template injection | `statement` | `{param}` interpolation in action descriptions is plain string substitution, not a template engine. Server-rendered HTML interpolations pass `html_escape` (`routes/connect_gate.rs:294-307`, `routes/oauth_upstream.rs:620-680`). One rough edge to fix or disclose: `oauth_upstream.rs:646` puts an HTML-escaped value inside a JavaScript string literal (`window.location.href = '{return_to}'`) — the wrong encoder for that context. It holds today (entities are not decoded inside `<script>`, and `'` → `&#x27;` blocks termination) but backslash is not escaped | Med |
| 5.1.5 | Prevent Server-Side Request Forgery | `statement` | **V1 fixed.** Action execution, webhook delivery and OIDC issuer discovery now resolve, check and pin every target through `services/ssrf_guard.rs`, re-running the guard on each redirect hop and stripping credentials that would cross a host boundary; the transport (`services/http_caller.rs`) owns client construction so a new call site cannot bypass it. Tests: `tests/ssrf_guard.rs`. Two things still need saying to a lab: the operator allow-list a self-hoster uses for its own private network (`OVERSLASH_SSRF_ALLOWED_CIDRS` — environment-only, never set on the multi-tenant deployment) and the scoping argument in [dast-readiness.md](dast-readiness.md) — outbound HTTP on user-supplied input *is* the product, so the control is a deny-list of destinations, not an absence of egress | Medium |
| 5.1.6 | Protect against XPath / XML injection | `n/a` | No XML is parsed anywhere. No `quick-xml`, `roxmltree`, `xml-rs` or `serde-xml` in `Cargo.lock`; all payloads are JSON, and templates are YAML | — |
| 5.1.7 | Context-aware escaping against reflected, stored and DOM XSS | `statement` | Six `{@html}` sinks in the dashboard, each fed by an escaping helper — `lib/api.ts:53-87` escapes both values and keys, `lib/approvals/format.ts:107-118`, `components/api-explorer/ResponsePanel.svelte:54-59`. No unescaped sink found. Svelte escapes by default elsewhere. Disclose the JS-context issue from 5.1.4; the scan confirms the rest | Med |
| 5.1.8 | Protect against database injection | `pass` | Effectively every query is a compile-time-checked `sqlx::query!` / `query_as!` macro with bind parameters, and `clippy.toml:1-5` sets `disallowed-methods` to **ban** runtime-string SQL, enforced by `cargo clippy -D warnings` in CI. The only dynamic SQL is `services/key_rotation.rs:218-291`, built from a `const TARGETS: &[Target]` of `&'static str` table and column names | — |
| 5.1.9 | Protect against OS command injection | `pass` | No `std::process::Command` in any server crate; no shell invocation on any request path | — |
| 5.1.10 | Protect against local / remote file inclusion | `pass` | No user input reaches a filesystem path. `/icons/{file}` resolves against a compiled-in allowlist (`routes/icons.rs:68-79`). Remote inclusion is the SSRF question — 5.1.5 | — |
| 5.2.1 | Restrict uploads to expected types; prevent execution of uploaded content | `statement` | Overslash stores and serves no uploads. `POST /v1/uploads/{token}` redeems a one-shot capability token and forwards bytes to a pinned upstream; the redeemer controls nothing but the bytes and a Content-Type hint (`routes/uploads.rs:15-24,58-67`). Nothing is written to disk, nothing is served back, nothing is executed. Needs a written statement, not a control | Low |

## 6 Configuration

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 6.1.1 | No 3P components with known exploitable vulnerabilities | `pass` | **Closed 2026-09-23.** Three scanners run over every lockfile from `.github/workflows/deps-audit.yml`: `cargo-deny` (`deny.toml`: RustSec advisories, yanked, licenses, sources; all features), `npm audit --audit-level=high` for `dashboard/` and `sdk/`, and OSV (`osv-scanner.toml`) at every severity. `ci.yml` calls it on any change to a manifest, lockfile or scanner config, gated by `ci-ok`; a daily schedule scans `dev` and `master` and files a `needs-triage` issue on failure. Policy (SLAs, ownership, exception process with ≤ 90-day review dates enforced in CI): [dependency-vulnerability-policy.md](dependency-vulnerability-policy.md). The 2026-09-22 findings are resolved. Four fixable advisories were cleared by lockfile bumps: `h2` → 0.4.16 (RUSTSEC-2026-0258), `rustls` → 0.23.45 (RUSTSEC-2026-0285), `crossbeam-epoch` → 0.9.20 (RUSTSEC-2026-0204), `event-listener` → 5.4.2. So were three yanked versions (`chacha20`, `der`, `spin`) and one advisory OSV found in the dashboard that npm audit had missed: `devalue` → 5.9.2 (GHSA-9rgm-9g3h-6x36, moderate). Two justified exceptions remain, both review-by 2026-12-22. **`rsa 0.9.10`** (RUSTSEC-2023-0071, Marvin, CVSS 5.9, no fix) arrives via `jsonwebtoken`'s `rust_crypto` backend, but only HS256 keys are ever constructed (`services/jwt.rs`), so no RSA private key exists to attack. **`paste 1.0.15`** (RUSTSEC-2024-0436) is unmaintained, not vulnerable: a build-time proc-macro via `fastembed`. Container-image OS packages are out of this row's tooling and tracked with the GCP findings | — |
| 6.2.1 | Debug modes disabled in production | `gap` | Three things a lab will find. (a) `dev_auth_enabled: env::var("DEV_AUTH").is_ok()` — `config/from_env.rs:143` — so `DEV_AUTH=0`, `false` and `""` all **enable** it, and when on, `GET /auth/dev/token?profile=admin&org=<any-slug>` mints a 7-day admin session for an auto-created org with zero authentication (`routes/auth/dev_token.rs:136-321`), plus IdP seeding and org deletion via `routes/dev_e2e.rs`. There is no `OVERSLASH_ENV` interlock — contrast the preview-handoff feature, which requires both gates (`config/mod.rs:554`). (b) `rust_log = "overslash=debug,info"` in production, byte-identical to dev (`infra/env/prod.tfvars:4`). (c) unauthenticated `/health` echoes truncated sqlx error text, which commonly leads with host/port/user (`routes/health.rs:55-57,85-96`) | **High** |
| 6.3.1 | `Origin` header not used for authentication or access control | `pass` | `Origin` is used only by the CORS layer. Authorization derives from the session cookie or the `osk_` key, resolved in `extractors.rs` — never from a header a caller sets. CORS itself is an explicit origin predicate, never `Any`, and correctly rejects `evil.attacker.app.example.com` against a single-label wildcard (`lib.rs:709-756`) | — |
| 6.4.1 | Not susceptible to subdomain takeover | `statement` | Needs an inventory before it can be answered. Ten hostnames exist under `overslash.com` (`api`, `app`, `www`, `dev`, `docs`, `status`, `mail`, `mailbox`, `acme`, plus per-org `<slug>.app`) spread across GCLB, Cloud Run domain mappings, Vercel and Better Stack — and `enable_dns = false` in both environments (`infra/env/prod.tfvars:56`), so the records live outside IaC. Produce a record-by-record inventory with the owning service and a dangling-CNAME check | Med |
| 6.5.1 | Do not log credentials or payment details; session tokens only hashed | `statement` | The deliberate controls are good: `scrub_transport_error` maps `reqwest::Error` to fixed strings and **explicitly refuses** to include `Display` output or `e.url()`, because injected secrets live in path and query (`services/audit_capture.rs:93-118`); the rate limiter logs only a 12-character `osk_` prefix (`middleware/rate_limit.rs:149-151`); `Keyring` has a redacting `Debug` with a test asserting it (`overslash-core/src/crypto.rs:43-51,440-450`). **But** there is no `tracing`-layer scrubber and no loggable-field allowlist, and prod runs at `debug` (6.2.1b). One known leak bypasses the scrubber: `services/deferred_download.rs:308-309` formats `reqwest::Error` straight into a `BadGateway` message that is returned verbatim to the caller (`error/mod.rs:427`). Evidence for this row is a **log sample**, so capture one after dropping the log level | Med |
| 6.6.1 | Browser storage cleared on logout | `pass` | No authentication material is ever placed in browser storage. The only `localStorage` writes are theme and shell UI preferences (`dashboard/src/lib/stores.ts:11-17`, `lib/stores/shell.ts:7-29`). The session lives solely in an `HttpOnly` cookie, so there is nothing for logout to clear | — |
| 6.7.1 | Securely store access tokens, API keys and server-side secrets | `gap` | The *storage* half passes comfortably: AES-256-GCM with a two-slot versioned keyring, `active_id > previous_id` invariant, and a CAS-safe re-encryption walker over 10 encrypted columns (`overslash-core/src/crypto.rs:78-93`, `services/key_rotation.rs:42-91`); Argon2id for API keys; every production secret injected from Secret Manager via `secret_key_ref` with no plaintext credential in any Cloud Run env var (`infra/modules/cloud-run/main.tf:586-597`). The requirement's other two clauses are unmet: **no documented access-control policy** for server-side secrets, and **access is not logged or monitored** — there is no `google_project_iam_audit_config` anywhere in `infra/`, so Secret Manager Data Access logs are off by GCP default, and there is no log sink, no retention policy and no alert on `AccessSecretVersion`. **Confirmed in production:** the project IAM policy returns `auditConfigs: NONE` — so an `AccessSecretVersion` against the vault master key leaves no record — only the two default log sinks exist, `_Default` retention is 30 days and unlocked, all 16 secrets carry no rotation or expiry metadata, and the run service account's `secretAccessor` grant is project-wide. `overslash-prod-valkey` is confirmed to run with **no AUTH and `transitEncryptionMode: DISABLED`** — a finding that had no dev counterpart and rested entirely on the module until this scan — [gcp-posture.md](gcp-posture.md). Two storage caveats to disclose: the generated secrets — `db_password`, `signing_key` and **the vault master key** — live in plaintext Terraform state (`infra/modules/secret-manager/main.tf:35-76`) in a bucket with 90-day version history and no CMEK; and `Keyring::test()`, which returns a hardcoded `[0xAB; 32]` key, is `pub` **outside** any `#[cfg(test)]` block and therefore compiled into the production library (`overslash-core/src/crypto.rs:145-152`) | **High** |

## 7 Webhook Security

Overslash is **both** a webhook provider (`approval.created`, `approval.resolved`,
`service.activated`, the DLQ digest) and a webhook consumer (Stripe). The consumer side is
already correct; the provider side has not been built to this section, which did not exist
when it was written.

| Req | Requirement | Verdict | Evidence / gap | Sev |
|-----|-------------|---------|----------------|-----|
| 7.1.1 | Webhook traffic exclusively HTTPS, TLS 1.2+ | `pass` | Registration parses the URL into a typed `HttpsUrl` (`services/https_policy.rs`) and refuses `http://` and every other scheme with a 400 (`routes/webhooks.rs::create_webhook`); there is no update endpoint. The dispatcher re-checks on every attempt — from the string, then against the address the SSRF guard pinned — and records a refusal as a failed delivery without dialing (`services/webhook_dispatcher.rs::deliver`). Pre-existing `http://` subscriptions were disabled by migration 124 (`active = false`, `disabled_reason = needs_https`, still listed to the owner). Sole exception: plain `http` to **loopback**, and only when the operator allow-lists loopback in `OVERSLASH_SSRF_ALLOWED_CIDRS` — the same rule OIDC discovery uses; nothing sent that way leaves the host. TLS 1.2+ holds by construction: reqwest 0.13 is built on rustls, which implements only TLS 1.2 and 1.3. Tests: `tests/webhook_https.rs` | — |
| 7.1.2 | Provider verifies endpoint ownership before delivering events | `gap` | No challenge-response handshake and no manual verification step; the first event ships on the first trigger after registration. Partial compensating control: registration is org-admin-only (`AdminAcl` at `routes/webhooks.rs:51`). At AL2 the lab registers a callback it controls and checks that nothing arrives before verification, so the compensating control alone will not pass | **High** |
| 7.2.1 | Payloads authenticated with HMAC-SHA256 or stronger | `pass` | **Provider:** HMAC-SHA256 over the raw serialized envelope, sent as `X-Overslash-Signature: sha256=<hex>` (`services/webhook_dispatcher.rs:111-121`), with a 256-bit CSPRNG signing secret minted per subscription (`routes/webhooks.rs:57-61`). **Consumer:** the Stripe handler computes over `"<timestamp>.<raw body>"` using the raw bytes, never a re-serialization (`routes/billing/webhook.rs:360-370`) | — |
| 7.2.2 | Signature verification uses a timing-safe comparison | `pass` | `subtle::ConstantTimeEq` over every candidate `v1` signature — `routes/billing/webhook.rs:371-384`. This is the code snippet to paste into the evidence pack verbatim | — |
| 7.2.3 | Payloads include replay protection via signed timestamps | `gap` | **Consumer side passes** — Stripe's `t=` is inside the signed payload and events outside a ±tolerance window are rejected (`routes/billing/webhook.rs:310-358`). **Provider side fails** — our outbound signature is `sha256=<hmac>` with no timestamp header and no signed time component, so a captured delivery replays forever. Fixing it changes the signature format, so it needs a versioned header and a migration note for existing consumers | **High** |
| 7.3.1 | Provider implements SSRF mitigations for user-supplied callback URLs | `pass` | `services/webhook_dispatcher.rs::deliver` resolves the registrant's URL through `ssrf_guard::outbound_client` on **every** attempt — first try and each retry — so loopback, RFC1918, link-local and CGNAT targets are refused before a socket opens, the validated IP is pinned against rebinding, and redirects are off. A refusal is recorded on the delivery row with no `status_code`, so the oracle reads as a failure rather than a response. Tests: `tests/ssrf_guard.rs::webhook_delivery_refuses_a_link_local_endpoint` plus a loopback positive control | — |
| 7.3.2 | Signing secrets not hardcoded or in version control | `pass` | Generated per subscription from 32 CSPRNG bytes at creation time (`routes/webhooks.rs:57-61`), stored in the database, returned to the registrant once. No webhook secret appears in the repo. `STRIPE_WEBHOOK_SECRET` is a Secret Manager entry injected via `secret_key_ref` (`infra/modules/cloud-run/main.tf:426-455`) | — |

---

## Tally

| Verdict | Count |
|---------|-------|
| `pass` | 30 |
| `statement` | 13 |
| `gap` | 9 |
| `scan` | 1 |
| `n/a` | 2 |

Of the 9 gaps, **none is a live vulnerability** any more, and 2 are the unbuilt
webhook-provider section. The counts moved from the original assessment because the two
vulnerabilities closed four rows between them: V2 made 3.1.2 and 3.1.4 `pass`, and V1
made 7.3.1 `pass` and 5.1.5 `statement`. The prefixed-cookie rework then made 2.3.1 `pass`,
dependency scanning made 6.1.1 `pass`, and HTTPS-only webhooks made 7.1.1 `pass`.

## Priority ladder

Remediation is tracked in [TODO.md §1.6](../../../TODO.md). The ordering:

**P0 — live vulnerabilities. Both done.** ~~V2~~ — the org comes from the credential, the
identity resolves through that scope, migration 121 enforces the pair, and the
unauthenticated bootstrap branch is gone. ~~V1~~ — Mode A and webhook delivery run through
the SSRF guard, and so, since then, does OIDC issuer discovery. One follow-up survives
V1, not a P0: the default `Everyone → admin on http` grant (a behaviour change for new
orgs, so a human decision).

**P1 — hard CASA fails.** ~~`Secure` on `oss_session` plus `__Host-`/`__Secure-` prefixes
(2.3.1)~~ — done; **server-side sessions** — a sessions table with a `jti` claim checked per
request, which keeps the 7-day UX while satisfying 2.2.1, 2.2.2 and 2.2.3 at the cost of
one indexed lookup (cacheable in Valkey) (2.2.x); ~~a security-headers layer on the API and
a `headers` block in `dashboard/vercel.json` (4.x/6.x adjacency)~~ — done: HSTS, nosniff,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` and a CSP on every API response
(`middleware/security_headers.rs`), and an enforced dashboard CSP with no `'unsafe-inline'`
in `script-src` (`kit.csp`, with the rest of the baseline in `vercel.json`); **the rest of webhook
section 7** — a challenge-response ownership handshake, and a signed timestamp header
behind a versioned signature (7.1.2, 7.2.3; delivery through `ssrf_guard` and HTTPS-only
endpoints, 7.1.1, are done); ~~dependency vulnerability scanning in CI plus clearing the four
fixable advisories (6.1.1)~~ — done; ~~require TLS on outbound calls (4.1.1)~~ — done for action
traffic (MCP OAuth upstream remains); `SECURITY.md` with a disclosure policy. (The `redirect_uri` allowlist on DCR, 3.2.2, is done.)

**P2 — will be raised.** MFA or step-up for admin-class operations (3.3.1); `DEV_AUTH`
parsed as a boolean with an `OVERSLASH_ENV` interlock, weak-key rejection at boot, and
`RUST_LOG` off `debug` in production (6.2.1, 1.2.1); rate limiting extended to
session-cookie and MCP-bearer traffic and to the `/oauth/*` subrouter (1.1.1, 3.1.5);
Secret Manager Data Access logs, a log sink with locked retention, and a documented
secrets access policy (6.7.1); a subdomain inventory (6.4.1); `deletion_protection` and
`ssl_mode` on Cloud SQL; an explicit `google_compute_ssl_policy` and Cloud Armor on the
LB; `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`; least-privilege IAM in place of the
project-wide `secretmanager.secretAccessor` and `cloudsql.admin` bindings; Memorystore
`auth_enabled` + `transit_encryption_mode`; move `Keyring::test()` behind `#[cfg(test)]`;
trusted-proxy configuration so `X-Forwarded-For` is not attacker-controlled
(`extractors.rs:102-111`); ~~`Cache-Control: no-store` on `secrets/reveal` and other
sensitive responses~~ — done, as the default on every API response that does not set its own.

**P3 — document rather than fix.** CMEK; SBOM, artifact signing and build provenance
(`--provenance=false` at `infra/modules/cloud-build/main.tf:217`); ~~the `rsa` and `paste`
advisories~~ — documented as time-boxed exceptions in
[dependency-vulnerability-policy.md](dependency-vulnerability-policy.md), justified as
unreached and as unmaintained-with-no-fix, both of which the Test Guide explicitly permits; `db-f1-micro` sizing; an org-policy baseline; the three
production alert policies disabled at `infra/env/prod.tfvars:113-119`, which already carry
their verification procedure inline and are exactly the shape of evidence a lab accepts.

## Cite these affirmatively

An assessment that lists only gaps misrepresents the codebase. Lead the submission with:
the AES-256-GCM keyring and its CAS-safe rotation walker; Argon2id API-key hashing over
256 bits of entropy; the `scopes/` capability model; PKCE-S256 with exact-match
`redirect_uri` and refresh rotation with replay detection and chain revocation; the
`ssrf_guard` implementation itself (correct, just under-deployed); `scrub_transport_error`,
which refuses to log a URL because credentials live in its query; the generic-message
error boundary; one-shot capability tokens with indistinguishable 404s; CORS with an
explicit origin predicate; every GitHub Action SHA-pinned under a written decision (D31)
with a 7-day publish cooldown (D30); no `danger_accept_invalid_certs` anywhere; non-root
multi-stage Docker images; PITR with 7-day log retention; and the unusually high density of
recorded rationale in the HCL, which is itself good evidence for the architecture
requirements.
