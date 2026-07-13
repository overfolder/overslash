# Email Integration — overfwd (Mailbox Gateway)

**Status**: Implemented (Inline-mode core path, 2026-07-13). Own-inbox, real-time
inbound, and overfwd Portfolio/Session modes remain deferred (see below).

## Implementation notes (2026-07-13)

Built as designed — overfwd is consumed as an ordinary HTTP service via the shipped
`services/email.yaml` template. The three core changes the design anticipated landed as:

1. **`x-overslash-encode: base64` on an apiKey security scheme** (Core-change #1). The
   decrypted secret is base64'd *before* the `x-overslash-prefix` is prepended, so a
   `user:pass` secret with `prefix: "Basic "` emits `X-Mailbox-Auth: Basic base64(user:pass)`.
   The prefix stays generic — `base64` never includes `"Basic "`. (`SecretRef::encode`,
   `secret_injection::inject_secrets`.)
2. **Multi-injection via `x-overslash-secret_source: instance | org`** (Core-change #2).
   `ServiceDefinition.auth` was already a `Vec`; `resolve_instance_auth` now emits a
   `SecretRef` per apiKey scheme. `instance` (default, backward-compatible) resolves the
   instance's bound `secret_name` (the per-mailbox `user:pass`); `org` resolves the scheme's
   fixed `default_secret_name` from the org vault (the shared gateway key). A template may
   declare at most one `instance`-source apiKey scheme (validated).
3. **Per-instance `url` override promoted to HTTP Mode C** — the URL piece of the deferred
   Core-change #3, pulled forward. The HTTP resolver now prefers `service_instances.url`
   (verbatim base, scheme + port preserved) over the template host, mirroring the MCP fork.
   This is how an org points its catalog entry at its own overfwd deployment. A derived
   `configurable_url` flag on the templates API drives the dashboard to reveal a "Gateway URL"
   field. The generic per-instance `config jsonb` (for host/port param overrides) remains
   deferred; autoconfig covers the common providers.

Coverage: `search`/`get` (`read`, auto-approvable) + `send` (`write`, gated, discloses
To/From/Subject). End-to-end test: `crates/overslash-api/tests/email_overfwd.rs`.

---

**Original design** (settled grilling session 2026-07-08/09):

Direct email integration for Overslash: let agents **send** and **read/search** mail
across arbitrary providers, without adding a non-HTTP execution path to the core. The
provider-facing work lives in **overfwd**, a separate MIT-licensed OSS Mailbox Gateway;
Overslash consumes it as an ordinary HTTP service.

---

## Terminology

**Mailbox Gateway**:
The *role* — a service that presents a REST facade over a remote IMAP/SMTP mailbox,
translating REST calls into IMAP/SMTP against the end user's provider. In the Inline mode
Overslash uses, it holds no credentials and no mail at rest.
_Avoid_: "JMAP proxy" (retired — JMAP was dropped as an internal protocol), "mail relay",
"SMTP relay" (it does more than relay; it reads too).

**overfwd**:
The concrete OSS implementation of the Mailbox Gateway — a standalone, MIT-licensed Rust
project (repo `overspiral/overfwd`) with its own mandate to disrupt EmailEngine / Nylas /
Unipile. Overslash is just one consumer.

---

## Scope

**In scope (this effort):**
- **(a) Send** from a user's mailbox.
- **(b) On-demand read / search** of a mailbox (request/response).
- Coverage: the **standard-IMAP long tail** — providers reachable with a presented
  credential (Migadu, Fastmail, iCloud, Zoho, Proton Bridge, corporate Dovecot/Cyrus, …).

**Explicitly deferred (deliberate no, not omission):**
- **(c) Agent's own inbox** — programmatic inbox creation.
- **(d) Real-time inbound** — "wake the agent on new mail." Requires an inbound-event
  ingestion subsystem Overslash does not have today (its only inbound seam is outbound
  webhook *dispatch*). Materially larger build; independent of the decisions here.
- **Big-two native APIs** — Gmail already ships (`services/gmail.yaml`, REST/OAuth);
  **Microsoft Graph** (`msgraph.yaml`) is a **separate later track**. The Mailbox Gateway
  **explicitly does not cover Gmail/Outlook**: Google/Microsoft now require OAuth XOAUTH2
  for IMAP, so routing them through the gateway buys nothing over their REST APIs and
  loses fidelity (labels, threads, search operators).

---

## Decisions settled (this session)

1. **Scope = send + on-demand read, universal via gateway.** Own-inbox and real-time
   inbound deferred.
2. **Coverage boundary.** Big-two on native REST (Gmail shipped, Graph later); gateway
   owns standard-IMAP long tail only, explicitly not Gmail/Outlook.
3. **Contract = REST facade.** Overslash speaks a REST surface we define
   (`POST /email/search`, `/email/get`, `/email/send`) — **not** raw JMAP. This keeps the
   existing OpenAPI-per-action model, per-action `risk`/`disclose`/permission-keys, and
   needs **no YAML-schema extension** on the email critical path. JMAP is not used, even
   internally.
4. **Implementation = from-scratch thin Rust gateway**, no JMAP. Crates: `async-imap`,
   `lettre` (SMTP), `mail-parser` + `mail-builder` (Stalwart, RFC-conformant, zero-copy).
   The a+b surface is small (IMAP `LOGIN/SELECT/SEARCH/FETCH/APPEND` + SMTP submit).
5. **Delivered as a separate open-source project**, not an Overslash-internal module. It
   must stand alone as a product, with a mandate to disrupt EmailEngine / Nylas / Unipile.
6. **State model.** **Zero-persistence _by default_ (Inline mode)**; an **optional
   credential store** backs the Portfolio/Session modes. **Ephemeral in-memory connection
   pooling** (short TTL, per-credential, bounded, LRU, lost on restart) amortizes IMAP
   `LOGIN`/`SELECT` cost regardless of mode.
7. **Multi-tenant, shared deployment.** One shared gateway (horizontally scaled); tenancy
   is a deployment topology, not a code difference (per-instance available as an option).
8. **Credential & auth model — two independent axes:**
   - **Gateway access** = `api_key` (`Authorization: Bearer`). Server config
     `require_api_key` (on for Cloud, optional self-host). Scoped api_keys see only their N
     accounts.
   - **Mailbox credential**, one of three *sources*:
     - **Inline** — creds-only secret (`user:pass`) presented per request as
       `X-Mailbox-Auth: Basic base64(user:pass)`; the mailbox **host/port are non-secret**
       (see decision 10). Zero gateway persistence. **This is the only mode Overslash
       uses.**
     - **Portfolio** — creds stored in the gateway's own encrypted store, referenced by
       `X-Mailbox-Account: <account_id>`. Standalone-product only; disabled in Overslash
       Cloud.
     - **Session = ephemeral Portfolio account** — `create_session` mints a TTL'd (ghost)
       account; the `session_token` is a scoped handle. No creds at rest.
   - `Authorization` is reserved for the gateway api_key; the mailbox concern lives in
     `X-Mailbox-*` headers. SMTP + IMAP are both covered by one mailbox credential
     (commonly a shared user/app-password, e.g. Migadu).
9. **Wire layout (accepted).** `Authorization: Bearer <api_key>` = gateway access;
   `X-Mailbox-Auth: Basic …` (creds) + `X-Mailbox-Imap`/`X-Mailbox-Smtp` (host/port) —
   or `X-Mailbox-Account` in Portfolio mode. On the Overslash→gateway hop the api_key is a
   **single static Overslash-identity bearer** (not per-tenant); Overslash's tenancy is
   carried per-request by the differing mailbox credential, so the gateway never sees
   Overslash tenants.
10. **Single generic template**, not per-provider. One template (working name **`email`** /
    **`mailbox-gateway`**) instantiated by **gateway URL + a `user:pass` secret name +
    non-secret host/port config**. Nothing provider-specific in the template; the secret
    holds **only `user:pass`**. Migadu/Fastmail/etc. turnkey variants are **optional
    org/user template forks** (existing template tiers + curated catalogs), created by an
    org admin if wanted.
11. **v1 facade + risk.** Actions: `search` (`read`), `get` (`read`), `send` (`write`,
    gated — approval discloses To/From/Subject + clamped Body; `Basic` header redacted).
    **Reads are ordinary `read`** (auto-approvable); consent boundary is *whether the owner
    grants read permission*, not per-fetch approval. Attachments (`get_attachment`, binary +
    `prefer_stream`) and `list_folders` are later additions.
12. **Cloud hosting = Cloud Run**, one shared stateless service alongside the API (Portfolio
    store disabled in Cloud). Fly/GCE unjustified without per-tenant state. Standalone = the
    overfwd docker image. In-memory pools are best-effort per instance under Cloud Run's
    lifecycle; per-request login is the correct fallback.
13. **Scope-outs (this effort):** the generic managed-backing-container abstraction
    (WhatsApp/npx-MCP hosting) and the `x-overslash-fixed-params` YAML extension are **out
    of scope** — each its own future track. Email needs neither.
14. **OSS project:** name **overfwd**, repo **`overspiral/overfwd`**, **MIT** license,
    separate top-level repo (Overslash consumes it as a third party).

### Core changes this implies (Overslash side)

`secret_injection` already loops over a `Vec<SecretRef>` (headers/query, prefix-only — **no
encode, no body injection**); `ServiceAuth` (`types/service.rs:171`) declares a **single**
injection; and a `service_instance` carries only `url` + `secret_name` + `connection_id`
(**no generic per-instance config**, migrations 016/048/090). Three bounded changes — but
only the first two are built now:

1. **`encode: base64` option on `SecretRef`** — emit `Basic base64(user:pass)`. Reusable for
   any Basic-auth API.
2. **Multi-injection** — Cloud needs the gateway `api_key` **and** the creds on one request;
   `ServiceAuth` must express two injections. **Self-host (`require_api_key=false`) needs
   only #1.** Multi-injection is Cloud-only.
3. ~~Per-instance non-secret param overrides~~ — **deferred.** Interim: host/port come from
   **prefilled forked templates** (org/user fork of the generic `email` template with
   host/port baked as `default` params — existing template-tier + defaulting machinery,
   **zero core change**). A generic **`config jsonb`** per-instance override (superseding the
   one-off `url` field) is a tracked **later** enhancement, not built now.

---

## Requirements (initial)

Two overlapping requirement sets: what Overslash needs from the gateway, and what makes the
gateway a credible standalone disruptor. The overlap (statelessness, credential-free
operation) is the thesis.

### A. Overslash-integration requirements

- **Speaks the REST facade** Overslash targets: `search`, `get`, `send` to start, each a
  clean operation with stable request/response schemas.
- **Credential-free / no persistence (Inline).** In the mode Overslash uses, the gateway
  holds no long-lived credentials and no mail at rest. Overslash's vault presents the
  backend mailbox credential **per request**; the gateway uses it and forgets it.
- **Per-request auth over HTTP.** The `user:pass` credential arrives as
  `X-Mailbox-Auth: Basic base64(user:pass)`, so it maps onto Overslash's existing
  header secret-injection (plus the `encode: base64` option — see Core changes).
- **Stateless horizontal scale.** Any gateway instance can serve any request — no
  account-pinned state — so it fits both per-instance deployment and a shared pool.
- **Provider target in the request.** IMAP/SMTP host+port travel as non-secret
  `X-Mailbox-*` headers (sourced from the template/forked-template config), so one gateway
  serves many providers.
- **Bounded, typed errors.** Auth failure, host unreachable, mailbox/message not found,
  TLS failure — mapped to stable machine-readable codes Overslash can gate/approve on.
- **Runs identically standalone and inside Overslash Cloud.** No dependency on Overslash to
  boot.

### B. Disruptor requirements (vs EmailEngine / Nylas / Unipile)

Competitive weaknesses to beat:
- **EmailEngine**: self-hosted but **stateful** (Redis + its own encrypted store of each
  account's credentials), Node runtime, **$995/yr commercial license**, account-pinned.
- **Nylas / Unipile**: **cloud-only**; **credentials and mail content flow through a third
  party**; per-connected-account pricing; vendor lock-in; no real self-host story.

Differentiators the gateway commits to:
- **Zero-persistence by default.** No credential store, no message store in Inline mode.
  "Your secrets never touch our disk" is the headline — the sharpest wedge against
  EmailEngine (stores creds) and Nylas/Unipile (store everything).
- **Bring-your-own-secrets.** Credentials are presented per request from *your* vault; the
  gateway is a pure function of (request + credential). Trivially audited: nothing to leak.
- **Single small binary, Rust.** Low footprint, no Redis/DB required for the core path —
  vs Node + Redis.
- **Permissive OSS license (MIT).** Vs EmailEngine's paid license.
- **Stateless horizontal scale** — vs account-pinned competitors.
- **Standard-IMAP-first, provider-agnostic.** No per-provider SaaS integration tax for the
  long tail.
- **Privacy→convenience ladder.** Inline (stateless) → Session (ephemeral) → Portfolio
  (managed) meet developers wherever they sit on the curve, in one binary.

Resolved during this session (see decision 6): the per-request-login vs. pooling tension is
settled as **ephemeral in-memory pooling with a short TTL** — ephemeral state, never
persisted — so "zero-persistence" stays honest.

---

## Deferred / later tracks

- **Microsoft Graph** (`msgraph.yaml`) — separate REST track for Outlook/M365.
- **Own-inbox** and **real-time inbound** (needs an inbound-event ingestion subsystem).
- **Generic `config jsonb` per-instance param overrides** (would supersede the one-off
  `url` field) — interim is prefilled forked templates.
- **Generic managed-backing-container** hosting pattern (WhatsApp/npx-MCP).
- **`x-overslash-fixed-params`** extension (for third-party overgeneric APIs).
- **overfwd Portfolio/Session modes** — standalone-product surfaces, disabled in Overslash
  Cloud; can land after the Inline path Overslash depends on.
