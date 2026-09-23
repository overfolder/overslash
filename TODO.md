# Overslash — TODO

Roadmap to public launch. Phases 1–4 are shipped (see [STATUS.md](STATUS.md)); what remains is the commercial + trust surface around the product engine, plus the dashboard residuals that still ship visibly broken or missing.

Three blocks, in priority order:

1. **Launch Blockers** — must ship before opening the public signup funnel.
2. **Launch +1** — polish within the first weeks of GA.
3. **Backlog** — post-launch, not gating.

A PR can ladder up to a block by tagging its first line `[launch]`, `[launch+1]`, or `[backlog]`. When everything in §1 is checked, we cut GA.

---

## 1. Launch Blockers

### 1.1 Transactional email

No mailer exists today. Billing has no receipts and new accounts get no welcome / verification touch. Approvals and secret-requests are explicitly **not** email-driven — email is the wrong channel for real-time decisions (latency, deliverability, off-device), and the dashboard + webhook + `oversla.sh` link is the path of record.

- [x] Pick a provider and wire it (likely Resend — we already template a service for it). Config: `EMAIL_PROVIDER`, `EMAIL_FROM`, `EMAIL_REPLY_TO`; secret via the existing vault.
- [x] Templated emails — store templates in `crates/overslash-core/templates/email/` with `{var}` interpolation matching the audit-description style.
- [x] **Billing**: receipt on `invoice.payment_succeeded`; dunning on `invoice.payment_failed`; subscription canceled / trial ending.
- [x] **Welcome / first login** for both root signups and corp-org JIT provisioning.
- [x] **Webhook DLQ digest** → daily digest to org admins listing webhook endpoints with terminal failures.
- [x] Per-user unsubscribe state for non-transactional (welcome) emails only — billing emails are exempt by policy.
- [ ] (Optional, post-MVP) User-level opt-in email for newly remembered permissions — informational only, not a control surface.

### 1.2 Onboarding & trust domains

D12 keeps trust domains clean. Corp-org admins still need a way to onboard the *first* teammate before that teammate has logged in via the org's IdP. Slug squatting is intentionally **not** mitigated pre-launch — paid org creation is the natural gate; we'll deal with squatters reactively if any appear.

- [x] **Corp-org invite path** — email-gated against the org's `org_idp_configs.allowed_email_domains`. Invite resolves on first IdP login (binds the new identity to the invite's role). Does **not** bypass the IdP; only pre-authorizes the email.
- [x] Audit events on creator-admin add (`POST /v1/orgs`) and removal (`DELETE /v1/account/memberships/{org_id}` when the leaver is the original creator).
- [x] Login page on a corp subdomain renders a clear empty state when no IdP is configured + a "you've been invited, please log in via X" state when the visitor's email matches a pending invite.

### 1.3 Human-facing documentation site

`SKILL.md` covers agents. Humans (the people swiping the credit card) have nothing past `www.overslash.com`. The single biggest sales blocker after email.

- [-] Docs site at `docs.overslash.com` (or `/docs` on the marketing site). MDX or VitePress; ship as static.
- [ ] Concepts: identity hierarchy, permissions/approvals, secrets, services, groups, rate limits.
- [ ] Quickstart: 10-minute "first authed call" against Resend or GitHub.
- [ ] Per-template setup guides for the 9 shipped services (Eventbrite, GitHub, Gmail, Google Calendar, Google Drive, Resend, Slack, Stripe, X).
- [ ] REST API reference auto-generated from the routes (consider serving `/openapi.json` from the API and rendering with Scalar/Redoc).
- [ ] MCP setup guide (Claude Desktop, Cursor, Claude Code) — fold in `dashboard/src/routes/docs/claude-code/` content.
- [ ] Self-hosting guide (`overslash web`, OpenTofu module, single-org mode).

### 1.4 Operational readiness

Monitoring is deployed; paging and recovery procedures are not yet exercised.

- [x] Bind `pagerduty_integration_key` in `infra/env/prod.tfvars` (or a Slack channel via a custom notification channel) so P0 alerts actually page someone.
- [x] Public status page (Better Stack / Statuspage / Instatus) wired to the existing P0 uptime check + a manual override.
- [ ] **Master-key rotation runbook** — documented procedure to rotate the AES-256-GCM master key with zero downtime (dual-key read, re-encrypt loop, drop old key). Run the drill end-to-end on dev.
- [ ] **Postgres PITR restore drill** — document and execute a full restore-to-new-instance against the dev DB; record RTO/RPO observed.
- [ ] On-call runbook: how to roll back a Cloud Run revision, how to disable a webhook target, how to revoke a leaked API key, how to suspend an org.

### 1.5 Legal / compliance

- [ ] (later) `security.txt` at `https://www.overslash.com/.well-known/security.txt` + vuln disclosure policy page.
- [ ] (later) DPA template + signing flow (DocuSign / PandaDoc / countersigned PDF). Procurement asks for this on every B2B deal.
- [x] Subprocessor list page on the marketing site (Cloud Run, Cloud SQL, Stripe, Cloudflare, Resend, configured IdPs). On www.overslash.com/privacy
- [ ] (later) **GDPR request handling** — document the manual process for data-export and hard-delete requests (intake → DPO ack → manual SQL → audit row). Automated endpoints are a post-launch backlog item; volume expected to be near zero at GA.

### 1.6 CASA readiness

The annual security assessment Google requires of apps holding restricted OAuth scopes —
we ship `gmail.*`, `drive` and `keep` templates, so the system OAuth client needs it.
Full assessment in [docs/compliance/casa/](docs/compliance/casa/README.md); the gap list
is [gap-assessment.md](docs/compliance/casa/gap-assessment.md). 12 of 55 requirements
are gaps today.

**P0 — live vulnerabilities, not compliance items. Decide on a security timeline.**

- [x] **SSRF on the action-execution path** — `services/http_caller.rs` now builds its own pinned client from the URL via `ssrf_guard::outbound_client` instead of accepting `state.http_client`, so all five action-execution call sites are covered by construction; `webhook_dispatcher::deliver` does the same per attempt. Tests in `tests/ssrf_guard.rs`. (CASA 5.1.5, 7.3.1)
- [ ] **Decide the default `Everyone → admin on http` grant** — org bootstrap (`crates/overslash-db/src/repos/org_bootstrap.rs:143-153`) grants it to preserve the old `allow_raw_http=true` default, and users skip Layer 2, so raw HTTP is available to every member on day one. Removing it makes raw HTTP a deliberate grant and lets [dast-readiness.md](docs/compliance/casa/dast-readiness.md) tell a lab the default-configured product has no unbounded egress. Behaviour change for new orgs — a human call, not an agent's.
- [x] **SSRF on OIDC issuer discovery** — `services/oidc_discovery.rs` no longer takes `state.http_client` or runs its own string check: every hop, including each redirect, goes through `ssrf_guard::outbound_client_validated` (resolve, check every address, pin). `https` is required, with plain `http` accepted only to loopback, and that is re-checked after resolution on every hop, so http to an allow-listed private range is still refused. Any failure after the input check returns a generic `OIDC discovery failed` 400, and the detail is logged server-side, so neither handler echoes an upstream error or body any more. Tests in `tests/ssrf_guard.rs`. (CASA 5.1.5)
- [x] **Cross-tenant API-key minting** — `POST /v1/api-keys` no longer takes an `org_id` at all: it uses `AdminAcl` + the `OrgScope` extractor, so the org is the presented credential's currently-active org. `identity_id` resolves through that scope, and migration 121 adds a composite `api_keys (org_id, identity_id) -> identities (org_id, id)` FK. The unauthenticated bootstrap branch — the only reason a body `org_id` existed — is gone; `POST /v1/orgs` returns the first admin key instead. (CASA 3.1.2, 3.1.4 — both now `pass`)

**P1 — hard CASA fails.**

- [x] `Secure` on every auth cookie, plus `__Host-`/`__Secure-` prefixes — one builder in `crates/overslash-api/src/cookies.rs`; the unprefixed `oss_session` is no longer read and is cleared on login/logout. One-time logout of every user on deploy. (2.3.1 — now `pass`)
- [ ] **Server-side sessions** — a sessions table with a `jti` claim checked per request. Keeps the 7-day UX while making logout, identity change and admin revoke effective, and gives a "terminate all other sessions" surface. One indexed lookup per request, cacheable in Valkey. (2.2.1, 2.2.2, 2.2.3)
- [ ] **Webhook section 7** — `https://` enforced at registration, a challenge-response endpoint-ownership handshake before first delivery, and a signed timestamp header behind a versioned signature (breaking for existing consumers — needs a migration note). Delivery through the SSRF guard is done (7.3.1). (7.1.1, 7.1.2, 7.2.3)
- [x] Security-headers layer on the API + a `headers` block in `dashboard/vercel.json`. The API's outermost middleware (`middleware/security_headers.rs`) sets HSTS (1y, `includeSubDomains`), nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a `Permissions-Policy` and a CSP on every response, each only if the handler did not: `default-src 'none'` for JSON/SSE, a style-only policy for the HTML pages the API renders, and a per-page script hash for the two that run one. The dashboard's CSP is **enforced** through SvelteKit's `kit.csp` (a per-response nonce on Vercel, a hash in the static build), so `script-src` carries no `'unsafe-inline'`; it includes `frame-ancestors 'none'`. The rest of the baseline is in `vercel.json`, which sets no CSP itself so the two never collide, and which `vite preview` also serves so e2e runs under it (`scripts/screenshot-security-headers.mjs` fails on any violation).
- [ ] **Dependency vulnerability scanning in CI** — `cargo-deny` + `npm audit` + OSV, with a written triage policy. Clear the four fixable advisories (`h2`, `rustls`, `crossbeam-epoch`, `event-listener`); justify `rsa` (unreached) and `paste` (unmaintained, no fix). (6.1.1)
- [ ] Require TLS on outbound calls — reject `http://` for Mode A and for instance/org base URLs, since vault credentials ride those requests. (4.1.1)
- [x] `redirect_uri` scheme allowlist + loopback-only rule + array cap on Dynamic Client Registration. https, loopback-only http, and reverse-DNS or named app schemes (cursor, vscode, windsurf); at most 10 URIs of 2048 bytes each (`services/oauth_redirect_uri.rs`). (3.2.2)
- [ ] Per-IP registration cap on `POST /oauth/register` — the residual from 3.2.2, and the anti-automation half of 3.1.5.
- [ ] `SECURITY.md` with a vulnerability disclosure policy and a security contact. Pairs with the `security.txt` item in §1.5.

**P2 — will be raised by a lab.**

- [ ] MFA or step-up for admin-class operations, or restrict magic-link login for admin identities so the IdP's MFA is the only path. (3.3.1, 2.4.1)
- [ ] `DEV_AUTH` parsed as a boolean with an `OVERSLASH_ENV != prod` interlock; weak-key rejection at boot so a copied `.env.example` cannot start; `RUST_LOG` off `debug` in production; drop `db_error` from the unauthenticated `/health`. (6.2.1, 1.2.1)
- [ ] Extend rate limiting to session-cookie and MCP-bearer traffic, and to the `/oauth/*` subrouter — unauthenticated DCR is currently unthrottled. (1.1.1, 3.1.5)
- [ ] Secret Manager Data Access audit logs + a log sink with locked retention + a documented secrets access-control policy. (6.7.1)
- [ ] Subdomain inventory and dangling-CNAME check across all ten `overslash.com` hostnames. (6.4.1)
- [ ] Infra hardening: `deletion_protection` and `ssl_mode` on Cloud SQL; an explicit `google_compute_ssl_policy` and Cloud Armor on the LB; `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER`; least-privilege IAM in place of project-wide `secretmanager.secretAccessor` and `cloudsql.admin`; Memorystore `auth_enabled` + `transit_encryption_mode`.

**P2 — raised by Google's own Recommender.** Measured on **both** `overslash` and `overslash-dev`; see [gcp-posture.md](docs/compliance/casa/gcp-posture.md). Remediating these closes them in Google's console, which is itself the evidence artifact.

- [ ] **P2 `REQUIRE_SSL`** — **production** `overslash-prod-db` runs `sslMode=ALLOW_UNENCRYPTED_AND_ENCRYPTED`, behind a **HIGH**-severity insight. Set `ssl_mode = "ENCRYPTED_ONLY"` in `infra/modules/cloud-sql/main.tf` so it applies to both environments. (CASA 4.1.1)
- [ ] **P2 unused `roles/editor`** — on production, **two** GCP-default service accounts hold Editor: the default Compute Engine SA (**0 permissions used in 90 days** → remove) and the cloudservices agent (12 used → downgrade to `roles/compute.editor`). Both invisible to Terraform. Add `constraints/iam.automaticIamGrantsForDefaultServiceAccounts` so they do not come back. (CASA 3.1.1)
- [ ] **P3/P4 Cloud SQL policies + auditing** — no instance or user password policy, and no database auditing. Add `cloudsql.enable_pgaudit`, `log_connections`, `log_disconnections` as database flags; decide whether built-in password policies are meaningful given the only human path is the Auth Proxy. (CASA 1.1.1, 6.7.1)
- [ ] **Audit logging is entirely off** — the project IAM policy returns `auditConfigs: NONE`, so Secret Manager, Cloud SQL and Cloud Run Data Access logs are not written. Add `google_project_iam_audit_config`, a sink to a locked bucket, and a log-based alert on `AccessSecretVersion`. This is the measured half of the 6.7.1 gap. (CASA 6.7.1)
- [ ] **`_Default` log bucket is 30 days and unlocked** — no export sink exists. Everything an assessor wants to see is in the bucket that is neither retained nor tamper-evident. (CASA 6.7.1)
- [ ] **`<project>_cloudbuild` bucket** — auto-created, not in Terraform, holds repository source archives with uniform bucket-level access **off** and public-access prevention merely `inherited`. Enforce both, or move builds to a managed bucket.
- [ ] Enable container image vulnerability scanning (`containerscanning.googleapis.com`); none of Container Scanning, Container Analysis, Binary Authorization or Security Command Center is enabled. Pairs with the CI-side 6.1.1 work.
- [ ] Secret Manager: 16 secrets, none with `rotation`, `next_rotation_time` or `expire_time`. Nothing schedules or alerts on rotation age. (CASA 6.7.1)
- [ ] **Memorystore has neither AUTH nor transit encryption** — `overslash-prod-valkey` confirmed live: `authEnabled` unset, `transitEncryptionMode: DISABLED`, `BASIC` tier. Set both in `infra/modules/memorystore/main.tf`. The cache holds resolver output the codebase itself describes as names, addresses and phone numbers. (CASA 6.7.1)
- [ ] **Production has 0 uptime checks and no `[P0] API Down` alert** — 8 alert policies are deployed, which is exactly 12 declared minus 3 disabled in tfvars minus the API-down policy `count`-gated on `api_domain != ""`. The only deployed P0 is `API High 5xx Rate`, which cannot fire when the service returns nothing at all.
- [ ] **No SSL policy and no Cloud Armor on the production LB** — both `gcloud compute ssl-policies list` and `security-policies list` are empty. TLS 1.2/1.3-only is currently true but unpinned and uncitable. (CASA 4.1.1)
- [ ] Set the org-policy baseline that would make the above guardrails rather than conventions: `sql.restrictPublicIp`, `iam.disableServiceAccountKeyCreation`, `run.allowedIngress`, `storage.publicAccessPrevention`. None is currently set.
- [ ] Move `Keyring::test()` behind `#[cfg(test)]` — it is `pub` and returns a hardcoded `[0xAB; 32]` key in the production library.
- [ ] Trusted-proxy configuration so `X-Forwarded-For` is not attacker-controlled; every per-IP throttle and every audit `ip_address` currently trusts it.
- [x] `Cache-Control: no-store` on `secrets/reveal` and other sensitive authenticated responses — the default on every API response that does not set its own (`/icons/*` keeps `public, max-age=86400`; streamed and deferred-download passthrough keeps the upstream's).
- [ ] Fix `ci-ok`: it accepts `cancelled` as success, and the paths-filter omits `services/**`, `scripts/**`, `.githooks/**` and the other four workflows — so a PR touching only those skips every substantive job and the one required check goes green.
- [ ] `CODEOWNERS` + a documented required-review count, so four-eyes is evidenceable from the repo.

**P3 — document rather than fix.** CMEK; SBOM, artifact signing and build provenance
(`--provenance=false` in Cloud Build); `db-f1-micro` sizing; an org-policy baseline; the
three production alert policies disabled in `infra/env/prod.tfvars`.

**Assessment logistics.**

- [ ] Close the dev-environment deltas (public Cloud SQL IP with no `authorized_networks`; `DEV_AUTH` on) or stand up a dedicated scan environment. See [dast-readiness.md](docs/compliance/casa/dast-readiness.md).
- [ ] Write the SSRF scoping memo **before** engaging a lab — the product looks exactly like SSRF to a DAST scanner, and the argument has to be supplied during scoping, not after the report.
- [ ] Run the ADA Burp Audit Scan Configuration ourselves against the scan target and fix what it finds. At AL1 this is also the deliverable.
- [ ] Assemble the evidence pack — [evidence-index.md](docs/compliance/casa/evidence-index.md).
- [ ] Engage an authorized lab.


---

## 2. Launch +1 (first weeks after GA)

### 2.1 Dashboard residuals

- [ ] **IdP config edit UI** on `/org` — backend `PUT /v1/org-idp-configs/{id}` already supports it (TECH_DEBT.md §3).
- [ ] **Notification bell** dropdown in the top bar (review card `504a7`). Dashboard-side sibling of the agent inbox — the same "what's waiting on me?" question the `overslash` `get_events` action answers; reuse `services::inbox` classification rather than inventing a second one.
- [ ] **Archived sub-agents** — list + restore button on `/agents`, plus per-org cleanup config form (`subagent_idle_timeout_secs`, `subagent_archive_retention_days`).
- [ ] **Per-agent permission management** — rules, scopes, "Allow & Remember" review/edit on the agent detail page.
- [ ] **`/account` profile editing** — name + avatar editable.
- [ ] **Org webhook management UI** — list, create, rotate signing secret, disable.
- [ ] **Toggle Switch** component (`ToggleSwitch.svelte`) adopted everywhere replacing checkboxes (review card `2e268`).
- [ ] **OAuth Connections UX** (review card `c2575`): stop creating phantom Identity Provider + UUID connection when an admin adds a Google OAuth Client ID; reuse connections across services sharing the same provider; show provider email instead of UUIDs; support incremental scopes auth.
- [ ] **Services view fixes** (review card `73d90`): show username/email for service owners, fix `/users/{name}` 404, correct the `overslash` meta-service "Needs Setup" copy, group pills as a column, services connectable to groups from the detail view.

### 2.2 Templates & coverage

- [ ] Ship 11 more service templates to hit top 20 (priority order: Notion, Linear, Jira, Asana, HubSpot, Salesforce, Airtable, Discord, PagerDuty, Zendesk, Intercom).
- [ ] Complete the OpenAPI **bulk import** UX at `/services/templates/import` — currently scaffolded; needs overlay-default suggestions and a diff preview before save.
- [ ] **User-to-org template sharing** — propose / approve / deny flow (review card `7e5ee`).
- [x] **Declare a credential probe on every template that can have one.** `x-overslash-test` (D83) is on 20 of the 23. The three without one are deliberate: `deepwiki` (every tool needs a repo name, and it authenticates with nothing), `overslash` itself (`runtime: platform`), and the hidden fixture `test_email`. Any template added from here should declare one, and `shipped_test_actions_resolve_to_read_actions` holds a floor so the practice cannot quietly lapse.
- [ ] **Hard pins on `instance_defaults`** — a layer default is a *preset* an instance may override (D36, D38). Add an opt-in "not instance-changeable" flag so an org layer can mandate a value: the instance form renders it read-only and `instance_config::validate_config` rejects a key the layer has hard-pinned. Deferred deliberately — the preset is the useful case for per-instance values like a mailbox username, and a ceiling only matters once a layer wants to mandate an org-wide constant.

### 2.3 API surface gaps

- [ ] **Approval visibility scoping** — `GET /v1/approvals?scope=actionable` vs `?scope=mine` (Phase 3 carry-over).
- [ ] **Webhook payload**: include `gap_identity` and `can_be_handled_by` on approval events (Phase 3 carry-over).
- [ ] **Live Map follow-ups** (D58, dev-gated behind `OVERSLASH_LIVE_MAP`):
  - Structural agent→service edges from permission rules. Today they only
    appear once traffic reveals them, because `GET /v1/permissions` is
    per-identity and deriving them up front would cost one request per agent.
  - Resolve an approval from the map. The amber state is real (it comes off
    `approval.pending`); the design's click-a-packet Allow/Deny popover was
    dropped rather than built against a half-modelled in-flight approval.
  - The force layout's repulsion pass is O(n²) over every structural node,
    every frame — inherited from the design prototype. Fine for a few hundred
    nodes, and the reason the map is dev-gated is not this, but it is the first
    thing to fix if it ever ships wider. A spatial grid is the usual answer.
  - Decide whether `activity` can ever be on by default. It is the only topic
    whose volume scales with the gateway's hot path — one durable `events` row
    per call — so ungating it means answering that first.
- [ ] **A setup page that handles every slot at once.** A template with two unbound per-instance credential slots gets two setup links today (D83), handed over in sequence; the page names the outstanding siblings but cannot link to them, because each link is a separate capability. No shipped template declares two, which is why this is a documented limit rather than a blocker.
- [ ] **Wire the Deny button on the provide / setup pages.** Still local-only (`TODO(secret-request-deny)`): declining leaves the request pending until it expires, and the requesting agent is never told.
- [ ] **Let an agent verify its own service.** `POST /v1/services/{id}/activate` is owner-or-admin, and an agent is deliberately not an ancestor of its own owner-user, so the agent that created an instance cannot probe it — which is exactly why D86's gate defaults off for a create with no human in it. Exposing it as a platform action means synthesising an `AuthContext` and re-entering `call_action_impl` from inside a call; worth doing only if the re-entrancy (permission chain, audit rows) can be shown not to double.
- [ ] **Take the credential value on the wizard's *configure* step, not only on its failure step.** D86 put a `SecretValueField` behind "Edit and retry" because a named-but-empty vault secret is otherwise a dead end under the gate. The first pass through the form still only binds a *name* (`SecretNamePicker`, whose hint tells you to go to the Secrets page), so the common case takes one extra round trip through a red verdict.
- [ ] **The setup-draft purge does not clean up orphaned connections.** `DELETE /v1/services/{name}` calls `cleanup_orphaned_connection`; the sweeper cannot, because `fire_connection_deleted` wants an actor for its audit row and event. Identity-owned connections are reusable, so the cost is a row rather than a leak.
- [ ] **MCP Login Flow Fixes** (review card `877cb`) — assignment/consent page served from dashboard, default `inherit_permissions=true` for new MCP agents, reuse the existing agent on reauth, hide revoked MCP clients from the UI after 3s.

---

## 3. Backlog (post-launch)

- Global service registry community contribution workflow (PR-based, with the validator endpoint as CI).
- Multi-region / data residency (EU instance separate from US).
- SOC 2 prep — separate workstream; controls audit, evidence collection, vendor (Vanta / Drata).
- Bulk permission operations on the Org Settings view.
- Light mode + theme toggle on the dashboard.
- More e2e: MCP approval-bubbling and elicitation full-chain (puppet + scaffold specs in; deterministic gap-trigger pending — likely via a seeded service template + a no-permissions sub-agent).
- Increase integration coverage across all API routes; unit tests for permission resolution; OAuth refresh + BYOC fallback edge cases.
- **Priority-aware compact truncation.** `compact_response::shrink_to_budget` applies uniform limits across the whole JSON tree, so a payload that ships column descriptors alongside rows (Metabase, BigQuery, Snowflake, most tabular APIs) spends the 8 KB budget on metadata before the truncator reaches the rows — a 254-row Metabase result renders as 10 rows plus `…+244 more items`. Make it priority-aware: detect the principal collection by shape, drop sibling metadata before it, and add a depth lever so nested descriptor subtrees (`cols[i].fingerprint`) collapse while their scalar leaves (`cols[i].name`) survive. Heuristic rather than a template `x-overslash-*` extension: the motivating traffic arrives over Mode A (`service: "http"`), which has no template action to annotate. D57 (advertised paging params, a reachable `filter`) and D61 (a cropped result now carries a URL to its own full bytes) both made this less urgent, but neither made it wrong. The **key-cap** half is now done — #537 made `truncate` rank survivors structurally (cursor keys, then arrays, then the rest) instead of keeping whatever sorted first, which is why `metadata` no longer beats `rows` to the cap. What remains here is the budget ladder itself: detecting the principal collection by shape, and the depth lever.
- **Priority-aware compact truncation.** `compact_response::shrink_to_budget` applies uniform limits across the whole JSON tree, so a payload that ships column descriptors alongside rows (Metabase, BigQuery, Snowflake, most tabular APIs) spends the 8 KB budget on metadata before the truncator reaches the rows — a 254-row Metabase result renders as 10 rows plus `…+244 more items`. Make it priority-aware: detect the principal collection by shape, drop sibling metadata before it, and add a depth lever so nested descriptor subtrees (`cols[i].fingerprint`) collapse while their scalar leaves (`cols[i].name`) survive. Heuristic rather than a template `x-overslash-*` extension: the motivating traffic arrives over Mode A (`service: "http"`), which has no template action to annotate. D57 (advertised paging params, a reachable `filter`) and D61 (a cropped result now carries a URL to its own full bytes) both made this less urgent, but neither made it wrong.
- **Inbound media for MCP services.** `x-overslash-download` (D61) lets an MCP tool result hand back a capability URL, so bytes leave a container without passing through a context window. There is no counterpart in the other direction. A tool that takes a *reference* to bytes the caller must upload first — `send_file` / `send_audio_message` on `services/whatsapp.yaml`, and the same shape on any MCP server that moves files, since MCP cannot carry bytes in either direction — can only be given a reference a previous read produced (`download_media` without `deliver: "url"`). That covers forwarding an attachment someone sent you, which is the common case; it does not cover originating one, because uploading needs the container's own URL and bearer token and the gateway deliberately hands out neither. Closing it means an upload capability URL: mint on a permission-checked action call, redeem with a `PUT` the gateway proxies upstream, credentials re-resolved at redeem time exactly as `services::deferred_download` already does — plus the `Ext` variant and token table to match. Deferred at the v0.7.0 WhatsApp template sync, where the forwarding path was judged enough to ship on.
- **Template async markers.** Let an action declare that it runs async by default (`x-overslash-async-default`), resolved at template-resolution time rather than mid-flight, and surfaced in the MCP tool schema and `/v1/search` so a caller sees it before calling. This is the answerable half of D56's objection to auto-promotion: the response shape stays a function of the request plus the *published* contract. Worth its own decision record, since it revisits D56.
- ~~**Hybrid mode** (`execution: "hybrid"`)~~ — **shipped, D68.** The re-dial problem this entry said had to be solved first was dissolved rather than solved: hybrid is not sync-that-promotes but *async that the connection waits on*, so the request path never dials and there is no in-flight request to hand over. The job owns a durable, already-claimed row from before the first byte; the connection is a spectator with a deadline, and the handoff changes only who reports the result.
- **Do not auto-promote a long-running sync call to async.** Considered and rejected: promotion either re-dials the upstream (duplicate side effects, and there are no idempotency keys) or spawns a detached task (no lease, dies on scale-in — a second async path with strictly weaker guarantees than the first). It also makes the response shape depend on runtime behaviour rather than on the request plus the published contract. The cheap fix for the underlying need is to have the 504 name `execution: "async"` in its hint.
- Async execution follow-ups (D62/D66): (a) `execution` on the `overslash_read` MCP tool — the canonical async case, a slow analytics query, is read-class, but that tool has its own required-args schema and body-builder so it needs a second forwarder plus tests; (b) binary async results — currently a 400, because `http_caller::call` runs bodies through `from_utf8_lossy` before they reach the row; the real fix is the worker writing to object storage with the row keeping `{result_url, mime, size_bytes}`, which needs a bucket + IAM in Terraform; (c) `NOTIFY`-driven wake-up so a queued job starts immediately instead of within one 2s tick — the `LISTEN` bridge already exists in `services::events::bus`; (d) `orgs.max_async_call_timeout_ms`, if an org ever complains that the sync ceiling they set to bound connection-holding also bounds their background jobs; (e) a *direct* async row records no `actions_executions_total` at all — `stored_call` only records the upstream response — so since D66 a gated async call is strictly more observable than a direct one, which is backwards.

---

## Done

Through 2026-05. Highlights below; full detail in [STATUS.md](STATUS.md).

- **Phases 1–4 backend**: orgs, identities, secrets (versioned + encrypted), permission rules, approvals (with bubbling), webhooks, audit, API keys.
- **OAuth + Service Registry**: native OAuth engine with three-tier BYOC, 9 OpenAPI 3.1 templates, three-tier template registry, template validation endpoint, per-service scopes, `on_behalf_of`.
- **Mode A/B collapse** (SPEC §8): single Service + HTTP verb execution surface; typed `reauth_required` envelopes; dry-run `/v1/actions/validate`; stable webhook envelope.
- **Identity hierarchy**: parent/child + `inherit_permissions` live pointer; approval bubbling; sub-agent idle archive + retention (backend).
- **Groups (Layer 1 ceiling)**: read/write/admin grants, `auto_approve_level` (a second ceiling on the same ladder), raw HTTP as the `http` singleton.
- **Rate limiting**: two-tier (User bucket + identity caps), Redis/Valkey or in-memory, standard headers + 429.
- **Multi-provider OIDC** + per-org IdP configs + GitHub social login + email-domain provisioning.
- **Multi-org auth**: subdomain routing on `*.app|api.overslash.com`, switch-org, account memberships, corp-org creation with creator-admin.
- **MCP**: Streamable HTTP + OAuth 2.1 AS endpoints, `overslash mcp login` CLI, annotated tools split into `overslash_search` / `_read` / `_call` / `_auth`, metaservice bridge for self-management actions, typed error envelopes.
- **Stripe billing**: checkout-creates-org, customer portal, geo-priced EUR/USD, automatic tax, `free_unlimited` tier, full Stripe fake + Playwright Checkout e2e.
- **Monitoring**: 5 GCP dashboards (overview / api-use / actions-and-oauth / cloudsql-use / business) + P0/P1/P2 alerts + uptime + OTel sidecar + JSON logs.
- **Dashboard**: Agents tree, Services + templates, Secrets list + detail with reveal/restore, Audit Log with CSV export, Approval queue redesign, Members, Account, Billing flows, OAuth consent, API Explorer with Try-it, per-agent MCP Connection card, responsive shell.
- **Real-stack e2e**: scenarios library, MCP puppet client (Rust + REST + TS), OAuth fake AS, Auth0/Okta IdP fakes, Mode-C e2e against connected GitHub.
- **CLI**: single `overslash` binary with `serve` / `web` / `mcp` / `mcp login` subcommands.
