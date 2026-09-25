# CASA evidence index

What the lab asks for, per requirement, and where each artifact comes from. Derived from
the **Evidence** clauses of the CASA Test Guide v2.1.1.

At **AL1** we supply all of this and the lab reviews it. At **AL2** most rows become
"to be collected by labs" — but the lab still asks for the written statements, the code
snippets and the policies, because those are the parts it cannot test for. Assume every
`statement` and `policy` row below is needed at either level.

`have` = the artifact exists or is a copy-paste from the repo today.
`need` = it must be written, captured or produced.

---

## Written statements

| For | Statement | Status | Source |
|-----|-----------|--------|--------|
| 1.1.1 | The list of external authentication services (Google, GitHub, per-org OIDC), plus the magic-link anti-automation policy: per-IP 30/600s, per-email 5/900s, opaque response on every outcome | `need` | `routes/auth/magic_link.rs:16-19,76-113` |
| 1.1.3 | "No passwords exist." Describe the API-key analogue: Argon2id, 256-bit entropy, prefix-indexed, revocable, expiring | `need` | `routes/api_keys.rs:191-209` |
| 2.1.1 | Why three capability tokens legitimately appear in URLs, and their compensating properties (single-use / short-TTL, SHA-256 at rest, clean redirect after use) | `need` | `gap-assessment.md` 2.1.1 |
| 2.3.3 | Why `osk_` API keys coexist with session tokens — programmatic access, not user sessions | `need` | — |
| 5.1.3 | The jq sandbox: in-process, JSON-only, syntax-validated, timeout-bounded, no filesystem / network / shell | `need` | `services/response_filter.rs:145-199` |
| 5.2.1 | "Overslash stores and serves no uploads." One-shot capability token, bytes forwarded to a pinned upstream, nothing written to disk, nothing served back | `need` | `routes/uploads.rs:15-24,58-67` |
| 6.4.1 | Subdomain inventory: every record under `overslash.com`, its owning service, and a dangling-CNAME check | `need` | — |
| 7.1.1 / 7.1.2 / 7.3.1 | The webhook-provider posture — this is one document covering scheme enforcement, ownership verification and SSRF mitigation on callback URLs. Scheme enforcement, the ownership handshake, SSRF mitigation and replay protection (7.2.3) have all landed | `need` | `gap-assessment.md` §7 |
| 5.1.5 | The SSRF scoping memo — the single most important piece of evidence in the pack | `need` | [dast-readiness.md](dast-readiness.md) |

## Code snippets

The Test Guide asks for a portion of code, not the whole file — a screenshot or a text
excerpt, without calling functions or underlying libraries.

| For | Snippet | Status | Source |
|-----|---------|--------|--------|
| 7.2.2 | The timing-safe comparison. Ready to paste verbatim | `have` | `routes/billing/webhook.rs:371-384` |
| 7.2.1 | HMAC-SHA256 over the raw body (consumer) and over the raw envelope (provider) | `have` | `routes/billing/webhook.rs:360-370`; `services/webhook_dispatcher.rs::sign` |
| 7.2.3 | Timestamp tolerance on the consumer side; signed timestamp on the provider side, re-signed per attempt | `have` | `routes/billing/webhook.rs:310-358`; `services/webhook_dispatcher.rs::sign` + `tests/webhook_signing.rs` |
| 1.1.2 / 1.3.3 | CSPRNG token generation and SHA-256-only storage | `have` | `routes/auth/magic_link.rs:118-129` |
| 1.1.3 | Argon2id hashing of API keys | `have` | `routes/api_keys.rs:191-209` |
| 4.1.3 | AES-256-GCM encrypt/decrypt with per-call nonce; the versioned keyring | `have` | `overslash-core/src/crypto.rs:78-93,184-186` |
| 5.1.8 | A representative `sqlx::query!` call site **and** the `disallowed-methods` lint that bans runtime-string SQL | `have` | `clippy.toml:1-5` |
| 3.1.1 | An `OrgScope` method showing `org_id` injected into the query | `have` | `crates/overslash-db/src/scopes/` |
| 3.2.1 | PKCE S256 enforcement and exact-match `redirect_uri` at both authorize and token exchange | `have` | `routes/oauth/authorize.rs:39-51,85-87`; `routes/oauth/token.rs:102-103` |
| 2.3.4 | The `aud` split preventing cookie↔bearer replay | `have` | `services/jwt.rs:6-11` |
| 6.5.1 | `scrub_transport_error` — a strong affirmative artifact, since it declines to log a URL *because* credentials live in the query | `have` | `services/audit_capture.rs:93-118` |
| 2.3.1 | Cookie construction: one builder, `Secure` + `__Host-`/`__Secure-` on every cookie, prefixed-only reader | `have` | `crates/overslash-api/src/cookies.rs` |
| 2.2.x | Server-side session lookup | `need` | Lands with the P1 session work |
| 5.1.5 | `ssrf_guard` denial ranges, `.resolve()` pinning, `Policy::none()` — **and** the call sites proving it is on the execution path | `have` / `need` | `services/ssrf_guard.rs:17-43,121-129`; call sites land with P0 |

## Screenshots

| For | What to capture | Status |
|-----|-----------------|--------|
| 1.1.1 | Anti-automation in action: the magic-link throttle tripping, and the identical opaque response before and after | `need` |
| 3.3.1 | MFA enforcement on an admin account — either our own step-up, or the IdP's challenge if we answer 3.3.1 by IdP delegation | `need` |
| 7.1.1 | An `http://` webhook endpoint being rejected at registration | `have` — `dashboard/scripts/screenshot-webhook-https.mjs` (`webhook-https-rejected.png`) |
| 6.2.1 | Debug surfaces absent in production — `/auth/dev/token` returning 404, `/health` with no `db_error` field | `need` |

Capture these with the existing scenarios library rather than by hand:
[`dashboard/tests/scenarios/`](../../../dashboard/tests/scenarios/README.md) boots the real
stack via `make e2e-up` and seeds fixtures against the real API, so the screenshots show
what the product actually renders.

## Log samples

| For | Sample | Status |
|-----|--------|--------|
| 6.5.1 | An extract of production application logs demonstrating no credentials, no payment details, and no session tokens in reversible form | `need` — capture **after** `RUST_LOG` drops off `debug`, otherwise the sample argues against us |

## Policies and documents

| For | Document | Status |
|-----|----------|--------|
| 6.7.1 | A documented access-control policy for server-side secrets: who can read what, through which path, and how access is logged and monitored | `need` |
| 6.7.1 | Evidence that secret access is logged — requires `google_project_iam_audit_config` for Secret Manager Data Access logs plus a sink with locked retention | `need` |
| 6.1.1 | A dependency-update and vulnerability-response policy: scan cadence, severity triage, patch SLA, and the justified-exception process for `rsa` and `paste` | `have`: [dependency-vulnerability-policy.md](dependency-vulnerability-policy.md), with the exceptions as config in `deny.toml` / `osv-scanner.toml` |
| — | `SECURITY.md` with a vulnerability disclosure policy and a security contact. Not a numbered CASA requirement, but its absence on a public repo hosting a credential vault is the cheapest possible finding to avoid | `need` |
| — | Master-key rotation runbook. [TODO.md](../../../TODO.md) marks it done; no file exists in `docs/runbooks/`, and [STATUS.md](../../../STATUS.md) — authoritative per the repo's Rule 1 — lists it as outstanding | `need` |
| — | DR plan: RTO/RPO, restore procedure, and a recorded restore drill. PITR is configured (`infra/modules/cloud-sql/main.tf:69-78`) but never exercised | `need` |

## Scan output

| For | Artifact | Status |
|-----|----------|--------|
| 6.1.1 | Dependency scan output: the *Dependency audit* jobs (`cargo-deny`, `npm audit`, OSV). Take a recent scheduled run against `master`, which shows the two justified ignores filtered with their reasons | `have`: GitHub Actions, `.github/workflows/deps-audit.yml` |
| The 18 DAST-validated requirements | An authenticated Burp Suite scan run with the ADA Burp Audit Scan Configuration. Developer-run at AL1; lab-run at AL2 | `need` — see [dast-readiness.md](dast-readiness.md) |
