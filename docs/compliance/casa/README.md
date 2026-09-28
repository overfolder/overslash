# CASA readiness

Overslash's readiness for the annual security assessment Google requires of apps that
request restricted OAuth scopes.

| Document | What it is |
|----------|------------|
| [gap-assessment.md](gap-assessment.md) | All 55 CASA requirements, verdict + evidence per requirement |
| [evidence-index.md](evidence-index.md) | What the lab will ask for, and where each artifact comes from |
| [dast-readiness.md](dast-readiness.md) | The authenticated-scan problem, and how to answer it |
| [dependency-vulnerability-policy.md](dependency-vulnerability-policy.md) | 6.1.1: what is scanned and when, severity SLAs, who triages, and the time-boxed exception register |
| [gcp-posture.md](gcp-posture.md) | Live Google Recommender findings + measured configuration, **both** `overslash` and `overslash-dev` |

---

## Why we are in scope

Overslash ships service templates that request **Google restricted scopes**:

| Scope | Template |
|-------|----------|
| `gmail.readonly`, `gmail.modify`, `gmail.compose`, `gmail.metadata` | [`services/gmail.yaml`](../../../services/gmail.yaml) |
| `auth/drive` (full Drive) | [`services/google_drive.yaml`](../../../services/google_drive.yaml) |
| `auth/keep` | [`services/google_keep.yaml`](../../../services/google_keep.yaml) |

Google's rule: every app that requests restricted scopes **and** can move that data
through a third-party server must pass a security assessment by a Google-empanelled
assessor before its OAuth client leaves testing mode. Overslash is squarely that shape —
it holds the tokens, it makes the calls, and the data transits our infrastructure.

Re-verification is required at least every 12 months from the Letter of Assessment date.

### Relationship to the per-org credentials strategy

[SPEC.md §7](../../../SPEC.md) already records the escape hatch: a Workspace customer can
create their own GCP project, mark the consent screen **Internal**, and hand us the client
ID + secret via Org Settings. Internal-tier clients skip Google verification entirely
regardless of scope, so those tenants never touch CASA.

That strategy is real and worth pushing, but it does not remove the requirement. It covers
Workspace tenants only. The **system** OAuth client — the default for consumer accounts
and for anyone who has not brought their own — still needs the assessment, and it is the
client that makes the product work out of the box.

---

## What "CASA Tier 2" means in 2026

The naming has moved on, and searching for "Tier 2" now returns stale guidance. Current
state:

- The program is the **App Defense Alliance Application Security Assessment** scheme. The
  live requirement set is the **CASA Specification v2.1.1 (2026-06-03)**, published at
  [`appdefensealliance/ASA-WG`](https://github.com/appdefensealliance/ASA-WG/blob/develop/CASA/CASA%20Specification.md),
  with acceptance criteria in the companion
  [CASA Test Guide](https://github.com/appdefensealliance/ASA-WG/blob/develop/CASA/CASA%20Test%20Guide.md).
  This assessment is pinned to that version; re-pin on the next revalidation.
- **55 numbered requirements** across 7 sections, derived from OWASP ASVS 4.0.3. Section 7
  (Webhook Security) has no direct ASVS ancestor and is the newest addition — it matters
  disproportionately to us, because we are a webhook *provider*.
- Tiers became **assurance levels**:
  - **AL1 — verified self-assessment.** We supply written statements, code snippets,
    screenshots and scan output; the lab reviews the evidence but does not touch the app.
  - **AL2 — lab assessment.** The lab tests the application, the deployment infrastructure
    and the data storage directly.
  - **All 55 requirements apply at both levels.** Only the assessment method differs.
- **Google picks the level**, not the developer, from data sensitivity, user counts and
  risk signals. Restricted scopes plus a multi-tenant credential vault points at **AL2**,
  and this assessment plans for AL2.
- **18 of the 55** requirements are validated by an *authenticated* Burp Suite scan run
  with the ADA Burp Audit Scan Configuration — developer-run at AL1, lab-run at AL2. See
  [dast-readiness.md](dast-readiness.md), because this is the part of the assessment most
  likely to go badly for a gateway product.

### The 7 sections

| # | Section | Reqs | Our exposure |
|---|---------|------|--------------|
| 1 | Authentication | 8 | Passwordless — no password requirements apply, but anti-automation does |
| 2 | Session Management | 9 | The 7-day stateless JWT is the weak point |
| 3 | Access Control | 9 | Multi-tenant isolation + OAuth flow correctness |
| 4 | Communications | 4 | TLS config; crypto strength |
| 5 | Data Validation & Sanitization | 11 | **SSRF (5.1.5) is the defining requirement for this product** |
| 6 | Configuration | 7 | Dependency vulnerability process; debug modes; secret storage |
| 7 | Webhook Security | 7 | We are both provider *and* consumer; provider side is unbuilt |

---

## Status

This directory is an **assessment**, not a remediation. Nothing here changes code or
infrastructure. The work it identifies is tracked in [TODO.md §1.6](../../../TODO.md) and,
for the P0/P1 items, as GitHub issues.

Two findings in [gap-assessment.md](gap-assessment.md) were **live vulnerabilities**
rather than compliance gaps, to be decided on their own timeline rather than waiting for
a CASA engagement. They are marked `P0` and repeated at the top of that document. Both are
now fixed — **V2** (cross-tenant API-key minting), then **V1** (SSRF on the
action-execution path), and OIDC issuer discovery has since moved onto the same guard.
One follow-up survives V1 and is tracked in TODO §1.6: the default `Everyone → admin on
http` grant, which is a behaviour change for new orgs and so a human decision.
