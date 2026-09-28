# Security policy

Overslash holds other people's credentials, so we take reports about its security
seriously and would much rather hear about a problem from you than from an incident.
This page covers how to report a vulnerability, what happens after you do, and what is
in scope.

The same contact details are published in machine-readable form at
[`https://app.overslash.com/.well-known/security.txt`](https://app.overslash.com/.well-known/security.txt)
(RFC 9116).

## Reporting a vulnerability

Email **[security@overslash.com](mailto:security@overslash.com)**.

**Please do not open a public GitHub issue, pull request or discussion for a security
problem.** Those are public the moment they are filed.

A useful report includes:

- the affected component (hosted service URL, API route, MCP tool, dashboard page,
  `overslash` binary version, SDK version or service template);
- step-by-step reproduction, with requests and responses where you have them;
- the impact as you understand it: what an attacker gains, and from what starting position
  (anonymous, a user in another org, an agent key, ...);
- how you would like to be credited, if at all.

Reports in English or Spanish are equally welcome.

We have no PGP key at the moment. If the details are too sensitive for plain email, send
a short first message without them and we will agree a channel with you.

## What to expect

| Step | Target |
|------|--------|
| Acknowledgement of your report | 2 business days |
| Initial assessment: confirmed or not, and a severity | 5 business days |
| Status updates while a fix is in progress | at least every 14 days |

Severity is assessed with CVSS v3.1. Once a report is confirmed, we fix it, or ship a
mitigation that removes the exposure, within:

| Severity | Fixed within |
|----------|--------------|
| Critical (CVSS ≥ 9.0) | 7 days |
| High (7.0–8.9) | 30 days |
| Medium (4.0–6.9) | 90 days |
| Low (< 4.0) | 180 days |

These are the same windows our
[dependency vulnerability policy](docs/compliance/casa/dependency-vulnerability-policy.md)
applies to advisories in third-party code, and the clock starts at the same point: when
the issue is confirmed, not when someone gets round to it. If we cannot meet a window we
will tell you why and when we expect to.

The hosted service is fixed by deploying. For self-hosted users a fix ships in a new
release, and the release notes say that it contains a security fix.

## Coordinated disclosure

We ask you to keep the details private until a fix is released, or for **90 days** from
your report, whichever comes first. If a fix needs longer we will explain why and ask to
agree a new date with you; we will not ask for an open-ended embargo. Once a fix is out we
are happy to publish an advisory together and credit you in it, unless you would rather
stay anonymous.

We do not currently run a paid bug bounty.

## Scope

**In scope**

- The hosted service: `app.overslash.com` and organization subdomains
  (`<org>.app.overslash.com`), and `api.overslash.com` / `<org>.api.overslash.com`.
  That covers the REST API, the OAuth authorization server (`/oauth/*`,
  `/.well-known/oauth-*`), the MCP server (`/mcp`) and the dashboard.
- This repository's code: the API and workers (`crates/`), the `overslash` self-hosted
  binary, the dashboard (`dashboard/`) and the SDK (`sdk/`, published as
  `@overslash/sdk`).
- The service templates in `services/`, where a template causes Overslash to send a
  credential or data somewhere it should not.

Issues we are particularly interested in: cross-tenant access (reading or acting on
another organization's secrets, connections, approvals or audit log), permission-chain or
approval bypasses, secret disclosure through any API response, log or error message,
SSRF through action execution or webhooks, and OAuth flaws.

**Out of scope**

- Vulnerabilities in the third-party services Overslash connects to (Google, GitHub,
  Slack, ...). Report those to the vendor. A flaw in how *Overslash* talks to them is in
  scope.
- `*.dev.overslash.com`. It is a staging environment, not a test target; reproduce against
  production with your own accounts, or against a local build (`make local`).
- `status.overslash.com` and other hosted third-party pages.
- Denial of service, load testing and volumetric attacks.
- Social engineering, phishing and physical attacks against Overspiral staff or offices.
- Findings that require a compromised device or browser, a malicious browser extension,
  or physical access to an unlocked machine.
- Reports from automated scanners without a demonstrated impact, including missing
  headers or best-practice suggestions with no exploit path.
- Self-XSS, logout CSRF, and clickjacking of pages with no state-changing action.
- Known-vulnerable dependency versions without a demonstration that the vulnerable code
  is reachable. Our dependency scanning already reports these to us.

## Supported versions

| Version | Supported |
|---------|-----------|
| Hosted service (`app.overslash.com`) | Always the current deployment |
| Latest minor release of the self-hosted `overslash` binary | Yes |
| Older releases | No. Please upgrade |
| `@overslash/sdk` | Latest published version |

Overslash is pre-1.0 and moves quickly, so we do not backport fixes to older release
lines. A security fix lands in the next release.

## Safe harbor

We will not pursue or support legal action against you, and will not ask law enforcement
to, for security research carried out in good faith under this policy. We consider such
research authorized, including under any anti-hacking or anti-circumvention law that would
otherwise apply, and we waive any terms of service restriction that would conflict with it
for the purposes of that research.

Good faith means that you:

- test only against accounts and organizations you own or have explicit permission to
  use;
- stop as soon as you reach data that is not yours (another tenant's secret, message or
  record), access no more than you need to prove the issue, do not keep or share it, and
  tell us what you accessed in your report;
- do not degrade the service for other users, and do not use denial of service, spam or
  social engineering;
- give us a reasonable chance to fix the issue before disclosing it, as described above;
- do not demand payment or anything else in exchange for not disclosing.

If a third party brings legal action against you for research that followed this policy,
we will make it known that your work was authorized. If you are unsure whether something
is covered, ask us first at security@overslash.com.

This policy is published by Overspiral S.L., which develops and operates Overslash.
