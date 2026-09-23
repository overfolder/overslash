# DAST readiness

Eighteen of the 55 CASA requirements are validated by an **authenticated Burp Suite scan**
run with the [ADA Burp Audit Scan Configuration](https://github.com/appdefensealliance/ASA-WG/blob/main/CASA/ADA%20Burp%20Audit%20Scan%20Configuration.json).
At AL1 we may run it ourselves; at AL2 an authorized lab runs it.

The requirements that hang on the scan: 2.1.1, 2.3.1, 2.3.2, 2.3.4, 3.1.5, 3.1.6, 5.1.1,
5.1.2, 5.1.3, 5.1.4, **5.1.5**, 5.1.6, 5.1.7, 5.1.8, 5.1.9, 5.1.10, 6.2.1, 6.3.1.

---

## The problem

**Overslash's core function is indistinguishable from SSRF to a scanner.**

The product exists to take a caller-supplied URL and make an authenticated HTTP request to
it. A DAST scanner's SSRF probe does exactly that: it injects a Burp Collaborator hostname
into every parameter and watches for an out-of-band interaction. Point one at
`POST /v1/actions/call` and it will inject into `url`, Overslash will faithfully fetch the
Collaborator host — because that is the feature — and the scan will report:

- **1051136** — Out-of-band resource load (HTTP)
- **3146240** — External service interaction (DNS)
- **3146256** — External service interaction (HTTP)

Those are the exact three finding IDs that requirement 5.1.5's AL1 verification names as
disqualifying. Left unaddressed, this is a guaranteed fail on the single requirement that
matters most for this product, and it will recur on every annual revalidation.

## The opening the standard leaves

The AL2 verification text for 5.1.5 is written for exactly this case:

> Test shall confirm that the application does not initiate arbitrary HTTP or DNS requests
> to either internal or external resources based on user-supplied input, **unless it is a
> necessary part of the application functionality. In such cases, ensure application
> implements robust input validation and uses allowlists to restrict requests to trusted
> and necessary domains or IP addresses.**

So the finding is adjudicable. But the exemption is conditional. The first condition —
robust input validation with an IP deny-list on the path the scanner will hit — is now
**met** on action execution and webhook delivery (V1 in
[gap-assessment.md](gap-assessment.md) is fixed). The second — "allowlists to restrict
requests to trusted and necessary domains" — is the one still to argue, because raw Mode A
has no destination allowlist by design, and the `http` pseudo-service grant decides
whether that capability is on by default.

## What has to be true before a lab scans us

**1. The deny-list must exist and be on the path. — Done.**
`ssrf_guard` denies loopback, RFC 1918, link-local, CGNAT, ULA, multicast, broadcast,
unspecified and documentation ranges, on both IPv4 and IPv4-mapped/compatible IPv6; it
pins the resolved IP via `.resolve()` to close DNS rebinding, and sets `Policy::none()` so
a cooperative upstream cannot 3xx us inward. It is now on the action-execution path —
`services/http_caller` builds its client from the URL through the guard rather than
accepting one, so all five call sites are covered by construction — and on the webhook
dispatcher, per attempt. The lab's `http://169.254.169.254/` and `https://127.0.0.1/`
probes return a **400**, and the *internal* half of 5.1.5 — the half that is unambiguously
a vulnerability — passes cleanly. `crates/overslash-api/tests/ssrf_guard.rs` is the
evidence to hand the lab, including that a 302 toward the metadata endpoint is returned
rather than followed.

Two things for the memo. First, the allow-list: a self-hosted deployment can declare its
own private ranges in `OVERSLASH_SSRF_ALLOWED_CIDRS`, which is read from the process
environment and is therefore not reachable by anything a scanner can send. A scan target
should have it unset, and the memo should say so — an operator who set it and then
commissioned a scan would get findings about their own network, correctly.

Second, OIDC issuer discovery (`routes/org_idp_configs.rs`), which a scan run with an
admin credential will reach, goes through the same guard on every hop. It accepts plain
`http` only to loopback, and it returns one generic error whatever the upstream said, so
it is neither a path inward nor an oracle.

**2. The external half must be framed as an allowlist, not as unrestricted egress.**
The distinction to make, and it is a real one:

| Path | Egress bound | Status |
|------|--------------|--------|
| Service + HTTP verb (template-bound) | Host allowlist from the template's `svc.hosts`; the permission key derives as `{service}:{METHOD}:{path}` | **Already an allowlist.** This is the argument |
| MCP-runtime services | Pinned upstream URL from the template, through `ssrf_guard` | Already bounded |
| Webhook delivery | Registrant-supplied URL | Unbounded today; P1 adds scheme enforcement + ownership verification + the guard |
| The `http` pseudo-service (Mode A) | None — any host | **The one genuinely unbounded surface** |

The `http` pseudo-service is what makes the scan finding hard to argue, and it is granted
to the `Everyone` group with `admin` at org bootstrap
(`crates/overslash-db/src/repos/org_bootstrap.rs:143-153`), so it is on by default for
every member. Two ways to close it, in descending order of how well they argue:

- Make the grant **opt-in** — remove it from bootstrap so raw HTTP requires a deliberate
  org-admin grant, and the default-configured product has no unbounded egress at all.
  Then the scan target can simply not have the grant, and 5.1.5 becomes a plain pass.
- Keep it on but require a **per-org host allowlist** before a raw call resolves. Heavier,
  and it changes product behaviour for existing tenants.

Either way the answer stops being "we fetch whatever you ask" and becomes "egress is
allowlisted per service; raw HTTP is an explicitly granted capability, denied by default,
and still deny-listed against internal ranges".

**3. The scoping memo must be written before the engagement, not after the finding.**
A one-page document handed to the lab up front: what Overslash is, why outbound HTTP on
user-supplied input is the product rather than a defect, the table above, the deny-list
implementation, the permission and approval chain that gates which caller may reach which
host, and the audit trail every call writes. Labs adjudicate findings against documented
intent; a memo supplied during scoping costs one conversation, the same argument made
after a report is issued costs a re-test cycle.

## Scan target and scoping

**Target.** `dev.overslash.com` exists as a full environment
(`infra/env/dev.tfvars`) and is the natural candidate — scanning production means a
scanner authenticating as a tenant and firing injection payloads at real upstream
providers on real OAuth tokens. Before offering it, close the two dev-only deltas that
would themselves become findings: dev's Cloud SQL has a **public IP with no
`authorized_networks`** (`infra/env/dev.tfvars:70`, `infra/modules/cloud-sql/main.tf:61-67`),
and `DEV_AUTH` is enabled there, which hands the scanner an unauthenticated admin-session
endpoint (`routes/auth/dev_token.rs:136-321`). A scanner that finds `/auth/dev/token` will
report it under 6.2.1 and 1.2.1 regardless of which environment it is in.

**Authentication.** The Test Guide offers three routes, and ours should be the third:
manually crawl the authenticated dashboard in Burp, then scan from the crawled pages with
the captured state. The dashboard is a SvelteKit SPA against a JSON API, so Burp's
built-in login recording will not crawl it usefully, and the API is the part that needs
the coverage. Supply the lab with: a seeded org, an admin identity and a non-admin
identity (so 3.1.4 IDOR testing has two tenants to cross), a session cookie, an `osk_` API
key, and an OpenAPI description of `/v1` so the scan reaches every endpoint rather than
whatever the crawler happens to find.

**Two tenants, deliberately.** 3.1.1, 3.1.2 and 3.1.4 are all cross-tenant requirements
and a single-account scan cannot exercise them. Provision org A and org B with distinct
admins and hand over both. V2 is precisely the bug that configuration finds.

**Expect noise on the approval surface.** Injection payloads sent to `/v1/actions/call`
against a gated action create pending approvals rather than executing. That is correct
behaviour, but it means a large scan leaves a full approval queue and generates webhook
deliveries. Set `auto_approve_level` and the webhook subscriptions on the scan org
deliberately rather than discovering this mid-run.

## Sequence

1. ~~Land the P0 SSRF work (V1)~~ **done** — the scan's internal-target probes are
   refused on action execution and webhook delivery. OIDC issuer discovery followed. Still to
   land: the P1 webhook work.
2. Decide the `http` pseudo-service default grant, since it determines which argument the
   memo makes.
3. Close the dev-environment deltas above, or stand up a dedicated scan environment.
4. Write the scoping memo.
5. Run the ADA Burp configuration ourselves against the target. Fix what it finds on our
   own schedule — this is the cheap rehearsal, and at AL1 it is also the deliverable.
6. Only then engage the lab.

Running step 5 before step 6 is the difference between one assessment round and three.
