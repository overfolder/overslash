# SSRF scoping memo

**For the assessor scoping an authenticated DAST scan of Overslash.**
Read this *before* the engagement, not after the report. CASA 5.1.5 findings are
adjudicable against documented intent, and the whole of this memo is that intent: a
one-conversation cost now versus a re-test cycle later. It is the companion to
[dast-readiness.md](dast-readiness.md), which covers the scan logistics (target,
authentication, two-tenant setup); this document covers the single argument that the scan
turns on — that outbound HTTP on caller-supplied input is Overslash's function, bounded by
a deny-list and a permission chain, not a defect.

Every code path below was checked against the tree it cites. Line numbers drift; the
function and file names are the stable reference.

---

## 1. What Overslash is, in one paragraph

Overslash is a multi-tenant actions-and-authentication gateway for AI agents. Its core
operation is: take a caller-supplied (or template-supplied) URL, inject a credential from
the vault, make the HTTP request, and return the response under a permission and approval
chain. **That is the product.** A scanner's SSRF probe — inject a Burp Collaborator
hostname into a parameter, watch for an out-of-band interaction — describes the feature
exactly. Pointed at `POST /v1/actions/call`, a scanner will inject into `url`, Overslash
will faithfully fetch the Collaborator host *because an agent asked it to*, and the scan
will raise:

- **1051136** — Out-of-band resource load (HTTP)
- **3146240** — External service interaction (DNS)
- **3146256** — External service interaction (HTTP)

These are the three finding IDs CASA 5.1.5's AL1 verification names as disqualifying. They
are **expected** against this product and will recur on every revalidation. The question a
lab must adjudicate is not "does it make outbound requests on user input" — it does, by
design — but "are those requests bounded, and is the dangerous half (internal targets)
refused." Both halves of that are answered below.

## 2. The standard's own exemption

The AL2 verification text for 5.1.5 is written for exactly this shape of application:

> Test shall confirm that the application does not initiate arbitrary HTTP or DNS requests
> to either internal or external resources based on user-supplied input, **unless it is a
> necessary part of the application functionality. In such cases, ensure application
> implements robust input validation and uses allowlists to restrict requests to trusted
> and necessary domains or IP addresses.**

So the finding is adjudicable, against two conditions:

1. **Robust input validation with an IP deny-list on the path the scanner hits.** Met. §3.
2. **Allowlists restricting requests to trusted destinations.** Met for every
   template-bound surface; the one genuinely unbounded surface is raw HTTP (Mode A), and
   its *reachability* is a permission-gated capability, not an open relay. §5, §7.

## 3. The control: resolve → check → pin, on every hop

All SSRF mitigation lives in one module, `crates/overslash-api/src/services/ssrf_guard.rs`,
and every outbound request whose URL a caller can influence is constructed through it. The
transport owns client construction (it does not accept a client), so a new call site
*cannot* reach the wire without the guard — this is D92 and the reason the fix is "by
construction" rather than "by remembering."

**What the guard does, per request:**

1. **Parse and scheme-check** (`resolve_and_validate`, `ssrf_guard.rs:338`). Only
   `http`/`https`. The error never echoes the URL — on the action path this runs *after*
   secret injection, so the string can carry a vault value.
2. **Resolve the host, with a bounded DNS timeout** (same function). `getaddrinfo` has no
   deadline of its own and runs before any reqwest client exists, so a hostile resolver is
   capped here.
3. **Check *every* returned address**, not just the one dialed (same function). A host that
   answers with one public and one private address is a rebinding attempt in a round-robin
   costume and is refused outright.
4. **Deny-list** (`is_disallowed_ip`, `ssrf_guard.rs:35`): loopback, RFC 1918, link-local,
   broadcast, multicast, unspecified, documentation, and CGNAT `100.64.0.0/10` on IPv4;
   loopback, multicast, unspecified, ULA `fc00::/7`, link-local `fe80::/10` on IPv6; and
   the IPv4-mapped / IPv4-compatible IPv6 spellings of all of the above, recursed as v4.
5. **Metadata hard block, ahead of everything** (`METADATA_CIDRS`, `ssrf_guard.rs:78`;
   `policy_with`, `ssrf_guard.rs:309`): `169.254.0.0/16` and AWS's IPv6 spelling
   `fd00:ec2::/32` are denied *before* the operator allow-list is consulted, so **no**
   allow-list entry — not `169.254.169.254/32`, not `0.0.0.0/0` — reaches the instance
   metadata endpoint. The asymmetry is deliberate: every other private range is one
   internal service; metadata hands out the instance's own service-account credentials, so
   a token minted there is the whole deployment. The single gate past it,
   `OVERSLASH_DANGER_ALLOW_METADATA_CIDR`, grants nothing on its own (§4).
6. **Pin the validated IP** (`pinned_client`, `ssrf_guard.rs:435`) via reqwest's
   `.resolve()` override, closing the DNS-rebinding window between validation and dial.
7. **Disable redirects** (`pinned_client`, `ssrf_guard.rs:442`: `Policy::none()`), so a
   cooperative upstream cannot `3xx` the request inward after a clean first hop.

**Redirects are followed by hand, with the full guard re-run on every hop.** Refusing all
redirects is not an option — a Google Drive download *is* a redirect to a signed URL on
another host — so `send_following_redirects` (`http_caller.rs:265`) resolves, re-checks and
re-pins each hop (max 5, `MAX_REDIRECTS` at `http_caller.rs:222`), and strips credential
headers (`Authorization`, `Cookie`, `Proxy-Authorization`, `WWW-Authenticate`;
`is_credential_header` at `http_caller.rs:232`) on any cross-host or scheme-downgrade hop
(`credential_may_follow`, `http_caller.rs:247`). OIDC discovery and OpenAPI template import
run the same hop loop.

**What the scanner sees.** `http://169.254.169.254/` and `https://127.0.0.1/` probes
return a **400** with no body oracle, and a `302` toward the metadata endpoint is *returned
to the caller rather than followed*. The internal half of 5.1.5 — the half that is
unambiguously a vulnerability rather than a feature — passes cleanly.

### Evidence to hand the lab

`crates/overslash-api/tests/ssrf_guard.rs` exercises the guard end-to-end on the two paths
that carry a caller-supplied URL all the way to a socket:

| Test | Proves |
|------|--------|
| `mode_a_refuses_the_cloud_metadata_endpoint` (`:68`) | Mode A → `169.254.169.254` is 400 |
| `mode_a_refuses_private_and_cgnat_addresses` (`:89`) | RFC 1918 + CGNAT refused |
| `mode_a_refuses_a_non_http_scheme` (`:116`) | scheme allow-list |
| `mode_a_refuses_the_metadata_endpoint_when_streaming` (`:127`) | the streaming path is guarded too |
| `mode_a_still_reaches_a_loopback_fake` (`:149`) | positive control — the guard is not refusing everything |
| `a_redirect_toward_the_metadata_endpoint_is_refused_at_the_next_hop` (`:163`) | per-hop re-validation |
| `a_cross_host_redirect_drops_the_injected_credential` (`:186`) | credential stripping on redirect |
| `webhook_delivery_refuses_a_link_local_endpoint` (`:294`) + loopback positive control (`:347`) | webhook delivery is on the guard |
| `oidc_discovery_refuses_a_private_ip_issuer` / `_a_redirect_to_a_private_address` / `_does_not_echo_the_upstream_body` (`:457`, `:469`, `:499`) | OIDC discovery is on the guard and is not an oracle |

The unit decision table for the metadata-block / allow-list ordering is in the same file's
`mod tests` (`no_allow_list_entry_reaches_metadata_without_the_override`,
`the_override_alone_opens_nothing`, `an_allowed_ipv6_range_does_not_open_ipv4`).

## 4. The operator allow-list, and why a scan target must not set it

The one way past the deny-list is `OVERSLASH_SSRF_ALLOWED_CIDRS`
(`operator_allowed_ranges`, `ssrf_guard.rs:162`) — a comma-separated list of CIDR blocks a
self-hosted deployment declares so it can reach its own internal services (a GitLab on
`10.42.0.7`, a MinIO on a container network). Four properties make it a narrowing, not a
hole, and all four matter to a scanner's threat model:

- **Operator-only.** Read from the process environment at boot. No org, user, template or
  API request can reach it, so **a tenant cannot widen its own egress** and the scanner,
  authenticating as a tenant, cannot touch it.
- **Explicit.** `10.42.0.0/16` opens that range and nothing else; it does not re-open the
  rest of RFC 1918.
- **Cannot reach metadata.** The metadata CIDRs are denied *before* this list is read
  (§3.5), so even `0.0.0.0/0` here does not open them.
- **Still pinned and re-checked.** An allowed address is validated and pinned exactly like
  a public one, and a redirect away from it is re-checked from scratch.

**The multi-tenant production deployment never sets this variable** — confirmed absent from
`docker/docker-compose.prod.yml` and the Cloud Run env (`infra/modules/cloud-run/`), where
only loopback-free config is injected. The integration suite and `scripts/e2e-up.sh` set it
to `127.0.0.0/8,::1/128` because the fakes bind to loopback — the same mechanism a
self-hoster uses, so the suite exercises the real code path rather than a test-only bypass.

**For the lab:** the scan target must have `OVERSLASH_SSRF_ALLOWED_CIDRS` **unset**. An
operator who set it and then commissioned a scan would get findings about their own
network, correctly. If the scan environment is a clone of a self-hosted install, confirm
the variable is empty before the run.

## 5. Egress is allowlisted per surface

The distinction the memo rests on. "We fetch whatever you ask" is false for every surface
but one, and that one is a permission-gated capability:

| Surface | Egress bound | Where |
|---------|--------------|-------|
| **Service + action (Mode C)** | The template's own OpenAPI `servers` / `hosts`; the permission key derives as `{service}:{action}:{arg}` | `routes/actions/resolve.rs`, `service_resolve.rs::effective_base` |
| **Service + HTTP verb (Mode B)** | The instance's bound host (`svc.hosts` / instance `url`); key `{service}:{METHOD}:{path}` | `service_resolve.rs::resolve_verb_host_and_path` |
| **MCP-runtime services** | The pinned upstream `mcp.url` from the template, through the guard | `services/mcp_caller.rs:102` |
| **MCP OAuth upstream hops** | Resource/AS metadata, dynamic client registration, token exchange — each pinned and TLS-checked | `routes/oauth_upstream.rs:419` |
| **OIDC issuer discovery** | Admin-supplied `issuer_url`, through the guard on every hop | `services/oidc_discovery.rs:72` |
| **Webhook delivery** | Registrant-supplied URL, through the guard per attempt, HTTPS-only, ownership-verified first | `services/webhook_dispatcher.rs:117` |
| **OpenAPI template import** | Caller-supplied source URL, through the guard's hop loop | `routes/templates/fetch.rs` |
| **The `http` pseudo-service (Mode A)** | **None — any host.** This is the one genuinely unbounded surface | `routes/actions/` (`service: "http"`) |

Every row but the last is bounded by a template or an instance binding. Mode A is bounded
only by the deny-list (it still cannot reach internal ranges) and, crucially, by **who is
permitted to use it at all** — which is a permission decision, not an egress one, and is
the subject of §7.

### Outbound TLS, reinforcing the picture

Independently of SSRF, every outbound action request must use `https`
(`services/outbound_tls.rs`, D96), because any such request can carry a vault credential.
Plain `http` is refused at three points — when an endpoint is written (instance `url`,
org-layer `instance_defaults.url`, template `mcp.url`, reported as
`endpoint_requires_https`), when a call is resolved, and on every transport hop against the
pinned address — with the *same* `OVERSLASH_SSRF_ALLOWED_CIDRS` escape hatch and no second
knob. So a scanner's plaintext Collaborator probe is refused for want of TLS *before* the
SSRF guard is even consulted. Tests: `tests/outbound_tls.rs`, `tests/oauth_upstream_tls.rs`.

### One honest boundary

The user-login OAuth path (`routes/auth/providers.rs`, `services/oauth.rs`) dials provider
token and userinfo endpoints on the shared `state.http_client`, which is *not* the pinned
guard client. This is not a scanner-injectable SSRF surface: those endpoints are not
per-request caller input — they come from a provider row that an operator seeded (Google,
GitHub) or, for a custom per-org OIDC provider, from a document fetched through the
*guarded* `oidc_discovery` path (`org_idp_configs.rs::create_idp_config`, behind `AdminAcl`).
A DAST scanner injects into request parameters; the parameter it could influence here is
`issuer_url` on discovery, and that is guarded. Hardening the login-path token/userinfo
dials onto the pinned client is tracked separately and is worth mentioning to the lab so
the boundary is documented rather than discovered.

## 6. The permission and approval chain gates *reachability*

A scanner firing injection payloads at `/v1/actions/call` does not get a free relay even
within the deny-list, because every call is gated before it executes:

- **Group ceiling (Layer 1).** The caller's owner-user must hold a grant on the service
  through a group (`overslash-core/src/permissions/ceiling.rs::check_group_ceiling`). For
  Mode A that is a grant on the `http` pseudo-service (D15); the access level gates the
  verb (read = GET/HEAD, write = + POST/PUT/PATCH, admin = + DELETE).
- **Hierarchical chain (Layer 2).** For a non-user identity, every ancestor must authorize
  — either `inherit_permissions=true` (defers to parent) or its own rules cover the
  requested keys (`services/permission_chain.rs::enforce_permission_chain`). The first
  level that does neither is the **gap**, and a gap does not execute — it files an approval
  (`ChainWalkResult::Gap`), resolvable by an ancestor.
- **Audit.** Every executed call writes an `action.executed` row with the mode tag
  (`routes/actions/call.rs`; `mode_tag` in `routes/actions/tags.rs`), so even a scan that
  clears the gate leaves a complete trail.

**Expect noise, and set it deliberately.** Injection payloads against a gated action create
*pending approvals* rather than executing — correct behaviour, but a large scan leaves a
full approval queue and generates webhook deliveries. Set `auto_approve_level` and the scan
org's webhook subscriptions deliberately before the run (see dast-readiness.md). The
scanner's own findings on the approval surface are the chain working, not a defect.

## 7. The open question: the default `Everyone → admin on http` grant

This is the one item the memo states as **pending a human decision**, and it is **not
changed by this document.**

At org bootstrap, the `Everyone` group is granted `admin` on the `http` pseudo-service
(`crates/overslash-db/src/repos/org_bootstrap.rs:143-153`), preserving the pre-D15
`allow_raw_http = true` default so the Mode A → `http`-service migration did not silently
revoke access. The effect: raw HTTP (Mode A, the one unbounded-egress surface in §5) is
**on by default for every member of every new org.** The deny-list still refuses internal
targets, so this is not an SSRF-into-the-metadata-endpoint problem — it is the "allowlists
to restrict requests to trusted domains" half of 5.1.5's exemption, where Mode A has no
destination allowlist by design.

Two ways to close it, in descending order of how cleanly they argue to a lab:

- **Make the grant opt-in** — drop it from bootstrap, so raw HTTP requires a deliberate
  org-admin grant and the default-configured product has no unbounded-egress surface at
  all. 5.1.5 then becomes a plain pass for the default configuration. This is a
  **behaviour change for new orgs**, which is why it is a human decision, not a code
  cleanup.
- **Keep it on, add a per-org host allowlist** before a raw call resolves. Heavier, and it
  changes behaviour for existing tenants.

Either way the answer stops being "we fetch whatever you ask" and becomes "egress is
allowlisted per service; raw HTTP is an explicitly granted capability, deny-listed against
internal ranges." Until that decision is taken, **the scan target's org should simply not
grant `Everyone` admin on `http`** (or use an org provisioned without it), so the scanned
configuration demonstrates the bounded case. The decision itself is tracked in
[TODO.md §1.6](../../../TODO.md) and summarised in
[gap-assessment.md](gap-assessment.md) (V1 follow-up); this memo does not pre-empt it.

## 8. The argument in one line

Overslash makes outbound HTTP on caller-supplied input because that *is* the product; the
control is therefore a **deny-list of destinations plus a permission chain**, not an
absence of egress. The internal half of SSRF — the half that is unambiguously a
vulnerability — is refused on every path, by construction, and proven by
`tests/ssrf_guard.rs`. The external half is an allowlist on every surface but raw HTTP,
and raw HTTP is a permission-gated capability whose default grant is a documented, pending
human decision. Supply this memo during scoping; adjudicate the three OOB finding IDs
against it.

---

## Evidence map

| Claim | Code | Tests |
|-------|------|-------|
| Deny-list, metadata hard block, `.resolve()` pin, `Policy::none()` | `services/ssrf_guard.rs` (`is_disallowed_ip:35`, `METADATA_CIDRS:78`, `policy_with:309`, `resolve_and_validate:338`, `pinned_client:435`) | `tests/ssrf_guard.rs` (`mod tests` + the e2e cases above) |
| Guard on the action-execution transport, redirects re-validated per hop, credentials stripped | `services/http_caller.rs` (`guarded_client:199`, `send_following_redirects:265`, `credential_may_follow:247`) | `tests/ssrf_guard.rs:68–186` |
| Guard on webhook delivery, per attempt | `services/webhook_dispatcher.rs::deliver:117` | `tests/ssrf_guard.rs:294,347` |
| Webhook HTTPS-only + ownership handshake before any delivery | `services/https_policy.rs`, `services/webhook_dispatcher.rs::verify_endpoint` | `tests/webhook_https.rs`, `tests/webhook_verification.rs` |
| Guard on OIDC issuer discovery, generic error, no body oracle | `services/oidc_discovery.rs` (`discover:72`, `fetch:124`, `OidcDiscoveryError::Failed`) | `tests/ssrf_guard.rs:457–499`, `tests/oidc_auth.rs::oidc_discovery_rejects_private_ips:753` |
| Guard + TLS on MCP OAuth upstream hops | `routes/oauth_upstream.rs::upstream_client:419`, `services/mcp_caller.rs:102` | `tests/oauth_upstream_tls.rs` |
| Outbound TLS rule, three enforcement points, same allow-list hatch | `services/outbound_tls.rs` (`check_resolved:56`, `check_url:62`, `check_url_resolving:71`) | `tests/outbound_tls.rs` |
| Operator allow-list is environment-only, never set in prod | `services/ssrf_guard.rs::operator_allowed_ranges:162`; `docker/docker-compose.prod.yml`, `infra/modules/cloud-run/` | unit decision table in `tests/ssrf_guard.rs` `mod tests` |
| Permission chain + approvals gate Mode A/B/C | `permissions/ceiling.rs::check_group_ceiling`, `services/permission_chain.rs::enforce_permission_chain` | `tests/integration.rs`, `tests/approvals_cascade.rs` |
| Default `Everyone → admin on http` grant (the open question) | `overslash-db/src/repos/org_bootstrap.rs:143-153` (D15) | — (behaviour, pending decision) |

Decisions: **D92** (transport owns its client; loopback-only hatch), **D96** (outbound TLS
required), **D15** (Mode A is the `http` service instance), **D14** (free-form authed calls
go through Service + HTTP verb).
