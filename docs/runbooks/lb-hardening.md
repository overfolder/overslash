# API load balancer hardening — applying it

`infra/modules/api-lb/main.tf` adds two resources to the production API load balancer
(`enable_api_lb = true`, so prod only — dev has no LB):

| Resource | Name in prod | Attached to | Setting | CASA |
|---|---|---|---|---|
| `google_compute_ssl_policy.api` | `overslash-prod-api-ssl-policy` | HTTPS proxy `overslash-prod-api-https-proxy` | `min_tls_version = TLS_1_2`, `profile = RESTRICTED` | 4.1.1 |
| `google_compute_security_policy.api` | `overslash-prod-api-armor` | backend service `overslash-prod-api-backend` | default allow; OWASP CRS rule sets at priority 1000+ with `preview = true` | 4.1.1 (edge), defence in depth |

It also covers serving the LB over IPv6 (`api_lb_enable_ipv6`), including the Namecheap
records. See [IPv6](#ipv6).

Infra is never auto-applied. This page is the human half.

## What changes for clients

**SSL policy.** Today the proxy runs GCP's default profile, which already refuses TLS 1.0/1.1
in practice (external probe, 2026-09-22). `RESTRICTED` at TLS 1.2 additionally drops the
CBC and SHA-1 suites `MODERN` still allows, leaving ECDHE with AES-GCM or ChaCha20-Poly1305
at 1.2, and everything at 1.3. Any client from the last decade — browsers, `curl`,
`reqwest`/rustls, Python `requests`, Node, Go — negotiates one of those. A client that only
offers CBC suites at TLS 1.2 will now fail the handshake; to fall back, set
`api_lb_ssl_profile = "MODERN"` in `infra/env/prod.tfvars` (still TLS 1.2+).

**Cloud Armor.** Nothing is blocked. The only non-preview rule is the default `allow`. The
OWASP rule sets (`sqli`, `xss`, `lfi`, `rfi`, `rce`, `scannerdetection`, `protocolattack`,
`sessionfixation`, all `-v33-stable` at sensitivity 1) are in **preview**: a match is
written to the LB request log and the request goes through. They stay in preview because
agent action bodies legitimately carry SQL, shell, HTML and file paths — exactly what CRS
rules look for. JSON parsing is on, so the WAF inspects JSON fields rather than the raw body.

The dashboard (`app.overslash.com`) is served by Vercel, not this LB, so neither resource
touches it. Its calls to the API do pass through both.

Cloud Armor only sees traffic that comes through the LB. The API's Cloud Run ingress is
`INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` (`infra/main.tf`) whenever the LB is on, which
makes the policy unbypassable: the service's `*.run.app` URL answers 404 to everyone.
Applied and measured in prod on 2026-10-22 (see [Verify](#verify--evidence-for-the-casa-pack)).

Nothing calls the API by its `*.run.app` URL. The callers, checked before the switch:

| Caller | Reaches the API at | Under LB-only ingress |
|---|---|---|
| Vercel rewrites (`dashboard/vercel.json`), prod apex and org subdomains | `api.overslash.com`, `<sub>.api.overslash.com` | Through the LB |
| Better Stack status page ([status-page.md](status-page.md)) | `api.overslash.com/health`, `/auth/providers` | Through the LB |
| Agents, MCP clients, OAuth callbacks | `api.overslash.com` and org subdomains | Through the LB |
| MCP tool calls back into the API | `http://127.0.0.1:<port>` inside the instance (`services/loopback.rs`) | Not ingress at all |
| Metrics exporter job, Cloud Scheduler | Postgres and `run.googleapis.com` / `sqladmin.googleapis.com`, never the API | Unaffected |
| Cloud Build | Deploys by service name (`gcloud run deploy`) | Unaffected |
| CI (`.github/workflows/`) | Nothing deployed: no smoke test hits a live API | Unaffected |

**Dev stays `INGRESS_TRAFFIC_ALL`.** Dev has no LB (`enable_api_lb = false`) and serves
`api.dev.overslash.com` and its per-org hosts through Cloud Run domain mappings, which
count as internet ingress: LB-only would take dev offline. That is an accepted dev residual
(recorded in [gcp-posture.md](../compliance/casa/gcp-posture.md#cloud-run)); a dev LB is not
planned. overfwd and the
shortener have no LB in either environment and stay `all` for the same reason; both
authenticate their own callers.

## Apply — prod

There is no dev LB to rehearse on. The change is additive and in place: two resources
created, the proxy and backend service updated. Attaching an SSL policy or security policy
does not recreate the proxy, forwarding rule or IP, and does not drop connections.

```bash
make tofu-init
make tofu-plan ENV=prod
# Expect, under module.api_lb[0]:
#   + google_compute_ssl_policy.api
#   + google_compute_security_policy.api
#   ~ google_compute_target_https_proxy.api      (ssl_policy added)
#   ~ google_compute_backend_service.api_backend (security_policy added)
# Nothing destroyed or replaced. If unrelated drift shows up and you don't want it now:
#   cd infra && tofu workspace select prod && \
#   tofu plan -var-file=env/prod.tfvars -target=module.api_lb -out=prod.tfplan
make tofu-apply ENV=prod   # asks you to type `prod`
```

Policies propagate to Google's edge within a few minutes.

## Verify — evidence for the CASA pack

Save the output of each block with the date.

Configuration:

```bash
gcloud compute ssl-policies list --project overslash
gcloud compute ssl-policies describe overslash-prod-api-ssl-policy --project overslash \
  --format='yaml(name,minTlsVersion,profile,enabledFeatures)'
gcloud compute target-https-proxies describe overslash-prod-api-https-proxy \
  --global --project overslash --format='value(sslPolicy)'

gcloud compute security-policies list --project overslash
gcloud compute security-policies describe overslash-prod-api-armor --project overslash \
  --format='yaml(name,type,advancedOptionsConfig,rules)'
gcloud compute backend-services describe overslash-prod-api-backend \
  --global --project overslash --format='value(securityPolicy)'
```

Expect `minTlsVersion: TLS_1_2`, `profile: RESTRICTED`, the proxy and backend pointing at
the two policies, and every rule except priority `2147483647` showing `preview: true`.

Behaviour on the wire:

```bash
H=api.overslash.com
# Refused: TLS 1.0 / 1.1 (expect a handshake failure / "no protocols available")
openssl s_client -connect $H:443 -servername $H -tls1   </dev/null
openssl s_client -connect $H:443 -servername $H -tls1_1 </dev/null
# Refused: a CBC suite at TLS 1.2 (RESTRICTED only; under MODERN this one connects)
openssl s_client -connect $H:443 -servername $H -tls1_2 \
  -cipher 'ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA' </dev/null
# Accepted: TLS 1.2 AEAD and TLS 1.3
openssl s_client -connect $H:443 -servername $H -tls1_2 </dev/null | grep -E 'Protocol|Cipher'
openssl s_client -connect $H:443 -servername $H -tls1_3 </dev/null | grep -E 'Protocol|Cipher'
# Full cipher inventory (one artefact that covers all of the above)
nmap --script ssl-enum-ciphers -p 443 $H
# Service still healthy
curl -fsS https://$H/ready
```

Cloud Armor is evaluating (preview hits, last 24 h):

```bash
gcloud logging read --project overslash --freshness=1d --limit=50 \
  'resource.type="http_load_balancer"
   jsonPayload.previewSecurityPolicy.name="overslash-prod-api-armor"
   jsonPayload.previewSecurityPolicy.outcome="DENY"' \
  --format='table(timestamp,httpRequest.requestMethod,httpRequest.requestUrl,jsonPayload.previewSecurityPolicy.preconfiguredExprIds)'
```

Every request also carries `jsonPayload.enforcedSecurityPolicy` with
`name=overslash-prod-api-armor` and `outcome=ACCEPT`, which shows the policy is attached
even on a day with no preview hits.

Ingress is LB-only, so the policy cannot be bypassed:

```bash
gcloud run services describe overslash-prod-api --region europe-west1 --project overslash \
  --format='value(metadata.annotations."run.googleapis.com/ingress")'
# Expect: internal-and-cloud-load-balancing   (the v1 spelling of INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER)

RUN=$(gcloud run services describe overslash-prod-api --region europe-west1 --project overslash --format='value(status.url)')
curl -s -o /dev/null -w '%{http_code}\n' "$RUN/health"         # Expect: 404 (Cloud Run refuses non-LB ingress)
curl -s -o /dev/null -w '%{http_code}\n' https://api.overslash.com/health   # Expect: 200
```

Measured 2026-10-22: `internal-and-cloud-load-balancing`; `*.run.app/health` and
`/auth/providers` 404; `api.overslash.com/health` 200.

Afterwards, re-run the load-balancer block of [gcp-posture.md](../compliance/casa/gcp-posture.md)
and record the new values there.

## Moving WAF rules out of preview

Do it per rule set, not all at once:

1. Let preview run for at least two weeks of normal traffic.
2. Group the preview hits above by `preconfiguredExprIds`. For each signature that fires on
   legitimate requests, either exclude it
   (`evaluatePreconfiguredWaf('sqli-v33-stable', {'sensitivity': 1, 'opt_out_rule_ids': [...]})`
   — needs a module change) or keep that rule set in preview.
3. A rule set with no false positives can be enforced. `api_lb_cloud_armor_preview` flips all
   of them together; to enforce selectively, split the variable in the module first.

## Rollback

- TLS: set `api_lb_ssl_profile = "MODERN"` and apply (keeps TLS 1.2+). Removing the policy
  entirely means reverting the module change; the proxy then falls back to GCP's default.
- Cloud Armor: while in preview it cannot block. If it ever does after enforcement, set
  `api_lb_cloud_armor_preview = true` and apply, or detach in an emergency with
  `gcloud compute backend-services update overslash-prod-api-backend --global
  --project overslash --security-policy=""` and then reconcile Terraform.

## IPv6

`api_lb_enable_ipv6 = true` (prod) gives the LB a second, IPv6 anycast address
(`overslash-prod-api-lb-ipv6`) and a forwarding-rule pair on it,
`overslash-prod-api-https-fr-v6` (443) and `overslash-prod-api-http-fr-v6` (80). Both
target the **existing** HTTPS and HTTP proxies. The cert map and the SSL policy are
on the HTTPS proxy, and the Cloud Armor policy is on the backend service, so v6 traffic
gets all three without anything being duplicated. Whichever family the client uses, the
LB stamps the address it saw into `X-Overslash-Edge-Client-Ip`. The API keys every per-IP
throttle on that address's /64 (`services::client_ip::rate_limit_subject`), so a v6 client
can't rotate through its prefix to reset a bucket.

Cost: about $0. Forwarding rules go from 2 to 4, which is still inside the base charge
for the first 5. A global address costs nothing while a forwarding rule uses it.

### Stop-gap: no Terraform

An IPv6-preferring client fails with `SSL_ERROR_SYSCALL` when `api` answers AAAA lookups
with something other than this LB. The cause is the `CNAME ghs.googlehosted.com` from the
pre-LB domain mapping, which resolves to Google's v6 frontends. Deleting that CNAME at
Namecheap fixes the failures by itself. With no AAAA record, clients use the `A` record.
Check whether it is still there:

```bash
dig +short CNAME api.overslash.com @dns1.registrar-servers.com   # want: empty
dig +short AAAA  api.overslash.com @dns1.registrar-servers.com   # want: empty until step 2
```

### 1. Apply (additive)

```bash
make tofu-init
make tofu-plan ENV=prod
# Expect exactly, under module.api_lb[0]:
#   + google_compute_global_address.api_lb_ipv6[0]
#   + google_compute_global_forwarding_rule.api_https_v6[0]
#   + google_compute_global_forwarding_rule.api_http_v6[0]
# and the output api_lb_ipv6. Nothing on the IPv4 path changes.
make tofu-apply ENV=prod   # asks you to type `prod`

cd infra && tofu workspace select prod && tofu output -raw api_lb_ipv6
# or, without Terraform:
gcloud compute addresses describe overslash-prod-api-lb-ipv6 --global \
  --project overslash --format='value(address)'
```

The IPv4 address, its forwarding rules and the proxies are left untouched, so existing
traffic doesn't notice the apply.

**Apply anything else pending first.** `-target` can't isolate this change.
`module.api_lb` depends on `module.cloud_run`, and so does anything wired into Cloud Run
(Memorystore, since [memorystore-auth-tls.md](memorystore-auth-tls.md)). Even
`-target=module.api_lb` therefore plans those modules' pending changes too, and `-exclude`
drops `api_lb` along with them. If the plan shows more than the three additions above,
finish the runbook those changes belong to, then come back. On 2026-10-13 the targeted
plan was `3 to add, 0 to change, 0 to destroy` before #769 merged. After it, the same plan
also carried #769's Valkey **replacement**, which has its own maintenance window.

### 2. DNS at Namecheap

On `overslash.com` → Advanced DNS:

1. **Delete the `CNAME` on `api`** (`ghs.googlehosted.com`) if it is still there. Do this
   first: a name that has a CNAME can't have any other record type, so Namecheap won't let
   you add the AAAA while it exists.
2. Add `AAAA` host `api` → `<api_lb_ipv6>`.
3. Add `AAAA` host `*.api` → `<api_lb_ipv6>`. Today `*.api` has only the `A` record.

Leave the `A` records (`api`, `*.api` → `34.36.8.174`) as they are. TTL: Automatic.

### 3. Verify

```bash
V6=$(dig +short AAAA api.overslash.com)
dig +short AAAA api.overslash.com          # the lb_ipv6 address
dig +short AAAA acme.api.overslash.com     # same (wildcard)
dig +short CNAME api.overslash.com         # empty

curl -6 -fsS -v https://api.overslash.com/health   # 200 over v6
curl -6 -fsS https://acme.api.overslash.com/health

# The SSL policy applies on v6 too: 1.0/1.1 and CBC suites refused, 1.2 AEAD / 1.3 accepted
openssl s_client -connect "[$V6]:443" -servername api.overslash.com -tls1_1 </dev/null   # fails
openssl s_client -connect "[$V6]:443" -servername api.overslash.com -tls1_2 \
  -cipher 'ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA' </dev/null                      # fails
openssl s_client -connect "[$V6]:443" -servername api.overslash.com -tls1_2 </dev/null | grep -E 'Protocol|Cipher'
openssl s_client -connect "[$V6]:443" -servername api.overslash.com -tls1_3 </dev/null | grep -E 'Protocol|Cipher'

# Port 80 still upgrades
curl -6 -sI http://api.overslash.com/health | grep -i '^location: https://'
```

You need a host with IPv6 egress for `curl -6`. Cloud Shell has none; a home connection
or <https://ipv6-test.com/validate.php> works. The LB request log then shows v6 client
addresses, each with `jsonPayload.enforcedSecurityPolicy.name=overslash-prod-api-armor`,
which shows Cloud Armor evaluates the new rules too:

```bash
gcloud logging read --project overslash --freshness=1h --limit=20 \
  'resource.type="http_load_balancer" httpRequest.remoteIp:":"' \
  --format='table(timestamp,httpRequest.remoteIp,httpRequest.requestUrl,jsonPayload.enforcedSecurityPolicy.outcome)'
```

### Trusted proxies (optional)

Client IP comes from the LB-stamped header. `trusted_proxy_hops` and `trusted_proxy_cidrs`
are only the fallback for a request that arrives without the header. That fallback still
works on v6 by position (`hops = 2`). To also trust the v6 LB address by range, append it
to `trusted_proxy_cidrs` in `infra/env/prod.tfvars`
(`"34.36.8.174/32,<api_lb_ipv6>/128"`) and apply again. That apply changes the Cloud Run
env, so it rolls out a new revision.

### Rollback

Delete the two AAAA records first, so clients stop resolving the v6 address. Then set
`api_lb_enable_ipv6 = false` and apply, which destroys the three v6 resources. Once the
address is released, its value is gone for good, so a later re-enable means new AAAA
records.
