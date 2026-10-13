# API load balancer hardening — applying it

`infra/modules/api-lb/main.tf` adds two resources to the production API load balancer
(`enable_api_lb = true`, so prod only — dev has no LB):

| Resource | Name in prod | Attached to | Setting | CASA |
|---|---|---|---|---|
| `google_compute_ssl_policy.api` | `overslash-prod-api-ssl-policy` | HTTPS proxy `overslash-prod-api-https-proxy` | `min_tls_version = TLS_1_2`, `profile = RESTRICTED` | 4.1.1 |
| `google_compute_security_policy.api` | `overslash-prod-api-armor` | backend service `overslash-prod-api-backend` | default allow; OWASP CRS rule sets at priority 1000+ with `preview = true` | 4.1.1 (edge), defence in depth |

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
`INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` in code (`infra/main.tf`) whenever the LB is on, but
[gcp-posture.md](../compliance/casa/gcp-posture.md) measured `all` in prod. If a plan shows
that ingress change too, it is the same apply and makes the policy unbypassable.

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
