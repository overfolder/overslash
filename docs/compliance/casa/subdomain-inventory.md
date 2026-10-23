# Subdomain inventory — CASA 6.4.1

Every DNS record Overslash publishes under `overslash.com` and `oversla.sh`, what each one
points at, and who owns the target. The table below is not only documentation:
[`scripts/check-subdomains.sh`](../../../scripts/check-subdomains.sh) reads it and fails the
daily Dependency audit when live DNS disagrees with it — a dangling CNAME, a target no longer
claimed by its provider, a record or hostname the table does not list. Change the table in the
same PR as the change that adds or removes a hostname; the operator steps are in
[docs/runbooks/subdomain-inventory.md](../../runbooks/subdomain-inventory.md).

Measured 2026-10-22 against `1.1.1.1`, Certificate Transparency (CertSpotter), the Vercel
project-domain API and RDAP.

## Where the records live

Both zones are hosted on **Namecheap BasicDNS** (`dns1/dns2.registrar-servers.com`), at the
same registrar the domains are registered with. They are **not** in Terraform:
`enable_dns = false` in both `infra/env/*.tfvars`, so `infra/modules/dns/` (a Cloud DNS zone
with DNSSEC) is written but unused, and every record the Terraform stacks need — the Cloud Run
domain-mapping CNAMEs, the Certificate Manager ACME CNAME — is created by hand from their
outputs. Nothing enforces agreement between the registrar and the repo except this file and
the script that checks it.

| Domain | Registrar | Status | Expires | DNSSEC |
|--------|-----------|--------|---------|--------|
| `overslash.com` | NameCheap, Inc. | `clientTransferProhibited` | 2027-03-28 | unsigned |
| `oversla.sh` | NameCheap, Inc. | — (`.sh` has no public RDAP) | — | unsigned |

## Owners

| Provider | Account | What it serves |
|----------|---------|----------------|
| Vercel | team `amanuelmartincanto-2204s-projects` | project `overslash-landing`: `overslash.com` (redirect) + `www`; project `overslash` (the dashboard): `app`, `*.app` (production), `app.dev`, `*.app.dev`, `overfolder.app.dev`, `overfolder-dev.app.dev` (git branch `dev`) |
| GCP `overslash` (prod) | `infra/` with `prod.tfvars` | Global external LB (`infra/modules/api-lb`) on `api` + `*.api`, wildcard cert via Certificate Manager DNS authorization; Cloud Run domain mappings `mailbox` (overfwd) and `oversla.sh` (shortener) |
| GCP `overslash-dev` | `infra/` with `dev.tfvars` | Cloud Run domain mappings `api.dev` (`domain`), the `extra_api_domain_mappings` list, `mailbox.dev` |
| Better Stack | status page ([runbook](../../runbooks/status-page.md)) | `status` |
| Migadu | mail hosting for `overslash.com` | MX, SPF, DKIM, domain verification |
| Namecheap | email forwarding for `oversla.sh` | MX, SPF |
| Google Search Console | domain-property verification | the `google-site-verification` TXT on each apex — this is what lets our GCP projects create Cloud Run domain mappings, and what stops anyone else from doing so |

## How each provider decides who may claim a name

This is the property subdomain takeover depends on: whether a record pointing at a provider
can be served by *someone else's* account once ours lets go.

- **Vercel** — the `vercel` expectation accepts Vercel's anycast pool (`216.150.x`,
  `64.29.17.x`, `66.33.60.x`) and the two addresses its docs tell you to configure
  (`76.76.21.21`, `216.198.79.1`); any other address passes only if ARIN registers it to
  Vercel (a `VERCEL-*` net), with a warning to add it to the list. A domain already attached to a team can only be added by another team after a
  `_vercel` TXT verification on our zone. While attached, an unclaimed name answers with
  `x-vercel-error: DEPLOYMENT_NOT_FOUND`; the script treats that header as unclaimed.
- **Cloud Run domain mappings (`ghs.googlehosted.com`, 216.239.32-38.21)** — a mapping can only
  be created by a project whose principal is a verified owner of the domain in Search Console.
  An unmapped name resolves but serves no certificate for itself, so the TLS check fails.
- **GCLB** — the A/AAAA records point at reserved static addresses (`api_lb_enable_ipv6`).
  The takeover shape here is an address released back to Google's pool while the record still
  names it; the script pins the exact addresses, and the TLS check fails if the address stops
  serving our certificate.
- **Better Stack** — a custom domain is bound to one status page; an unbound one gets no
  certificate.
- **Certificate Manager** — the `_acme-challenge.api` target lives under
  `authorize.certificatemanager.goog`, a Google-controlled zone that is only populated while a
  challenge is open, so it is **expected to be NXDOMAIN** between renewals. Nobody but Google
  can publish there, so the check is `delegated`: the CNAME must match, the target need not
  resolve.
- **Migadu** — DKIM CNAMEs point at per-domain names under `migadu.com`; Migadu binds the
  domain to our account through the `hosted-email-verify` TXT.

## Records

Columns the script reads: **Name** (`*.` = a single-label wildcard, probed with a random
label), **Type** (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, or `absent` for a name that must not
resolve), **Expect** (comma-separated values; `vercel` = any Vercel edge address or
`*.vercel-dns*.com` target; a TXT value is a prefix), **Check** (`tls` — HTTPS must present a
valid certificate for the name, at every A/AAAA address the row resolves to, and no provider "unclaimed" marker; `dns` — the record and its
CNAME/MX target must resolve; `delegated` — record must match, target may be NXDOMAIN; `pending` — the record may be
missing, because the row was merged before the registrar change or is about to be deleted
after it, but a value that is present must still match; `-` for `absent`). The other columns are for people.

<!-- inventory:begin -->
| Name | Type | Expect | Check | Provider | Notes |
|------|------|--------|-------|----------|-------|
| `overslash.com` | A | `vercel` | tls | Vercel `overslash-landing` | Redirects to `www` |
| `overslash.com` | MX | `aspmx1.migadu.com,aspmx2.migadu.com` | dns | Migadu | |
| `overslash.com` | TXT | `v=spf1 include:spf.migadu.com` | dns | Migadu | `-all` |
| `overslash.com` | TXT | `hosted-email-verify=` | dns | Migadu | Domain ownership |
| `overslash.com` | TXT | `google-site-verification=` | dns | Search Console | Gates Cloud Run domain mappings |
| `_dmarc.overslash.com` | TXT | `v=DMARC1` | dns | Migadu | `p=quarantine` |
| `key1._domainkey.overslash.com` | CNAME | `key1.overslash.com._domainkey.migadu.com` | dns | Migadu | DKIM |
| `key2._domainkey.overslash.com` | CNAME | `key2.overslash.com._domainkey.migadu.com` | dns | Migadu | DKIM |
| `key3._domainkey.overslash.com` | CNAME | `key3.overslash.com._domainkey.migadu.com` | dns | Migadu | DKIM |
| `www.overslash.com` | CNAME | `vercel` | tls | Vercel `overslash-landing` | Marketing site |
| `app.overslash.com` | A | `vercel` | tls | Vercel `overslash` | Dashboard, prod |
| `*.app.overslash.com` | A | `vercel` | tls | Vercel `overslash` | Per-org dashboard hosts |
| `app.dev.overslash.com` | A | `vercel` | tls | Vercel `overslash` (`dev`) | Dashboard, dev |
| `*.app.dev.overslash.com` | A | `vercel` | tls | Vercel `overslash` (`dev`) | Per-org dashboard hosts, dev |
| `api.overslash.com` | A | `34.36.8.174` | tls | GCP `overslash` GCLB | `infra/modules/api-lb` |
| `api.overslash.com` | AAAA | `2600:1901:0:cc9c::` | tls | GCP `overslash` GCLB | `api_lb_enable_ipv6` |
| `*.api.overslash.com` | A | `34.36.8.174` | tls | GCP `overslash` GCLB | Per-org API hosts, wildcard cert |
| `*.api.overslash.com` | AAAA | `2600:1901:0:cc9c::` | tls | GCP `overslash` GCLB | |
| `_acme-challenge.api.overslash.com` | CNAME | `f58a2805-9200-4c60-b894-1a964135f304.18.authorize.certificatemanager.goog` | delegated | GCP Certificate Manager | `acme_challenge_record_data` output of `api-lb` |
| `api.dev.overslash.com` | CNAME | `ghs.googlehosted.com` | tls | GCP `overslash-dev` Cloud Run | `domain` in `dev.tfvars` |
| `overfolder.api.dev.overslash.com` | CNAME | `ghs.googlehosted.com` | tls | GCP `overslash-dev` Cloud Run | `extra_api_domain_mappings` |
| `overfolder-dev.api.dev.overslash.com` | CNAME | `ghs.googlehosted.com` | tls | GCP `overslash-dev` Cloud Run | `extra_api_domain_mappings` |
| `reveni-dev.api.dev.overslash.com` | CNAME | `ghs.googlehosted.com` | tls | GCP `overslash-dev` Cloud Run | `extra_api_domain_mappings` |
| `*.api.dev.overslash.com` | CNAME | `ghs.googlehosted.com` | dns | GCP `overslash-dev` Cloud Run | Per-org dev API hosts (`api_host_suffix`); **accepted risk**, see Findings |
| `mailbox.overslash.com` | CNAME | `ghs.googlehosted.com` | tls | GCP `overslash` Cloud Run | overfwd Mailbox Gateway |
| `mailbox.dev.overslash.com` | CNAME | `ghs.googlehosted.com` | tls | GCP `overslash-dev` Cloud Run | overfwd Mailbox Gateway |
| `status.overslash.com` | CNAME | `statuspage.betteruptime.com` | tls | Better Stack | |
| `dev.overslash.com` | absent | | - | — | Parent of the dev hosts only |
| `docs.overslash.com` | absent | | - | — | Docs are on `overslash-docs.vercel.app` (TODO §1 docs site) |
| `mail.overslash.com` | absent | | - | — | Mail goes straight to Migadu's MX |
| `acme.overslash.com` | absent | | - | — | Example org slug in docs only |
| `oversla.sh` | A | `216.239.32.21,216.239.34.21,216.239.36.21,216.239.38.21` | tls | GCP `overslash` Cloud Run | Shortener domain mapping |
| `oversla.sh` | AAAA | `2001:4860:4802:32::15,2001:4860:4802:34::15,2001:4860:4802:36::15,2001:4860:4802:38::15` | tls | GCP `overslash` Cloud Run | |
| `oversla.sh` | MX | `eforward1.registrar-servers.com,eforward2.registrar-servers.com,eforward3.registrar-servers.com,eforward4.registrar-servers.com,eforward5.registrar-servers.com` | dns | Namecheap forwarding | |
| `oversla.sh` | TXT | `v=spf1 include:spf.efwd.registrar-servers.com` | dns | Namecheap forwarding | |
| `oversla.sh` | TXT | `google-site-verification=` | dns | Search Console | Gates the shortener's domain mapping |
<!-- inventory:end -->

The `gap-assessment.md` 6.4.1 row used to count "ten hostnames" including `dev`, `docs`,
`mail` and `acme`. None of those four resolve; they are listed above as `absent` so that one
appearing without an inventory change fails the check.

## Findings

**`*.api.dev.overslash.com` is a wildcard CNAME to `ghs.googlehosted.com`, accepted on dev
(2026-10-23).** Only the names in `extra_api_domain_mappings` (plus `api.dev`) are mapped.
Every other label resolves to Google's frontends and serves no certificate for itself, which
is the "record pointing at a target nobody claims" shape 6.4.1 asks about. It is kept because:

- **No third party can claim a name under it.** A Cloud Run domain mapping can only be
  created by a principal that is a verified owner of `overslash.com` in Search Console, and
  only we are. The worst an unmapped label does is fail TLS on a hostname nobody publishes.
  On a provider that lets any account claim a name (Vercel, GitHub Pages, S3), the same
  wildcard would be a real takeover; on Cloud Run it is not.
- **It mirrors prod.** The API serves per-org hosts under `api_host_suffix`; prod's
  `*.api.overslash.com` is the same pattern on the GCLB. With the wildcard, onboarding a dev
  org's host needs only the domain mapping in `dev.tfvars`, no registrar change.
- **It is dev only.** No production data or customer traffic is behind `*.api.dev`.

What it costs: the check cannot tell a missing dev mapping from an unused label under the
wildcard, so the row is `dns` (record present, target resolves), not `tls`. Each mapped host
keeps its own explicit `tls` row above, so a mapping that is deleted while still in use does
fail. Revisit if dev ever holds real customer data, or if the zone moves to Cloud DNS (where
explicit records would come from Terraform for free).

No other record failed: every CNAME target resolves (bar the expected Certificate Manager
case), every `tls` row presents a valid certificate for its own name, and no name seen in
Certificate Transparency resolves without a row.

## Hardening options considered

Not needed to pass 6.4.1, but asked about while it was done. In order of value for effort:

1. **Enable DNSSEC at Namecheap** — *recommended, low effort.* Both zones are unsigned
   (RDAP `delegationSigned: false`). Signing stops a resolver-cache poisoning answer for
   `api.` or `app.` from being accepted by validating resolvers, and it is one toggle on
   BasicDNS for `.com` (Namecheap generates the keys and submits the DS). Check `.sh` support
   in the panel before assuming it. The one real hazard is later: a DNS-provider move must
   remove the DS record (and wait out its TTL) *before* changing nameservers, or the domain
   goes dark for validating resolvers. That step is written into the runbook.
2. **CAA records** — *recommended, with care.* No CAA exists, so any public CA may issue for
   our names. Today's issuers are Let's Encrypt (Vercel, Better Stack) and Google Trust
   Services (GCLB, Cloud Run): `0 issue "letsencrypt.org"`, `0 issue "pki.goog"`,
   `0 issuewild "letsencrypt.org"`, `0 issuewild "pki.goog"`, `0 iodef "mailto:security@overslash.com"`.
   A CAA set that omits a CA a provider silently switches to fails that provider's next
   renewal, so add it after confirming each provider's documented CA, and let the inventory
   carry it.
3. **Move the zone to Cloud DNS, not Cloudflare** — *worth doing, separate project.* The real
   weakness this inventory papers over is that DNS is click-ops at the registrar: the script
   has to probe and mine CT logs because there is no API to list the zone. Putting the zone
   in Terraform fixes that properly, and `infra/modules/dns/` already exists with DNSSEC on,
   is gated on one variable, would publish the ACME and domain-mapping records from the
   resources that need them (`dns_zone_name` in `api-lb`), and changes land in the Cloud
   Audit Logs the audit-logging module already retains for 400 days — evidence a lab can be
   shown, with no new vendor or new set of admin credentials. Cloudflare would give the same
   DNS-as-code via its Terraform provider plus a free WAF and DNSSEC, but it adds a third
   control plane beside GCP and Vercel, and its main draw — the proxy — must stay **off** for
   every host here: Vercel discourages proxying in front of it (it breaks its certificate
   issuance and caching), and in front of GCLB it would hide client addresses from Cloud
   Armor and the trusted-proxy client-IP resolution. DNS-only Cloudflare is just a DNS host,
   and Cloud DNS is the one we already have code for. Either move needs the Vercel wildcard
   domains re-verified, the DNSSEC sequencing above, and this file regenerated from the zone.
4. **Smaller items** — keep registrar 2FA and auto-renew on (the domain expiring is the
   ultimate takeover; the script warns 60 days and fails 14 days before the RDAP expiry);
   DMARC could move from
   `quarantine` to `reject` with an `rua` address once reports show only Migadu sends.
