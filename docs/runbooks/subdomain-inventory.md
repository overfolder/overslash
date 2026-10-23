# Subdomain inventory — DNS changes and check failures

The `overslash.com` and `oversla.sh` zones live at Namecheap (BasicDNS), outside Terraform.
[docs/compliance/casa/subdomain-inventory.md](../compliance/casa/subdomain-inventory.md) is
the record of what they should contain, and
[`scripts/check-subdomains.sh`](../../scripts/check-subdomains.sh) compares it with live DNS
every morning (the **Subdomain inventory** job of the Dependency audit, `dev` branch). A
failure opens or bumps the "Dependency audit failing" triage issue. CASA 6.4.1.
A PR runs the live check only if it edits the inventory or the script. Any other
dependency PR gets the offline parse, so DNS drift never blocks an unrelated merge.

Run it locally the same way CI does:

```bash
bash scripts/check-subdomains.sh            # live
bash scripts/check-subdomains.sh --offline  # table syntax only
```

It needs `dig`, `curl` and `jq`, and takes about half a minute.

## Adding a hostname

1. Add the row(s) to the inventory in the PR that needs the hostname — a new
   `extra_api_domain_mappings` entry in `dev.tfvars`, a Vercel domain, a Better Stack page —
   with Check **`pending`**. The PR runs the check, and the record does not exist yet;
   `pending` lets a missing record pass while still rejecting a wrong one.
2. Merge, then create the target first (apply the Terraform, attach the domain in Vercel),
   and only then the record at Namecheap. The other order leaves a record pointing at an
   unclaimed target, which is the thing this check exists to catch.
3. Once the provider has issued the certificate (a few minutes), switch the row from
   `pending` to `tls` (or `dns`) in a follow-up PR, which now checks it in full. Don't leave
   a row `pending`: it never checks the certificate, so it cannot see an unclaimed target.

## Removing a hostname

The reverse order. Switch the row to `pending` in a PR first, so the daily check tolerates
the record's absence. Then **delete the Namecheap record**, wait for its TTL (30 min), then
release the target — destroy the Cloud Run domain mapping, remove the Vercel domain, delete
the status page, release the GCLB address — and then delete the inventory row. A record
whose target is gone is a dangling record anyone who can claim that target may serve.

## When the check fails

| Message | Meaning | Do |
|---------|---------|----|
| `dangling CNAME/MX — target … is NXDOMAIN` | The record points at a name that no longer exists | Delete the record at Namecheap now, then find out what released the target |
| `unclaimed target — HTTPS … has no valid certificate` / `Vercel has no deployment` | The name resolves to a provider, but no account of ours serves it | If the hostname is still wanted, re-attach it (domain mapping / Vercel domain); if not, delete the record. Either way, the same day |
| `HTTPS to … failed (curl N: …)` | Not a certificate problem: curl could not connect (7), timed out (28) or failed otherwise, after three tries. An HTTP error status never causes it, because a 5xx from a sleeping dev backend still counts as claimed | Rerun. If it persists, check that provider's status page; a GCLB or Cloud Run host that stays unreachable may be a released address, so compare the record with `tofu output` |
| `… is not in the inventory (…)` on a row | The record's value changed | If someone changed it on purpose, update the row; otherwise treat it as a hijack of the zone — check the Namecheap account's audit log and sessions |
| `… resolves but is not in the inventory` / `unlisted … record` | A record exists that nobody wrote down | Add the row with its owner, or delete the record |
| `listed as absent but resolves` | One of the `absent` names started resolving | As above |
| `registration expires …` | Under 14 days to the RDAP expiry and still not renewed (a warning from 60 days) | Renew at Namecheap; confirm auto-renew is on |
| `resolver … failed N queries` | dig timed out or got SERVFAIL/REFUSED; those names were not checked, so the run is not trusted | Rerun. If it persists, try `DNS_RESOLVER=8.8.8.8` — a broken zone (e.g. bad DNSSEC) shows up as SERVFAIL everywhere |
| warning `Certificate Transparency lookup … failed` | CertSpotter was unreachable | Nothing; the other checks still ran. It fails nothing on purpose |

The `_acme-challenge.api` row is expected to point at an NXDOMAIN target between certificate
renewals (`delegated`). If the cert map is ever recreated, its value changes: take the new one
from `tofu output` (`acme_challenge_record_name` / `_data` of the `api_lb` module).

## The `*.api.dev` wildcard (accepted)

`*.api.dev.overslash.com` stays a wildcard CNAME to `ghs.googlehosted.com`; the reasoning
is in the inventory's Findings. A new dev org host therefore needs no registrar change:

1. Add it to `extra_api_domain_mappings` in `infra/env/dev.tfvars`, and in the same PR add
   its inventory row as `pending`: the row's CNAME is checked, but not TLS, so the PR can
   pass before the mapping exists. Apply.
2. Once Google has issued the mapping's certificate (`gcloud beta run domain-mappings
   describe --domain <host> --region <region>` shows `CertificateProvisioned` true,
   usually within the hour), switch the row to `tls` in a follow-up PR. From then on the
   daily check fails if the mapping disappears while the name is still in use.

To narrow it after all, in this order so the daily check never sees a record its row
contradicts:

1. Add an explicit `ghs.googlehosted.com.` CNAME at Namecheap for every host in
   `extra_api_domain_mappings`.
2. Merge a PR switching the `*.api.dev.overslash.com` row to `pending`.
3. Delete the wildcard at Namecheap and, after the TTL, confirm
   `dig @1.1.1.1 zz-test.api.dev.overslash.com` is NXDOMAIN.
4. Delete the wildcard row and run the script; it must pass.

### Optional hardening

Reasoning for each is in the inventory's "Hardening options considered".

- **DNSSEC** — Namecheap → domain → Advanced DNS → DNSSEC → enable, for `overslash.com`
  (and `oversla.sh` if the panel offers it). Verify:
  `dig @1.1.1.1 +dnssec overslash.com SOA | grep -E 'flags:.* ad'` and
  `dig +short DS overslash.com @a.gtld-servers.net`. Then set the inventory's DNSSEC column.
  **Before any future nameserver change: disable DNSSEC, wait for the DS TTL (a day) and
  only then switch**, or validating resolvers stop resolving the domain.
- **CAA** — after confirming each provider's CA, add `CAA` records on the apex:
  `0 issue "letsencrypt.org"`, `0 issue "pki.goog"`, `0 issuewild "letsencrypt.org"`,
  `0 issuewild "pki.goog"`, `0 iodef "mailto:security@overslash.com"`. Add matching rows
  (the script does not check CAA yet — extend `rr`'s type list when you add them). Watch the
  next renewal of every `tls` host.
