# Subdomain inventory — DNS changes and check failures

The `overslash.com` and `oversla.sh` zones live at Namecheap (BasicDNS), outside Terraform.
[docs/compliance/casa/subdomain-inventory.md](../compliance/casa/subdomain-inventory.md) is
the record of what they should contain, and
[`scripts/check-subdomains.sh`](../../scripts/check-subdomains.sh) compares it with live DNS
every morning (the **Subdomain inventory** job of the Dependency audit, `dev` branch). A
failure opens or bumps the "Dependency audit failing" triage issue. CASA 6.4.1.

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
| `… is not in the inventory (…)` on a row | The record's value changed | If someone changed it on purpose, update the row; otherwise treat it as a hijack of the zone — check the Namecheap account's audit log and sessions |
| `… resolves but is not in the inventory` / `unlisted … record` | A record exists that nobody wrote down | Add the row with its owner, or delete the record |
| `listed as absent but resolves` | One of the `absent` names started resolving | As above |
| `registration expires …` | Under 60 days to the RDAP expiry | Renew at Namecheap; confirm auto-renew is on |
| `resolver … failed N queries` | dig timed out or got SERVFAIL/REFUSED; those names were not checked, so the run is not trusted | Rerun. If it persists, try `DNS_RESOLVER=8.8.8.8` — a broken zone (e.g. bad DNSSEC) shows up as SERVFAIL everywhere |
| warning `Certificate Transparency lookup … failed` | CertSpotter was unreachable | Nothing; the other checks still ran. It fails nothing on purpose |

The `_acme-challenge.api` row is expected to point at an NXDOMAIN target between certificate
renewals (`delegated`). If the cert map is ever recreated, its value changes: take the new one
from `tofu output` (`acme_challenge_record_name` / `_data` of the `api_lb` module).

## Pending operator steps

### Narrow the `*.api.dev` wildcard

*In code, pending apply.* `*.api.dev.overslash.com` is a wildcard CNAME to
`ghs.googlehosted.com`, but only the hosts in `dev.tfvars` are mapped, so every other label
resolves to Google with nothing behind it. The inventory already lists those hosts
explicitly; the wildcard row is the only thing left.

1. At Namecheap → `overslash.com` → Advanced DNS, add a `CNAME` for each of these hosts
   that is not already an explicit record (value `ghs.googlehosted.com.`):
   `overfolder.api.dev`, `overfolder-dev.api.dev`, `reveni-dev.api.dev` (`api.dev` itself
   already has one — confirm it does).
2. Delete the `*.api.dev` CNAME.
3. Verify, after the TTL:

   ```bash
   dig @1.1.1.1 +short CNAME overfolder.api.dev.overslash.com   # ghs.googlehosted.com.
   dig @1.1.1.1 zz-test.api.dev.overslash.com | grep status      # NXDOMAIN
   ```

4. Delete the `*.api.dev.overslash.com` row from the inventory and run the script; it must
   pass. (The row is already `pending`, so the daily check stays green between step 2 and
   this PR.) From then on a new dev org mapping needs its own CNAME *and* row (see the comment on
   `extra_api_domain_mappings` in `infra/env/dev.tfvars`).

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
