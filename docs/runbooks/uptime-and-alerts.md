# Uptime check, `[P0] API Down`, and the PromQL alert gates

Infra is never auto-applied. This page is the human half of the change that gives
production a GCM uptime check and a paging API-down alert, and switches on the three
PromQL alerts that were off in every environment.

## What changes

| | dev | prod |
|---|---|---|
| Uptime check `overslash-<env>-api-health` on `https://<host>/health` | already exists (`api.dev.overslash.com`) | **created** on `api.overslash.com` |
| `[P0] overslash-<env> API Down` | already exists | **created**, routed to PagerDuty (EU) + email |
| Overview dashboard uptime tile | already wired | **dashboard replaced** so the tile points at the new check |
| `[P1] API Slow Requests` | **created** | **created** |
| `[P1] OAuth Refresh Failure Rate` | **created** | **created** |
| `[P1] Upstream Error Rate` | **created** | **created** |
| `[P1] Webhook Delivery Failure Rate` | query updated in place | query updated in place |
| Actions & OAuth dashboard | replaced (two ratio charts) | replaced (two ratio charts) |

### Why prod had no uptime check

`modules/monitoring` creates the uptime check and `[P0] API Down` only when `api_domain` is
non-empty, and the root module fed it `var.domain`. Prod leaves `domain = ""` on purpose:
the GCLB serves `api.overslash.com` and `*.api.overslash.com` (`api_host_suffix`) instead
of a Cloud Run domain mapping. So both resources were silently dropped. The only P0 left
was `API High 5xx Rate`, which cannot fire when the API returns nothing at all.

`infra/main.tf` now passes `domain`, or `api_host_suffix` when `domain` is empty and the
LB is on. With neither set, nothing public answers, and the check stays off.

### Why the three PromQL alerts were off, and why they are on now

Each one is gated (`*_alert_enabled` in tfvars) because GMP rejects a policy whose metric
descriptor does not exist yet. The descriptors were measured present in **both** projects
on 2026-10-27:

```
prometheus.googleapis.com/overslash_http_request_duration_seconds/histogram
prometheus.googleapis.com/overslash_oauth_events_total/counter
prometheus.googleapis.com/overslash_upstream_responses_total/counter
```

So all three flags are `true` in both tfvars. **But turning on the OAuth and upstream
alerts as they were would have added two alerts that cannot fire.** They divided by
`clamp_min(sum(rate(...)), 1)`. Prod traffic is well under one event per second, so the
denominator was always clamped to 1, and the "ratio" was really failures per second,
which never reaches 0.10 or 0.20. The deployed webhook alert had the same flaw. All three
now copy the latency alert's pattern: a `0.001` floor that only guards against division
by zero, plus an explicit `and` that requires a minimum sample in the window:

| Alert | Window | Minimum sample | Fires at |
|---|---|---|---|
| OAuth Refresh Failure Rate | 15m | rate > 0.011/s (~10 refreshes) | > 10% failed |
| Upstream Error Rate | 15m | rate > 0.022/s (~20 responses) | > 20% `5xx` / `error` |
| Webhook Delivery Failure Rate | 30m | rate > 0.0056/s (~10 terminal deliveries) | > 5% failed |

The two matching dashboard charts on *Actions & OAuth* had the same clamp, so they showed
ratios close to zero. They now use the same `0.001` floor.

### Relationship to the status page

[status.overslash.com](status-page.md) (Better Stack) probes the same `/health` URL from
outside GCP. It is a public status signal, managed in the Better Stack console, and it
does not page. Paging comes from this GCM check: it is in IaC, reviewable, and routed
to PagerDuty. Keep both.

## Apply

Dev first. That is where GMP gets to reject a malformed PromQL query before prod sees it.

```bash
make tofu-plan ENV=dev
# expect: 4 to add, 2 to change, 1 to destroy — all under module.monitoring
make tofu-apply ENV=dev

make tofu-plan ENV=prod
# expect, under module.monitoring only:
#   + google_monitoring_uptime_check_config.api_health[0]
#   + google_monitoring_alert_policy.api_down[0]
#   + google_monitoring_alert_policy.{api_slow_requests,oauth_refresh_failure_rate,upstream_error_rate}[0]
#   ~ google_monitoring_alert_policy.webhook_failure_rate[0]
#   -/+ google_monitoring_dashboard.{overview,actions_and_oauth}
#   ~ terraform_data.dashboard_hash["overview"], ["actions_and_oauth"]
make tofu-apply ENV=prod
```

A full prod plan also shows whatever else is pending apply on `dev`. Read the whole plan,
not only the monitoring lines. To apply only this change:
`tofu plan -var-file=env/prod.tfvars -target=module.monitoring -out=prod.tfplan`.

The agent sandbox could only make a `-refresh=false -target=module.monitoring` plan: the
module's `depends_on` drags in IAM, which the factory SA cannot read, and the plan stops at
the PagerDuty secret read. Up to that point the prod plan matched the list above, minus
`api_down`, whose channels depend on that secret.

## Verify

```bash
# 1. The uptime check exists and targets the apex.
gcloud monitoring uptime list-configs --project=overslash \
  --format="table(displayName,monitoredResource.labels.host,httpCheck.path,period)"
# expect: overslash-prod-api-health  api.overslash.com  /health  60s

# 2. It passes from every checker region (give it ~5 minutes after apply).
#    Console: Monitoring → Uptime checks → overslash-prod-api-health.
#    Or the metric itself (replace <id> with the check's ID, the last segment of `name`):
curl -s -G -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://monitoring.googleapis.com/v3/projects/overslash/timeSeries" \
  --data-urlencode 'filter=metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND metric.labels.check_id="<id>"' \
  --data-urlencode "interval.startTime=$(date -u -d '10 min ago' +%FT%TZ)" \
  --data-urlencode "interval.endTime=$(date -u +%FT%TZ)" \
  | jq -r '.timeSeries[] | [.metric.labels.checker_location, .points[0].value.boolValue] | @tsv'
# expect: one row per region, all true

# 3. The alert policies exist, are enabled, and P0 pages both channels.
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://monitoring.googleapis.com/v3/projects/overslash/alertPolicies?pageSize=100" \
  | jq -r '.alertPolicies[] | [.displayName, .enabled, (.notificationChannels|length)] | @tsv' | sort
# expect 14: the 10 already there + [P0] API Down (2 channels) + API Slow Requests,
#            OAuth Refresh Failure Rate, Upstream Error Rate

# 4. The new dashboard tile resolves: Monitoring → Dashboards → overslash-prod Overview,
#    the uptime chart shows data instead of "No data".
```

`gcloud alpha monitoring policies list` works too, if the alpha component is installed.

### Test the page without an outage (optional)

Do this on dev. It pages the dev email channel only:

```bash
ID=$(gcloud monitoring uptime list-configs --project=overslash-dev \
  --filter='displayName=overslash-dev-api-health' --format='value(name.basename())')
# Point the check at a path that 404s. This drifts from Terraform on purpose.
gcloud monitoring uptime update "$ID" --project=overslash-dev --path=/health-uptime-drill
# Wait ~3-5 minutes (2 failing 60s probes from ≥2 regions); expect
# "[P0] overslash-dev API Down" to open and an email to alert@overspiral.com.
# Revert, either by hand or with an apply, which puts /health back:
gcloud monitoring uptime update "$ID" --project=overslash-dev --path=/health
```

There is no safe way to do it in prod short of an outage. The dev run plus check (3)
above, which shows the prod policy wired to PagerDuty, is the evidence.

## Evidence for CASA

Record in [gcp-posture.md](../compliance/casa/gcp-posture.md#monitoring--the-count-gate-confirmed):
the output of steps 1 and 3 with the date, and the policy count going from 10 to 14.
