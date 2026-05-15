# Public status page

Public URL: <https://status.overslash.com>

## What it is

- **Vendor**: Better Stack.
- **Components**: `api.overslash.com` and `app.overslash.com`, each backed by
  an HTTPS uptime check on 60s cadence.
- **Relationship to GCM**: Better Stack runs independent HTTPS probes from
  outside GCP. It is intentionally not driven by Google Cloud Monitoring alerts
  — if GCM itself has an outage the public page stays truthful.

The Better Stack monitors mirror the *target* of the GCM uptime check in
`infra/modules/monitoring/uptime.tf`. The GCM `[P0] api_down` alert
(`infra/modules/monitoring/alerts_p0.tf`) continues to page on-call
independently.

## Who has access

Admins are managed in Better Stack → Team settings. Anyone in the on-call
rotation should have full incident-management permissions. Request access from
a current admin if yours is missing.

## Post a manual incident update

For known issues — degraded performance, partial outage, a customer-facing bug
not picked up by the monitor.

1. Better Stack → **Status pages** → Overslash → **Report incident**.
2. Pick the affected component(s), severity, and a one-line impact summary.
3. Post follow-up updates as the picture changes; resolve when fixed.

The page renders the update history under the component. Be specific about
what's affected and what isn't — the page is the public source of truth during
an incident.

## Schedule maintenance

Use the same flow with the **Scheduled maintenance** toggle and a start/end
time. The component banner shows a maintenance badge during the window and the
monitor history is annotated rather than counted as downtime.

## Override an auto-detected incident

If a monitor flaps or fires on a known-cosmetic issue, open the auto-opened
incident and resolve it with a one-line note. The override does not silence
the underlying monitor — fix or pause the monitor itself if the false-positive
is structural.

## On-call

Page is wired only as a status signal. Paging is via the GCM P0 alert pipeline
(PagerDuty integration tracked in TODO.md §1.4, first bullet). When that lands,
link the rotation schedule from this page.

## Verifying after changes

To sanity-check the monitor without faking an outage:

- Hit `https://api.overslash.com/health` from a browser — expect `{"status":"ok"}`.
- The Better Stack monitor page shows the last probe time and HTTP response.

To exercise the public flip without affecting production, change a monitor's
URL to a 404 path on the dev environment, wait two probe cycles, confirm the
component flips to "Degraded", then revert.
