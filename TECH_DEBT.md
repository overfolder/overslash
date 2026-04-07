# Overslash — Tech Debt

Known workarounds and deferred improvements.

---

## Dashboard: Org Groups page

- **Auto-approve toggle uses DELETE + POST.** `/v1/groups/{id}/grants` has no PATCH endpoint, so toggling `auto_approve_reads` removes the grant and re-adds it with the new value. Add a PATCH route and switch the dashboard to use it.
- **Member and grant counts derived client-side.** The list view fetches per-group grants/members in parallel to compute counts. Add aggregated counts to `GroupResponse` (or a `/v1/groups?include=counts` query) once group volume grows.
- **"Everyone" group not implemented.** UI_SPEC §Groups specifies an always-present "Everyone" group containing all users. Backend has no concept of it yet — the dashboard does not synthesize one.
