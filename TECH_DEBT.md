# Overslash — Tech Debt

Known workarounds and deferred improvements.

---

## `serde_yaml` is deprecated upstream

`overslash-core` uses `serde_yaml = "0.9"` for the registry loader and the template validator's YAML entry point. The crate was archived by dtolnay in 2024 and is no longer receiving updates. Current behavior is stable and well-tested, but we should migrate to `saphyr` / `yaml-rust2` eventually. The validator's duplicate-action-key detection parses a serde_yaml error string to extract the offending key — a drop-in replacement will need to re-derive that from whatever API the replacement exposes (probably easier, since `yaml-rust2`'s event API surfaces every key emission directly).

Scoped feature gate (`overslash-core/yaml`) already isolates the dependency so swapping it out shouldn't touch the rest of the crate.

---

## Dashboard: Org Groups page

- **Auto-approve toggle uses DELETE + POST.** `/v1/groups/{id}/grants` has no PATCH endpoint, so toggling `auto_approve_reads` removes the grant and re-adds it with the new value. Add a PATCH route and switch the dashboard to use it.
- **Member and grant counts derived client-side.** The list view fetches per-group grants/members in parallel to compute counts. Add aggregated counts to `GroupResponse` (or a `/v1/groups?include=counts` query) once group volume grows.
- **"Everyone" group not implemented.** UI_SPEC §Groups specifies an always-present "Everyone" group containing all users. Backend has no concept of it yet — the dashboard does not synthesize one.
