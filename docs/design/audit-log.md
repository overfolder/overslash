# Audit Log Design

**Status**: Implemented (PR #7)
**Date**: 2026-03-27

## Problem

Overslash had an audit_log table and basic infrastructure (migration 007) but only 5 out of ~16 mutable operations were logged. The IP address column existed but was never populated, and the query API only supported limit/offset pagination with no filtering.

## Goals

1. Every mutable API operation produces an audit log entry
2. Client IP addresses are captured for forensic traceability
3. The query API supports filtering by action, resource type, identity, and date range
4. Zero new migrations required

## Non-goals

- Real-time webhook dispatch for audit events (deferred)
- Audit log retention/archival policies
- Dashboard UI for browsing audit entries
- ~~Composite indexes for filtered queries (premature; add when needed)~~ —
  retired by migration 110. "When needed" arrived; see § "Index behaviour under
  load" for the measurement that justified them.

## Design

### Action naming convention

All actions follow `resource.verb` with lowercase snake_case resource and past-tense verb:

```
org.created          identity.created       api_key.created
secret.put           secret.deleted         permission_rule.created
permission_rule.deleted  approval.created   approval.resolved
action.executed      connection.created     connection.deleted
byoc_credential.created  byoc_credential.deleted
webhook.created      webhook.deleted
```

16 total action types.

### IP address capture

A `ClientIp` extractor resolves the client IP from (in order):
1. `X-Forwarded-For` header (first IP in comma-separated list)
2. `X-Real-IP` header
3. `ConnectInfo<SocketAddr>` fallback (direct connection)

The extractor never fails -- it returns `Option<String>`. This is a separate extractor from `AuthContext` because IP is a request-level concern, and some handlers (org creation, API key creation) are unauthenticated.

`main.rs` uses `into_make_service_with_connect_info::<SocketAddr>()` to make the socket address available.

### Audit entry struct

The `audit::log()` function accepts an `AuditEntry` struct instead of 8 positional arguments:

```rust
pub struct AuditEntry<'a> {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub action: &'a str,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub ip_address: Option<&'a str>,
}
```

This avoids the clippy `too_many_arguments` warning and makes call sites self-documenting.

### Logging pattern

All audit calls follow fire-and-forget: `let _ = audit::log(...).await;`

- Audit is written **after** the successful operation, never before
- Failures in audit logging do not fail the handler
- Delete operations only log when `deleted == true`
- Secret values and webhook signing secrets are never included in detail

### Filtered query API

`GET /v1/audit` now accepts optional query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | i64 | Max results (default 50) |
| `offset` | i64 | Pagination offset |
| `action` | string | Exact match (e.g. `secret.put`) |
| `resource_type` | string | Exact match (e.g. `secret`) |
| `identity_id` | UUID | Filter by actor |
| `since` | RFC3339 datetime | `created_at >= since` |
| `until` | RFC3339 datetime | `created_at <= until` |
| `risk` | comma-separated | `read` / `write` / `delete`; a row matches **any** listed value |
| `risk_min` | string | Lowest rung on `read < write < delete`; `write` means "write or worse" |

The query uses optional parameter matching (`$N::type IS NULL OR column = $N`) to avoid dynamic SQL construction. The existing `(org_id, created_at DESC)` index covers the base case.

Response now includes `ip_address`.

`risk` **ORs** where `tag` **ANDs**, and the asymmetry is deliberate: tags narrow
along independent axes, so requiring all of them is what a caller means, whereas
risk is a single axis with mutually exclusive values where an AND is always
empty. `risk_min` is expanded to its set by the handler (`Risk::at_least`) and
intersected with `risk`, so both parameters narrow and the SQL keeps a single
`risk = ANY(...)` predicate — the ladder is defined in exactly one place. An
unparseable value is a 400 rather than an ignored parameter: silently dropping
it would *widen* the result set, and a filter that quietly returns more than was
asked for is the wrong failure mode for an audit log. Note `admin` is rejected
here — it is a rung of the neighbouring `AccessLevel` ladder, not of `Risk`.

## Future: Human-readable audit descriptions (Mode C)

Currently, Mode C audit entries store the static action description from the service YAML (e.g. `"Delete a calendar event (Google Calendar)"`). This is useful but doesn't tell you *which* event was deleted — you'd need to cross-reference the URL's UUID with an external system.

### Goal

Audit entries like `Deleted event "Team Standup" (Google Calendar)` instead of `Delete a calendar event (Google Calendar)`.

### Proposed approach

Add two optional fields to each action in the service YAML:

```yaml
delete_event:
  description: Delete a calendar event
  audit_template: 'Deleted event "{summary}"'
  audit_resolve:
    summary:
      from: params       # "params" or "response"
      path: summary      # dot-path into the source object
```

**Resolution sources:**

| Source | When to use | Example |
|--------|-------------|---------|
| `params` | Value is in the request params (create/update actions) | `summary` from create_event params |
| `response` | Value is in the API response body (read/delete actions) | `summary` from get_event response before deletion |

**For delete actions**, the response body is often empty (204 No Content). Two options:
1. **Pre-fetch**: Before executing the delete, do a GET to retrieve the resource name. Adds latency but gives the best description.
2. **Params only**: Only resolve from request params. For deletes that only take an ID, fall back to the static description.

**Recommendation**: Start with `params`-only resolution (zero extra API calls). Add `response` resolution as a second pass. Skip pre-fetch for deletes initially — the static description + URL is enough context.

### Implementation sketch

1. Add `audit_template` and `audit_resolve` to `ActionDefinition` in `overslash-core/types.rs`
2. After `resolve_request()` builds the `ActionRequest`, check if the action has `audit_resolve`
3. For `from: params`, substitute values from `req.params` into the template
4. For `from: response`, parse `result.body` as JSON and extract the value
5. Store the resolved string as `detail.description` in the audit entry
6. Fall back to the static `action.description` if resolution fails

### Service YAML examples

```yaml
# Google Calendar — create uses params
create_event:
  audit_template: 'Created event "{summary}"'
  audit_resolve:
    summary: { from: params, path: summary }

# Google Calendar — list uses response (count)
list_events:
  audit_template: 'Listed {count} events'
  audit_resolve:
    count: { from: response, path: items.length }

# Resend — send uses params
send_email:
  audit_template: 'Sent email to {to}'
  audit_resolve:
    to: { from: params, path: to }

# GitHub — create PR uses response
create_pull:
  audit_template: 'Created PR #{number} "{title}"'
  audit_resolve:
    number: { from: response, path: number }
    title: { from: response, path: title }
```

## Index behaviour under load (measured 2026-08-11)

Reproduce with `scripts/bench_audit_query.sh` — it seeds 500k synthetic rows
(400k in the queried org, 100k in a second org as noise) and `EXPLAIN ANALYZE`s
every shape below. Both columns were taken on the same machine against
identically-sized tables; run the "before" column by pointing `MIGRATIONS` at a
migration set without 110.

| Query | before (`LIMIT 50`) | after (migration 110) |
|---|---|---|
| No filters, first page | 0.24 ms | 0.12 ms |
| `q` = one common term | 0.56 ms | 0.28 ms |
| `q` = two common terms | 0.55 ms | 0.38 ms |
| `action =` matching 1 row in 4 (dense) | 0.22 ms | 0.27 ms |
| **`action =` matching 1 row in 5000 (sparse)** | **48.8 ms** | **0.62 ms** |
| `resource_type =` matching 1 row in 4 | 0.23 ms | 0.28 ms |
| `ip_address =` matching 1 row in 250 | 3.2 ms | 5.8 ms |
| **`q` matching nothing** | **1584 ms** | **0.28 ms** |
| No filters, `OFFSET 5000` | 7.8 ms | 2.8 ms |
| Keyset cursor at the same depth | — | 0.14 ms |
| Insert 10k rows, one session | ~350 ms | ~640 ms |

### What the original measurement established

1. **`idx_audit_log_org (org_id, created_at DESC)` drove every query.** It
   satisfied the org predicate *and* the `ORDER BY created_at DESC LIMIT n`, so
   an unfiltered page touched five buffers. Pairing the org column with the sort
   column is what makes that work — any new index on this table intended for the
   dashboard's query shape must end in `created_at DESC` for the same reason.
   Migration 110 widens it to `(org_id, created_at DESC, id DESC)` rather than
   adding an index beside it, so the keyset cursor's total order is served
   without a sort node.

2. **Every other predicate was a post-index filter, and cost scaled with how
   many rows had to be walked before `LIMIT` was satisfied.** Dense filters were
   free; a filter matching nothing walked the org's entire history.

3. **`idx_audit_log_tags` (GIN) was not used by this query.** The planner
   prefers the ordered index because it can stop at `LIMIT 50`, where a bitmap
   scan would have to sort the whole match set first.

### Migration 112: the `risk` column

`risk` is the one tag namespace promoted to a column of its own. That is a
direct consequence of point 3 above: the value was already minted on every
gated call as `risk:read|write|delete`, and `?tag=risk:write` worked, but inside
a `text[]` it could not be indexed (the GIN the planner never chose), could not
be rendered as a table column, and could not answer an ordered question.

The index takes the shape this section established — `(org_id, risk,
created_at DESC)` — and adds `WHERE risk IS NOT NULL`, because on a mature org
most rows are control-plane events that no risk query ever wants. The partial
predicate is sound for every query that reaches the conjunct: `risk = ANY(...)`
over non-NULL values can never select the excluded rows.

Measured on 50k rows (45k unclassified, 4.9k `read`, 100 `delete`), the split is
the same sparse/dense one the `action` composite showed:

| Query | Plan | Time |
|---|---|---|
| `risk = delete` (sparse, 100 rows) | `idx_audit_log_org_risk` | **0.09 ms** |
| same, index dropped | Seq Scan | 4.69 ms |
| `risk = read` (dense, 4.9k rows) | `idx_audit_log_org_created_id` | 0.07 ms |
| whole ladder | `idx_audit_log_org_created_id` | 0.03 ms |

The dense and whole-ladder cases do **not** use the new index, and that is the
planner making the right call: the ordered index stops at `LIMIT 50` where the
risk index would have to sort thousands of matches first. The index earns its
place on the sparse case, which is also the interesting one — `risk = delete` is
the query an auditor actually types.

One correction to the intuition behind "any new index must end in
`created_at DESC`": here it does not buy a sort-free plan. `= ANY` is a
scalar-array op, so Postgres cannot prove the multi-rung scan is ordered and a
sort node remains. The trailing column still helps — a scalar `risk =` gets an
Incremental Sort that stops early — but the actual win is that only the matched
rows reach the sort, rather than the org's history.

The column is derived inside `log_tagged` from the tag rather than threaded down
to each audit write. Besides sparing ~149 call sites, it is the only correct
source on the replay and expiry paths, which act on an approval minted hours
earlier and hold no live `Risk` — re-deriving there could disagree with what the
approver actually saw.

### What migration 110 changed, and why the cliff needed two fixes

The 2553 ms no-match case was **not** primarily a missing-index problem. Roughly
two thirds of it was the per-row `identities` join: the plan was a nested loop
over 400k candidate rows, and materializing the actor name (D59) removed it
outright. That alone took the case to ~500 ms.

The rest needed the trigram index, and getting the planner to use it took a
second change. A `pg_trgm` GIN index cannot serve the multi-term free-text
clause #533 introduced: the pattern is a correlated column of `unnest`, so the
clause is an anti-join subplan evaluated per row, not an indexable predicate.
The query therefore carries **one redundant conjunct** over a single parameter —
the longest term of three characters or more, matched against
`action || ' ' || description || ' ' || actor_name`, the exact expression
`idx_audit_log_search_trgm` is built on. It is sound because it is a *superset*
of the real predicate: any row matching one column matches the concatenation, so
it can only admit extra rows, which the `NOT EXISTS` then rejects. Terms shorter
than three characters have no trigram to look up and keep the sequential filter.

Composite indexes are now justified rather than assumed: a **sparse** `action =`
went from 48.8 ms to 0.62 ms. A *dense* one did not need them and is marginally
slower through the composite (0.22 → 0.27 ms), which is the honest shape of that
trade.

### Costs this bought

- **Writes are ~1.8× slower**: ~35 µs → ~64 µs per row on a 500k-row table.
  Attributed by dropping indexes one at a time: the trigram GIN is ~27 µs/row of
  it and the two composites ~5 µs/row. `audit_log` is the hottest insert path in
  the system, so this is the number to watch; it is the price of the 5600× read
  win on the case that was timing out.
- **The row is wider by two names**, so filters that still walk the ordered index
  touch more heap pages: `ip_address =` went 3.2 → 5.8 ms. Reproducible across
  runs, not noise. If IP filtering ever matters at scale, it takes the same
  composite shape as `action`.
- Two indexes were dropped in the same migration, which gives some of the write
  cost back: the tags GIN above, and `idx_audit_log_impersonated_by`, which was
  dead — `impersonated_by_identity_id` appears only in `SELECT` lists and
  `INSERT`s, never in a `WHERE`, anywhere in the tree.

`OFFSET` remains linear and is still accepted by the API, but the dashboard now
pages with `before` / `before_id`. `id` is in the cursor because rows written in
one transaction share `now()`; without a tiebreaker the boundary between pages
silently skips or repeats them.

Caveat: synthetic uniform data. The plan *shapes* are the durable result; the
millisecond figures are directional.

## Alternatives considered

**Middleware-based logging**: An Axum middleware could intercept all requests and log automatically. Rejected because it can't capture resource-specific context (resource_type, resource_id, semantic action names, detail payloads). The per-handler pattern gives precise control over what's logged.

**Dynamic SQL for filtering**: Building WHERE clauses dynamically would be more efficient for the query planner when parameters are absent. Rejected for simplicity -- the optional parameter matching approach is straightforward and the existing index covers performance needs at current scale.

**Webhook integration**: Publishing audit events as webhooks for real-time monitoring. Deferred because it couples audit writes to HTTP dispatch, increasing blast radius. Better to add as a separate `audit.*` event category after audit coverage is complete.

## Files changed

| File | Change |
|------|--------|
| `crates/overslash-db/src/repos/audit.rs` | `AuditEntry` struct, `ip_address` in `log()`, `AuditFilter` + `query_filtered()` |
| `crates/overslash-api/src/extractors.rs` | `ClientIp` extractor |
| `crates/overslash-api/src/main.rs` | `into_make_service_with_connect_info` |
| `crates/overslash-api/src/routes/audit.rs` | Filter params, `ip_address` in response |
| 10 route files | Added `ClientIp` extractor + audit calls |
