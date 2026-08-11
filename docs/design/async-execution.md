# Async (non-blocking) action calls

**Status**: In progress (behind `ASYNC_EXECUTION_ENABLED`, default off)
**Decision record**: [D57](../../DECISIONS.md)
**Supersedes nothing.** Extends [D56](../../DECISIONS.md) (call timeouts).

## The problem

`POST /v1/actions/call` is synchronous end to end. D56 made the wait
configurable but clamped it at `CALL_TIMEOUT_MAX_MS` (110000), because Cloud
Run cuts every request at `request_timeout_seconds = 120`. Raising that is
possible but does not scale: a 10-minute Metabase export is not a
request-shaped thing, and no proxy timeout is the right place to express it.

D56 deliberately refused to auto-promote an over-ceiling call to a background
one, because that would change the response shape based on a number in a
template the caller never saw. It returns a 400 naming the ceiling instead.
This document describes what that 400 points at.

## What constrains the design

The obvious reading of the infrastructure is wrong, and the correction matters
enough to record.

`infra/modules/cloud-run/main.tf` never sets `cpu_idle`, which looks like the
API is on the Cloud Run v2 throttled default — CPU allocated only during a
request, and any detached task starved. It is not. The Terraform provider
defaults `cpu_idle` to `true` only when the `resources` block is **absent**;
this service specifies `resources`, so an omitted `cpu_idle` is sent as `false`
([provider #17246](https://github.com/hashicorp/terraform-provider-google/issues/17246)).
The sibling `cloud-run-shortener` and `cloud-run-overfwd` modules set
`cpu_idle = true` *explicitly* to opt **into** throttling, which is what lifts
Cloud Run's 512Mi floor and lets them run at 256Mi — both say so in comments.
This API sits at 512Mi/1Gi precisely because it is not throttled.

Consequences: background work on the API instance already works, the 60s
maintenance loop and `events::emit_all` and `spawn_auto_call` were never
silently throttled, and no Terraform apply gates this feature.

**What does bind is scale-in.** `cpu_idle = false` guarantees CPU while the
instance exists; it does not keep the instance alive.

- Cloud Run's autoscaler is request-driven. A container doing background work
  with no in-flight requests still reads as idle, and a `pending` row in
  Postgres creates no scale-out pressure — Cloud Run cannot see the queue.
- Prod runs `min_instances = 1`, so one instance persists and background work
  there is a supported pattern.
- Dev ran `min_instances = 0`. With no instance, nothing drains the queue and a
  job would sit until unrelated traffic warmed one. Dev moves to 1.
- `max_instances = 3` means three replicas sweeping concurrently.
- Scale-in and every revision rollout send SIGTERM, then SIGKILL ~10s later.

So **instance death is the normal case, not the exceptional one.** That single
fact rules out fire-and-forget `tokio::spawn` and forces the work into a
durable row under a renewable lease, so a killed job is *late*, never lost.

## Shape

`execution: "sync" | "async"` on `CallRequest`. Named `execution` rather than
`async` because `async` is a Rust keyword and reserved in JS/TS, which would
make the field unnameable in generated clients.

Async returns **202 `{"status": "accepted"}`** with an `execution_id`.
`CallResponse` is already `#[serde(tag = "status")]`, so this is an additive
variant. Note 202 is also what `pending_approval` returns — two bodies under
one status code, disambiguated by `status`, which is the documented contract
everywhere else in this API.

### Where the fork sits

After the *entire* validation and authorisation pipeline, and before every
dispatch fork. That position is the whole argument for a field on `CallRequest`
rather than a new endpoint: an async call inherits alias resolution, instance
config, coercion, `validate_args`, the D42 SQL policy, owner impersonation, the
group ceiling, the deny screen, the permission-chain walk, and D56 timeout
resolution — unchanged, and with no possibility of drift. Placing it above the
gate would let an agent launch an ungated background call; placing it below
`resolve_request` means a fumbled parameter is a synchronous 400 rather than an
async row that fails 200ms later out of band.

### Gated async

A gated async call returns the ordinary `pending_approval` envelope, not a 202.
The gate fires before the fork, and the two are different axes: an agent must
be able to tell "queued" from "waiting on a human" without a second field.

The async intent is persisted on `approvals.execution_mode` — a column rather
than a field inside `replay_payload`, because the resolve auto-call branch and
`POST /v1/approvals/{id}/call` must both branch on async-ness *before* parsing
a payload that has three different shapes. On approval the replay is routed
through the worker rather than run inline, which is what dodges the 120s cap
that `/approvals/{id}/call` would otherwise impose on the exact query async
exists to enable.

## The row

`executions`, extended — not a sibling table. That reuses the six-state CHECK,
the expiry sweep, `ExecutionSummary`, `result_viewed_at`, `tags`, MCP
`get_result` and CLI `get-result`.

`approval_id` becomes nullable and **`request IS NOT NULL`** marks a row as
worker-run. The two axes are deliberately orthogonal, giving three legal shapes:

| `approval_id` | `request` | meaning |
|---|---|---|
| NULL | NOT NULL | direct async call |
| NOT NULL | NOT NULL | gated call, approved, run async |
| NOT NULL | NULL | every row that existed before this change |

A fourth is meaningless and `executions_has_origin` forbids it.

Keeping them independent is what lets the new lease sweeps say
`AND request IS NOT NULL` while the pre-existing orphan sweep gains
`AND request IS NULL`. Neither can reach the other's rows, so the old sweep's
semantics are *unchanged* rather than merely untouched — and that is provable
from the predicates rather than argued from call sites.

## Worker

A claim-and-lease sweeper, not fire-and-forget.

- **Claim** is `FOR UPDATE SKIP LOCKED` over `status='pending' AND request IS
  NOT NULL`. This is new to the codebase: the only prior cross-replica claim is
  `webhook_digest_run::try_claim`'s `INSERT … ON CONFLICT`, which works because
  its key is `(org, date)` and known in advance. Here the key is "whatever is
  next", which that idiom cannot express. Note `webhook_dispatcher`'s retry
  loop has *no* claim at all and has every replica retrying the same rows —
  that is the wrong precedent to copy.
- **Lease** (60s) with a heartbeat at TTL/3. The heartbeat's
  `RETURNING cancel_requested` doubles as the cancel poll, so "I still own this
  row" and "I should stop" are a single atomic observation.
- **`attempts`** counts attempts that *lost* a lease, and is incremented by the
  reclaim sweep, never by the claim. That makes a clean hand-back at shutdown
  free — release is a plain `status='pending'` with no arithmetic and nothing
  to decrement. It defaults to **1**: an action call is not idempotent and
  there is no idempotency-key concept, so a `POST` that already reached the
  upstream must not be replayed because a worker died.
- **Requeue and release extend `expires_at`.** Without this, a row claimed at
  T+14m of a 15m queue TTL whose worker dies is requeued already-expired and
  silently killed by `expire_stale`, losing the retry.

### Shutdown

A SIGTERM listener flips a `watch` channel; the worker stops claiming and
releases in-flight leases within a 3s budget. It never waits for the *job* — an
async job may legitimately have minutes left.

Deliberately **not** wired into `axum::serve(...).with_graceful_shutdown(...)`.
Draining HTTP means waiting on `/v1/events/stream` responses designed to stay
open 30s, which cannot finish inside Cloud Run's ~10s window — so it would end
in SIGKILL anyway, while changing request-path semantics for every endpoint and
adding a new hang mode to tests that build the router many times per process.
The only thing that genuinely benefits from advance notice is the worker.

Residual risk, accepted and documented: if SIGTERM lands after the upstream
request was sent but before it returned, a released row re-runs a call that
already had its effect. Unavoidable without idempotency keys, and the reason
`ASYNC_MAX_ATTEMPTS` defaults to 1.

## Rejected and deferred

- **A new endpoint** (`POST /v1/actions/call-async`). Rejected: it would have to
  re-implement or delegate every step of the pipeline, and the delegating
  version is just this design with extra routing.
- **`download_tokens` for results.** Rejected: `GET /v1/downloads/{token}`
  *re-dials the upstream*, so routing an async result through it would re-run
  the query on fetch — the opposite of the point.
- **Binary results.** Deferred and rejected at the boundary with a 400.
  `http_caller::call` runs bodies through `String::from_utf8_lossy` before they
  reach the row, so binary is already corrupted on the buffered path; pretending
  otherwise would be worse than refusing. The real fix — worker writes to GCS,
  row stores `{result_url, mime, size_bytes}` — needs a bucket and IAM in
  Terraform and is a follow-up. This does **not** solve `export_query`.
- **`NOTIFY`-driven wake-up.** Deferred. The `LISTEN` bridge already exists in
  `services/events/bus.rs`, so enqueue could wake the worker instantly instead
  of waiting up to one 2s tick. Not worth the coupling for v1.
- **`execution` on `overslash_read`.** Deferred. The canonical async case (a
  slow analytics query) is read-class, but that tool has its own required-args
  schema and body-builder, so it is a second forwarder plus a second schema
  plus tests.
- **`orgs.max_async_call_timeout_ms`.** Deferred. Async is currently clamped by
  the existing `orgs.max_call_timeout_ms`, which means an org that set 60000 to
  bound connection-holding has also bounded its async jobs. Kept knowingly:
  governance that binds only the cheap path is not governance. Revisit if a
  real org complains.
