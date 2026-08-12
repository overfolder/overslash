-- Async (non-blocking) action calls.
--
-- A call made with `execution: "async"` is accepted, persisted, and dialled off
-- the request path by a worker. It reuses `executions` rather than a sibling
-- table so the six-state CHECK, the expiry sweep, `ExecutionSummary`,
-- `result_viewed_at`, `tags`, MCP `get_result` and CLI `get-result` all keep
-- working unchanged.
--
-- `request IS NOT NULL` marks a row as worker-run, and is deliberately
-- ORTHOGONAL to `approval_id`. Three shapes are legal:
--
--   approval_id NULL,     request NOT NULL  -- direct async call
--   approval_id NOT NULL, request NOT NULL  -- gated call, approved, run async
--   approval_id NOT NULL, request NULL      -- every row that exists today
--
-- The fourth is meaningless and `executions_has_origin` forbids it. Keeping the
-- two axes independent is what lets the new lease sweeps say
-- `AND request IS NOT NULL` and the old orphan sweep say `AND request IS NULL`,
-- so neither can ever touch the other's rows.
--
-- Concurrency here is a claim-and-lease, not the CAS-in-WHERE the synchronous
-- path uses. CAS is sufficient there because the claimant IS the HTTP request
-- and dies with its connection. An async row is claimed by a process that
-- outlives any request and that Cloud Run may recycle mid-call, so ownership
-- has to be a renewable fact in the row rather than an implicit one.

ALTER TABLE executions
    ALTER COLUMN approval_id DROP NOT NULL;

ALTER TABLE executions
    -- Whose call this is. Needed to re-mint OAuth credentials, attribute the
    -- audit row, and pick the event audience — all of which the synchronous
    -- path reads off the joined `approvals` row, which an async row may lack.
    ADD COLUMN identity_id         UUID REFERENCES identities(id) ON DELETE CASCADE,
    -- Credential-free stored payload, same shape as `approvals.replay_payload`
    -- (StoredCallRequest / StoredMcpCall / StoredPlatformCall). Never holds a
    -- live token: `service_key` + `service_instance_id` record where the
    -- credential came from so the worker re-mints one at run time.
    ADD COLUMN request             JSONB,
    ADD COLUMN service_key         TEXT,
    ADD COLUMN service_instance_id UUID REFERENCES service_instances(id) ON DELETE SET NULL,
    -- Lease. `executing` is only meaningful while this is in the future.
    ADD COLUMN lease_expires_at    TIMESTAMPTZ,
    ADD COLUMN worker_id           TEXT,
    -- Attempts that ended by LOSING a lease. Incremented by the reclaim sweep,
    -- never by the claim — so handing a row back cleanly at shutdown costs
    -- nothing and only a genuinely dead worker is charged.
    ADD COLUMN attempts            INTEGER NOT NULL DEFAULT 0,
    -- Cooperative cancel. The worker observes it on its next heartbeat. This
    -- stops Overslash waiting; it does not stop the upstream.
    ADD COLUMN cancel_requested    BOOLEAN NOT NULL DEFAULT false,
    -- Presentation + audit provenance the worker needs, captured at accept
    -- time because it cannot be recovered later. `render_verbose` is a rendering
    -- choice about our response, not part of the upstream request, which is
    -- why it is a column and not a field inside `request`.
    ADD COLUMN render_verbose      BOOLEAN,
    ADD COLUMN template_key        TEXT,
    ADD COLUMN description         TEXT,
    ADD COLUMN client_ip           TEXT;

-- Every existing row is approval-backed, so the requester is recoverable.
UPDATE executions e
   SET identity_id = a.identity_id
  FROM approvals a
 WHERE a.id = e.approval_id
   AND e.identity_id IS NULL;

-- Every execution has a requester, async or not. Enforcing it globally rather
-- than only for async rows removes a conditional CHECK and lets the read
-- endpoints derive authz without joining `approvals`.
ALTER TABLE executions
    ALTER COLUMN identity_id SET NOT NULL;

ALTER TABLE executions
    ADD CONSTRAINT executions_has_origin
        CHECK (approval_id IS NOT NULL OR request IS NOT NULL),
    ADD CONSTRAINT executions_attempts_nonneg
        CHECK (attempts >= 0);

-- The at-most-one-execution-per-approval invariant becomes partial. Postgres
-- would tolerate many NULLs regardless (unique indexes are NULLS DISTINCT by
-- default), but there is no reason to index a column half the table no longer
-- uses, and being explicit forecloses a future NULLS NOT DISTINCT foot-gun.
DROP INDEX idx_executions_approval_id;
CREATE UNIQUE INDEX idx_executions_approval_id
    ON executions (approval_id)
    WHERE approval_id IS NOT NULL;

-- Claim: the worker takes the oldest queued async rows. `expires_at > now()`
-- cannot live in the predicate (now() is not IMMUTABLE) and does not need to —
-- this is scanned in created_at order over a queue measured in tens of rows.
CREATE INDEX idx_executions_async_queue
    ON executions (created_at)
    WHERE status = 'pending' AND request IS NOT NULL;

-- Reclaim + wall-clock sweeps. Bounded above by (replicas x worker
-- concurrency) rows globally, so this stays tiny and hot.
CREATE INDEX idx_executions_async_lease
    ON executions (lease_expires_at)
    WHERE status = 'executing' AND request IS NOT NULL;

-- "My executions" listing.
CREATE INDEX idx_executions_identity_recent
    ON executions (org_id, identity_id, created_at DESC);

COMMENT ON COLUMN executions.request IS
    'Credential-free stored call payload, same shape as approvals.replay_payload. NOT NULL marks this row as worker-run (async).';
COMMENT ON COLUMN executions.lease_expires_at IS
    'While status=executing, the instant after which the claiming worker is presumed dead and the row may be reclaimed. Renewed by heartbeat.';
COMMENT ON COLUMN executions.attempts IS
    'Attempts that ended by losing their lease. Incremented only by the reclaim sweep, never by the claim.';
COMMENT ON COLUMN executions.cancel_requested IS
    'Cooperative cancel. Stops Overslash waiting on the upstream; does not cancel the upstream operation itself.';

-- Whether a gated call should run async once approved.
--
-- RESERVED: nothing reads this yet. Gated async is not in the first cut, so an
-- approved call runs synchronously regardless of what the caller asked for.
-- The column ships now because the shape is settled and adding it later means a
-- second migration for one default-valued column.
--
-- A column rather than a field inside `replay_payload` because the resolve
-- auto-call branch and POST /v1/approvals/{id}/call must both branch on
-- async-ness BEFORE parsing the payload, and the payload has three different
-- shapes. One read, no shape-sniffing.
ALTER TABLE approvals
    ADD COLUMN execution_mode TEXT NOT NULL DEFAULT 'sync'
        CHECK (execution_mode IN ('sync', 'async'));
