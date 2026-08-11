-- Materialize the actor's name (and their owning user's) onto the audit row,
-- and rebuild the table's indexes around the query the dashboard actually runs.
--
-- The names are denormalized for two reasons, and the second is the one that
-- forced the change:
--
--   1. An audit row should record who acted under the name they had at the
--      time. Reading the name through a live join renames history. See D59.
--   2. `q` searched the *joined* identity name, and a free-text predicate that
--      reaches outside audit_log forecloses every indexing strategy on it: the
--      planner cannot use a trigram index for an OR spanning two tables. A term
--      matching nothing therefore walked the org's entire history — 2.5 s on
--      400k rows, of which ~1.7 s was the per-row identity join alone.
--
-- Both columns stay NULL when `identity_id` is NULL or the identity has since
-- been hard-deleted (`ON DELETE SET NULL`), which is what the LEFT JOIN they
-- replace did — except that now a deleted identity's name survives on the rows
-- it wrote, instead of vanishing from the log entirely.

ALTER TABLE audit_log ADD COLUMN actor_name TEXT;
ALTER TABLE audit_log ADD COLUMN owner_user_name TEXT;

COMMENT ON COLUMN audit_log.actor_name IS
  'Name of identity_id as of write time. Historical by design (D59) — the row records the name the actor had when they acted, not their current one.';
COMMENT ON COLUMN audit_log.owner_user_name IS
  'Name of the root user of the actor''s identity chain, as of write time. Root, not direct parent: a sub-agent resolves to the human at the top, matching the audit table''s User column.';

-- Backfill: actor.
UPDATE audit_log a SET actor_name = i.name
  FROM identities i
 WHERE i.id = a.identity_id AND i.org_id = a.org_id;

-- Backfill: root user of each actor's chain. Recursive because a sub-agent is
-- two hops from its human; the depth guard is a cycle backstop, `owner_id`
-- being an application-maintained pointer rather than a constrained tree.
WITH RECURSIVE chain AS (
    SELECT id AS leaf_id, id, org_id, owner_id, kind, name, 1 AS depth
      FROM identities
    UNION ALL
    SELECT c.leaf_id, i.id, i.org_id, i.owner_id, i.kind, i.name, c.depth + 1
      FROM identities i
      JOIN chain c ON i.id = c.owner_id AND i.org_id = c.org_id
     WHERE c.depth < 10
),
root_user AS (
    SELECT DISTINCT ON (leaf_id) leaf_id, name
      FROM chain
     WHERE kind = 'user'
     ORDER BY leaf_id, depth DESC
)
UPDATE audit_log a SET owner_user_name = r.name
  FROM root_user r
 WHERE r.leaf_id = a.identity_id;

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

-- Keyset pagination needs a deterministic total order, and rows written in one
-- transaction share `now()` — so `id` joins the sort key, and the index that
-- already drove every query is widened to keep serving it without a sort node.
-- Replaces `idx_audit_log_org`; not an addition.
CREATE INDEX idx_audit_log_org_created_id ON audit_log (org_id, created_at DESC, id DESC);
DROP INDEX idx_audit_log_org;

-- Sparse equality filters. `docs/design/audit-log.md` listed composite indexes
-- as a non-goal ("premature; add when needed"); a sparse `action =` walking the
-- whole org history at 400k rows is the "when needed".
CREATE INDEX idx_audit_log_org_action ON audit_log (org_id, action, created_at DESC);
CREATE INDEX idx_audit_log_org_resource_type ON audit_log (org_id, resource_type, created_at DESC);

-- Free text. Guarded like migration 037's pgvector: a deployment without
-- pg_trgm still migrates and still searches, it just keeps the sequential
-- filter it has today. The expression matches the pruning conjunct in
-- `query_filtered` verbatim — an expression index is only used when the query
-- spells the expression the same way.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_trgm') THEN
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
        CREATE INDEX idx_audit_log_search_trgm ON audit_log USING GIN (
            (action || ' ' || COALESCE(description, '') || ' ' || COALESCE(actor_name, ''))
            gin_trgm_ops
        );
    ELSE
        RAISE NOTICE 'pg_trgm not available; skipping the audit search index (free-text search falls back to a sequential filter)';
    END IF;
END $$;

-- Two indexes that earn nothing, both measured in #533. Dropped here rather
-- than left to rot: audit_log is the hottest insert path in the system, and an
-- unused index is pure write amplification.
--
-- `idx_audit_log_tags` (GIN): `tags @>` appears in exactly one query — the
-- dashboard's — and the planner never picks the GIN for it, because the ordered
-- index can stop at LIMIT 50 where a bitmap scan must first sort the whole
-- match set.
DROP INDEX idx_audit_log_tags;
-- `idx_audit_log_impersonated_by`: dead. `impersonated_by_identity_id` appears
-- only in SELECT lists and INSERTs, never in a WHERE, anywhere in the tree.
DROP INDEX idx_audit_log_impersonated_by;
