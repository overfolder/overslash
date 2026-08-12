-- Promote the effective risk of a gated call out of the `tags` array and onto
-- a column of its own.
--
-- The value already exists: `tags::call_tags` pushes `risk:read|write|delete`
-- unconditionally on every action and approval event, and `?tag=risk:write`
-- already works. Three things it cannot do from inside a text[]:
--
--   1. Be indexed. Migration 110 dropped `idx_audit_log_tags` after measuring
--      that the planner never chooses a GIN for `tags @>` here — the ordered
--      index stops at LIMIT 50 where a bitmap scan must first sort the whole
--      match set. A column takes the `(org_id, <col>, created_at DESC)` shape
--      that same migration measured actually working (sparse `action =`:
--      48.8 ms -> 0.62 ms).
--   2. Be rendered. The audit table cannot show a column that only exists once
--      a row is expanded and its 20-odd tags are scanned by eye.
--   3. Be asked an *ordered* question. `risk >= write` ("write or worse") has
--      no meaning against a set-containment operator.
--
-- Nullable, and deliberately so: risk is minted on the gated action/approval
-- path only. The ~135 control-plane call sites (secret.put, identity.deleted,
-- org.settings.*) write `tags = '{}'` today and NULL here — the same boundary
-- the tags column already draws, not a new one.

ALTER TABLE audit_log ADD COLUMN risk TEXT
    CHECK (risk IS NULL OR risk IN ('read', 'write', 'delete'));

COMMENT ON COLUMN audit_log.risk IS
  'Effective risk of a gated call (declared risk merged with the SQL classifier''s floor), promoted out of the risk: metadata tag so it can be indexed, rendered and range-queried. NULL for events outside the action/approval path. Searchable via GET /v1/audit?risk= and ?risk_min=.';

-- Backfill from the tag, which has carried exactly this value since migration
-- 104. Ordered most-severe-first: a row carries exactly one `risk:` tag, but
-- the CASE should not depend on that to stay correct.
--
-- Rows written before 104 have no tags and keep NULL. That is honest — the
-- value was never recorded — and matches how 110 left `actor_name` NULL for
-- rows whose identity had already been hard-deleted.
UPDATE audit_log SET risk = CASE
        WHEN tags @> ARRAY['risk:delete'] THEN 'delete'
        WHEN tags @> ARRAY['risk:write']  THEN 'write'
        WHEN tags @> ARRAY['risk:read']   THEN 'read'
    END
 WHERE tags <> '{}';

-- Partial: on a mature org the overwhelming majority of rows are control-plane
-- events with risk IS NULL, and no query ever asks for them by risk. Keeping
-- them out holds the index to the action path it serves, and it is sound for
-- every query that reaches the conjunct — `risk = ANY(...)` over non-NULL
-- values can never want the excluded rows.
--
-- Measured on 50k rows (45k unclassified, 4.9k read, 100 delete):
--
--   * sparse (`risk = delete`) — this index, 0.09 ms, against 4.69 ms for the
--     sequential scan without it. That case is the whole justification.
--   * dense (`risk = read`) — the planner keeps idx_audit_log_org_created_id
--     and stops at LIMIT 50, which is the better plan and is left alone.
--
-- `created_at DESC` trails the key so the sort input arrives nearly ordered
-- (a scalar `risk =` gets an Incremental Sort that stops early). It does *not*
-- eliminate the sort node: `= ANY` is a scalar-array op, so Postgres cannot
-- prove the multi-rung scan is ordered. The win is that only matched rows are
-- sorted, not the org's history.
CREATE INDEX idx_audit_log_org_risk ON audit_log (org_id, risk, created_at DESC)
    WHERE risk IS NOT NULL;
