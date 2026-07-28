-- System-derived metadata tags on approvals, executions and audit rows.
--
-- The D42 SQL content policy (migration-less, #496) derives a rich fact set
-- for every classified statement — read tables, mutation targets, referenced
-- columns, why a statement classified write — and then throws almost all of
-- it away. The only thing that survived a request was a three-field `sql`
-- block in `audit_log.detail`, and only on the buffered HTTP dispatch fork.
--
-- These columns give those facts a home. A tag is a flat `namespace:value`
-- string minted by Overslash from facts it already computed at request time
-- (`sql:write`, `table:warehouse/orders`, `service:metabase`, `host:…`).
-- Nothing here is caller-supplied, so a tag is always trustworthy — there is
-- no spoofing surface and no need to namespace untrusted input separately.
--
-- text[] rather than jsonb because the whole point is search: `@>` over a GIN
-- index answers "every call that touched warehouse.customers" in one index
-- scan, which is the question an operator actually asks. The structured facts
-- keep their existing home in `audit_log.detail->'sql'` for the detail pane.
--
-- An execution's tags are copied from its approval at insert time rather than
-- re-derived: replay re-executes a stored payload without a second classifier
-- pass, so re-deriving could disagree with what the approver was shown.
ALTER TABLE approvals  ADD COLUMN tags text[] NOT NULL DEFAULT '{}';
ALTER TABLE executions ADD COLUMN tags text[] NOT NULL DEFAULT '{}';
ALTER TABLE audit_log  ADD COLUMN tags text[] NOT NULL DEFAULT '{}';

-- Only the audit log is searchable by tag today, so only it pays for an index.
CREATE INDEX idx_audit_log_tags ON audit_log USING GIN (tags);

COMMENT ON COLUMN approvals.tags IS
  'System-derived `namespace:value` metadata tags describing the gated call (sql:*, table:*, service:*, host:*, risk:*). Never caller-supplied.';
COMMENT ON COLUMN executions.tags IS
  'Copied verbatim from the originating approval at insert time — an execution can never disagree with what its approver saw.';
COMMENT ON COLUMN audit_log.tags IS
  'System-derived `namespace:value` metadata tags. Searchable via GET /v1/audit?tag=. Populated on action/approval events; other events carry an empty array.';
