-- Per-(agent × MCP client) `auto_call_on_approve` toggle (default TRUE) and
-- `executions.result_viewed_at` to track whether the requesting agent has
-- pulled the upstream result for an auto-executed call. Together these power
-- the "called but output unread" pending-calls state surfaced on the
-- /approvals dashboard.

ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN auto_call_on_approve BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE executions
    ADD COLUMN result_viewed_at TIMESTAMPTZ;

-- Partial index keyed on the unread terminal states so the dashboard's
-- pending-calls listing stays fast as the executions table grows.
CREATE INDEX idx_executions_unread
    ON executions (org_id, completed_at)
    WHERE status IN ('executed', 'failed') AND result_viewed_at IS NULL;
