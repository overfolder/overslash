-- Org-level opt-in for persisting upstream response bodies on
-- action.executed audit rows. 'off' (default) stores nothing,
-- 'errors_only' stores bodies when the normalized detail.is_error flag
-- is true, 'all' stores every captured body.
ALTER TABLE orgs
    ADD COLUMN audit_response_body_mode TEXT NOT NULL DEFAULT 'off'
        CHECK (audit_response_body_mode IN ('off', 'errors_only', 'all'));
