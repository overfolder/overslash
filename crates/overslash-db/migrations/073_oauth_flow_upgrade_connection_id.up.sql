-- Persist the in-flight upgrade target on the flow row so the OAuth callback
-- can read it back from the DB instead of carrying it in a state segment.
-- When NULL the callback mints a new connection; when set, it updates that
-- connection in place (incremental scope upgrade).
--
-- No FK to `connections` because the referenced connection may legitimately
-- be deleted between flow mint and callback — the column is a flow-control
-- hint, not a constraint.

ALTER TABLE oauth_connection_flows
    ADD COLUMN upgrade_connection_id UUID;
