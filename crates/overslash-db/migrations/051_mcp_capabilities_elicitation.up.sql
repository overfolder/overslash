-- MCP capability capture + per-binding elicitation toggle + SSE elicitation
-- session state. Backs the "MCP Connection" section on the Agent detail page
-- and the form-mode elicitation approval flow ("Flow A" in
-- docs/design/mcp-elicitation-approvals.md).

ALTER TABLE oauth_mcp_clients
    ADD COLUMN capabilities      JSONB,
    ADD COLUMN client_info       JSONB,
    ADD COLUMN protocol_version  TEXT,
    ADD COLUMN last_session_id   UUID;

ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN elicitation_enabled BOOLEAN NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------------
-- pending_mcp_elicitations
-- ---------------------------------------------------------------------------
-- One row per in-flight tools/call that's been promoted to an SSE elicitation.
-- The originator pod inserts the row and polls for `status` to flip to
-- 'completed' / 'failed' / 'cancelled' (the receiver pod — which may or may
-- not be the same — drives resolve+call and writes `final_response`). See
-- crates/overslash-api/src/services/mcp_session.rs.
CREATE TABLE pending_mcp_elicitations (
    elicit_id          TEXT        PRIMARY KEY,
    session_id         UUID        NOT NULL,
    agent_identity_id  UUID        NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    approval_id        UUID        NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
    status             TEXT        NOT NULL DEFAULT 'pending',
    final_response     JSONB,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at       TIMESTAMPTZ
);

-- Receiver pods re-mint resolver/agent JWTs from the binding looked up by
-- `agent_identity_id`, so no bearer is stored here. This avoids leaking a
-- token into the DB and naturally cancels the row when the binding is
-- removed (the FK cascade on `agent_identity_id`).

CREATE INDEX idx_pending_mcp_elicit_session
    ON pending_mcp_elicitations (session_id);

CREATE INDEX idx_pending_mcp_elicit_status
    ON pending_mcp_elicitations (status, created_at);
