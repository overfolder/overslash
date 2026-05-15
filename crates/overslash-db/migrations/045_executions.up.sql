-- Two-stage approval flow: approving an action no longer runs it. A pending
-- execution row is created at /resolve time and must be triggered via
-- POST /v1/approvals/{id}/execute (by the requester agent or the resolver user).
-- Pending executions expire 15 minutes after creation.

CREATE TABLE executions (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_id       UUID NOT NULL REFERENCES approvals(id) ON DELETE CASCADE,
    org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    status            TEXT NOT NULL CHECK (status IN (
                          'pending',
                          'executing',
                          'executed',
                          'failed',
                          'cancelled',
                          'expired'
                      )),
    remember          BOOLEAN NOT NULL DEFAULT false,
    remember_keys     TEXT[],
    remember_rule_ttl TIMESTAMPTZ,
    result            JSONB,
    error             TEXT,
    triggered_by      TEXT,
    started_at        TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One execution row per approval; cancel/expire/fail is terminal.
CREATE UNIQUE INDEX idx_executions_approval_id ON executions(approval_id);

-- Lookup for the dashboard's "pending executions" panel.
CREATE INDEX idx_executions_org_status_expires
    ON executions(org_id, status, expires_at);

-- Sweeper lookup for the 15-minute pending timeout.
CREATE INDEX idx_executions_pending_expiry
    ON executions(expires_at)
    WHERE status = 'pending';
