-- Secret requests: a one-shot, signed-URL request for a user to provide
-- a secret value out-of-band (no login). The accompanying JWT in the URL
-- is what authenticates the public page; this row is the server-side
-- record that scopes the request to a single secret slot on a single
-- identity, enforces single-use, and tracks expiry.
CREATE TABLE secret_requests (
    id              TEXT PRIMARY KEY,                            -- "req_<uuid-no-dashes>"
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    secret_name     TEXT NOT NULL,
    requested_by    UUID NOT NULL REFERENCES identities(id),
    reason          TEXT,
    token_hash      BYTEA NOT NULL,                              -- SHA-256(token), single-use binding
    expires_at      TIMESTAMPTZ NOT NULL,
    fulfilled_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_secret_requests_org ON secret_requests(org_id);
CREATE INDEX idx_secret_requests_pending
    ON secret_requests(expires_at)
    WHERE fulfilled_at IS NULL;
