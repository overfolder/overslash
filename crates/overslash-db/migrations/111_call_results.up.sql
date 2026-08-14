-- Stored call results: the bytes an agent already paid for, kept long enough
-- to be delivered a second way.
--
-- An agent calling over MCP gets the compact rendering (`verbose: false`), which
-- crops the body to ~8 KB. Until now the only way past that crop was to issue a
-- *new* call — `verbose: true`, or `deliver: "url"`. Both re-run the upstream.
-- For a 30-second analytics query that is the same expensive work twice, to
-- recover bytes the gateway had in hand and threw away.
--
-- A row here is those bytes: the full `ActionResult` of a call that was
-- truncated on the way out, encrypted at rest, reachable only through a
-- `download_tokens` row that points at it. Nothing about the authorization
-- decision changes — the call was permission-checked and audited when it ran.
-- This defers *rendering*, exactly as migration 107 defers *byte delivery*.
CREATE TABLE call_results (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Who made the call. Only tokens minted for this identity ever point here,
    -- and the identity is re-checked at fetch time via the download_tokens row.
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    service_key     TEXT,
    action_key      TEXT,
    -- The serialized `ActionResult` — status_code, headers, body, duration_ms,
    -- filtered_body — encrypted with the same AES-256-GCM keyring as
    -- secret_versions and mcp_upstream_tokens: [version | nonce | ct+tag].
    --
    -- Encrypted because we do not choose the contents. An upstream is free to
    -- return a refresh token in a JSON field, and response headers (Set-Cookie,
    -- echoed Authorization) ride inside the same blob. Every neighbour holding
    -- upstream payloads at rest is encrypted; the one that isn't
    -- (audit_logs.detail.response) is 64 KB-capped *and* off by default.
    --
    -- BYTEA, not JSONB, is the deliberate consequence: nothing may query inside
    -- a stored call output. Audit capture is the consented path for that.
    body_ciphertext BYTEA NOT NULL,
    -- Cleartext descriptor fields — only what the download Descriptor needs, so
    -- serving a token never has to decrypt just to build response headers.
    status_code     INTEGER NOT NULL,
    content_type    TEXT,
    body_bytes      BIGINT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX call_results_expiry_idx ON call_results (expires_at);

COMMENT ON TABLE call_results IS
    'Full ActionResult of a call whose compact rendering was truncated, stored so '
    'the same bytes can be delivered again without re-running upstream. Written by '
    'POST /v1/actions/call when verbose=false truncated; read via GET /v1/downloads/{token}.';
COMMENT ON COLUMN call_results.body_ciphertext IS
    'AES-256-GCM [version|nonce|ct+tag] over the serialized ActionResult. Response '
    'headers live inside the blob, which is why the whole thing is encrypted.';
COMMENT ON COLUMN call_results.body_bytes IS
    'Plaintext size, for the download Descriptor. Bounded by call_result_max_bytes.';

-- A download token now has two possible sources of bytes: replay the stored
-- request (migration 107), or serve a stored result. Exactly one, enforced here
-- rather than in the handler — the redemption path branches on this column, and
-- a row that satisfied neither (or both) would be an unreachable state the
-- handler would have to invent an answer for.
ALTER TABLE download_tokens
    ADD COLUMN call_result_id UUID REFERENCES call_results(id) ON DELETE CASCADE;

ALTER TABLE download_tokens
    ALTER COLUMN request DROP NOT NULL;

ALTER TABLE download_tokens
    ADD CONSTRAINT download_tokens_one_byte_source
    CHECK (num_nonnulls(request, call_result_id) = 1);

COMMENT ON COLUMN download_tokens.call_result_id IS
    'When set, redemption serves these stored bytes instead of replaying `request`. '
    'Mutually exclusive with `request` (download_tokens_one_byte_source).';
