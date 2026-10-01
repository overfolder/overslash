-- Staged uploads: bytes the gateway itself holds, briefly, for an HTTP action
-- that carries a file inline — an email attachment sent through the stateless
-- Mailbox Gateway (overfwd), which has nowhere of its own to put them.
--
-- The upload capability mirrors upload_tokens (116): mint, then one anonymous
-- push to POST /v1/uploads/{token}, single-use. What differs is where the bytes
-- land. An upload_tokens row streams them into the *service's* storage and
-- hands back its reference; a staged row keeps them *here*, encrypted, and the
-- action that later names `upload_id` has them inlined into its body at send
-- time. The approval and replay payload only ever carry the descriptor
-- (filename, type, size, digest), never the bytes.
--
-- A row is written at MINT, before any bytes exist, so that the declared size
-- counts against the quota immediately. Otherwise a caller could mint any
-- number of tokens under the quota and redeem them all at once.
CREATE TABLE staged_uploads (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Who minted it. Quotas and forced eviction are both per identity: an agent
    -- can only ever evict what it staged itself.
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    -- The minter's ceiling user. A reference resolves for any identity under
    -- the same user, so a sub-agent can send what its parent staged, and for
    -- nobody outside that tree.
    owner_user_id       UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    -- sha256(raw_token), as everywhere else a secret is at rest here. Cleared
    -- by the claim, which is what makes the token single-use.
    token_hash          BYTEA UNIQUE,
    -- pending: minted, no bytes yet · uploading: claimed, bytes in flight ·
    -- ready: stored and referenceable.
    status              TEXT NOT NULL DEFAULT 'pending',
    -- Fixed at mint. The redeemer contributes bytes and nothing else, same
    -- invariant as D76: a filename chosen at push time could get `notes.txt`
    -- approved and deliver `payroll.xlsx`.
    filename            TEXT NOT NULL,
    content_type        TEXT NOT NULL,
    -- Required, unlike upload_tokens: the reservation is what the quota counts,
    -- and the meter cuts the push the moment it goes past it.
    declared_size_bytes BIGINT NOT NULL CHECK (declared_size_bytes > 0),
    declared_sha256     TEXT,
    -- Measured while the bytes streamed in. Set with status = 'ready'.
    size_bytes          BIGINT,
    sha256              TEXT,
    -- AES-256-GCM [version | nonce | ct+tag], the same keyring as secrets and
    -- call_results. Encrypted because we do not choose the contents: this is a
    -- user's attachment, and the neighbours holding user payloads at rest are
    -- all encrypted.
    body_ciphertext     BYTEA,
    -- Set when a pending approval (or a queued async call) names this upload,
    -- to that approval's expiry. Forced eviction skips a pinned row, and the
    -- sweeper keeps it past its own TTL, so an attachment cannot vanish from
    -- under a send a human is still reviewing.
    pinned_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- For a pending row this is the token's expiry; redemption moves it to the
    -- staged TTL.
    expires_at          TIMESTAMPTZ NOT NULL,
    redeemed_at         TIMESTAMPTZ,
    CONSTRAINT staged_uploads_status_check
        CHECK (status IN ('pending', 'uploading', 'ready')),
    -- A row is referenceable exactly when its bytes are here.
    CONSTRAINT staged_uploads_ready_has_bytes
        CHECK ((status = 'ready') = (body_ciphertext IS NOT NULL
                                      AND size_bytes IS NOT NULL
                                      AND sha256 IS NOT NULL))
);

-- Quota and eviction scan one identity's rows oldest-first; the org quota scans
-- the org's.
CREATE INDEX staged_uploads_identity_idx ON staged_uploads (identity_id, created_at);
CREATE INDEX staged_uploads_org_idx ON staged_uploads (org_id);
CREATE INDEX staged_uploads_expiry_idx ON staged_uploads (expires_at);

COMMENT ON TABLE staged_uploads IS
    'Bytes the gateway holds briefly so an HTTP action can carry them inline '
    '(x-overslash-staged-upload). Minted by overslash:upload_file, pushed to '
    'POST /v1/uploads/{token}, inlined at send time. Quota-bounded and TTL''d.';
COMMENT ON COLUMN staged_uploads.body_ciphertext IS
    'AES-256-GCM [version|nonce|ct+tag] over the raw bytes. NULL until redeemed.';
COMMENT ON COLUMN staged_uploads.pinned_until IS
    'Referenced by a pending approval or queued call until this time: not evictable, '
    'not swept.';
