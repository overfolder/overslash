-- Proxy uploads: capability tokens for pushing bytes *into* a service, and the
-- ledger of what those bytes turned out to be.
--
-- The inbound mirror of download_tokens (107). An MCP service whose media moves
-- over plain HTTP — bytes never ride a JSON-RPC call in either direction — has
-- a byte route behind the same credential as its tool endpoint. Overslash could
-- fetch from it and could not push to it, so an agent could forward a file
-- someone sent it but could never send a file it made. Originating bytes was
-- out-of-band work for whoever operated the container.
--
-- Handing the agent that host and credential instead is the one thing the vault
-- exists to prevent: these credentials are static and unscoped, so the bearer
-- that authorizes an upload authorizes every write the service has. The token
-- below is the narrower thing that did not otherwise exist.
--
-- A row is a promise in the opposite direction from a download token: "bytes
-- matching this description may be pushed once, by whoever holds the token,
-- until expires_at". The authorization decision is still made and audited at
-- mint time by the ordinary action call; only the bytes are deferred.
CREATE TABLE upload_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- sha256(raw_token), as everywhere else a secret is at rest here.
    token_hash          BYTEA NOT NULL UNIQUE,
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Who the push acts as. Re-checked at redemption, so a deleted identity's
    -- outstanding tokens die with it rather than outliving their principal.
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    service_instance_id UUID REFERENCES service_instances(id) ON DELETE CASCADE,
    service_key         TEXT,
    action_key          TEXT,
    -- The upstream request to make when the bytes arrive: {method, url,
    -- headers, body}. `body` is always null — the bytes are not here, they
    -- arrive at redemption — and secrets are named as SecretRef rather than
    -- carried, exactly as download_tokens.request does.
    request             JSONB NOT NULL,
    -- How to re-mint the credential at redemption, never the credential.
    credential_ref      JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- The declared half: what the caller said it was going to push, fixed at
    -- mint time and therefore the thing a reviewer actually approved.
    --
    -- declared_sha256 is what makes an approval mean something. Without it the
    -- approval authorizes "some bytes, to be chosen later"; with it, exactly
    -- one file, because the redemption hashes the stream and refuses to hand
    -- back a reference when the two disagree.
    declared_sha256     TEXT,
    declared_size_bytes BIGINT,
    declared_mime       TEXT,
    declared_filename   TEXT,
    -- Hard ceiling for this token, already clamped to the deployment's limit.
    max_bytes           BIGINT NOT NULL,
    -- Which query parameter the byte route takes the filename in, from the
    -- template. NULL means the route takes none, and the redemption appends
    -- nothing rather than guessing a name.
    filename_param      TEXT,
    -- The template's `result` jq block, resolved at mint and carried here.
    --
    -- Redemption resolves nothing: it holds a token, not an action key, so it
    -- cannot look the declaration back up — the same constraint that puts
    -- `timeout_ms` and `pagination` on an approval's replay payload rather than
    -- re-deriving them. NULL means the target answers the conventional flat
    -- descriptor and needs no filters.
    result_spec         JSONB,

    -- The stored half: what the upstream actually recorded. Written only on a
    -- successful redemption, so a token whose consumed_at is set while these
    -- are still null is a push that started and did not land — legible in the
    -- table rather than inferred from its absence.
    stored_media_path   TEXT,
    stored_sha256       TEXT,
    stored_size_bytes   BIGINT,
    stored_mime         TEXT,
    stored_filename     TEXT,
    completed_at        TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ
);

-- Single-use, and deliberately the opposite of download_tokens' multi-use rule.
-- Redeeming a download twice re-fetches the same bytes, which is why a resumed
-- `curl -C -` is allowed to; redeeming an upload twice stores two *different*
-- payloads under one authorization, so "what the reviewer approved" would stop
-- having an answer. The claim is an UPDATE guarded on consumed_at IS NULL, so
-- concurrent redemptions cannot both win.
CREATE INDEX upload_tokens_expiry_idx ON upload_tokens (expires_at);

COMMENT ON TABLE upload_tokens IS
    'Single-use capability tokens for pushing bytes into a service. Minted by an '
    'action carrying x-overslash-upload, redeemed by POST /v1/uploads/{token}.';
COMMENT ON COLUMN upload_tokens.token_hash IS
    'sha256 of the raw token; the raw value exists only in the minted URL.';
COMMENT ON COLUMN upload_tokens.declared_sha256 IS
    'Content hash the caller declared at mint time. Verified against the stream during '
    'redemption; a mismatch refuses the descriptor so no later call can reference the bytes.';
COMMENT ON COLUMN upload_tokens.consumed_at IS
    'Set by the claim. A row with consumed_at but no completed_at is a push that started '
    'and did not land.';

-- What the gateway knows about bytes it has moved.
--
-- Both send tools take a media reference — a content-addressed path — so an
-- approval to send a file could only ever show a reviewer the hash. That is a
-- request to approve something unreadable. The gateway sees a full descriptor
-- at exactly two moments (a download tool's result passing through, and an
-- upload redemption completing), and this is where it keeps them so a later
-- approval can say "invoice-march.pdf (application/pdf, 240 KB)" instead.
--
-- Scoped to the instance, not just the org: a content address is only
-- meaningful on the host that stores it, so the same hash on two instances is
-- the same bytes but not the same stored object.
CREATE TABLE media_descriptors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    service_instance_id UUID REFERENCES service_instances(id) ON DELETE CASCADE,
    service_key         TEXT,
    -- The reference as the send tools take it, e.g. `/media/<sha256>`.
    media_path          TEXT NOT NULL,
    sha256              TEXT,
    mime                TEXT,
    size_bytes          BIGINT,
    filename            TEXT,
    -- 'download' (seen passing through a tool result) or 'upload' (pushed
    -- through the gateway). Kept because provenance is the useful thing to show
    -- a reviewer next to a filename someone else chose.
    source              TEXT NOT NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT media_descriptors_source_check CHECK (source IN ('download', 'upload'))
);

-- The lookup key, and the upsert target. NULLS NOT DISTINCT so a Mode A row
-- with no instance still collides with itself rather than accumulating
-- duplicates on every re-observation.
CREATE UNIQUE INDEX media_descriptors_ref_idx
    ON media_descriptors (org_id, service_instance_id, media_path) NULLS NOT DISTINCT;

COMMENT ON TABLE media_descriptors IS
    'What the gateway recorded about bytes it moved, so an approval that references them '
    'can describe them instead of showing a bare content hash. Best-effort: bytes that '
    'never passed through the gateway are simply absent.';
