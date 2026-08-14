-- Deferred downloads: capability tokens for out-of-band byte delivery.
--
-- Overslash could return bytes exactly one way before this: `prefer_stream:
-- true` on `POST /v1/actions/call`, which is a REST-DTO field. MCP callers
-- cannot set it, and the buffered path they *do* reach runs every response
-- through `String::from_utf8_lossy` and then crops strings at 200 chars. So an
-- agent talking to Overslash over MCP had no way to obtain a file at all, and
-- an agent that wants a 40 MB video has no business putting it in a context
-- window even if it could.
--
-- A row here is a promise: "these bytes are fetchable at this URL, by whoever
-- holds the token, until expires_at". The action call itself is still fully
-- permission-checked and audited at mint time; this table only defers *byte
-- delivery*, never the authorization decision. Same shape as an S3 presigned
-- URL, and the same reason — the fetcher (curl in a sandboxed VM, a browser)
-- is not the caller and holds none of the caller's credentials.
CREATE TABLE download_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- sha256(raw_token). The raw token exists only in the minted URL, exactly
    -- as magic_link_tokens and api_keys treat their secrets.
    token_hash          BYTEA NOT NULL UNIQUE,
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Who the fetch acts as. Re-checked at fetch time, so revoking an
    -- identity's permission invalidates outstanding tokens without a sweep.
    identity_id         UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    -- Which binding to re-resolve credentials against. Nullable because a
    -- Mode A raw-HTTP call has no instance behind it.
    service_instance_id UUID REFERENCES service_instances(id) ON DELETE CASCADE,
    service_key         TEXT,
    action_key          TEXT,
    -- The replayable upstream request: {method, url, headers, body}. It names
    -- secrets (as SecretRef) rather than carrying them; a call that would put a
    -- credential in a caller-supplied header is rejected at mint time rather
    -- than written here. See credential_ref for why.
    request             JSONB NOT NULL,
    -- How to re-mint the credential at fetch time, NOT the credential itself.
    -- Storing the resolved Authorization header here would put a second copy
    -- of a live secret at rest, outside the vault, with a lifetime we don't
    -- control. Re-resolving instead means a rotated secret is picked up and a
    -- revoked connection fails closed.
    credential_ref      JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Descriptor metadata, surfaced to the caller at mint time so it can decide
    -- whether to fetch before committing to the bytes.
    mime                TEXT,
    size_bytes          BIGINT,
    filename            TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ,
    use_count           INTEGER NOT NULL DEFAULT 0
);

-- Deliberately multi-use, unlike magic_link_tokens.consume(). The motivating
-- payload is a large video fetched by curl in a sandboxed VM: a dropped
-- connection resumes with a Range request, and `curl -C -` retries on its own.
-- Single-use would turn every transient network blip into an unrecoverable
-- failure. Exposure is bounded by a short TTL instead, and use_count /
-- last_used_at make an abnormally re-fetched token visible.
CREATE INDEX download_tokens_expiry_idx ON download_tokens (expires_at);

COMMENT ON TABLE download_tokens IS
    'Capability tokens for deferred (out-of-band) byte delivery. Minted by '
    'POST /v1/actions/call with deliver:"url", redeemed by GET /v1/downloads/{token}.';
COMMENT ON COLUMN download_tokens.token_hash IS
    'sha256 of the raw token; the raw value exists only in the minted URL.';
COMMENT ON COLUMN download_tokens.credential_ref IS
    'How to re-resolve the upstream credential at fetch time. Never the credential itself.';
COMMENT ON COLUMN download_tokens.request IS
    'Replayable upstream request {method,url,headers,body}. Names secrets rather than '
    'carrying them; inline credential headers are rejected at mint time.';
