-- Passwordless email magic-link login. One row per requested sign-in link.
--
-- We store only the SHA-256 hash of the raw token, never the token itself —
-- the raw value lives solely in the emailed URL, so a DB read can't be
-- replayed into a login. (Contrast `email_unsubscribe_tokens`, which stores a
-- bare UUID: that token's blast radius is an unsubscribe, this one's is a full
-- session, so it gets hashing + a short TTL + single-use.)
--
-- `email` is the normalized (trimmed + lowercased) address the link was minted
-- for; verification provisions / loads the Overslash-backed user keyed on
-- (overslash_idp_provider='email', overslash_idp_subject=email). `next_path` is
-- the already-sanitized post-login redirect, carried across the email bounce.
-- Single-use is enforced by stamping `redeemed_at` in the same UPDATE that
-- claims the row (see repos/magic_link_token.rs::consume).
CREATE TABLE magic_link_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  BYTEA NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    next_path   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ
);

-- Supports a future sweep of expired/spent rows; not on the verification hot
-- path (that looks up by the UNIQUE token_hash).
CREATE INDEX idx_magic_link_tokens_expires ON magic_link_tokens (expires_at);
