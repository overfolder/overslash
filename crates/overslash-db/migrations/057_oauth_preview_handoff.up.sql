-- Vercel preview-deployment OAuth handoff. Bridges the cookie-domain gap
-- between `*.vercel.app` (where browser-side previews live) and the API on
-- `api.dev.overslash.com`: the preview origin is captured in
-- `oauth_preview_origins` at login start, then a one-time-use `oauth_handoff_codes`
-- row is minted at OAuth callback so the API can set `oss_session` on the
-- preview's host-only response without sharing a parent domain.
--
-- Both tables are intentionally short-lived (origin = 10 min, code = 60 s).
-- Only ever populated when `PREVIEW_ORIGIN_ALLOWLIST` is set on the API; on
-- prod they stay empty.

CREATE TABLE oauth_preview_origins (
    preview_id UUID PRIMARY KEY,
    origin     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oauth_preview_origins_expires
    ON oauth_preview_origins (expires_at);

CREATE TABLE oauth_handoff_codes (
    code        TEXT PRIMARY KEY,
    jwt         TEXT NOT NULL,
    origin      TEXT NOT NULL,
    next_path   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX idx_oauth_handoff_codes_expires
    ON oauth_handoff_codes (expires_at);
