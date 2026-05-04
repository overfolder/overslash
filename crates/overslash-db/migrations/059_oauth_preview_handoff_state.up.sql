-- Persist OAuth login auth-state on the `oauth_preview_origins` row so the
-- preview-deployment handoff can survive Google's round-trip without relying
-- on the `oss_auth_*` cookies — those would carry `Domain=.app.dev.overslash.com`
-- and the browser rejects them when login starts on a `*.vercel.app` host
-- (no shared parent), causing the callback to 400 with
-- "missing auth nonce cookie" before the preview branch ever runs.
--
-- `nonce` is `NOT NULL` going forward. The `DEFAULT ''` is solely to satisfy
-- that constraint when this `ALTER TABLE` rewrites any 057-era rows present
-- at deploy time — it does NOT keep those in-flight logins working: the
-- callback compares the row's nonce against the state-param nonce, and an
-- empty stored nonce will never match a real UUID. Pre-058 in-flight
-- logins will have to retry; the row's 10-min TTL bounds the window. New
-- code never inserts an empty nonce, so once the deploy finishes the
-- column behaves as a plain `NOT NULL TEXT`.

ALTER TABLE oauth_preview_origins
    ADD COLUMN nonce         TEXT NOT NULL DEFAULT '',
    ADD COLUMN pkce_verifier TEXT,
    ADD COLUMN org_slug      TEXT,
    ADD COLUMN next_path     TEXT;
