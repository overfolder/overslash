ALTER TABLE oauth_preview_origins
    DROP COLUMN IF EXISTS next_path,
    DROP COLUMN IF EXISTS org_slug,
    DROP COLUMN IF EXISTS pkce_verifier,
    DROP COLUMN IF EXISTS nonce;
