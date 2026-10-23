ALTER TABLE user_sessions
    DROP CONSTRAINT IF EXISTS user_sessions_idp_has_provider,
    DROP COLUMN IF EXISTS idp_acr,
    DROP COLUMN IF EXISTS idp_amr,
    DROP COLUMN IF EXISTS authenticated_at,
    DROP COLUMN IF EXISTS auth_provider,
    DROP COLUMN IF EXISTS auth_method;
