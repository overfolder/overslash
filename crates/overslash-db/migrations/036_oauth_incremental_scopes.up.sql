-- Google supports incremental authorization via `include_granted_scopes=true`.
-- Setting it unconditionally is idempotent and matches Google's own guidance:
-- the upgrade-scopes flow re-authorizes with the union of old + new scopes, and
-- Google suppresses the consent screen for scopes the user has already granted.
-- `extra_auth_params` is appended verbatim to every auth URL by
-- `services::oauth::build_auth_url`, so this change is wire-complete on its own.
UPDATE oauth_providers
SET extra_auth_params = extra_auth_params || '{"include_granted_scopes": "true"}'::jsonb
WHERE key = 'google';
