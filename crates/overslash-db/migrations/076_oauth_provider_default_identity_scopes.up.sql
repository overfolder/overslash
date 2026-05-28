-- Per-provider identity scopes always included on every OAuth flow.
--
-- The OAuth callback calls the provider's `userinfo_endpoint` to label the
-- connection with `account_email`. Google's `oauth2/v3/userinfo` returns 401
-- unless `openid` + `email` were granted, so a Google connection created with
-- only `auth/calendar` lands without an email and shows as `—` on the
-- dashboard. The scopes needed for identity retrieval are provider-specific
-- (OIDC `openid email profile` for Google/Microsoft, `read:user user:email`
-- for GitHub, etc.) and orthogonal to whichever service action the caller
-- wants to invoke, so the right home is the provider row.

ALTER TABLE oauth_providers
    ADD COLUMN default_identity_scopes TEXT[] NOT NULL DEFAULT '{}';

UPDATE oauth_providers SET default_identity_scopes = '{openid,email,profile}'
    WHERE key = 'google';
UPDATE oauth_providers SET default_identity_scopes = '{openid,email,profile}'
    WHERE key = 'microsoft';
UPDATE oauth_providers SET default_identity_scopes = '{read:user,user:email}'
    WHERE key = 'github';
UPDATE oauth_providers SET default_identity_scopes = '{users:read,users:read.email}'
    WHERE key = 'slack';
UPDATE oauth_providers SET default_identity_scopes = '{user-read-email,user-read-private}'
    WHERE key = 'spotify';
