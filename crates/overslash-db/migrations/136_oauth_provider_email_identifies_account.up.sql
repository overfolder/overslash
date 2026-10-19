-- Whether a provider's account email names exactly one account it can grant.
--
-- The OAuth callback re-authorizes an existing connection in place, instead of
-- inserting a duplicate, when the same user connects the same provider through
-- the same OAuth client with the same `account_email`. That is only sound where
-- the email identifies the grant. Where one login reaches several separately
-- authorized tenants, the same email can come back for a *different* grant, and
-- matching on it would overwrite the first tenant's tokens with the second's:
--
--   google      true   One Google account per address.
--   github      true   One GitHub user per address (or per synthesized
--                      `{login}@users.noreply.github.com`).
--   linkedin    true   One member per address.
--   spotify     true   One user per address.
--   eventbrite  true   One user per address.
--   x           true   X returns no email today; harmless either way.
--   microsoft   false  `/me` in a guest tenant can report the home `mail`, and
--                      each tenant is a separate grant.
--   slack       false  One email, one grant per workspace.
--   hubspot     false  One login, one grant per portal.
--   notion      false  One login, one grant per workspace.
--
-- Defaults to false, so custom (OIDC-discovered) providers always get a new
-- connection per connect: a duplicate row is recoverable, overwritten tokens
-- are not.

ALTER TABLE oauth_providers
    ADD COLUMN email_identifies_account BOOLEAN NOT NULL DEFAULT false;

UPDATE oauth_providers SET email_identifies_account = true
    WHERE key IN ('google', 'github', 'linkedin', 'spotify', 'eventbrite', 'x');
