ALTER TABLE orgs
    DROP COLUMN oauth_redirect_url;
ALTER TABLE orgs
    ADD COLUMN oauth_callback_allowed_hosts TEXT NOT NULL DEFAULT '';
