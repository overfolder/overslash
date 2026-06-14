ALTER TABLE orgs
    ADD COLUMN oauth_redirect_url text NOT NULL DEFAULT '';

ALTER TABLE oauth_connection_flows
    ADD COLUMN redirect_uri text;

ALTER TABLE connections
    DROP COLUMN integration_managed;
