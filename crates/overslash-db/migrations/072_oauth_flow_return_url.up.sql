-- Optional tenant-supplied redirect target read by the OAuth callback after
-- token exchange completes. When present (and the host appears in the
-- operator's allow-list at callback time) the callback returns a 302 to
-- `{return_url}?status=…&connection_id=…&provider=…` instead of the default
-- JSON. Backward-compatible: NULL leaves the existing JSON response path
-- untouched.

ALTER TABLE oauth_connection_flows
    ADD COLUMN return_url TEXT;
