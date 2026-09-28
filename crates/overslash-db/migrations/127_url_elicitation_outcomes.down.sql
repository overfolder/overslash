ALTER TABLE secret_requests DROP COLUMN IF EXISTS declined_at;
ALTER TABLE oauth_connection_flows DROP COLUMN IF EXISTS failure;
