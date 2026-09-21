DELETE FROM oauth_providers WHERE key = 'figma';
ALTER TABLE oauth_providers DROP COLUMN refresh_endpoint;
