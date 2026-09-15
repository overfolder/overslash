DROP INDEX IF EXISTS idx_secret_requests_service;
ALTER TABLE secret_requests
    DROP CONSTRAINT IF EXISTS secret_requests_service_binding_complete;
ALTER TABLE secret_requests
    DROP COLUMN IF EXISTS credential_key,
    DROP COLUMN IF EXISTS service_instance_id;
