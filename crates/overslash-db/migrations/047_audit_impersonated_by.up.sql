ALTER TABLE audit_log
    ADD COLUMN impersonated_by_identity_id UUID
        REFERENCES identities(id) ON DELETE SET NULL;

CREATE INDEX idx_audit_log_impersonated_by
    ON audit_log(org_id, impersonated_by_identity_id)
    WHERE impersonated_by_identity_id IS NOT NULL;
