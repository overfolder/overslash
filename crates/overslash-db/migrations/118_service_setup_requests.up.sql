-- A secret request can now name the service instance and credential slot the
-- value is for, which is what turns a bare "paste a value for `resend_key`"
-- link into a "finish setting up Resend" screen.
--
-- Both columns NULL is the pre-existing shape and stays the default: a plain
-- secret request, minted for a vault name and nothing else. Both set means the
-- fulfilment handler binds `service_instances.credentials[credential_key]` to
-- the secret it just wrote, so the instance goes from credential-less to
-- callable in the same POST.
--
-- Deliberately additive rather than a `credential_requests` table with a kind
-- discriminator (the shape docs/design/agent-credential-provisioning.md
-- proposes): the OAuth half of setup is already carried by `oauth_flows` +
-- `service_instances.connection_id`, so a second table would have exactly one
-- kind in it today.
ALTER TABLE secret_requests
    ADD COLUMN service_instance_id UUID REFERENCES service_instances(id) ON DELETE CASCADE,
    ADD COLUMN credential_key TEXT;

COMMENT ON COLUMN secret_requests.service_instance_id IS
    'Service instance this request is provisioning a credential for. NULL for a plain secret request, which is the pre-118 shape. ON DELETE CASCADE: an outstanding setup link for a deleted instance has nothing left to bind.';
COMMENT ON COLUMN secret_requests.credential_key IS
    'Template securityScheme slot key to bind on fulfilment, validated against the template at mint time. NULL whenever service_instance_id is.';

-- Both or neither: a slot key with no instance names nothing, and an instance
-- with no slot key leaves the fulfilment handler with no binding to make.
ALTER TABLE secret_requests
    ADD CONSTRAINT secret_requests_service_binding_complete
    CHECK ((service_instance_id IS NULL) = (credential_key IS NULL));

-- "Which links are outstanding for this instance?" — asked by the audit trail
-- and by anything reconciling a half-finished setup. Partial, because the
-- column is NULL for every plain secret request.
CREATE INDEX idx_secret_requests_service
    ON secret_requests(service_instance_id)
    WHERE service_instance_id IS NOT NULL;
