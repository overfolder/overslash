-- Per-instance NON-SECRET configuration: {param name -> scalar value}.
--
-- The counterpart to `credentials` (migration 100). That column holds vault
-- references; this one holds ordinary values that happen to vary per
-- deployment rather than per template — an IMAP host, an API region, a
-- tenant id. Nothing here is a secret and nothing here is encrypted; a
-- secret belongs in the vault and is bound via `credentials`.
--
-- Only params a template explicitly marks `x-overslash-instance-config: true`
-- may be stored, and the API rejects anything else, so this stays a typed,
-- template-declared surface rather than a free-for-all bag.
--
-- This is Core-change #3 from docs/design/email-integration.md, deferred at
-- the time with "interim: prefilled forked templates". Forking a whole
-- template to change a hostname turned out to be the wrong shape: overfwd
-- takes its mailbox host/port as request headers, so `services/email.yaml`
-- could not reach any self-hosted mailbox at all without one fork per
-- deployment.
ALTER TABLE service_instances ADD COLUMN config jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN service_instances.config IS
  'Per-instance non-secret param values: {param name -> scalar}. Only params the template marks x-overslash-instance-config may appear. Never secrets — those are vault references in credentials.';
