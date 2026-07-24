-- Per-scheme credential bindings: {securityScheme key -> secret NAME in the
-- org vault}. Values are vault references by construction — never secret
-- values (rule: secrets never leave the vault). An empty map falls back to
-- the legacy scalar `secret_name` for the template's sole instance-source
-- scheme, so existing instances behave identically. `secret_name` stays for
-- one release (rolling deploys: old binaries still read/write it) and is
-- dropped in a follow-up migration.
ALTER TABLE service_instances ADD COLUMN credentials jsonb NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN service_instances.credentials IS
  'Per-scheme secret bindings: {securityScheme key -> secret NAME in the org vault}. Names only, never values. Empty map falls back to legacy secret_name for the sole instance-source scheme.';
