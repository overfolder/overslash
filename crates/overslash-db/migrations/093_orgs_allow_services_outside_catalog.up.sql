-- Hard vs. soft enforcement of the curated global-template catalog.
--
-- The `enabled_global_templates` allow-list (see migration 030) already hides
-- curated-out global templates from discovery surfaces when
-- `global_templates_enabled` is false. This flag governs whether curation is
-- also enforced at *instantiation*: when false (default), non-admins cannot
-- create a service instance from a global template outside the curated
-- catalog; when true, curated-out globals stay hidden from discovery but
-- remain instantiable by callers who already know the key.
--
-- Defaults to `false` so curation is a real restriction out of the box; org
-- admins are always exempt.
ALTER TABLE orgs
    ADD COLUMN allow_services_outside_catalog BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN orgs.allow_services_outside_catalog IS
    'When false (default), non-admins cannot instantiate global templates outside the curated catalog.';
