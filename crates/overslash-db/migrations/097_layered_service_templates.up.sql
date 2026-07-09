-- Layered service templates: unify forks and catalog overlays into one `layer`
-- primitive. A `service_templates` row is a layer whose `extends` field decides
-- its nature:
--   * standalone (extends IS NULL): holds a full OpenAPI doc in `openapi`
--     (this is today's org/user template — every existing row is one).
--   * derived (extends set): holds a `delta` jsonb over the base template named
--     by `extends`. The base is resolved by KEY (against DB rows, then the
--     in-memory global registry) — deliberately NOT an FK, because global
--     templates are shipped YAML, not rows.
--
-- See docs/design/layered-service-templates.md.
ALTER TABLE service_templates ADD COLUMN extends text;   -- base template key; NULL = standalone
ALTER TABLE service_templates ADD COLUMN delta   jsonb;  -- derived-layer content; NULL = standalone

-- Derived layers carry no full doc, so `openapi` is no longer globally NOT NULL.
-- Existing rows are all standalone and keep their openapi, so the drop is safe.
ALTER TABLE service_templates ALTER COLUMN openapi DROP NOT NULL;

-- Shape invariant:
--   standalone (extends NULL): openapi present, delta NULL
--   derived   (extends set):   delta present, openapi NULL or a reserved
--                              materialized resolved-cache (future)
ALTER TABLE service_templates
    ADD CONSTRAINT service_templates_layer_shape CHECK (
        (extends IS NULL     AND delta IS NULL     AND openapi IS NOT NULL)
        OR
        (extends IS NOT NULL AND delta IS NOT NULL)
    );

-- Index derived layers by their base so the resolver's dependent lookup (delete
-- referential guard, cascade of resolution warnings) is cheap.
CREATE INDEX idx_service_templates_extends
    ON service_templates (org_id, extends) WHERE extends IS NOT NULL;

-- Generalize the `allow_user_templates` boolean into a three-valued policy enum,
-- migrated in place. v1 honors `none` (users may not create layers) and `full`
-- (users may create any user-namespace layer). `restrictive` (mask-only user
-- layers) is reserved — its enforcement lights up with the deferred
-- restrictive/expansive classifier, with no future migration.
ALTER TABLE orgs ADD COLUMN user_template_policy text NOT NULL DEFAULT 'none'
    CHECK (user_template_policy IN ('none', 'restrictive', 'full'));

UPDATE orgs
    SET user_template_policy = CASE WHEN allow_user_templates THEN 'full' ELSE 'none' END;

ALTER TABLE orgs DROP COLUMN allow_user_templates;

COMMENT ON COLUMN service_templates.extends IS
    'Base template key for a derived layer (delta over a live base). NULL = standalone full-doc layer.';
COMMENT ON COLUMN service_templates.delta IS
    'Derived-layer content: masks (allowlist/denylist/action_patch/hidden/relabel) + extensions (actions/hosts). NULL = standalone.';
COMMENT ON COLUMN orgs.user_template_policy IS
    'Whether org members may create user-namespace layers: none | restrictive (reserved) | full.';
