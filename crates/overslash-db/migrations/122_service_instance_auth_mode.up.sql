-- Which of its template's alternative credential kinds this instance uses.
--
-- A template may declare `components.x-overslash-auth-modes`: named
-- alternatives, each naming the securitySchemes it activates. Figma, GitHub and
-- Notion all accept either an OAuth connection or a long-lived token against
-- the same host and the same paths, and before this there was no way to say so
-- — the gateway assumed a template was OAuth-backed *or* secret-backed, and the
-- shipped answer to a vendor offering both was a second template file.
--
-- Stored rather than inferred from whichever credential happens to be bound.
-- The state that decides the question is a *freshly created* instance, which
-- has neither bound yet: that is exactly when `derive_credentials_status` has
-- to say whether the operator still owes us an OAuth connection or an API
-- token, and when `create_service` has to decide whether to mint
-- `connect.auth_url` or `setup.setup_url`. Inference has no answer there.
--
-- NULL means "the template's default mode", which is the only thing every
-- pre-existing row can mean — no backfill, and a template that declares no
-- modes has exactly one anyway.
ALTER TABLE service_instances ADD COLUMN auth_mode text;

COMMENT ON COLUMN service_instances.auth_mode IS
    'Which of the template''s x-overslash-auth-modes this instance authenticates with (e.g. oauth, token). NULL = the template''s default mode, and the only possibility for a template declaring no modes.';
