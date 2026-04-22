-- Vector store for service/action embeddings used by GET /v1/search (§10).
-- Tier layout mirrors service_templates: a row keyed by (template_key,
-- action_key) for global templates; additionally scoped by org_id for org
-- templates and by owner_identity_id for user-tier templates. `source_text`
-- is the exact text we embedded — kept so we can detect staleness and
-- re-embed on template updates without round-tripping the model weights.
--
-- Guarded by the `vector` TYPE so the migration no-ops cleanly on vanilla
-- Postgres where 037 couldn't create the extension.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vector') THEN
        CREATE TABLE IF NOT EXISTS service_action_embeddings (
            id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tier              TEXT NOT NULL CHECK (tier IN ('global', 'org', 'user')),
            org_id            UUID NULL REFERENCES orgs(id) ON DELETE CASCADE,
            owner_identity_id UUID NULL REFERENCES identities(id) ON DELETE CASCADE,
            template_key      TEXT NOT NULL,
            action_key        TEXT NOT NULL,
            source_text       TEXT NOT NULL,
            embedding         VECTOR(384) NOT NULL,
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE UNIQUE INDEX IF NOT EXISTS service_action_embeddings_global_unique
            ON service_action_embeddings (template_key, action_key)
            WHERE tier = 'global';

        CREATE UNIQUE INDEX IF NOT EXISTS service_action_embeddings_org_unique
            ON service_action_embeddings (org_id, template_key, action_key)
            WHERE tier = 'org';

        CREATE UNIQUE INDEX IF NOT EXISTS service_action_embeddings_user_unique
            ON service_action_embeddings (org_id, owner_identity_id, template_key, action_key)
            WHERE tier = 'user';

        -- HNSW at default ef_construction=64; the table is tiny (<10k rows
        -- expected) so we optimize for recall, not build speed.
        -- `vector_cosine_ops` matches `<=>` at query time.
        CREATE INDEX IF NOT EXISTS service_action_embeddings_hnsw
            ON service_action_embeddings USING hnsw (embedding vector_cosine_ops);
    ELSE
        RAISE NOTICE 'vector type not present; skipping service_action_embeddings table';
    END IF;
END $$;
