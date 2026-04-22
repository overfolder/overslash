-- Optional pgvector extension — backs semantic search for service/action
-- discovery (§10 of SPEC.md). Guarded so the migration is a no-op on a
-- Postgres deployment that lacks the pgvector binary (self-hosted vanilla
-- Postgres): the server still boots, the search endpoint still works, it
-- just drops the embedding signal and falls back to keyword + fuzzy.
-- Dev, CI, and the shipped compose images (pgvector/pgvector:pg16) ship
-- the extension, so in those environments the CREATE EXTENSION fires.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'vector') THEN
        CREATE EXTENSION IF NOT EXISTS vector;
    ELSE
        RAISE NOTICE 'pgvector not available; skipping CREATE EXTENSION (semantic search will be disabled)';
    END IF;
END $$;
