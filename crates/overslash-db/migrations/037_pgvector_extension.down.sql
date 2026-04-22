-- Safe to drop only because migration 038 guards every reference behind a
-- vector-type existence check and the embeddings table is dropped first.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
        DROP EXTENSION IF EXISTS vector;
    END IF;
END $$;
