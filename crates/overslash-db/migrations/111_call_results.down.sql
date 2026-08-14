ALTER TABLE download_tokens DROP CONSTRAINT download_tokens_one_byte_source;

-- Must precede the NOT NULL restore: a result-backed token has request IS NULL
-- by construction, so leaving these rows would fail the constraint. They are
-- unusable once call_results is gone anyway.
DELETE FROM download_tokens WHERE call_result_id IS NOT NULL;

ALTER TABLE download_tokens DROP COLUMN call_result_id;
ALTER TABLE download_tokens ALTER COLUMN request SET NOT NULL;

DROP TABLE call_results;
