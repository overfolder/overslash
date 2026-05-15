-- Backfill the 1-byte key-version prefix onto every blob encrypted with the
-- master key, so the new `Keyring`-aware `crypto::decrypt` (which reads
-- byte 0 as the key id) can read existing rows. Pre-migration layout was
-- `[nonce:12][ct+tag:N]`; post-migration is `[v:1][nonce:12][ct+tag:N]`
-- with `v = 1` (the only key id used historically).
--
-- This migration runs exactly once thanks to sqlx's `_sqlx_migrations`
-- tracker — re-running would double-prefix and brick decrypts. Down strips
-- the leading byte symmetrically.

UPDATE secret_versions
   SET encrypted_value = E'\\x01'::bytea || encrypted_value;

UPDATE connections
   SET encrypted_access_token  = E'\\x01'::bytea || encrypted_access_token,
       encrypted_refresh_token = CASE
         WHEN encrypted_refresh_token IS NULL THEN NULL
         ELSE E'\\x01'::bytea || encrypted_refresh_token
       END;

UPDATE byoc_credentials
   SET encrypted_client_id     = E'\\x01'::bytea || encrypted_client_id,
       encrypted_client_secret = E'\\x01'::bytea || encrypted_client_secret;

UPDATE org_idp_configs
   SET encrypted_client_id     = CASE WHEN encrypted_client_id     IS NULL THEN NULL ELSE E'\\x01'::bytea || encrypted_client_id     END,
       encrypted_client_secret = CASE WHEN encrypted_client_secret IS NULL THEN NULL ELSE E'\\x01'::bytea || encrypted_client_secret END;

UPDATE mcp_upstream_tokens
   SET access_token_ciphertext  = E'\\x01'::bytea || access_token_ciphertext,
       refresh_token_ciphertext = CASE
         WHEN refresh_token_ciphertext IS NULL THEN NULL
         ELSE E'\\x01'::bytea || refresh_token_ciphertext
       END;
