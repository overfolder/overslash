-- Strip the 1-byte key-version prefix added by 069.up. Only safe to run
-- when every blob is still tagged with key id `\x01` — if a rotation has
-- already happened (some rows tagged `\x02`+) this down migration would
-- corrupt them and rollback should be done via a Postgres PITR restore
-- instead.

UPDATE secret_versions
   SET encrypted_value = substring(encrypted_value FROM 2);

UPDATE connections
   SET encrypted_access_token  = substring(encrypted_access_token FROM 2),
       encrypted_refresh_token = CASE
         WHEN encrypted_refresh_token IS NULL THEN NULL
         ELSE substring(encrypted_refresh_token FROM 2)
       END;

UPDATE byoc_credentials
   SET encrypted_client_id     = substring(encrypted_client_id FROM 2),
       encrypted_client_secret = substring(encrypted_client_secret FROM 2);

UPDATE org_idp_configs
   SET encrypted_client_id     = CASE WHEN encrypted_client_id     IS NULL THEN NULL ELSE substring(encrypted_client_id     FROM 2) END,
       encrypted_client_secret = CASE WHEN encrypted_client_secret IS NULL THEN NULL ELSE substring(encrypted_client_secret FROM 2) END;

UPDATE mcp_upstream_tokens
   SET access_token_ciphertext  = substring(access_token_ciphertext FROM 2),
       refresh_token_ciphertext = CASE
         WHEN refresh_token_ciphertext IS NULL THEN NULL
         ELSE substring(refresh_token_ciphertext FROM 2)
       END;
