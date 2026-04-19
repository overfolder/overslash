UPDATE oauth_providers
SET extra_auth_params = extra_auth_params - 'include_granted_scopes'
WHERE key = 'google';
