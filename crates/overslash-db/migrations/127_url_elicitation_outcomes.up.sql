-- Why a browser hand-off ended, so a waiting MCP tool call can say so
-- (URL-mode elicitation, migration 126).
--
-- `oauth_connection_flows.failure` is the short reason stamped next to
-- `failed_at`: the provider's OAuth error code on a redirect like
-- `?error=access_denied`, `cancelled_by_user` from the consent
-- interstitial's Cancel button, or a coarse token for a callback that failed
-- on our side. Allow-listed characters only: it is shown to agents.
ALTER TABLE oauth_connection_flows ADD COLUMN failure TEXT;

COMMENT ON COLUMN oauth_connection_flows.failure IS
    'Short reason the flow failed (provider OAuth error code, cancelled_by_user, or a coarse callback token). Set with failed_at.';

-- The "Deny" button on the secret-provide page used to be purely local; it
-- now records the refusal, so the tool call waiting on the link can end.
-- Advisory: a later submission still fulfils the request.
ALTER TABLE secret_requests ADD COLUMN declined_at TIMESTAMPTZ;

COMMENT ON COLUMN secret_requests.declined_at IS
    'Set when the recipient pressed Deny on the provide page. Advisory; fulfilment still wins.';
