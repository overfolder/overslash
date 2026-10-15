-- Slack connections need a *user* token (xoxp-): the `slack` template drives
-- Slack's MCP server, which acts as the signed-in user, and `search:read` only
-- exists as a user scope.
--
-- The row from 009 pointed at `oauth/v2/authorize` + `oauth.v2.access`. On
-- that pair `scope=` means *bot* scopes, so an app with only user scopes is
-- rejected ("doesn't have a bot user to install"), and the user token would
-- come back nested under `authed_user` where the generic exchange never looks.
--
-- Slack's user-token flow takes the same `scope=` parameter as user scopes and
-- returns the user token top-level (`token_type: "user"`), so the generic
-- authorize/exchange/refresh code works unchanged.
UPDATE oauth_providers
SET authorization_endpoint = 'https://slack.com/oauth/v2_user/authorize',
    token_endpoint = 'https://slack.com/api/oauth.v2.user.access'
WHERE key = 'slack';
