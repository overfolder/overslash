UPDATE oauth_providers
SET authorization_endpoint = 'https://slack.com/oauth/v2/authorize',
    token_endpoint = 'https://slack.com/api/oauth.v2.access'
WHERE key = 'slack';
