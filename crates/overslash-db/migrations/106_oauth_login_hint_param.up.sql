-- Per-provider name of the authorize-URL parameter that pre-selects an account.
--
-- Reconnecting a connection labelled `aaa@google.com` used to send the user to
-- an account-agnostic authorize URL. With several Google sessions in the
-- browser the user gets a chooser (or silently lands on the default session)
-- and can end up granting `bbb@google.com`'s tokens onto the `aaa@google.com`
-- row — the callback's `account_email = COALESCE($7, account_email)` keeps the
-- stale label. Passing the connection's `account_email` back as a hint fixes
-- that, and lets API callers pre-select an account on a brand-new flow.
--
-- The parameter's *name* is provider-specific, so it belongs on the provider
-- row next to `extra_auth_params` / `default_identity_scopes` rather than in
-- Rust. NULL means "this provider takes no account hint" — the value is then
-- dropped rather than sent, so we never push an unknown parameter at a strict
-- authorization server.
--
-- No column DEFAULT: that would backfill every builtin, including the seven
-- that don't support hints.
--
-- Every provider we ship was checked against its current docs:
--
--   google     login_hint  OIDC Core; documented on the Google authorize endpoint.
--   microsoft  login_hint  OIDC Core; documented for the Microsoft identity platform.
--   github     login       Documented: "Suggests a specific account to use for
--                          signing in and authorizing the app." GitHub's sign-in
--                          field takes a username or an email. Our `account_email`
--                          for GitHub may be the synthetic
--                          `{login}@users.noreply.github.com` that `extract_email`
--                          falls back to when the user hides their address —
--                          `hint_from_account_email` unwraps that back to `{login}`
--                          before it reaches the URL.
--   linkedin   NULL        OIDC-shaped, but its discovery document advertises only
--                          issuer/endpoints/scopes and the docs list no account
--                          hint. Not sent rather than guessed.
--   hubspot    NULL        Authorize takes client_id/redirect_uri/scope/
--                          optional_scope/state only. Account pre-selection exists
--                          but as a path segment carrying a numeric portal id
--                          (`/oauth/{portalId}/authorize`), which is not an email
--                          and so can't be fed from `account_email`.
--   slack      NULL        Has `team` (a workspace id), not a per-user email hint.
--   notion     NULL        Only `owner=user`.
--   spotify    NULL        Only `show_dialog`.
--   x          NULL        No hint parameter.
--   eventbrite NULL        No hint parameter.
--
-- Custom providers created through OIDC discovery default to `login_hint` in
-- `oauth_provider::create_custom`, since that is the OIDC Core parameter.

ALTER TABLE oauth_providers
    ADD COLUMN login_hint_param TEXT;

UPDATE oauth_providers SET login_hint_param = 'login_hint'
    WHERE key IN ('google', 'microsoft');

UPDATE oauth_providers SET login_hint_param = 'login'
    WHERE key = 'github';
