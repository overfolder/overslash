-- Decouple "use the Overslash-managed IdP" from "admit invite-only".
--
-- Before this migration, `orgs.allow_overslash_managed_signin = true` forced
-- invite-only admission: the managed IdP (Google/GitHub env-var OAuth apps)
-- could authenticate a user, but membership required a pending `org_invites`
-- row. There was no way to say "admit anyone from @acme.com through the
-- managed IdP" without provisioning a per-org OAuth app (the legacy
-- `org_idp_configs.allowed_email_domains` path).
--
-- Two new columns on `orgs` split the axes:
--
--   * `require_invite_admission` — when a managed-signin org has this ON
--     (the default, preserving today's behavior) admission stays invite-only.
--     When OFF, admission falls back to the domain allowlist below.
--
--   * `managed_signin_allowed_domains` — the org-wide email-domain allowlist
--     consulted on the managed path when `require_invite_admission = false`.
--     Org-wide (not per-provider like `org_idp_configs.allowed_email_domains`)
--     because the managed path admits through multiple env-var providers
--     (Google OR GitHub) that share one trust boundary — the operator's env
--     creds. An EMPTY list here does NOT mean "admit the internet": with
--     require-invite off and no domains configured, admission is rejected as
--     misconfigured (`domain_admission_not_configured`). A non-empty list is
--     the whitelist; a matched domain admits, an unmatched one is rejected
--     (`domain_not_allowed`). See
--     `crates/overslash-api/src/routes/auth.rs::provision_org_subdomain`.
ALTER TABLE orgs
    ADD COLUMN require_invite_admission boolean NOT NULL DEFAULT true,
    ADD COLUMN managed_signin_allowed_domains text[] NOT NULL DEFAULT '{}';
