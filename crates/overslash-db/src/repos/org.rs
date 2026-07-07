use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub subagent_idle_timeout_secs: i32,
    pub subagent_archive_retention_days: i32,
    pub is_personal: bool,
    pub plan: String,
    pub default_deferred_execution: bool,
    /// When `true`, this org accepts authentication via any Overslash-managed
    /// env-var OAuth app (`GOOGLE_AUTH_*`, `GITHUB_AUTH_*`, …). Admission is
    /// gated by `org_invites` — the IdP authenticates but cannot admit absent
    /// an invite row. Default `false` for existing orgs; new corp orgs are
    /// flipped to `true` at create time so login works out-of-the-box.
    pub allow_overslash_managed_signin: bool,
    /// When `true` (the default), a managed-signin org admits members
    /// invite-only: the IdP authenticates but membership requires a pending
    /// `org_invites` row. When `false`, admission falls back to the
    /// `managed_signin_allowed_domains` allowlist below. Independent of
    /// `allow_overslash_managed_signin` — see migration 092 and
    /// `crates/overslash-api/src/routes/auth.rs::provision_org_subdomain`.
    pub require_invite_admission: bool,
    /// Org-wide email-domain allowlist consulted on the managed-signin path
    /// when `require_invite_admission = false`. Empty = domain admission is
    /// unconfigured (admission rejected as misconfigured, NOT open to all).
    /// Distinct from the per-provider `org_idp_configs.allowed_email_domains`
    /// used by the legacy per-org-IdP path.
    pub managed_signin_allowed_domains: Vec<String>,
    /// User who created this org via `POST /v1/orgs` (or the free-unlimited
    /// admin path). `None` for anonymous creator paths and for orgs created
    /// before migration 067 whose `org.created` audit row had no resolvable
    /// `user_id`. Used by the `membership.removed` audit event to flag
    /// departures by the founder.
    pub creator_user_id: Option<Uuid>,
    /// End of an instance-admin-managed trial window. `Some` only when
    /// `plan = 'trial'`; the org is "on trial" while this is in the future and
    /// "expired" once it passes. `None` for every non-trial org. Enforcement is
    /// banner-only (see DECISIONS D25). Self-serve Stripe trials do NOT use this
    /// field — they carry a `status='trialing'` subscription instead.
    pub trial_ends_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Insert a new org. `plan` must be one of the values allowed by the
/// `orgs.plan` CHECK constraint (`'standard'`, `'free_unlimited'`, `'trial'`).
/// Most callers pass `"standard"`; the instance-admin path passes
/// `"free_unlimited"` to skip Stripe. A brand-new org is never created directly
/// on `'trial'` — trials are applied afterward via [`set_trial`].
pub async fn create(
    pool: &PgPool,
    name: &str,
    slug: &str,
    plan: &str,
) -> Result<OrgRow, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "INSERT INTO orgs (name, slug, plan) VALUES ($1, $2, $3)
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, default_deferred_execution, allow_overslash_managed_signin, require_invite_admission, managed_signin_allowed_domains, creator_user_id, trial_ends_at, created_at, updated_at",
        name,
        slug,
        plan,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, default_deferred_execution, allow_overslash_managed_signin, require_invite_admission, managed_signin_allowed_domains, creator_user_id, trial_ends_at, created_at, updated_at
         FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Read `(plan, trial_ends_at)` for an org in one query. Used by the
/// billing-tier cache to answer both the `free_unlimited` bypass and the
/// trial-status render without two round-trips. Returns `None` if the org
/// doesn't exist.
pub async fn get_billing(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<(String, Option<OffsetDateTime>)>, sqlx::Error> {
    let row = sqlx::query!("SELECT plan, trial_ends_at FROM orgs WHERE id = $1", id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| (r.plan, r.trial_ends_at)))
}

/// Put an org on an instance-admin-managed trial: set `plan = 'trial'` and the
/// trial window end. Overwrites any existing trial. Returns `false` if the org
/// doesn't exist. Callers must invalidate the billing-tier cache afterward.
pub async fn set_trial(
    pool: &PgPool,
    id: Uuid,
    ends_at: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET plan = 'trial', trial_ends_at = $2, updated_at = now() WHERE id = $1",
        id,
        ends_at,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Bump the trial window end. Only affects orgs currently on `plan = 'trial'`
/// (the `AND plan = 'trial'` guard means a non-trial org returns `false` rather
/// than silently gaining a `trial_ends_at`). Callers must invalidate the cache.
pub async fn extend_trial(
    pool: &PgPool,
    id: Uuid,
    ends_at: OffsetDateTime,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET trial_ends_at = $2, updated_at = now()
         WHERE id = $1 AND plan = 'trial'",
        id,
        ends_at,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Set an org's plan tier directly (instance-admin opt-out path, e.g. flipping
/// a trial org to `free_unlimited` or back to `standard`). Clears
/// `trial_ends_at` whenever the target plan is not `'trial'`. `plan` must be a
/// CHECK-allowed value. Callers must invalidate the cache.
pub async fn set_plan(pool: &PgPool, id: Uuid, plan: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs
         SET plan = $2,
             trial_ends_at = CASE WHEN $2 = 'trial' THEN trial_ends_at ELSE NULL END,
             updated_at = now()
         WHERE id = $1",
        id,
        plan,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read just the `approval_auto_bubble_secs` setting for an org.
/// Returns `None` if the org doesn't exist.
pub async fn get_approval_auto_bubble_secs(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<i32>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT approval_auto_bubble_secs FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.approval_auto_bubble_secs))
}

/// Update the `approval_auto_bubble_secs` setting for an org.
pub async fn set_approval_auto_bubble_secs(
    pool: &PgPool,
    id: Uuid,
    secs: i32,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET approval_auto_bubble_secs = $2, updated_at = now() WHERE id = $1",
        id,
        secs,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `allow_user_templates` setting for an org.
pub async fn get_allow_user_templates(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!("SELECT allow_user_templates FROM orgs WHERE id = $1", id,)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.allow_user_templates))
}

/// Update the `allow_user_templates` setting for an org.
pub async fn set_allow_user_templates(
    pool: &PgPool,
    id: Uuid,
    allow: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET allow_user_templates = $2, updated_at = now() WHERE id = $1",
        id,
        allow,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `global_templates_enabled` setting for an org.
pub async fn get_global_templates_enabled(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT global_templates_enabled FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.global_templates_enabled))
}

/// Update the `global_templates_enabled` setting for an org.
pub async fn set_global_templates_enabled(
    pool: &PgPool,
    id: Uuid,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET global_templates_enabled = $2, updated_at = now() WHERE id = $1",
        id,
        enabled,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `allow_unsigned_secret_provide` setting for an org.
pub async fn get_allow_unsigned_secret_provide(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT allow_unsigned_secret_provide FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.allow_unsigned_secret_provide))
}

/// Update the `allow_unsigned_secret_provide` setting for an org.
pub async fn set_allow_unsigned_secret_provide(
    pool: &PgPool,
    id: Uuid,
    allow: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET allow_unsigned_secret_provide = $2, updated_at = now() WHERE id = $1",
        id,
        allow,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `default_deferred_execution` org default. When `true`, a newly-
/// created agent identity is seeded with `auto_call_on_approve = false`
/// instead of the column default (`true`). Existing agents are not touched
/// when this flag flips. Returns `None` if the org doesn't exist.
pub async fn get_default_deferred_execution(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT default_deferred_execution FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.default_deferred_execution))
}

/// Update the `default_deferred_execution` setting for an org.
pub async fn set_default_deferred_execution(
    pool: &PgPool,
    id: Uuid,
    value: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET default_deferred_execution = $2, updated_at = now() WHERE id = $1",
        id,
        value,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `audit_response_body_mode` setting for an org
/// (`'off' | 'errors_only' | 'all'`, enforced by a CHECK constraint).
/// Governs whether `action.executed` audit rows persist the upstream
/// response body. Returns `None` if the org doesn't exist.
pub async fn get_audit_response_body_mode(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT audit_response_body_mode FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.audit_response_body_mode))
}

/// Update the `audit_response_body_mode` setting for an org. The caller
/// must pass one of the CHECK-allowed values.
pub async fn set_audit_response_body_mode(
    pool: &PgPool,
    id: Uuid,
    mode: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET audit_response_body_mode = $2, updated_at = now() WHERE id = $1",
        id,
        mode,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Atomically update template settings and return the new values.
pub async fn update_template_settings(
    pool: &PgPool,
    id: Uuid,
    allow_user_templates: Option<bool>,
    global_templates_enabled: Option<bool>,
) -> Result<Option<(bool, bool)>, sqlx::Error> {
    let row = sqlx::query!(
        "UPDATE orgs SET \
         allow_user_templates = COALESCE($2, allow_user_templates), \
         global_templates_enabled = COALESCE($3, global_templates_enabled), \
         updated_at = now() \
         WHERE id = $1 \
         RETURNING allow_user_templates, global_templates_enabled",
        id,
        allow_user_templates,
        global_templates_enabled,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.allow_user_templates, r.global_templates_enabled)))
}

pub async fn get_by_slug(pool: &PgPool, slug: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, default_deferred_execution, allow_overslash_managed_signin, require_invite_admission, managed_signin_allowed_domains, creator_user_id, trial_ends_at, created_at, updated_at
         FROM orgs WHERE slug = $1",
        slug,
    )
    .fetch_optional(pool)
    .await
}

/// Read the `allow_overslash_managed_signin` flag for an org.
pub async fn get_allow_overslash_managed_signin(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT allow_overslash_managed_signin FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.allow_overslash_managed_signin))
}

/// Record the user who created an org. Idempotent: only sets the field
/// when it's currently NULL, so a re-run during retry/cleanup paths can't
/// silently rewrite history. Callers can ignore the bool return; nothing
/// in the create flow today branches on it.
pub async fn set_creator_user_id(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET creator_user_id = $2, updated_at = now()
         WHERE id = $1 AND creator_user_id IS NULL",
        id,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Flip the `allow_overslash_managed_signin` flag for an org. When `true`
/// the org accepts authentication via Overslash-managed env-var OAuth apps,
/// with admission gated by `org_invites`.
pub async fn set_allow_overslash_managed_signin(
    pool: &PgPool,
    id: Uuid,
    value: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET allow_overslash_managed_signin = $2, updated_at = now() WHERE id = $1",
        id,
        value,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Atomically update the managed-signin admission settings, COALESCEing so a
/// `None` leaves the current value untouched (partial PATCH). Callers
/// normalize `allowed_domains` (lowercase/trim/dedupe) before persisting.
/// Returns the updated row, or `None` if the org doesn't exist.
pub async fn update_managed_admission(
    pool: &PgPool,
    id: Uuid,
    allow_overslash_managed_signin: Option<bool>,
    require_invite_admission: Option<bool>,
    allowed_domains: Option<&[String]>,
) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "UPDATE orgs SET
            allow_overslash_managed_signin = COALESCE($2, allow_overslash_managed_signin),
            require_invite_admission = COALESCE($3, require_invite_admission),
            managed_signin_allowed_domains = COALESCE($4, managed_signin_allowed_domains),
            updated_at = now()
         WHERE id = $1
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, default_deferred_execution, allow_overslash_managed_signin, require_invite_admission, managed_signin_allowed_domains, creator_user_id, trial_ends_at, created_at, updated_at",
        id,
        allow_overslash_managed_signin,
        require_invite_admission,
        allowed_domains,
    )
    .fetch_optional(pool)
    .await
}

/// Read the `headless` flag for an org. `true` ⇒ white-label org whose end
/// users have no Overslash session, so auth-recovery returns URL-less envelopes
/// instead of gated `/connect-authorize` links. `None` (org missing) and the
/// default are both treated as `false` by callers.
pub async fn get_headless(pool: &PgPool, id: Uuid) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!("SELECT headless FROM orgs WHERE id = $1", id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.headless))
}

/// Flip the `headless` flag for an org. Admin/provisioning-only — a
/// white-label partner onboarding capability, not an end-user self-service
/// toggle.
pub async fn set_headless(pool: &PgPool, id: Uuid, value: bool) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET headless = $2, updated_at = now() WHERE id = $1",
        id,
        value,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Update an org's sub-agent cleanup configuration. Bounds validated by caller.
pub async fn update_subagent_cleanup_config(
    pool: &PgPool,
    id: Uuid,
    idle_timeout_secs: i32,
    archive_retention_days: i32,
) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "UPDATE orgs
         SET subagent_idle_timeout_secs = $2,
             subagent_archive_retention_days = $3,
             updated_at = now()
         WHERE id = $1
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, default_deferred_execution, allow_overslash_managed_signin, require_invite_admission, managed_signin_allowed_domains, creator_user_id, trial_ends_at, created_at, updated_at",
        id,
        idle_timeout_secs,
        archive_retention_days,
    )
    .fetch_optional(pool)
    .await
}
