-- Instance-admin-managed trial tier. An org on `plan='trial'` with a future
-- `trial_ends_at` is "on trial"; once `trial_ends_at` passes it is "expired".
-- Enforcement is banner-only (see DECISIONS D25): expiry changes dashboard
-- messaging, not API access. `free_unlimited` orgs are exempt (never 'trial').
--
-- Self-serve "trial for a month" org creation goes through Stripe instead
-- (`subscription_data[trial_period_days]`, status='trialing') and does NOT use
-- this tier — those orgs stay `plan='standard'` with a trialing subscription.
--
-- CHECK rather than ENUM so adding tiers stays a one-liner (mirrors 052).

ALTER TABLE orgs DROP CONSTRAINT orgs_plan_check;
ALTER TABLE orgs
    ADD CONSTRAINT orgs_plan_check CHECK (plan IN ('standard', 'free_unlimited', 'trial'));

-- Trial window end. NULL for every existing org — nobody is retroactively
-- trialed. Only set when an instance admin puts an org on `plan='trial'`.
ALTER TABLE orgs ADD COLUMN trial_ends_at TIMESTAMPTZ;
