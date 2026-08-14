use std::time::{Duration, Instant};

use dashmap::DashMap;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Trial lifecycle for an org, derived from `plan` + `trial_ends_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialStatus {
    /// Not on an instance-admin-managed trial (standard, free_unlimited, or a
    /// `plan='trial'` row with no end date set).
    None,
    /// On a trial that hasn't ended yet.
    Active { ends_at: OffsetDateTime },
    /// `plan='trial'` but `trial_ends_at` is in the past. Enforcement is
    /// banner-only (DECISIONS D25) — the org keeps working; the dashboard
    /// surfaces an "expired" banner.
    Expired { ends_at: OffsetDateTime },
}

/// Pure derivation of trial lifecycle from a billing snapshot. A trial is only
/// meaningful on `plan='trial'` with an end date; everything else (standard,
/// free_unlimited, a trial row missing its end date) is [`TrialStatus::None`].
pub fn derive_trial_status(
    plan: &str,
    trial_ends_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> TrialStatus {
    match (plan, trial_ends_at) {
        ("trial", Some(ends_at)) if ends_at > now => TrialStatus::Active { ends_at },
        ("trial", Some(ends_at)) => TrialStatus::Expired { ends_at },
        _ => TrialStatus::None,
    }
}

/// One cached billing snapshot for an org.
struct Cached {
    plan: String,
    trial_ends_at: Option<OffsetDateTime>,
    fetched_at: Instant,
}

/// Caches per-org billing-tier lookups so the rate-limit middleware (and the
/// subscription/trial-status reads) can decide without hitting Postgres on
/// every request.
///
/// A single cached snapshot answers both questions: whether the org is
/// `free_unlimited` (rate-limit bypass) and its trial status. Both are set
/// out-of-band — `free_unlimited` by an operator/instance admin, `trial` by the
/// instance-admin trial endpoints — so the only way an entry goes stale is a
/// column flip, which callers follow with [`invalidate`](Self::invalidate). A
/// 30s TTL bounds propagation even without an explicit invalidate.
pub struct FreeUnlimitedCache {
    entries: DashMap<Uuid, Cached>,
    ttl: Duration,
}

impl FreeUnlimitedCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Fetch `(plan, trial_ends_at)` from cache or DB. A DB error / missing org
    /// returns `None` (not cached), which each caller maps to its own
    /// fail-safe default (see below).
    async fn get_billing(
        &self,
        pool: &PgPool,
        org_id: Uuid,
    ) -> Option<(String, Option<OffsetDateTime>)> {
        if let Some(entry) = self.entries.get(&org_id)
            && entry.fetched_at.elapsed() < self.ttl
        {
            return Some((entry.plan.clone(), entry.trial_ends_at));
        }

        match overslash_db::repos::org::get_billing(pool, org_id).await {
            Ok(Some((plan, trial_ends_at))) => {
                self.entries.insert(
                    org_id,
                    Cached {
                        plan: plan.clone(),
                        trial_ends_at,
                        fetched_at: Instant::now(),
                    },
                );
                Some((plan, trial_ends_at))
            }
            _ => None,
        }
    }

    /// Returns true iff the org's `plan` is `free_unlimited`. A DB error is
    /// treated as "not free_unlimited" (fail closed — better to rate-limit a
    /// courtesy org during a DB blip than to let a paying org bypass).
    pub async fn is_free_unlimited(&self, pool: &PgPool, org_id: Uuid) -> bool {
        matches!(self.get_billing(pool, org_id).await, Some((plan, _)) if plan == "free_unlimited")
    }

    /// Resolve the org's [`TrialStatus`] as of `now`. Non-trial orgs (and DB
    /// errors) return [`TrialStatus::None`] — failing *open* so a DB blip never
    /// makes a healthy org look "expired". Because enforcement is banner-only,
    /// an over-generous `None` here is harmless.
    pub async fn trial_status(
        &self,
        pool: &PgPool,
        org_id: Uuid,
        now: OffsetDateTime,
    ) -> TrialStatus {
        match self.get_billing(pool, org_id).await {
            Some((plan, trial_ends_at)) => derive_trial_status(&plan, trial_ends_at, now),
            None => TrialStatus::None,
        }
    }

    /// Drop the cached entry for an org so the next lookup hits the DB. Called
    /// by the instance-admin trial/plan endpoints after a write and by tests.
    pub fn invalidate(&self, org_id: Uuid) {
        self.entries.remove(&org_id);
    }

    /// Remove entries past their TTL. Reads only check freshness — without
    /// periodic eviction, every org that ever hits the API stays resident for
    /// the life of the process.
    pub fn evict_expired(&self) {
        self.entries
            .retain(|_, cached| cached.fetched_at.elapsed() < self.ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration as TimeDuration;

    fn insert(
        cache: &FreeUnlimitedCache,
        plan: &str,
        trial_ends_at: Option<OffsetDateTime>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        cache.entries.insert(
            id,
            Cached {
                plan: plan.into(),
                trial_ends_at,
                fetched_at: Instant::now(),
            },
        );
        id
    }

    #[test]
    fn evict_expired_drops_stale_entries() {
        // TTL of zero → every entry is stale the moment it's inserted.
        let cache = FreeUnlimitedCache::new(Duration::ZERO);
        insert(&cache, "free_unlimited", None);

        cache.evict_expired();

        assert!(cache.entries.is_empty());
    }

    #[test]
    fn evict_expired_keeps_fresh_entries() {
        let cache = FreeUnlimitedCache::new(Duration::from_secs(60));
        insert(&cache, "free_unlimited", None);

        cache.evict_expired();

        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn trial_status_active_when_future() {
        let now = OffsetDateTime::now_utc();
        let ends = now + TimeDuration::days(5);
        assert_eq!(
            derive_trial_status("trial", Some(ends), now),
            TrialStatus::Active { ends_at: ends }
        );
    }

    #[test]
    fn trial_status_expired_when_past() {
        let now = OffsetDateTime::now_utc();
        let ends = now - TimeDuration::days(1);
        assert_eq!(
            derive_trial_status("trial", Some(ends), now),
            TrialStatus::Expired { ends_at: ends }
        );
    }

    #[test]
    fn trial_status_none_for_non_trial_plans() {
        let now = OffsetDateTime::now_utc();
        let ends = now + TimeDuration::days(5);
        assert_eq!(
            derive_trial_status("standard", None, now),
            TrialStatus::None
        );
        assert_eq!(
            derive_trial_status("free_unlimited", None, now),
            TrialStatus::None
        );
        // A trial plan with no end date is treated as not-on-trial.
        assert_eq!(derive_trial_status("trial", None, now), TrialStatus::None);
        // free_unlimited wins even if a stray trial_ends_at lingers.
        assert_eq!(
            derive_trial_status("free_unlimited", Some(ends), now),
            TrialStatus::None
        );
    }
}
