//! Capability-based authorization scopes.
//!
//! Scopes are the public surface of `overslash-db` for callers who hold a
//! verified identity. A handler that holds a scope value has, by construction,
//! been authorized at that level — and can only reach the database through
//! methods on the scope, which always include the appropriate `org_id` /
//! `user_id` / `agent_id` filters in their SQL.
//!
//! ## The hierarchy
//!
//! ```text
//! SystemScope        // internal jobs, cross-org admin
//!    │
//! OrgScope           // any authenticated org member
//!    │
//! UserScope          // a user (or agent acting as its user)
//!    │
//! AgentScope         // an agent — may itself have a parent agent
//! ```
//!
//! Every agent is rooted at a user (the `on_behalf_of` owner). Some agents
//! additionally have a parent agent — that's just a `parent_agent_id: Option`
//! field on `AgentScope`, not a separate type. Permission inheritance walks
//! `parent_agent_id` upward until it hits the root user.
//!
//! Each child scope holds a strict superset of its parent's fields and exposes
//! a free downgrade (`agent.user()`, `user.org()`) — no DB call, no permission
//! check, because the parent relationship was verified when the child was
//! constructed. Upgrades (e.g. promoting a `UserScope` to admin powers) require
//! an explicit, fallible permission check and are NOT free.
//!
//! ## Construction
//!
//! Scope constructors are `pub` because Axum extractors live in
//! `overslash-api`, not in this crate. To prevent accidental misuse, the only
//! supported construction sites are:
//!
//! - `overslash_api::extractors` — verifies an API key or session cookie and
//!   mints the appropriate scope. This is the only path for HTTP requests.
//! - `#[cfg(test)] for_test(...)` — explicit test constructors.
//! - `SystemScope::new_internal(&db)` — for cron tasks and internal jobs.
//!
//! Calling `OrgScope::new(...)` directly from a handler is a bug — handlers
//! must obtain scopes through extractors only. This is enforced by code review.

pub mod agent;
pub mod org;
mod org_api_keys;
mod org_approvals;
mod org_audit;
mod org_byoc;
mod org_connections;
mod org_groups;
mod org_identities;
mod org_idp_config;
mod org_permission_rules;
mod org_rate_limits;
mod org_secrets;
mod org_service_instances;
mod org_webhooks;
pub mod system;
mod system_api_keys;
mod system_approvals;
mod system_identities;
mod system_idp_config;
mod system_webhooks;
pub mod user;
mod user_connections;
mod user_preferences;

pub use agent::AgentScope;
pub use org::OrgScope;
pub use org_idp_config::CredentialsUpdate as OrgIdpConfigCredentialsUpdate;
pub use system::SystemScope;
pub use user::UserScope;

#[cfg(test)]
mod tests {
    //! These tests exercise the field plumbing and the free downgrade chain.
    //! Per-resource SQL methods on scopes are tested in their own modules
    //! (e.g. `scopes::org_secrets`). A `PgPool`
    //! cannot be constructed without a live server, so these tests use
    //! `PgPool::connect_lazy` against a syntactically valid but unreachable
    //! URL: nothing here ever issues a query, so the connection is never
    //! opened.

    use super::*;
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use uuid::Uuid;

    fn dummy_pool() -> PgPool {
        PgPoolOptions::new()
            .connect_lazy("postgres://vet:vet@127.0.0.1:1/vet")
            .expect("lazy connect cannot fail for a syntactically valid URL")
    }

    #[tokio::test]
    async fn org_scope_exposes_org_id() {
        let org = Uuid::new_v4();
        let scope = OrgScope::new(org, dummy_pool());
        assert_eq!(scope.org_id(), org);
    }

    #[tokio::test]
    async fn user_scope_downgrades_to_org_scope_with_same_org() {
        let org = Uuid::new_v4();
        let user = Uuid::new_v4();
        let scope = UserScope::new(org, user, dummy_pool());
        assert_eq!(scope.org_id(), org);
        assert_eq!(scope.user_id(), user);
        assert_eq!(scope.org().org_id(), org);
    }

    #[tokio::test]
    async fn agent_scope_with_user_parent_downgrades_through_user_to_org() {
        let org = Uuid::new_v4();
        let user = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let scope = AgentScope::new(org, user, agent, None, dummy_pool());

        assert!(scope.parent_agent_id().is_none());

        let as_user = scope.user();
        assert_eq!(as_user.org_id(), org);
        assert_eq!(as_user.user_id(), user);

        assert_eq!(scope.org().org_id(), org);
    }

    #[tokio::test]
    async fn agent_scope_with_parent_agent_records_chain() {
        let org = Uuid::new_v4();
        let user = Uuid::new_v4();
        let parent_agent = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let scope = AgentScope::new(org, user, agent, Some(parent_agent), dummy_pool());

        assert_eq!(scope.parent_agent_id(), Some(parent_agent));
        assert_eq!(scope.agent_id(), agent);
        // Downgrade still goes straight to the root user, not the parent agent.
        assert_eq!(scope.user().user_id(), user);
        assert_eq!(scope.org().org_id(), org);
    }
}
