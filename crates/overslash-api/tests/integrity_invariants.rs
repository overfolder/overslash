//! The stored-reference integrity sweep (`overslash_db::integrity`,
//! docs/runbooks/data-integrity.md).
//!
//! The binding policies refuse cross-user and cross-org references on every
//! path they know about; this sweep is what notices the rows they never saw —
//! written before a fix, by hand, or by a path nobody listed. Each test plants
//! one such row in an otherwise well-formed world and checks that exactly its
//! invariant reports exactly that row, and that the well-formed world reports
//! nothing at all.
#![allow(clippy::disallowed_methods)] // planting rows the API refuses needs raw SQL

use crate::common;

use overslash_db::integrity::{Invariant, sweep};
use sqlx::{AssertSqlSafe, PgPool};
use uuid::Uuid;

/// Two orgs. In `org`: users alice and bob, alice's agent `bot`, and the
/// things a healthy deployment holds — vault secrets, user and org templates,
/// connections with their own BYOC clients, a user-level instance bound to
/// the org vault and alice's vault and pinned to her agent's connection, an
/// org-level instance bound to bob's vault (org-level instances may read any
/// vault in the org), pending approvals and a rule. `other` mirrors a piece of
/// it for mallory, so a test has something foreign to point at.
struct World {
    bob: Uuid,
    bot: Uuid,
    mallory: Uuid,
    /// alice's user-level instance.
    alice_svc: Uuid,
    /// The org-level instance.
    shared: Uuid,
    alice_github: Uuid,
    bot_google: Uuid,
    bob_google: Uuid,
    mallory_google: Uuid,
    alice_byoc_google: Uuid,
    mallory_byoc_google: Uuid,
    bob_template: Uuid,
    mallory_template: Uuid,
    org: Uuid,
}

async fn id(pool: &PgPool, sql: &str, binds: &[Uuid]) -> Uuid {
    let mut q = sqlx::query_scalar::<_, Uuid>(AssertSqlSafe(sql.to_owned()));
    for b in binds {
        q = q.bind(*b);
    }
    q.fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

async fn exec(pool: &PgPool, sql: &str, binds: &[Uuid]) {
    let mut q = sqlx::query(AssertSqlSafe(sql.to_owned()));
    for b in binds {
        q = q.bind(*b);
    }
    q.execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
}

async fn org(pool: &PgPool) -> Uuid {
    id(
        pool,
        "INSERT INTO orgs (name, slug) VALUES ('o', 'o-' || gen_random_uuid()) RETURNING id",
        &[],
    )
    .await
}

async fn user(pool: &PgPool, org: Uuid, name: &str) -> Uuid {
    id(
        pool,
        &format!(
            "INSERT INTO identities (org_id, name, kind) VALUES ($1, '{name}', 'user') RETURNING id"
        ),
        &[org],
    )
    .await
}

async fn agent(pool: &PgPool, org: Uuid, owner: Uuid) -> Uuid {
    id(
        pool,
        "INSERT INTO identities (org_id, name, kind, parent_id, owner_id, depth)
         VALUES ($1, 'bot', 'agent', $2, $2, 1) RETURNING id",
        &[org, owner],
    )
    .await
}

async fn connection(pool: &PgPool, org: Uuid, owner: Uuid, provider: &str) -> Uuid {
    id(
        pool,
        &format!(
            "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token, is_default)
             VALUES ($1, $2, '{provider}', '\\x00', false) RETURNING id"
        ),
        &[org, owner],
    )
    .await
}

async fn byoc(pool: &PgPool, org: Uuid, owner: Uuid, provider: &str) -> Uuid {
    id(
        pool,
        &format!(
            "INSERT INTO byoc_credentials (org_id, identity_id, provider_key, encrypted_client_id, encrypted_client_secret)
             VALUES ($1, $2, '{provider}', '\\x00', '\\x00') RETURNING id"
        ),
        &[org, owner],
    )
    .await
}

async fn template(pool: &PgPool, org: Uuid, owner: Option<Uuid>) -> Uuid {
    let sql =
        "INSERT INTO service_templates (org_id, owner_identity_id, key, display_name, openapi)
               VALUES ($1, $2, 'tpl', 'Tpl', '{}') RETURNING id";
    sqlx::query_scalar::<_, Uuid>(sql)
        .bind(org)
        .bind(owner)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn approval(pool: &PgPool, org: Uuid, requester: Uuid, resolver: Uuid) -> Uuid {
    id(
        pool,
        "INSERT INTO approvals (org_id, identity_id, current_resolver_identity_id,
                                action_summary, token, expires_at)
         VALUES ($1, $2, $3, 'x', gen_random_uuid()::text, now() + interval '1 hour')
         RETURNING id",
        &[org, requester, resolver],
    )
    .await
}

async fn seed(pool: &PgPool) -> World {
    let org_id = org(pool).await;
    let other = org(pool).await;
    let alice = user(pool, org_id, "alice").await;
    let bob = user(pool, org_id, "bob").await;
    let bot = agent(pool, org_id, alice).await;
    let mallory = user(pool, other, "mallory").await;

    // Vaults: the org's, alice's, bob's.
    exec(
        pool,
        "INSERT INTO secrets (org_id, owner_identity_id, name) VALUES
             ($1, NULL, 'x'), ($1, $2, 'y'), ($1, $3, 'z')",
        &[org_id, alice, bob],
    )
    .await;

    let alice_template = template(pool, org_id, Some(alice)).await;
    let org_template = template(pool, org_id, None).await;
    let bob_template = template(pool, org_id, Some(bob)).await;
    let mallory_template = template(pool, other, None).await;

    let alice_byoc_google = byoc(pool, org_id, alice, "google").await;
    let mallory_byoc_google = byoc(pool, other, mallory, "google").await;
    let alice_github = connection(pool, org_id, alice, "github").await;
    let bot_google = connection(pool, org_id, bot, "google").await;
    let bob_google = connection(pool, org_id, bob, "google").await;
    let mallory_google = connection(pool, other, mallory, "google").await;
    // An agent's connection minted with its owner's BYOC client.
    exec(
        pool,
        "UPDATE connections SET byoc_credential_id = $2 WHERE id = $1",
        &[bot_google, alice_byoc_google],
    )
    .await;
    exec(
        pool,
        "UPDATE connections SET byoc_credential_id = $2 WHERE id = $1",
        &[mallory_google, mallory_byoc_google],
    )
    .await;

    let alice_svc = id(
        pool,
        &format!(
            "INSERT INTO service_instances
                 (org_id, owner_identity_id, name, template_source, template_key, template_id,
                  secret_name, credentials, connection_id)
             VALUES ($1, $2, 'mine', 'user', 'tpl', $3, 'org/x',
                     jsonb_build_object('token', '{alice}/y'), $4)
             RETURNING id"
        ),
        &[org_id, alice, alice_template, bot_google],
    )
    .await;
    let shared = id(
        pool,
        &format!(
            "INSERT INTO service_instances
                 (org_id, name, template_source, template_key, template_id, credentials)
             VALUES ($1, 'shared', 'org', 'tpl', $2, jsonb_build_object('token', '{bob}/z', 'empty', ''))
             RETURNING id"
        ),
        &[org_id, org_template],
    )
    .await;

    // The agent asked; the gap was at the agent, then bubbled to alice.
    approval(pool, org_id, bot, bot).await;
    approval(pool, org_id, bot, alice).await;
    exec(
        pool,
        "INSERT INTO permission_rules (org_id, identity_id, action_pattern) VALUES ($1, $2, 'http:*')",
        &[org_id, bot],
    )
    .await;

    World {
        bob,
        bot,
        mallory,
        alice_svc,
        shared,
        alice_github,
        bot_google,
        bob_google,
        mallory_google,
        alice_byoc_google,
        mallory_byoc_google,
        bob_template,
        mallory_template,
        org: org_id,
    }
}

/// Exactly `expected` reports exactly `subject`; every other invariant is
/// silent. The second half is what keeps the labels from double-counting.
async fn assert_only(pool: &PgPool, expected: Invariant, subject: Uuid) {
    for (inv, rows) in sweep(pool).await.unwrap() {
        let ids: Vec<Uuid> = rows.iter().map(|v| v.subject_id).collect();
        if inv == expected {
            assert_eq!(ids, vec![subject], "{}: {rows:#?}", inv.as_str());
        } else {
            assert!(rows.is_empty(), "{} fired too: {rows:#?}", inv.as_str());
        }
    }
}

#[tokio::test]
async fn a_well_formed_database_reports_nothing() {
    // The bootstrapped template is what the real API writes at org creation
    // (system instances, groups, users) — the sweep must not flag any of it.
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    seed(&pool).await;
    for (inv, rows) in sweep(&pool).await.unwrap() {
        assert!(rows.is_empty(), "{}: {rows:#?}", inv.as_str());
    }
    assert_eq!(
        sweep(&pool).await.unwrap().len(),
        Invariant::ALL.len(),
        "one result per invariant, zeros included"
    );
}

#[tokio::test]
async fn a_bare_binding_is_unqualified() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        r#"UPDATE service_instances SET credentials = '{"token": "y"}' WHERE id = $1"#,
        &[w.alice_svc],
    )
    .await;
    assert_only(&pool, Invariant::BindingUnqualified, w.alice_svc).await;
}

#[tokio::test]
async fn a_binding_into_another_orgs_vault_is_outside_the_org() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    // Org-level instances may read any vault — of their own org.
    exec(
        &pool,
        "UPDATE service_instances SET credentials = jsonb_build_object('token', $2::text || '/z')
         WHERE id = $1",
        &[w.shared, w.mallory],
    )
    .await;
    assert_only(&pool, Invariant::BindingNamespaceOutsideOrg, w.shared).await;
}

#[tokio::test]
async fn a_binding_into_an_agents_namespace_is_outside_the_org() {
    // Agents have no vault (D119); a path naming one points at nothing.
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET secret_name = $2::text || '/y' WHERE id = $1",
        &[w.alice_svc, w.bot],
    )
    .await;
    assert_only(&pool, Invariant::BindingNamespaceOutsideOrg, w.alice_svc).await;
}

#[tokio::test]
async fn a_user_instance_bound_to_a_colleagues_vault_is_reported() {
    // The Reveni shape migration 133 NOTICE'd and left in place.
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET credentials = jsonb_build_object('token', $2::text || '/z')
         WHERE id = $1",
        &[w.alice_svc, w.bob],
    )
    .await;
    assert_only(&pool, Invariant::BindingForeignUserVault, w.alice_svc).await;
}

#[tokio::test]
async fn an_org_level_instance_with_a_pin_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET connection_id = $2 WHERE id = $1",
        &[w.shared, w.alice_github],
    )
    .await;
    assert_only(&pool, Invariant::PinOnOrgInstance, w.shared).await;
}

#[tokio::test]
async fn a_pin_to_another_orgs_connection_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET connection_id = $2 WHERE id = $1",
        &[w.alice_svc, w.mallory_google],
    )
    .await;
    assert_only(&pool, Invariant::PinCrossOrg, w.alice_svc).await;
}

#[tokio::test]
async fn a_pin_to_a_colleagues_connection_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET connection_id = $2 WHERE id = $1",
        &[w.alice_svc, w.bob_google],
    )
    .await;
    assert_only(&pool, Invariant::PinNotOwner, w.alice_svc).await;
}

#[tokio::test]
async fn a_byoc_client_from_another_org_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE connections SET byoc_credential_id = $2 WHERE id = $1",
        &[w.bot_google, w.mallory_byoc_google],
    )
    .await;
    assert_only(&pool, Invariant::ByocCrossOrg, w.bot_google).await;
}

#[tokio::test]
async fn a_byoc_client_for_another_provider_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE connections SET byoc_credential_id = $2 WHERE id = $1",
        &[w.alice_github, w.alice_byoc_google],
    )
    .await;
    assert_only(&pool, Invariant::ByocProviderMismatch, w.alice_github).await;
}

#[tokio::test]
async fn a_colleagues_byoc_client_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE connections SET byoc_credential_id = $2 WHERE id = $1",
        &[w.bob_google, w.alice_byoc_google],
    )
    .await;
    assert_only(&pool, Invariant::ByocNotOwner, w.bob_google).await;
}

#[tokio::test]
async fn a_secret_in_an_agents_vault_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    let secret = id(
        &pool,
        "INSERT INTO secrets (org_id, owner_identity_id, name) VALUES ($1, $2, 'bot') RETURNING id",
        &[w.org, w.bot],
    )
    .await;
    assert_only(&pool, Invariant::SecretOwnerNotUser, secret).await;
}

#[tokio::test]
async fn a_rule_for_another_orgs_identity_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    let rule = id(
        &pool,
        "INSERT INTO permission_rules (org_id, identity_id, action_pattern)
         VALUES ($1, $2, 'http:*') RETURNING id",
        &[w.org, w.mallory],
    )
    .await;
    assert_only(&pool, Invariant::OwnerCrossOrg, rule).await;
}

#[tokio::test]
async fn an_agent_parented_in_another_org_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE identities SET parent_id = $2 WHERE id = $1",
        &[w.bot, w.mallory],
    )
    .await;
    // Moving bot's parent also takes alice off its ancestor chain, so the
    // seeded approval bubbled to her is reported too. Check owner_cross_org
    // on its own here; the resolver chain has its own test.
    let rows = Invariant::OwnerCrossOrg.check(&pool).await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|v| (v.subject_table.as_str(), v.subject_id))
            .collect::<Vec<_>>(),
        vec![("identities", w.bot)],
    );
}

#[tokio::test]
async fn a_template_from_another_org_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET template_id = $2 WHERE id = $1",
        &[w.alice_svc, w.mallory_template],
    )
    .await;
    assert_only(&pool, Invariant::TemplateCrossOrg, w.alice_svc).await;
}

#[tokio::test]
async fn a_colleagues_user_template_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    exec(
        &pool,
        "UPDATE service_instances SET template_id = $2 WHERE id = $1",
        &[w.alice_svc, w.bob_template],
    )
    .await;
    assert_only(&pool, Invariant::TemplateCrossOwner, w.alice_svc).await;
}

#[tokio::test]
async fn an_approval_resolved_from_another_org_is_reported() {
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    let a = approval(&pool, w.org, w.bot, w.mallory).await;
    assert_only(&pool, Invariant::ApprovalCrossOrg, a).await;
}

#[tokio::test]
async fn an_approval_resolved_by_a_stranger_is_reported() {
    // Approvals only bubble upward; bob is not on bot's chain, and
    // may_read_approval would hand him alice's agent's payload.
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    let a = approval(&pool, w.org, w.bot, w.bob).await;
    assert_only(&pool, Invariant::ApprovalResolverOutsideChain, a).await;
}

#[tokio::test]
async fn resolved_approvals_and_deleted_secrets_are_not_swept() {
    // The sweep watches the live surface: a finished approval and a
    // soft-deleted secret can't leak anything, and the approvals table grows
    // without bound.
    let pool = common::test_pool().await;
    let w = seed(&pool).await;
    let a = approval(&pool, w.org, w.bot, w.bob).await;
    exec(
        &pool,
        "UPDATE approvals SET status = 'denied' WHERE id = $1",
        &[a],
    )
    .await;
    exec(
        &pool,
        "INSERT INTO secrets (org_id, owner_identity_id, name, deleted_at)
         VALUES ($1, $2, 'gone', now())",
        &[w.org, w.bot],
    )
    .await;
    for (inv, rows) in sweep(&pool).await.unwrap() {
        assert!(rows.is_empty(), "{}: {rows:#?}", inv.as_str());
    }
}
