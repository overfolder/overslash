// The adopted-member cases seed `external_id` with dynamic SQL.
#![allow(clippy::disallowed_methods)]
//! `email` on the identity CRUD API.
//!
//! `POST /v1/identities` and `PATCH /v1/identities/{id}` can set a user's email
//! alongside their name, so a caller can say "this is alice@acme.com **and**
//! she is called Alice Smith" in one request — something neither endpoint could
//! express before, and which `POST /v1/org-invites` cannot (it derives the name
//! from the address and sends mail as a side effect).
//!
//! The address is not a label: the OAuth callback adopts a pre-created identity
//! by verified email, so it decides which human can claim the account. That is
//! what the duplicate and adopted-member guards here protect.

use crate::common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Fresh org + admin key.
async fn setup() -> (String, reqwest::Client, sqlx::PgPool, String) {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "IdentityEmailOrg", "slug": format!("ie-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org["id"].as_str().unwrap(), "name": "admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    (base, client, pool, key["key"].as_str().unwrap().to_string())
}

async fn create_identity(
    base: &str,
    client: &reqwest::Client,
    key: &str,
    body: Value,
) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn patch_identity(
    base: &str,
    client: &reqwest::Client,
    key: &str,
    id: &str,
    body: Value,
) -> (u16, Value) {
    let resp = client
        .patch(format!("{base}/v1/identities/{id}"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn email_of(pool: &sqlx::PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT email FROM identities WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Name and address land together, normalised, on a member the login path can
/// later adopt — and the row gets the same group bootstrap every other
/// user-identity creation path performs.
#[tokio::test]
async fn create_user_with_email_pairs_name_and_address() {
    let (base, client, pool, key) = setup().await;

    let (status, body) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "Alice Smith", "kind": "user", "email": "Alice@Acme.COM"}),
    )
    .await;
    assert_eq!(status, 200, "unexpected body: {body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

    assert_eq!(body["name"], "Alice Smith");
    assert_eq!(
        email_of(&pool, id).await.as_deref(),
        Some("alice@acme.com"),
        "the address is lowercased so adopt-by-email matches"
    );

    let (ext_id, in_everyone): (Option<String>, i64) = sqlx::query_as(
        "SELECT i.external_id,
                (SELECT count(*) FROM identity_groups ig
                   JOIN groups g ON g.id = ig.group_id
                  WHERE ig.identity_id = i.id AND g.system_kind = 'everyone')
         FROM identities i WHERE i.id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(ext_id.is_none(), "pre-created member, never signed in");
    assert_eq!(in_everyone, 1);
}

/// One human, one identity per org — whichever endpoint creates the row.
#[tokio::test]
async fn create_user_with_a_taken_email_conflicts() {
    let (base, client, _pool, key) = setup().await;
    let body = json!({"name": "Alice", "kind": "user", "email": "dup@acme.com"});

    let (first, _) = create_identity(&base, &client, &key, body.clone()).await;
    assert_eq!(first, 200);

    let (second, _) = create_identity(&base, &client, &key, body).await;
    assert_eq!(second, 409);

    // The invite endpoint sees the same member and refuses too.
    let resp = client
        .post(format!("{base}/v1/org-invites"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"email": "dup@acme.com", "role": "member"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409);
}

/// Only people have email addresses.
#[tokio::test]
async fn create_agent_with_an_email_is_rejected() {
    let (base, client, _pool, key) = setup().await;
    let (_, user) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "owner", "kind": "user"}),
    )
    .await;

    let (status, _) = create_identity(
        &base,
        &client,
        &key,
        json!({
            "name": "henry",
            "kind": "agent",
            "parent_id": user["id"],
            "email": "henry@acme.com",
        }),
    )
    .await;
    assert_eq!(status, 400);
}

/// A pre-created member's address can still be corrected, atomically with
/// their name — a typo'd invite is otherwise unrecoverable without deleting
/// the row and everything hanging off it.
#[tokio::test]
async fn patch_sets_email_and_name_together() {
    let (base, client, pool, key) = setup().await;
    let (_, created) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "alcie", "kind": "user", "email": "alcie@acme.com"}),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, body) = patch_identity(
        &base,
        &client,
        &key,
        &id,
        json!({"name": "Alice Smith", "email": "alice@acme.com"}),
    )
    .await;
    assert_eq!(status, 200, "unexpected body: {body}");
    assert_eq!(body["name"], "Alice Smith");
    assert_eq!(
        email_of(&pool, id.parse().unwrap()).await.as_deref(),
        Some("alice@acme.com")
    );

    // Re-sending the address it already has is not a conflict with itself.
    let (again, _) = patch_identity(
        &base,
        &client,
        &key,
        &id,
        json!({"email": "alice@acme.com"}),
    )
    .await;
    assert_eq!(again, 200);
}

/// After a sign-in the address belongs to the identity provider. Rewriting it
/// would silently repoint which human can claim the account.
#[tokio::test]
async fn patch_email_on_an_adopted_member_is_refused() {
    let (base, client, pool, key) = setup().await;
    let (_, created) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "Alice", "kind": "user", "email": "alice@acme.com"}),
    )
    .await;
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    sqlx::query("UPDATE identities SET external_id = 'idp-subject-1' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    let (status, _) = patch_identity(
        &base,
        &client,
        &key,
        &id.to_string(),
        json!({"email": "attacker@evil.com"}),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(
        email_of(&pool, id).await.as_deref(),
        Some("alice@acme.com"),
        "a refused patch must not have moved the address"
    );

    // The name is still theirs to fix.
    let (name_only, _) = patch_identity(
        &base,
        &client,
        &key,
        &id.to_string(),
        json!({"name": "Alice Smith"}),
    )
    .await;
    assert_eq!(name_only, 200);
}

/// The duplicate guard applies on patch too, and a refusal leaves the whole
/// patch unapplied rather than landing the name and dropping the address.
#[tokio::test]
async fn patch_email_onto_another_member_conflicts() {
    let (base, client, pool, key) = setup().await;
    for (name, email) in [("Alice", "alice@acme.com"), ("Bob", "bob@acme.com")] {
        create_identity(
            &base,
            &client,
            &key,
            json!({"name": name, "kind": "user", "email": email}),
        )
        .await;
    }
    let (_, carol) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "Carol", "kind": "user", "email": "carol@acme.com"}),
    )
    .await;
    let id: Uuid = carol["id"].as_str().unwrap().parse().unwrap();

    let (status, _) = patch_identity(
        &base,
        &client,
        &key,
        &id.to_string(),
        json!({"name": "Carol Jones", "email": "bob@acme.com"}),
    )
    .await;
    assert_eq!(status, 409);

    let (name, email): (String, Option<String>) =
        sqlx::query_as("SELECT name, email FROM identities WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(name, "Carol", "the rename must not have landed either");
    assert_eq!(email.as_deref(), Some("carol@acme.com"));
}

/// An agent has no address to patch.
#[tokio::test]
async fn patch_email_on_an_agent_is_rejected() {
    let (base, client, _pool, key) = setup().await;
    let (_, user) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "owner", "kind": "user"}),
    )
    .await;
    let (_, agent) = create_identity(
        &base,
        &client,
        &key,
        json!({"name": "henry", "kind": "agent", "parent_id": user["id"]}),
    )
    .await;

    let (status, _) = patch_identity(
        &base,
        &client,
        &key,
        agent["id"].as_str().unwrap(),
        json!({"email": "henry@acme.com"}),
    )
    .await;
    assert_eq!(status, 400);
}

/// A malformed address is a 400 before anything is written.
#[tokio::test]
async fn rejects_a_malformed_email() {
    let (base, client, _pool, key) = setup().await;

    for bad in ["", "   ", "no-at-sign", "spaced @acme.com"] {
        let (status, _) = create_identity(
            &base,
            &client,
            &key,
            json!({"name": "Alice", "kind": "user", "email": bad}),
        )
        .await;
        assert_eq!(status, 400, "value {bad:?} must 400");
    }
}
