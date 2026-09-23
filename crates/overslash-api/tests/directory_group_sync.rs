// Test setup needs dynamic SQL to repoint the provider at the fake and to read
// back rows the API deliberately does not expose.
#![allow(clippy::disallowed_methods)]
//! Integration tests for directory group sync.
//!
//! The feature's claim is narrow and worth stating exactly: an org's **own**
//! IdP may say which humans belong together, and that statement becomes access
//! only where an admin has mapped it onto an Overslash group. These tests hold
//! that line from both directions — that a mapped claim really does confer a
//! ceiling, and that everything which is *not* that path confers nothing.
//!
//! Each test drives a real `/auth/callback/google` sign-in against the OAuth
//! fake, with the group claim set through the fake's `/control/userinfo-claims`
//! endpoint. Nothing is stubbed between the claim and the ceiling.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// An org whose `google` IdP is its own dedicated config, optionally syncing
/// groups. Returns `(base, client, pool, mock_addr, org_id, org_slug, admin_key)`.
///
/// The returned client is the harness's — it has redirect following disabled,
/// which every sign-in assertion here depends on, since a successful callback
/// answers 303 towards a dashboard host that does not exist in-process.
///
/// Managed sign-in is switched **off** so admission runs through the org's own
/// IdP config, which is the only configuration where group sync is permitted
/// at all.
async fn org_with_idp(
    group_sync_enabled: bool,
    group_claim: Option<&str>,
) -> (String, Client, PgPool, String, Uuid, String, String) {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, \
         userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock_addr}/oauth/authorize"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .bind(format!("http://{mock_addr}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) = common::start_api_with_auth_providers(
        pool.clone(),
        Some(("env_id".into(), "env_secret".into())),
        None,
        "http://localhost:3000",
    )
    .await;

    let (org_id, _, _, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let org_slug = sqlx::query_scalar::<_, String>("SELECT slug FROM orgs WHERE id = $1")
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Admission via the org's own IdP, not the managed path.
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/managed-signin"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "allow_overslash_managed_signin": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let mut body = json!({
        "provider_key": "google",
        "client_id": "org-client",
        "client_secret": "org-secret",
        "allowed_email_domains": [],
        "group_sync_enabled": group_sync_enabled,
    });
    if let Some(claim) = group_claim {
        body["group_claim"] = json!(claim);
    }
    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create idp config");

    (
        base,
        client,
        pool,
        mock_addr.to_string(),
        org_id,
        org_slug,
        admin_key,
    )
}

/// Point the fake's `/oidc/userinfo` at `claims`. `None` clears every extra
/// claim, which is how a test expresses "the IdP said nothing about groups".
async fn set_claims(client: &Client, mock_addr: &str, claims: Option<Value>) {
    let body = claims.unwrap_or_else(|| json!({}));
    let resp = client
        .post(format!("http://{mock_addr}/control/userinfo-claims"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// Drive one sign-in, asserting it succeeded. `nonce` must differ per call
/// within a test — it is the anti-replay binding.
async fn sign_in(client: &Client, base: &str, org_slug: &str, nonce: &str) {
    let state_param = format!("login:google:{nonce}");
    let resp = client
        .get(format!(
            "{base}/auth/callback/google?code={nonce}&state={state_param}"
        ))
        .header(
            "cookie",
            format!(
                "__Host-oss_auth_nonce={nonce}; __Host-oss_auth_verifier=v; \
                 __Host-oss_auth_org={org_slug}"
            ),
        )
        .send()
        .await
        .unwrap();
    let status = resp.status();
    if status != 303 {
        let body = resp.text().await.unwrap_or_default();
        panic!("sign-in failed: {status} {body}");
    }
}

async fn synced_identity_id(pool: &PgPool, org_id: Uuid) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM identities WHERE org_id = $1 AND email = 'testuser@example.com' \
         AND kind = 'user'",
    )
    .bind(org_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// External ids of the directory groups the signed-in human currently belongs
/// to, as sync left them.
async fn directory_memberships(pool: &PgPool, identity_id: Uuid) -> Vec<String> {
    let mut rows = sqlx::query_scalar::<_, String>(
        "SELECT dg.external_id FROM identity_directory_groups idg \
         JOIN directory_groups dg ON dg.id = idg.directory_group_id \
         WHERE idg.identity_id = $1",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.sort();
    rows
}

async fn create_group(client: &Client, base: &str, admin_key: &str, name: &str) -> Uuid {
    let body: Value = client
        .post(format!("{base}/v1/groups"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "name": name, "description": "" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn list_directory_groups(client: &Client, base: &str, admin_key: &str) -> Vec<Value> {
    client
        .get(format!("{base}/v1/directory-groups"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn map_source(
    client: &Client,
    base: &str,
    admin_key: &str,
    group_id: Uuid,
    directory_group_id: Uuid,
) -> reqwest::StatusCode {
    client
        .post(format!("{base}/v1/groups/{group_id}/directory-sources"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "directory_group_id": directory_group_id }))
        .send()
        .await
        .unwrap()
        .status()
}

// ── The happy path ───────────────────────────────────────────────────

/// A claim becomes discoverable directory groups, and a mapping turns one of
/// them into real Layer 1 membership.
#[tokio::test]
async fn a_mapped_claim_confers_group_membership() {
    let (base, client, pool, mock, org_id, slug, admin_key) = org_with_idp(true, None).await;
    set_claims(
        &client,
        &mock,
        Some(json!({ "groups": ["engineering", "oncall"] })),
    )
    .await;

    sign_in(&client, &base, &slug, "dgs-1").await;
    let identity_id = synced_identity_id(&pool, org_id).await;

    // Discovered, but inert: nothing is mapped yet.
    let discovered = list_directory_groups(&client, &base, &admin_key).await;
    let mut names: Vec<&str> = discovered
        .iter()
        .map(|d| d["external_id"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["engineering", "oncall"]);
    for d in &discovered {
        assert_eq!(
            d["mapped_group_ids"].as_array().unwrap().len(),
            0,
            "a discovered group must confer nothing until an admin maps it"
        );
        assert_eq!(d["member_count"], 1);
    }

    // Map "engineering" onto a real group.
    let engineers = create_group(&client, &base, &admin_key, "Engineers").await;
    let eng_dir: Uuid = discovered
        .iter()
        .find(|d| d["external_id"] == "engineering")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        map_source(&client, &base, &admin_key, engineers, eng_dir).await,
        200
    );

    // The human is now a member of Engineers without any identity_groups row.
    let listed: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{engineers}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed,
        vec![identity_id],
        "directory member should be listed"
    );

    let direct: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_groups WHERE identity_id = $1 AND group_id = $2",
    )
    .bind(identity_id)
    .bind(engineers)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(direct, 0, "membership must be derived, not materialised");

    // …and the origin endpoint says so.
    let origins: Vec<Value> = client
        .get(format!("{base}/v1/groups/{engineers}/member-origins"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(origins.len(), 1);
    assert_eq!(origins[0]["direct"], false);
    assert_eq!(
        origins[0]["via_directory_group_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// Every membership surface must agree about a directory-derived member. They
/// are separate queries over the same view, and a disagreement is the failure
/// mode that would let access work on one screen and 404 on another.
#[tokio::test]
async fn every_membership_surface_sees_a_derived_member() {
    let (base, client, pool, mock, org_id, slug, admin_key) = org_with_idp(true, None).await;
    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-agree").await;
    let identity_id = synced_identity_id(&pool, org_id).await;

    let engineers = create_group(&client, &base, &admin_key, "Engineers").await;
    let discovered = list_directory_groups(&client, &base, &admin_key).await;
    let eng_dir: Uuid = discovered[0]["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        map_source(&client, &base, &admin_key, engineers, eng_dir).await,
        200
    );

    // list_identity_ids_in_group
    let listed: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{engineers}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed.contains(&identity_id), "members");

    // count_members_in_group, surfaced through the directory listing
    let refreshed = list_directory_groups(&client, &base, &admin_key).await;
    assert_eq!(refreshed[0]["member_count"], 1, "member count");

    // list_groups_for_identity — `is_member` on the group list, read as the
    // synced human themselves.
    let user_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": identity_id,
            "name": "synced-user-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_key = user_key["key"].as_str().unwrap().to_string();

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("authorization", format!("Bearer {user_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let eng = groups
        .iter()
        .find(|g| g["id"].as_str().unwrap() == engineers.to_string())
        .expect("Engineers in list");
    assert_eq!(eng["is_member"], true, "is_member via directory");
}

// ── The safety rules ─────────────────────────────────────────────────

/// The rule the whole authoritative design rests on. An IdP that stops sending
/// the claim — a renamed claim, a changed release policy — must not be read as
/// "this human is in no groups", or one upstream edit silently revokes an org.
#[tokio::test]
async fn an_absent_claim_changes_nothing() {
    let (base, client, pool, mock, org_id, slug, _admin_key) = org_with_idp(true, None).await;

    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-2a").await;
    let identity_id = synced_identity_id(&pool, org_id).await;
    assert_eq!(
        directory_memberships(&pool, identity_id).await,
        vec!["engineering".to_string()]
    );

    // Second sign-in, claim gone entirely.
    set_claims(&client, &mock, None).await;
    sign_in(&client, &base, &slug, "dgs-2b").await;
    assert_eq!(
        directory_memberships(&pool, identity_id).await,
        vec!["engineering".to_string()],
        "an absent claim must not be read as an empty one"
    );
}

/// The other half of that rule: a claim that is present and empty *is* an
/// assertion, and revokes.
#[tokio::test]
async fn an_empty_claim_revokes() {
    let (base, client, pool, mock, org_id, slug, _admin_key) = org_with_idp(true, None).await;

    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-3a").await;
    let identity_id = synced_identity_id(&pool, org_id).await;
    assert_eq!(directory_memberships(&pool, identity_id).await.len(), 1);

    set_claims(&client, &mock, Some(json!({ "groups": [] }))).await;
    sign_in(&client, &base, &slug, "dgs-3b").await;
    assert!(
        directory_memberships(&pool, identity_id).await.is_empty(),
        "a present-but-empty claim is an assertion of no membership"
    );
}

/// Authoritative sync owns its own table and nothing else. An admin's manual
/// assignment is in `identity_groups`, which sync cannot reach — this is the
/// property that makes "fully authoritative" safe by construction.
#[tokio::test]
async fn a_manual_assignment_survives_an_authoritative_sync() {
    let (base, client, pool, mock, org_id, slug, admin_key) = org_with_idp(true, None).await;
    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-4a").await;
    let identity_id = synced_identity_id(&pool, org_id).await;

    // An admin hand-adds the same human to a different group.
    let manual = create_group(&client, &base, &admin_key, "Hand Picked").await;
    let resp = client
        .post(format!("{base}/v1/groups/{manual}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": identity_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A later sign-in revokes every directory group…
    set_claims(&client, &mock, Some(json!({ "groups": [] }))).await;
    sign_in(&client, &base, &slug, "dgs-4b").await;
    assert!(directory_memberships(&pool, identity_id).await.is_empty());

    // …and leaves the manual one untouched.
    let still: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{manual}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        still,
        vec![identity_id],
        "sync must not be able to reach a manual assignment"
    );
}

/// Only an org's own IdP may speak about its groups (D12). With group sync
/// switched off, the same claim is recorded nowhere.
#[tokio::test]
async fn sync_is_off_by_default() {
    let (base, client, pool, mock, org_id, slug, admin_key) = org_with_idp(false, None).await;
    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-5").await;

    let identity_id = synced_identity_id(&pool, org_id).await;
    assert!(directory_memberships(&pool, identity_id).await.is_empty());
    assert!(
        list_directory_groups(&client, &base, &admin_key)
            .await
            .is_empty(),
        "a claim from an IdP that was not asked to sync must not even be recorded"
    );
}

/// Auth0 namespaces its custom claims, so the claim name has to be
/// configurable rather than hardcoded to `groups`.
#[tokio::test]
async fn a_configured_claim_name_is_honoured() {
    let (base, client, pool, mock, org_id, slug, admin_key) =
        org_with_idp(true, Some("https://acme.example/groups")).await;
    set_claims(
        &client,
        &mock,
        Some(json!({
            "https://acme.example/groups": ["engineering"],
            // The default name is present and must be ignored.
            "groups": ["should-be-ignored"],
        })),
    )
    .await;
    sign_in(&client, &base, &slug, "dgs-6").await;

    let identity_id = synced_identity_id(&pool, org_id).await;
    assert_eq!(
        directory_memberships(&pool, identity_id).await,
        vec!["engineering".to_string()]
    );
    let discovered = list_directory_groups(&client, &base, &admin_key).await;
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0]["external_id"], "engineering");
}

/// Admins membership is held in lockstep with `identities.is_org_admin`. A
/// mapping onto it would let an IdP claim mint an org admin, so every system
/// group refuses the edge.
#[tokio::test]
async fn system_groups_refuse_a_directory_source() {
    let (base, client, _pool, mock, _org_id, slug, admin_key) = org_with_idp(true, None).await;
    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-7").await;

    let eng_dir: Uuid = list_directory_groups(&client, &base, &admin_key).await[0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups?include_self=true"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let system: Vec<&Value> = groups.iter().filter(|g| g["is_system"] == true).collect();
    assert!(
        system.len() >= 2,
        "expected Everyone/Admins/Myself, got {groups:?}"
    );

    for g in system {
        let id: Uuid = g["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            map_source(&client, &base, &admin_key, id, eng_dir).await,
            400,
            "system group {} must refuse a directory source",
            g["name"]
        );
    }
}

/// Unmapping is the revocation path, and it has to be immediate — no sync, no
/// re-login in between.
#[tokio::test]
async fn unmapping_revokes_immediately() {
    let (base, client, pool, mock, org_id, slug, admin_key) = org_with_idp(true, None).await;
    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-8").await;
    let identity_id = synced_identity_id(&pool, org_id).await;

    let engineers = create_group(&client, &base, &admin_key, "Engineers").await;
    let eng_dir: Uuid = list_directory_groups(&client, &base, &admin_key).await[0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        map_source(&client, &base, &admin_key, engineers, eng_dir).await,
        200
    );

    let listed: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{engineers}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed, vec![identity_id]);

    let resp = client
        .delete(format!(
            "{base}/v1/groups/{engineers}/directory-sources/{eng_dir}"
        ))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let listed: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{engineers}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(listed.is_empty(), "unmapping must revoke at once");

    // The directory group and its membership survive — only the edge went.
    assert_eq!(
        directory_memberships(&pool, identity_id).await,
        vec!["engineering".to_string()]
    );
}

/// Hand-removing a directory-derived member would report success and change
/// nothing, leaving an admin believing they had revoked access. Refuse with a
/// message that names the real fix.
#[tokio::test]
async fn a_derived_member_cannot_be_hand_removed() {
    let (base, client, pool, mock, org_id, slug, admin_key) = org_with_idp(true, None).await;
    set_claims(&client, &mock, Some(json!({ "groups": ["engineering"] }))).await;
    sign_in(&client, &base, &slug, "dgs-9").await;
    let identity_id = synced_identity_id(&pool, org_id).await;

    let engineers = create_group(&client, &base, &admin_key, "Engineers").await;
    let eng_dir: Uuid = list_directory_groups(&client, &base, &admin_key).await[0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        map_source(&client, &base, &admin_key, engineers, eng_dir).await,
        200
    );

    let resp = client
        .delete(format!(
            "{base}/v1/groups/{engineers}/members/{identity_id}"
        ))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    let msg = body.to_string();
    assert!(
        msg.contains("directory"),
        "the refusal should point at the mapping: {msg}"
    );

    // Still a member — the refusal was not a silent no-op.
    let listed: Vec<Uuid> = client
        .get(format!("{base}/v1/groups/{engineers}/members"))
        .header("authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed, vec![identity_id]);
}
