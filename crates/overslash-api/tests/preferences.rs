//! Integration tests for `/auth/me/preferences` and the underlying
//! `UserScope::update_self_preferences` / `get_self_identity` scope methods.

mod common;

use overslash_db::UserScope;
use serde_json::{Value, json};
use uuid::Uuid;

/// Mint a dev session and return `(base_url, http_client, session_token)`.
async fn dev_session() -> (String, reqwest::Client, String) {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let body: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = body["token"].as_str().unwrap().to_string();
    (base, client, token)
}

// ── HTTP-level tests ────────────────────────────────────────────────────

#[tokio::test]
async fn get_preferences_without_session_returns_401() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/me/preferences"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_preferences_with_invalid_session_returns_401() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!("{base}/auth/me/preferences"))
        .header("cookie", "oss_session=not-a-real-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_preferences_with_valid_session_returns_defaults() {
    let (base, client, token) = dev_session().await;

    let resp = client
        .get(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A freshly-bootstrapped identity has no stored prefs — `parse` of the
    // empty JSONB default yields a blank `UserPreferences`, which serializes
    // to `{}` because every field skips serialization when `None`.
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn put_preferences_persists_and_get_returns_them() {
    let (base, client, token) = dev_session().await;

    let put = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({ "theme": "dark", "time_display": "absolute" }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    let put_body: Value = put.json().await.unwrap();
    assert_eq!(put_body["theme"], "dark");
    assert_eq!(put_body["time_display"], "absolute");

    // Read-back through a fresh GET to make sure the row was actually written.
    let get_body: Value = client
        .get(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(get_body["theme"], "dark");
    assert_eq!(get_body["time_display"], "absolute");
}

#[tokio::test]
async fn put_preferences_partial_update_merges_with_existing() {
    let (base, client, token) = dev_session().await;

    // Seed both fields.
    let _ = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({ "theme": "light", "time_display": "relative" }))
        .send()
        .await
        .unwrap();

    // Now patch only `theme`.
    let patched: Value = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({ "theme": "dark" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(patched["theme"], "dark");
    // The previously-stored `time_display` must survive the partial PUT —
    // this is the whole point of merge semantics.
    assert_eq!(patched["time_display"], "relative");
}

#[tokio::test]
async fn put_preferences_concurrent_writes_do_not_clobber_each_other() {
    // Race regression for `update_self_preferences`. The handler reads,
    // merges, and writes inside a `SELECT ... FOR UPDATE` transaction so two
    // concurrent PUTs touching disjoint keys must both survive — the older
    // read-modify-write implementation could lose one of them.
    let (base, client, token) = dev_session().await;

    // Hammer alternating-key PUTs in parallel a few times. Without the
    // `FOR UPDATE`, this loop reliably loses one key on at least one round.
    for round in 0..5 {
        let theme_put = client
            .put(format!("{base}/auth/me/preferences"))
            .header("cookie", format!("oss_session={token}"))
            .json(&json!({ "theme": "dark" }))
            .send();
        let display_put = client
            .put(format!("{base}/auth/me/preferences"))
            .header("cookie", format!("oss_session={token}"))
            .json(&json!({ "time_display": "absolute" }))
            .send();
        let (a, b) = tokio::join!(theme_put, display_put);
        assert_eq!(a.unwrap().status(), 200, "round {round}: theme PUT failed");
        assert_eq!(
            b.unwrap().status(),
            200,
            "round {round}: time_display PUT failed"
        );

        let merged: Value = client
            .get(format!("{base}/auth/me/preferences"))
            .header("cookie", format!("oss_session={token}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            merged["theme"], "dark",
            "round {round}: theme was clobbered"
        );
        assert_eq!(
            merged["time_display"], "absolute",
            "round {round}: time_display was clobbered"
        );
    }
}

#[tokio::test]
async fn put_preferences_rejects_unknown_fields_silently() {
    // serde's default is to ignore unknown fields. Asserting it explicitly so
    // a future `#[serde(deny_unknown_fields)]` change is a deliberate choice
    // rather than an accidental break of dashboard forward-compat.
    let (base, client, token) = dev_session().await;
    let resp = client
        .put(format!("{base}/auth/me/preferences"))
        .header("cookie", format!("oss_session={token}"))
        .json(&json!({ "theme": "dark", "future_setting": "whatever" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["theme"], "dark");
    assert!(body.get("future_setting").is_none());
}

// ── Direct UserScope method tests ───────────────────────────────────────
//
// These bypass HTTP entirely and exercise the scope methods against a real
// PgPool. Tests construct a `UserScope` with `UserScope::new` (the same
// constructor the Axum extractor calls). They cover the not-found path and
// the cross-tenant isolation guarantee, neither of which is reachable from
// HTTP without significantly more setup.

#[tokio::test]
async fn user_scope_get_self_identity_returns_none_for_unknown_user() {
    let pool = common::test_pool().await;
    let scope = UserScope::new(Uuid::new_v4(), Uuid::new_v4(), pool);
    let result = scope.get_self_identity().await.unwrap();
    assert!(
        result.is_none(),
        "scope for a non-existent user must return None, not error"
    );
}

#[tokio::test]
async fn user_scope_update_self_preferences_returns_none_for_unknown_user() {
    let pool = common::test_pool().await;
    let scope = UserScope::new(Uuid::new_v4(), Uuid::new_v4(), pool);
    let result = scope
        .update_self_preferences(|_| json!({ "theme": "dark" }))
        .await
        .unwrap();
    assert!(
        result.is_none(),
        "update against a non-existent user must return None, not insert"
    );
}

#[tokio::test]
async fn user_scope_update_self_preferences_round_trips_via_direct_pool() {
    // Positive direct-pool path: seed a real identity through the API on a
    // cloned pool handle, then drive the scope methods directly. This is the
    // only test that exercises the merge callback against a row that
    // actually exists, without going through HTTP.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let dev: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = dev["org_id"].as_str().unwrap().parse().unwrap();
    let user_id: Uuid = dev["identity_id"].as_str().unwrap().parse().unwrap();

    let scope = UserScope::new(org_id, user_id, pool);

    // First write: callback receives the empty default `{}`.
    let row = scope
        .update_self_preferences(|existing| {
            assert!(
                existing.as_object().map(|o| o.is_empty()).unwrap_or(false),
                "first write should see an empty preferences object, got: {existing}"
            );
            json!({ "theme": "dark" })
        })
        .await
        .unwrap()
        .expect("identity exists, must return Some");
    assert_eq!(row.preferences, json!({ "theme": "dark" }));

    // Second write: callback now receives the value the first write stored.
    let row = scope
        .update_self_preferences(|existing| {
            assert_eq!(existing, &json!({ "theme": "dark" }));
            // Simulate a partial-merge that the route layer would compute.
            json!({ "theme": "dark", "time_display": "absolute" })
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.preferences,
        json!({ "theme": "dark", "time_display": "absolute" })
    );

    // And get_self_identity reads back the latest written value.
    let ident = scope.get_self_identity().await.unwrap().unwrap();
    assert_eq!(ident.id, user_id);
    assert_eq!(ident.org_id, org_id);
    assert_eq!(
        ident.preferences,
        json!({ "theme": "dark", "time_display": "absolute" })
    );
}

#[tokio::test]
async fn user_scope_cannot_read_user_in_a_different_org() {
    // Mint a real user via the dev login flow, then try to read it through
    // a UserScope whose org_id is wrong. `get_self_identity` filters on
    // (id = user_id AND org_id = self.org_id), so the lookup must miss.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let dev: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let real_user_id: Uuid = dev["identity_id"].as_str().unwrap().parse().unwrap();

    // Right user, wrong org → must be invisible.
    let bad_scope = UserScope::new(Uuid::new_v4(), real_user_id, pool.clone());
    assert!(bad_scope.get_self_identity().await.unwrap().is_none());

    // And update_self_preferences must also refuse to touch the row.
    let updated = bad_scope
        .update_self_preferences(|_| json!({ "theme": "dark" }))
        .await
        .unwrap();
    assert!(updated.is_none());
}
