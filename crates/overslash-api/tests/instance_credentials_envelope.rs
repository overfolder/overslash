//! An instance whose credentials can't resolve gets a typed
//! `needs_authentication` naming what to configure — not an unauthenticated
//! request upstream.
//!
//! `resolve_instance_auth` has always refused to emit a *partial* credential
//! set: an unbound secret slot, or (since D38) a `required` config var with no
//! value, takes the whole scheme down rather than sending a half-composed
//! header. What it did next was the problem. It fell through to
//! `resolve_service_auth`, which only knows OAuth and the env-backed OAuth
//! client cascade; for a secret-backed template like `email` that resolved
//! nothing, and the call went out with no credentials at all. The caller got
//! whatever the upstream says to an empty Authorization header — a 401 from a
//! real overfwd — instead of "go set `mailbox_user`".
//!
//! The safety half of that contract is pinned in `email_overfwd.rs`
//! (`email_unbound_mailbox_never_injects_gateway_key_alone`,
//! `email_missing_required_config_never_sends_a_truncated_credential`). This
//! file pins the recovery half: the envelope, the fields it names, and the
//! dashboard link that fixes it.
//!
//! Run with `--test-threads=4` (see CLAUDE.md).

#![allow(clippy::disallowed_methods)]

use serde_json::{Value, json};

use crate::common;
use crate::email_overfwd::{
    MAILBOX_PASS, MAILBOX_USER, setup_email_instance, setup_email_instance_custom,
    start_mock_overfwd,
};

/// `POST /v1/actions/call` with the given body, as the agent.
async fn call(base: &str, agent_key: &str, body: Value) -> (u16, Value) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    let json = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    (status, json)
}

fn search_call() -> Value {
    json!({ "service": "email", "action": "search", "params": { "query": "UNSEEN" } })
}

/// The unbound-slot case: the org gateway key exists but the instance binds no
/// mailbox password. Before, this dialled overfwd with neither credential and
/// surfaced the gateway's 401. Now it names the slot and links to the form.
#[tokio::test]
async fn email_unbound_mailbox_returns_needs_authentication() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, false, true).await;

    let (status, body) = call(&base, &agent_key, search_call()).await;

    assert_eq!(status, 401, "expected the typed 401 envelope, got: {body}");
    assert_eq!(body["error"], "needs_authentication", "{body}");
    assert_eq!(body["service"], "email", "{body}");

    // Both halves of the mailbox credential are unset on this instance: the
    // password slot has no binding and the username config var no value. The
    // envelope names them so the agent can tell the user what to fill in,
    // rather than making them guess from "401 from mailbox.overslash.com".
    let missing: Vec<&str> = body["missing_credentials"]
        .as_array()
        .unwrap_or_else(|| panic!("no missing_credentials in {body}"))
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        missing.contains(&"mailbox_pass"),
        "the unbound slot must be named: {body}"
    );

    // The optional org-source gateway key IS configured here, so it must not
    // be reported as something the user has to supply.
    assert!(
        !missing.contains(&"gateway"),
        "a satisfied optional slot must not be reported missing: {body}"
    );

    // Rule 6: the envelope points at the surface that fixes it.
    let hint = body["hint_url"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"));
    assert!(
        hint.contains("/services/") && hint.ends_with("?tab=credentials"),
        "hint_url must deep-link the instance's credentials form: {hint}"
    );
    assert!(
        hint.contains(body["service_instance_id"].as_str().unwrap()),
        "hint_url must name the instance that needs configuring: {hint} / {body}"
    );

    // No consent page exists for a secret-backed template, so the OAuth-shaped
    // fields are absent rather than null — consumers branch on key presence.
    assert!(body.get("auth_url").is_none(), "{body}");
    assert!(body.get("provider").is_none(), "{body}");

    assert!(
        sink.lock().unwrap().is_empty(),
        "nothing may reach the gateway once the call is refused"
    );
}

/// The D38 config-var case: the password is bound but the `required` username
/// is unset. Same envelope, naming the config key instead of the slot.
#[tokio::test]
async fn email_missing_required_config_returns_needs_authentication() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "status": "active",
            "credentials": { "mailbox_pass": "mailbox_pass" },
            // No `config`: the username is missing.
        }),
    )
    .await;

    let (status, body) = call(&base, &agent_key, search_call()).await;

    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "needs_authentication", "{body}");
    let missing: Vec<&str> = body["missing_credentials"]
        .as_array()
        .unwrap_or_else(|| panic!("no missing_credentials in {body}"))
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        missing,
        vec!["mailbox_user"],
        "only the unset config var is missing — the password IS bound: {body}"
    );
    assert!(body["hint_url"].is_string(), "{body}");
    assert!(sink.lock().unwrap().is_empty(), "must not dial the gateway");
}

/// `?wrap=true` re-renders auth 401s as a 200 with a `status` discriminant, so
/// MCP-style callers get one response shape. The two new fields have to ride
/// that path too, or the wrapped caller loses the only recovery affordance the
/// secret-backed shape has.
#[tokio::test]
async fn email_needs_authentication_wraps_as_ok() {
    let pool = common::test_pool().await;
    let (gateway_url, _sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, false, true).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call?wrap=true"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&search_call())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "wrap=true must not 401");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "needs_authentication", "{body}");
    assert!(
        body["missing_credentials"].is_array() && body["hint_url"].is_string(),
        "wrapped envelope dropped the secret-backed fields: {body}"
    );
}

/// The gate runs in the verb shape too. Both shapes call
/// `resolve_instance_auth`, so gating only the action shape would leave
/// `service` + HTTP verb dialling upstream unauthenticated.
#[tokio::test]
async fn verb_shape_gates_unbound_secret_instance() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, false, true).await;

    let (status, body) = call(
        &base,
        &agent_key,
        json!({
            "service": "email",
            "method": "POST",
            "path": "/email/search",
            "body": "{\"query\":\"UNSEEN\"}"
        }),
    )
    .await;

    assert_eq!(status, 401, "verb shape must gate the same way: {body}");
    assert_eq!(body["error"], "needs_authentication", "{body}");
    assert!(body["hint_url"].is_string(), "{body}");
    assert!(sink.lock().unwrap().is_empty(), "must not dial the gateway");
}

/// A global template invoked by key with no instance row at all. There is
/// nothing to point a credentials form at, so the hint sends the caller to the
/// wizard that creates the instance in the first place.
#[tokio::test]
async fn secret_template_without_instance_points_at_create() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Permission only — deliberately no `/v1/services` instance.
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": ident_id, "action_pattern": "test_email:*:*" }))
        .send()
        .await
        .unwrap();

    let (status, body) = call(
        &base,
        &agent_key,
        json!({ "service": "test_email", "action": "list_messages", "params": {} }),
    )
    .await;

    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "needs_authentication", "{body}");
    assert_eq!(
        body["missing_credentials"],
        json!(["token"]),
        "the template's one required slot: {body}"
    );
    let hint = body["hint_url"]
        .as_str()
        .unwrap_or_else(|| panic!("{body}"));
    assert!(
        hint.ends_with("/services/new?template=test_email"),
        "with no instance the fix is to create one: {hint}"
    );
    assert!(
        body.get("service_instance_id").is_none(),
        "there is no instance to name: {body}"
    );
}

/// The over-gating guard. `email`'s gateway slot is `optional` — a keyless
/// overfwd deployment is a supported configuration, not a misconfigured one.
/// A fully-bound mailbox with no gateway key must still go out.
#[tokio::test]
async fn optional_only_credentials_still_reach_upstream() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    // bind_mailbox = true, seed_gateway_key = false.
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, true, false).await;

    let (status, body) = call(&base, &agent_key, search_call()).await;

    assert_eq!(
        status, 200,
        "an unset OPTIONAL credential must not trip the gate: {body}"
    );
    let reqs = sink.lock().unwrap();
    assert_eq!(reqs.len(), 1, "the call must reach the gateway");
    assert!(
        reqs[0].mailbox_auth.is_some(),
        "the bound mailbox credential still rides: {:?}",
        reqs[0].mailbox_auth
    );
    assert!(
        reqs[0].authorization.is_none(),
        "no gateway key was configured, so none is sent: {:?}",
        reqs[0].authorization
    );
    let _ = MAILBOX_USER;
}

/// Regression: the OAuth-shaped envelope is untouched. An OAuth template with
/// no connection still gets `auth_url` and none of the secret-backed fields —
/// the two builders' domains must stay disjoint.
#[tokio::test]
async fn oauth_template_envelope_is_unchanged() {
    let pool = common::test_pool().await;
    // Minting a consent link needs an OAuth client; without one the cascade
    // 400s before the envelope is built. Same setup as `actions_reauth.rs` —
    // nextest runs each test in its own process, so the env writes don't leak.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_secret");
    }
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    common::grant_service_to_everyone(&base, &client, &admin_key, "x").await;
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": ident_id, "action_pattern": "x:*:*" }))
        .send()
        .await
        .unwrap();

    let (status, body) = call(
        &base,
        &agent_key,
        json!({ "service": "x", "action": "get_me", "params": {} }),
    )
    .await;

    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "needs_authentication", "{body}");
    assert!(
        body["auth_url"].is_string(),
        "OAuth recovery is still a consent link: {body}"
    );
    assert!(
        body.get("missing_credentials").is_none() && body.get("hint_url").is_none(),
        "the secret-backed fields must not leak onto the OAuth shape: {body}"
    );
}
