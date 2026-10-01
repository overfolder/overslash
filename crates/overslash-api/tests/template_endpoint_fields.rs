//! The instance form's endpoint and config fields, as `GET /v1/templates/{key}`
//! describes them.
//!
//! Every template's endpoint can be overridden per instance, so
//! `configurable_url` is true for all but the two with nothing to override.
//! What varies is prominence: a field is shown up front when the instance
//! cannot work without it, or when the template promotes it
//! (`x-overslash-promoted`), and otherwise sits behind "Show more options"
//! with its `default_url` / `default` visible.

use serde_json::{Value, json};

use crate::common::{self, auth};

async fn detail(key: &str) -> Value {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        // Present only so `email` loads; LANGFUSE_URL is deliberately unset so
        // the template's own literal default is what the form shows.
        overslash_core::template_vars::Vars::from_pairs([(
            "MAILBOX_HOST",
            "mailbox.overslash.com",
        )]),
        |_| {},
    )
    .await;
    let (_org, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let resp = client
        .get(format!("{base}/v1/templates/{key}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template {key}");
    resp.json().await.unwrap()
}

/// The report that opened this: a Langfuse region other than EU could not be
/// chosen from the dashboard. The field is now promoted, and its default is
/// named rather than implied.
#[tokio::test]
async fn langfuse_promotes_its_endpoint_and_names_the_default() {
    let d = detail("langfuse").await;
    assert_eq!(d["configurable_url"], json!(true));
    assert_eq!(d["url_promoted"], json!(true));
    assert_eq!(d["default_url"], json!("https://cloud.langfuse.com"));
}

/// An ordinary single-endpoint SaaS is still overridable, just not promoted.
#[tokio::test]
async fn a_plain_template_offers_its_endpoint_without_promoting_it() {
    let d = detail("github").await;
    assert_eq!(d["configurable_url"], json!(true));
    assert_eq!(d["url_promoted"], json!(false));
    assert_eq!(d["default_url"], json!("https://api.github.com"));
}

/// The pseudo-service takes a full URL on every call; there is no instance
/// endpoint to set.
#[tokio::test]
async fn the_http_pseudo_service_has_no_endpoint_field() {
    let d = detail("http").await;
    assert_eq!(d["configurable_url"], json!(false));
    assert!(d.get("default_url").is_none());
}

/// Promotion reaches instance-config params and config vars alike.
#[tokio::test]
async fn email_promotes_its_imap_and_smtp_pins() {
    let d = detail("email").await;
    let params = d["instance_config_params"].as_array().unwrap();
    let field = |name: &str| {
        params
            .iter()
            .find(|p| p["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing from {params:?}"))
    };
    assert_eq!(field("X-Mailbox-Imap")["promoted"], json!(true));
    assert_eq!(field("X-Mailbox-Smtp")["promoted"], json!(true));
    // Required with no default: shown up front without needing the flag.
    assert_eq!(field("mailbox_user")["required"], json!(true));
    assert!(field("mailbox_user").get("promoted").is_none());
}
