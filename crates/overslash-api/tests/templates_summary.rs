//! `info.summary` on the `/v1/templates` surfaces: the one-line catalog
//! tagline UI catalogs show in place of the agent-facing `description`.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

fn minimal_openapi(key: &str, display_name: &str) -> String {
    common::render_openapi(
        include_str!("fixtures/openapi/minimal.yaml.tmpl"),
        &[("key", key), ("display_name", display_name)],
    )
}

/// The minimal fixture with an `info.summary` line added under `title`.
fn openapi_with_summary(key: &str, summary: &str) -> String {
    minimal_openapi(key, "Summarized").replacen(
        "  title: Summarized\n",
        &format!("  title: Summarized\n  summary: {summary}\n"),
        1,
    )
}

async fn get_json(client: &Client, url: String, key: &str) -> Value {
    let resp = client
        .get(url)
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

fn find<'a>(list: &'a Value, key: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|t| t["key"] == key)
        .unwrap_or_else(|| panic!("{key} missing from {list}"))
}

#[tokio::test]
async fn global_template_summary_is_on_list_detail_and_admin() {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let key = &fixtures.admin_key;

    let list = get_json(&client, format!("{base}/v1/templates"), key).await;
    let gh = find(&list, "github");
    let summary = gh["summary"].as_str().expect("github has a summary");
    assert!(!summary.contains('\n') && summary.chars().count() <= 80);
    assert_ne!(gh["summary"], gh["description"]);

    let detail = get_json(&client, format!("{base}/v1/templates/github"), key).await;
    assert_eq!(detail["summary"], gh["summary"]);

    let admin = get_json(&client, format!("{base}/v1/templates/admin"), key).await;
    assert_eq!(find(&admin, "github")["summary"], gh["summary"]);
}

#[tokio::test]
async fn org_template_summary_is_present_when_set_and_omitted_when_unset() {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let key = &fixtures.admin_key;

    for openapi in [
        openapi_with_summary("tagged-api", "Short catalog tagline"),
        minimal_openapi("untagged-api", "Untagged"),
    ] {
        let resp = client
            .post(format!("{base}/v1/templates"))
            .header(auth(key).0, auth(key).1)
            .json(&json!({ "openapi": openapi }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    }

    let list = get_json(&client, format!("{base}/v1/templates"), key).await;
    assert_eq!(
        find(&list, "tagged-api")["summary"],
        "Short catalog tagline"
    );
    let untagged = find(&list, "untagged-api");
    assert!(
        !untagged.as_object().unwrap().contains_key("summary"),
        "an unset summary is omitted, not null: {untagged}"
    );

    let detail = get_json(&client, format!("{base}/v1/templates/tagged-api"), key).await;
    assert_eq!(detail["summary"], "Short catalog tagline");
    let detail = get_json(&client, format!("{base}/v1/templates/untagged-api"), key).await;
    assert!(!detail.as_object().unwrap().contains_key("summary"));
}
