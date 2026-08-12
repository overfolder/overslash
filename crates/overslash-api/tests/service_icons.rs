//! Integration tests for service icons: the public `/icons` route and the
//! resolved `icon_url` on the template and service-instance surfaces.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Empty registry — enough for the org-authored template paths.
async fn bootstrap() -> (String, Client, Uuid, String) {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    (format!("http://{addr}"), client, fx.org_id, fx.admin_key)
}

/// The shipped `services/*.yaml` registry, for the tests that assert on real
/// templates like `github`.
async fn bootstrap_with_shipped_registry() -> (String, Client, String) {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, client, admin_key)
}

fn template_yaml(key: &str, icon_line: &str) -> String {
    format!(
        r#"openapi: 3.1.0
info:
  title: {key} template
  key: {key}
{icon_line}
servers:
  - url: https://{key}.example.com
paths:
  /a:
    get:
      operationId: list_a
      summary: List A
      risk: read
"#
    )
}

// ── The public /icons route ───────────────────────────────────────────────

/// The whole point of mounting this outside the auth layer: an `<img>` carries
/// no Authorization header, and cross-origin it carries no cookie either. A
/// future auth-layer refactor that swallows this route breaks every icon in
/// the product, silently.
#[tokio::test]
async fn icons_are_served_without_any_credential() {
    let (base, client, _org, _admin) = bootstrap().await;

    let resp = client
        .get(format!("{base}/icons/github.svg"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"],
        "image/svg+xml; charset=utf-8"
    );
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    assert!(resp.headers().contains_key("cache-control"));
    assert!(resp.headers().contains_key("etag"));
    // An SVG is an active document; the CSP is what stops one executing on the
    // API origin if somebody navigates straight to it.
    assert!(
        resp.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<svg"),
        "expected SVG markup, got: {body:.120}"
    );
}

#[tokio::test]
async fn a_matching_etag_revalidates_as_304() {
    let (base, client, _org, _admin) = bootstrap().await;

    let first = client
        .get(format!("{base}/icons/github.svg"))
        .send()
        .await
        .unwrap();
    let etag = first.headers()["etag"].to_str().unwrap().to_string();

    let second = client
        .get(format!("{base}/icons/github.svg"))
        .header("If-None-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 304);
}

/// A missing icon must 404 rather than fall through to the SPA's
/// catch-all, which would answer 200 `text/html` and render as a broken image
/// instead of triggering the letter-tile fallback.
#[tokio::test]
async fn unknown_icons_404_and_do_not_return_html() {
    let (base, client, _org, _admin) = bootstrap().await;

    for name in ["nope.svg", "GitHub.SVG", "github", "github.png"] {
        let resp = client
            .get(format!("{base}/icons/{name}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "{name} should 404");
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(!ct.contains("text/html"), "{name} returned HTML: {ct}");
    }
}

// ── icon_url on the template surfaces ─────────────────────────────────────

/// The implicit rule, end to end: not one shipped template declares `icon:`,
/// and they still come back with an absolute URL on this deployment's origin.
#[tokio::test]
async fn shipped_templates_resolve_an_implicit_icon_url() {
    let (base, client, admin_key) = bootstrap_with_shipped_registry().await;

    let templates: Vec<Value> = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let github = templates
        .iter()
        .find(|t| t["key"] == "github")
        .expect("github template listed");
    assert_eq!(
        github["icon_url"],
        json!(format!("{base}/icons/github.svg")),
        "github should resolve its icon from its key alone"
    );

    // `github_legacy_oauth` is the one shipped template whose key does not
    // match an asset — it declares `icon: builtin:github` explicitly.
    if let Some(legacy) = templates.iter().find(|t| t["key"] == "github_legacy_oauth") {
        assert_eq!(
            legacy["icon_url"],
            json!(format!("{base}/icons/github.svg"))
        );
    }

    // A template with neither a matching asset nor a declared icon omits the
    // field entirely, rather than sending a URL that would 404.
    let slack = templates.iter().find(|t| t["key"] == "slack");
    if let Some(slack) = slack {
        assert!(
            slack.get("icon_url").is_none(),
            "slack ships no mark yet; icon_url should be omitted, got {:?}",
            slack.get("icon_url")
        );
    }

    // The detail endpoint agrees with the list.
    let detail: Value = client
        .get(format!("{base}/v1/templates/github"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["icon_url"],
        json!(format!("{base}/icons/github.svg"))
    );
}

#[tokio::test]
async fn an_org_template_may_declare_an_https_icon() {
    let (base, client, _org, admin_key) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": template_yaml("icontpl", "  icon: https://cdn.example.com/acme.svg")
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create failed: {:?}", resp.text().await);

    let detail: Value = client
        .get(format!("{base}/v1/templates/icontpl"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["icon_url"],
        json!("https://cdn.example.com/acme.svg")
    );

    let templates: Vec<Value> = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = templates
        .iter()
        .find(|t| t["key"] == "icontpl")
        .expect("listed");
    assert_eq!(row["icon_url"], json!("https://cdn.example.com/acme.svg"));
}

/// An icon is the one piece of template metadata that becomes a URL the
/// operator's browser fetches, so a non-https scheme is refused at write time
/// rather than dropped silently.
#[tokio::test]
async fn a_non_https_icon_is_rejected_at_write_time() {
    let (base, client, _org, admin_key) = bootstrap().await;

    for (key, icon) in [
        ("badicon1", "javascript:alert(1)"),
        ("badicon2", "http://cdn.example.com/a.svg"),
        ("badicon3", "data:image/svg+xml,<svg/>"),
    ] {
        let resp = client
            .post(format!("{base}/v1/templates"))
            .header(auth(&admin_key).0, auth(&admin_key).1)
            .json(&json!({
                "openapi": template_yaml(key, &format!("  icon: \"{icon}\""))
            }))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert_eq!(status, 400, "{icon} should be rejected, got {body}");
        assert!(
            body.contains("invalid_icon"),
            "{icon} should report invalid_icon, got {body}"
        );
    }
}

/// A derived layer keyed `<something>_curated` has no asset of its own, so it
/// only keeps the base's mark because the implicit lookup runs at compile time
/// and the fold inherits it.
#[tokio::test]
async fn a_derived_layer_inherits_and_can_override_the_base_icon() {
    let (base, client, _org, admin_key) = bootstrap().await;

    client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "openapi": template_yaml("iconbase", "  icon: https://cdn.example.com/base.svg")
        }))
        .send()
        .await
        .unwrap();

    // Inherits when the delta says nothing.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "iconbase",
            "key": "iconbase_curated",
            "display_name": "Curated",
            "delta": { "allowlist": ["list_a"] },
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let created: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "create layer: {created:?}");
    let layer_id = created["id"].as_str().expect("layer id").to_string();

    let detail: Value = client
        .get(format!("{base}/v1/templates/iconbase_curated"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["icon_url"],
        json!("https://cdn.example.com/base.svg"),
        "a layer with no icon of its own must keep the base's"
    );

    // And a delta icon rebrands it.
    let resp = client
        .put(format!("{base}/v1/templates/{layer_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "delta": { "allowlist": ["list_a"], "icon": "https://cdn.example.com/layer.svg" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "update layer: {:?}", resp.text().await);

    let detail: Value = client
        .get(format!("{base}/v1/templates/iconbase_curated"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        detail["icon_url"],
        json!("https://cdn.example.com/layer.svg")
    );
}

/// The derived-layer write path must not be a way around the https-only rule
/// the standalone path enforces.
#[tokio::test]
async fn a_delta_icon_cannot_smuggle_a_javascript_url() {
    let (base, client, _org, admin_key) = bootstrap().await;

    client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": template_yaml("smugglebase", "") }))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "smugglebase",
            "key": "smugglebase_bad",
            "display_name": "Bad",
            "delta": { "icon": "javascript:alert(1)" },
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 400, "delta icon should be rejected, got {body}");
    assert!(body.contains("invalid_icon"), "got {body}");
}

// ── icon_url on service instances ─────────────────────────────────────────

#[tokio::test]
async fn a_service_instance_carries_its_templates_icon() {
    let (base, client, admin_key) = bootstrap_with_shipped_registry().await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "template_key": "github", "name": "gh" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "create service: {:?}",
        resp.text().await
    );

    let services: Vec<Value> = client
        .get(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let gh = services
        .iter()
        .find(|s| s["name"] == "gh")
        .expect("service listed");
    assert_eq!(
        gh["icon_url"],
        json!(format!("{base}/icons/github.svg")),
        "an instance renders its template's mark"
    );
}
