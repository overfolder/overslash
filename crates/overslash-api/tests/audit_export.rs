//! `GET /v1/audit/export`: the whole filtered range, streamed as CSV or JSONL.
// Seeding thousands of audit rows needs one set-based INSERT, not the logger.
#![allow(clippy::disallowed_methods)]

use crate::common;

use crate::common::{auth, bootstrap_org_identity, start_api};
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// More than one export batch (1000), so every test crosses a keyset boundary.
const SEEDED: i64 = 1203;

/// Seed `SEEDED` rows one second apart, newest at `newest`.
async fn seed(pool: &PgPool, org_id: Uuid, newest: OffsetDateTime) {
    sqlx::query(
        "INSERT INTO audit_log (org_id, action, detail, description, created_at)
         SELECT $1, 'bulk.seeded', jsonb_build_object('n', g), 'row ' || g,
                $2 - make_interval(secs => g)
           FROM generate_series(0, $3 - 1) AS g",
    )
    .bind(org_id)
    .bind(newest)
    .bind(SEEDED)
    .execute(pool)
    .await
    .unwrap();
}

async fn export(base: &str, client: &Client, key: &str, qs: &str) -> reqwest::Response {
    client
        .get(format!("{base}/v1/audit/export?{qs}"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
}

fn ts(t: OffsetDateTime) -> String {
    urlencode(&t.format(&Rfc3339).unwrap())
}

fn urlencode(s: &str) -> String {
    s.replace(':', "%3A").replace('+', "%2B")
}

#[tokio::test]
async fn test_audit_export_jsonl_streams_every_row_past_one_batch() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, _ident, key_a, _) = bootstrap_org_identity(&base, &client).await;
    seed(&pool, org_a, OffsetDateTime::now_utc()).await;

    let resp = export(&base, &client, &key_a, "format=jsonl&action=bulk.seeded").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "application/x-ndjson"
    );
    let disposition = resp.headers()["content-disposition"].to_str().unwrap();
    assert!(disposition.starts_with("attachment; filename=\"audit-"));
    assert!(disposition.ends_with(".jsonl\""), "{disposition}");

    let body = resp.text().await.unwrap();
    let rows: Vec<Value> = body
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len() as i64, SEEDED);
    // Newest first, and no row repeated or skipped at the batch boundary.
    let ns: Vec<i64> = rows
        .iter()
        .map(|r| r["detail"]["n"].as_i64().unwrap())
        .collect();
    assert_eq!(ns, (0..SEEDED).collect::<Vec<_>>());
    // Same shape as `GET /v1/audit`.
    assert_eq!(rows[0]["action"], "bulk.seeded");
    assert!(rows[0]["identity_path_ids"].is_array());
}

#[tokio::test]
async fn test_audit_export_csv_covers_the_whole_range() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, _ident, key_a, _) = bootstrap_org_identity(&base, &client).await;
    seed(&pool, org_a, OffsetDateTime::now_utc()).await;

    let resp = export(&base, &client, &key_a, "format=csv&action=bulk.seeded").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "text/csv; charset=utf-8"
    );
    let body = resp.text().await.unwrap();
    let lines: Vec<&str> = body.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines[0],
        "timestamp,identity_id,user,agent,action,resource_type,resource_id,description,ip_address,tags,detail"
    );
    assert_eq!(lines.len() as i64, SEEDED + 1);
    assert!(lines[1].contains(",bulk.seeded,"), "{}", lines[1]);
    assert!(lines[1].contains(",row 0,"), "{}", lines[1]);
}

#[tokio::test]
async fn test_audit_export_honours_since_until() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, _ident, key_a, _) = bootstrap_org_identity(&base, &client).await;
    let newest = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    seed(&pool, org_a, newest).await;

    // Rows n = 10..=109: both bounds are inclusive.
    let until = newest - time::Duration::seconds(10);
    let since = newest - time::Duration::seconds(109);
    let qs = format!(
        "format=jsonl&action=bulk.seeded&since={}&until={}",
        ts(since),
        ts(until)
    );
    let body = export(&base, &client, &key_a, &qs)
        .await
        .text()
        .await
        .unwrap();
    let ns: Vec<i64> = body
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["detail"]["n"]
                .as_i64()
                .unwrap()
        })
        .collect();
    assert_eq!(ns, (10..=109).collect::<Vec<_>>());
}

#[tokio::test]
async fn test_audit_export_csv_escapes_quotes_newlines_and_formulas() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, _ident, key_a, _) = bootstrap_org_identity(&base, &client).await;
    for (action, description) in [
        ("csv.tricky", "a,\"b\"\nc"),
        ("csv.formula", "=HYPERLINK(\"http://evil\")"),
    ] {
        sqlx::query(
            "INSERT INTO audit_log (org_id, action, detail, description) VALUES ($1, $2, '{}', $3)",
        )
        .bind(org_a)
        .bind(action)
        .bind(description)
        .execute(&pool)
        .await
        .unwrap();
    }

    let body = export(&base, &client, &key_a, "format=csv&action_contains=csv.")
        .await
        .text()
        .await
        .unwrap();
    assert!(body.contains(",\"a,\"\"b\"\"\nc\","), "{body}");
    assert!(
        body.contains(",\"'=HYPERLINK(\"\"http://evil\"\")\","),
        "{body}"
    );
}

#[tokio::test]
async fn test_audit_export_is_org_scoped() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, _ia, _key_a, _) = bootstrap_org_identity(&base, &client).await;
    let (_org_b, _ib, key_b, _) = bootstrap_org_identity(&base, &client).await;
    seed(&pool, org_a, OffsetDateTime::now_utc()).await;

    let body = export(&base, &client, &key_b, "format=jsonl&action=bulk.seeded")
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(body, "");
    let csv = export(&base, &client, &key_b, "format=csv&action=bulk.seeded")
        .await
        .text()
        .await
        .unwrap();
    assert_eq!(csv.split("\r\n").filter(|l| !l.is_empty()).count(), 1);
}

#[tokio::test]
async fn test_audit_export_rejects_unknown_or_missing_format() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, key, _) = bootstrap_org_identity(&base, &client).await;

    assert_eq!(
        export(&base, &client, &key, "format=xlsx").await.status(),
        400
    );
    assert_eq!(export(&base, &client, &key, "").await.status(), 400);
    let anon = client
        .get(format!("{base}/v1/audit/export?format=csv"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status(), 401);
}

#[tokio::test]
async fn test_audit_export_is_itself_audited() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_a, ident_a, key_a, _) = bootstrap_org_identity(&base, &client).await;
    seed(&pool, org_a, OffsetDateTime::now_utc()).await;

    export(&base, &client, &key_a, "format=csv&action=bulk.seeded")
        .await
        .text()
        .await
        .unwrap();

    // Written from the stream's drop, on a spawned task: give it a moment.
    let mut rows: Vec<Value> = Vec::new();
    for _ in 0..50 {
        rows = client
            .get(format!("{base}/v1/audit?action=audit.exported"))
            .header(auth(&key_a).0, auth(&key_a).1)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(rows.len(), 1, "one audit.exported row");
    let row = &rows[0];
    assert_eq!(row["identity_id"], json!(ident_a));
    assert_eq!(row["detail"]["format"], "csv");
    assert_eq!(row["detail"]["row_count"], json!(SEEDED));
    assert_eq!(row["detail"]["completed"], true);
    assert_eq!(row["detail"]["query"], "format=csv&action=bulk.seeded");
}
