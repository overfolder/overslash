//! Secret rotation age sweep (CASA 6.7.1).
//!
//! Secret Manager's `rotation` block only sends a reminder on a fixed
//! calendar. It does not know whether anyone acted on it, and no platform
//! metric exposes a version's age. So this sweep reads each secret's metadata,
//! finds its newest enabled version, and compares that version's age with the
//! secret's own `rotationPeriod`. The period lives in Terraform
//! (`infra/modules/secret-manager/rotation.tf`) and nowhere else.
//!
//! Metadata only: the job's `roles/secretmanager.viewer` cannot read a payload,
//! and these calls are not `AccessSecretVersion`, so they do not trip the
//! unexpected-access alert. They are audit-logged, which is why the sweep runs
//! hourly and not on every 5-minute tick.

use std::future::Future;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Timelike, Utc};
use serde::Deserialize;
use tracing::warn;

use crate::cloud_monitoring::{MonitoredResource, TimeSeries, make_gauge, make_gauge_int};
use crate::metric;

const API_BASE: &str = "https://secretmanager.googleapis.com/v1";
const CLASS_LABEL: &str = "rotation-class";
const EXEMPT_CLASS: &str = "exempt";
const SECONDS_PER_DAY: f64 = 86_400.0;

/// The scheduler ticks every 5 minutes, so exactly one tick an hour lands here.
const SWEEP_MINUTES: u32 = 5;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretPage {
    #[serde(default)]
    secrets: Vec<Secret>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionPage {
    #[serde(default)]
    versions: Vec<Version>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Secret {
    name: String,
    #[serde(default)]
    labels: std::collections::HashMap<String, String>,
    rotation: Option<Rotation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rotation {
    rotation_period: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    create_time: DateTime<Utc>,
}

impl Secret {
    fn id(&self) -> &str {
        self.name.rsplit('/').next().unwrap_or(&self.name)
    }

    fn class(&self) -> Option<&str> {
        self.labels.get(CLASS_LABEL).map(String::as_str)
    }

    fn is_exempt(&self) -> bool {
        self.class() == Some(EXEMPT_CLASS)
    }
}

#[derive(Debug, PartialEq)]
pub struct SecretAge {
    pub secret: String,
    pub class: String,
    pub age_days: f64,
    pub overdue_days: f64,
}

/// A secret the sweep cannot put an age against. Each one is a gap in the
/// control, so it alerts instead of being skipped.
#[derive(Debug, PartialEq)]
pub struct Unmeasured {
    pub secret: String,
    pub reason: &'static str,
}

#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub ages: Vec<SecretAge>,
    pub unmeasured: Vec<Unmeasured>,
}

/// Whether this tick is the hourly one.
pub fn is_due(now: DateTime<Utc>) -> bool {
    now.minute() < SWEEP_MINUTES
}

/// Read every secret in the project and age the ones that declare a period.
pub async fn sweep(
    project_id: &str,
    token: &str,
    client: &reqwest::Client,
    now: DateTime<Utc>,
) -> Result<Report> {
    let secrets_url = format!("{API_BASE}/projects/{project_id}/secrets");
    let secrets = collect_pages(|page_token| {
        let url = &secrets_url;
        async move {
            let page: SecretPage = get_page(client, token, url, &[], page_token).await?;
            Ok((page.secrets, page.next_page_token))
        }
    })
    .await
    .context("failed to list secrets")?;

    let mut measured = Vec::with_capacity(secrets.len());
    for secret in secrets {
        if secret.is_exempt() {
            continue;
        }
        let versions_url = format!("{API_BASE}/{}/versions", secret.name);
        let versions = collect_pages(|page_token| {
            let url = &versions_url;
            async move {
                let page: VersionPage = get_page(
                    client,
                    token,
                    url,
                    &[("filter", "state:ENABLED")],
                    page_token,
                )
                .await?;
                Ok((page.versions, page.next_page_token))
            }
        })
        .await
        .with_context(|| format!("failed to list versions of {}", secret.id()))?;
        let newest = versions.iter().map(|v| v.create_time).max();
        measured.push((secret, newest));
    }
    evaluate(&measured, now)
}

async fn get_page<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    token: &str,
    url: &str,
    query: &[(&str, &str)],
    page_token: Option<String>,
) -> Result<T> {
    let mut params = vec![("pageSize", "100")];
    params.extend_from_slice(query);
    if let Some(page_token) = &page_token {
        params.push(("pageToken", page_token));
    }
    let url = reqwest::Url::parse_with_params(url, params)?;
    let response = client.get(url).bearer_auth(token).send().await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Secret Manager API error {status}: {body}");
    }
    Ok(response.json().await?)
}

/// Follow `nextPageToken` to the end. The API returns an absent or empty token
/// on the last page.
async fn collect_pages<T, F, Fut>(mut fetch: F) -> Result<Vec<T>>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<(Vec<T>, Option<String>)>>,
{
    let mut items = Vec::new();
    let mut page_token = None;
    loop {
        let (mut page, next) = fetch(page_token).await?;
        items.append(&mut page);
        match next.filter(|t| !t.is_empty()) {
            Some(next) => page_token = Some(next),
            None => return Ok(items),
        }
    }
}

/// `rotationPeriod` is a protobuf Duration: decimal seconds with an `s` suffix.
fn parse_period_secs(period: &str) -> Result<f64> {
    period
        .strip_suffix('s')
        .and_then(|secs| secs.parse::<f64>().ok())
        .filter(|secs| *secs > 0.0)
        .with_context(|| format!("unparseable rotationPeriod {period:?}"))
}

fn evaluate(secrets: &[(Secret, Option<DateTime<Utc>>)], now: DateTime<Utc>) -> Result<Report> {
    let mut report = Report::default();
    for (secret, newest) in secrets {
        let period = secret
            .rotation
            .as_ref()
            .and_then(|r| r.rotation_period.as_deref());
        let (class, period, newest) = match (secret.class(), period, newest) {
            (None, _, _) => {
                report.unmeasured(secret, "no rotation-class label");
                continue;
            }
            (_, None, _) => {
                report.unmeasured(secret, "no rotation period");
                continue;
            }
            (_, _, None) => {
                report.unmeasured(secret, "no enabled version");
                continue;
            }
            (Some(class), Some(period), Some(newest)) => (class, period, newest),
        };
        let period_secs =
            parse_period_secs(period).with_context(|| format!("failed to read {}", secret.id()))?;
        let age_secs = (now - *newest).num_seconds() as f64;
        report.ages.push(SecretAge {
            secret: secret.id().to_string(),
            class: class.to_string(),
            age_days: age_secs / SECONDS_PER_DAY,
            overdue_days: ((age_secs - period_secs) / SECONDS_PER_DAY).max(0.0),
        });
    }
    Ok(report)
}

impl Report {
    fn unmeasured(&mut self, secret: &Secret, reason: &'static str) {
        warn!(
            secret = secret.id(),
            reason, "secret cannot be measured for rotation age"
        );
        self.unmeasured.push(Unmeasured {
            secret: secret.id().to_string(),
            reason,
        });
    }

    /// Zero points are written too: the alert's absence condition reads a
    /// missing series as "the sweep stopped", not as "nothing is overdue".
    pub fn time_series(&self, now: &str, resource: &MonitoredResource) -> Vec<TimeSeries> {
        let mut out = Vec::with_capacity(self.ages.len() * 2 + 1);
        for age in &self.ages {
            let labels = [
                ("secret", age.secret.as_str()),
                ("rotation_class", age.class.as_str()),
            ];
            out.push(make_gauge(
                &metric("secret_version_age_days"),
                &labels,
                age.age_days,
                now,
                resource,
            ));
            out.push(make_gauge(
                &metric("secret_rotation_overdue_days"),
                &labels,
                age.overdue_days,
                now,
                resource,
            ));
        }
        out.push(make_gauge_int(
            &metric("secret_rotation_unmeasured"),
            &[],
            self.unmeasured.len() as i64,
            now,
            resource,
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud_monitoring::business_resource;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, day, 0, 0, 0).unwrap()
    }

    fn secret(json: serde_json::Value) -> Secret {
        serde_json::from_value(json).unwrap()
    }

    fn rotating(id: &str, period: &str) -> Secret {
        secret(serde_json::json!({
            "name": format!("projects/1/secrets/{id}"),
            "labels": { "rotation-class": "database" },
            "rotation": { "rotationPeriod": period, "nextRotationTime": "2027-01-01T00:00:00Z" },
        }))
    }

    const TEN_DAYS: &str = "864000s";

    #[test]
    fn parses_a_real_secret_page() {
        // Shape captured from the live API. `rotation` and `labels` are absent
        // on a secret without them, and the last page has no token.
        let page: SecretPage = serde_json::from_str(
            r#"{"secrets":[{"name":"projects/1/secrets/a","replication":{"automatic":{}},
                "createTime":"2026-03-29T16:47:07.473067Z","etag":"\"x\""}],"totalSize":1}"#,
        )
        .unwrap();
        assert_eq!(page.secrets[0].id(), "a");
        assert!(page.secrets[0].rotation.is_none());
        assert!(page.next_page_token.is_none());
    }

    #[test]
    fn parses_a_real_version_page() {
        let page: VersionPage = serde_json::from_str(
            r#"{"versions":[{"name":"projects/1/secrets/a/versions/1",
                "createTime":"2026-03-29T16:47:11.169655Z","state":"ENABLED",
                "replicationStatus":{"automatic":{}},"etag":"\"x\""}]}"#,
        )
        .unwrap();
        assert_eq!(page.versions.len(), 1);
    }

    #[test]
    fn a_version_inside_its_period_is_not_overdue() {
        let report = evaluate(&[(rotating("a", TEN_DAYS), Some(at(1)))], at(4)).expect("evaluate");
        assert_eq!(report.ages[0].age_days, 3.0);
        assert_eq!(report.ages[0].overdue_days, 0.0);
    }

    #[test]
    fn a_version_exactly_at_its_period_is_not_yet_overdue() {
        let report = evaluate(&[(rotating("a", TEN_DAYS), Some(at(1)))], at(11)).expect("evaluate");
        assert_eq!(report.ages[0].overdue_days, 0.0);
    }

    #[test]
    fn a_version_past_its_period_reports_the_days_overdue() {
        let report = evaluate(&[(rotating("a", TEN_DAYS), Some(at(1)))], at(14)).expect("evaluate");
        assert_eq!(report.ages[0].overdue_days, 3.0);
        assert_eq!(report.ages[0].class, "database");
    }

    #[test]
    fn a_secret_without_a_class_is_unmeasured() {
        // The shape of a secret made by hand, like the leftovers of a replaced
        // Memorystore instance.
        let orphan = secret(serde_json::json!({ "name": "projects/1/secrets/orphan" }));
        let report = evaluate(&[(orphan, Some(at(1)))], at(4)).expect("evaluate");
        assert!(report.ages.is_empty());
        assert_eq!(
            report.unmeasured,
            vec![Unmeasured {
                secret: "orphan".into(),
                reason: "no rotation-class label",
            }]
        );
    }

    #[test]
    fn a_classed_secret_without_a_period_is_unmeasured() {
        let drifted = secret(serde_json::json!({
            "name": "projects/1/secrets/a",
            "labels": { "rotation-class": "database" },
        }));
        let report = evaluate(&[(drifted, Some(at(1)))], at(4)).expect("evaluate");
        assert_eq!(report.unmeasured[0].reason, "no rotation period");
    }

    #[test]
    fn a_secret_with_no_enabled_version_is_unmeasured() {
        let report = evaluate(&[(rotating("a", TEN_DAYS), None)], at(4)).expect("evaluate");
        assert_eq!(report.unmeasured[0].reason, "no enabled version");
    }

    #[test]
    fn exempt_is_read_from_the_label() {
        let exempt = secret(serde_json::json!({
            "name": "projects/1/secrets/a",
            "labels": { "rotation-class": "exempt" },
        }));
        assert!(exempt.is_exempt());
        assert!(!rotating("a", TEN_DAYS).is_exempt());
    }

    #[test]
    fn a_malformed_period_fails_the_sweep() {
        // Failing is the loud path: no points, so the absence condition fires.
        let err = evaluate(&[(rotating("a", "90 days"), Some(at(1)))], at(4)).unwrap_err();
        assert!(format!("{err:#}").contains("rotationPeriod"));
    }

    #[test]
    fn period_parses_fractions_and_rejects_zero() {
        assert_eq!(parse_period_secs("7776000s").unwrap(), 7_776_000.0);
        assert_eq!(parse_period_secs("1.5s").unwrap(), 1.5);
        assert!(parse_period_secs("0s").is_err());
        assert!(parse_period_secs("7776000").is_err());
    }

    #[test]
    fn only_the_first_tick_of_the_hour_sweeps() {
        let at_minute = |m| Utc.with_ymd_and_hms(2026, 3, 1, 7, m, 12).unwrap();
        assert!(is_due(at_minute(0)));
        assert!(is_due(at_minute(4)));
        assert!(!is_due(at_minute(5)));
        assert!(!is_due(at_minute(55)));
    }

    #[tokio::test]
    async fn collect_pages_follows_tokens_to_the_end() {
        let mut seen = Vec::new();
        let items: Vec<i32> = collect_pages(|token| {
            seen.push(token.clone());
            async move {
                Ok(match token.as_deref() {
                    None => (vec![1, 2], Some("p2".to_string())),
                    Some("p2") => (vec![3], Some(String::new())),
                    other => panic!("unexpected token {other:?}"),
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(seen, vec![None, Some("p2".to_string())]);
    }

    #[tokio::test]
    async fn collect_pages_propagates_a_failed_page() {
        let result: Result<Vec<i32>> =
            collect_pages(|_| async { bail!("Secret Manager API error 403") }).await;
        assert!(result.is_err());
    }

    #[test]
    fn writes_zero_points_and_labels_each_secret() {
        let report = evaluate(&[(rotating("a", TEN_DAYS), Some(at(1)))], at(4)).unwrap();
        let resource = business_resource("p", "europe-west1");
        let series = report.time_series("2026-03-04T00:00:00Z", &resource);
        assert_eq!(series.len(), 3);

        let overdue = series
            .iter()
            .find(|s| {
                s.metric
                    .metric_type
                    .ends_with("/secret_rotation_overdue_days")
            })
            .unwrap();
        assert_eq!(overdue.points[0].value.double_value, Some(0.0));
        assert_eq!(overdue.metric.labels["secret"], "a");
        assert_eq!(overdue.metric.labels["rotation_class"], "database");

        let unmeasured = series
            .iter()
            .find(|s| {
                s.metric
                    .metric_type
                    .ends_with("/secret_rotation_unmeasured")
            })
            .unwrap();
        assert_eq!(unmeasured.points[0].value.int64_value.as_deref(), Some("0"));
    }
}
