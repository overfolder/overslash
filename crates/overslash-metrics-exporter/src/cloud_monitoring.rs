//! Cloud Monitoring API client (push model).
//!
//! Builds a `TimeSeriesRequest` and POSTs it to
//! `monitoring.googleapis.com/v3/projects/{id}/timeSeries`. Auth uses the
//! Cloud Run Job's workload identity via the GCE metadata server. Self-hosted
//! deployments without GCP just run with `--dry-run` (or `EXPORTER_DRY_RUN=1`)
//! and skip the POST entirely.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Serialize;

/// Cloud Monitoring v3 imposes a 200-timeseries limit per request.
const MAX_TIMESERIES_PER_REQUEST: usize = 200;

#[derive(Debug, Serialize)]
pub struct TimeSeriesRequest {
    #[serde(rename = "timeSeries")]
    pub time_series: Vec<TimeSeries>,
}

#[derive(Debug, Serialize, Clone)]
pub struct TimeSeries {
    pub metric: MetricDescriptor,
    pub resource: MonitoredResource,
    pub points: Vec<Point>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MetricDescriptor {
    #[serde(rename = "type")]
    pub metric_type: String,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MonitoredResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Point {
    pub interval: Interval,
    pub value: PointValue,
}

#[derive(Debug, Serialize, Clone)]
pub struct Interval {
    #[serde(rename = "endTime")]
    pub end_time: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PointValue {
    #[serde(rename = "doubleValue", skip_serializing_if = "Option::is_none")]
    pub double_value: Option<f64>,
    #[serde(rename = "int64Value", skip_serializing_if = "Option::is_none")]
    pub int64_value: Option<String>,
}

impl PointValue {
    pub fn double(v: f64) -> Self {
        Self {
            double_value: Some(v),
            int64_value: None,
        }
    }
    pub fn int64(v: i64) -> Self {
        Self {
            double_value: None,
            int64_value: Some(v.to_string()),
        }
    }
}

/// Resource type for business metrics: `generic_task`. Identifies the
/// exporter as a discrete reporter so multiple instances (dev/prod, A/B) can
/// coexist without overwriting each other's points.
pub fn business_resource(project_id: &str, location: &str) -> MonitoredResource {
    MonitoredResource {
        resource_type: "generic_task".to_string(),
        labels: [
            ("project_id".to_string(), project_id.to_string()),
            ("location".to_string(), location.to_string()),
            ("namespace".to_string(), "overslash".to_string()),
            ("job".to_string(), "metrics-exporter".to_string()),
            ("task_id".to_string(), "0".to_string()),
        ]
        .into(),
    }
}

pub fn make_gauge(
    metric_type: &str,
    labels: &[(&str, &str)],
    value: f64,
    end_time: &str,
    resource: &MonitoredResource,
) -> TimeSeries {
    TimeSeries {
        metric: MetricDescriptor {
            metric_type: metric_type.to_string(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        },
        resource: resource.clone(),
        points: vec![Point {
            interval: Interval {
                end_time: end_time.to_string(),
            },
            value: PointValue::double(value),
        }],
    }
}

pub fn make_gauge_int(
    metric_type: &str,
    labels: &[(&str, &str)],
    value: i64,
    end_time: &str,
    resource: &MonitoredResource,
) -> TimeSeries {
    TimeSeries {
        metric: MetricDescriptor {
            metric_type: metric_type.to_string(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        },
        resource: resource.clone(),
        points: vec![Point {
            interval: Interval {
                end_time: end_time.to_string(),
            },
            value: PointValue::int64(value),
        }],
    }
}

/// POST one or more `TimeSeriesRequest` chunks to Cloud Monitoring.
/// Splits the input into 200-series chunks (the API hard cap).
pub async fn write_time_series(
    project_id: &str,
    series: Vec<TimeSeries>,
    client: &reqwest::Client,
) -> Result<()> {
    if series.is_empty() {
        return Ok(());
    }
    let token = get_access_token(client)
        .await
        .context("failed to fetch GCP access token from metadata server")?;
    let url = format!("https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries");

    for chunk in series.chunks(MAX_TIMESERIES_PER_REQUEST) {
        let body = TimeSeriesRequest {
            time_series: chunk.to_vec(),
        };
        let resp = client
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .context("Cloud Monitoring POST failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Cloud Monitoring API error {status}: {text}");
        }
    }
    Ok(())
}

/// Fetch a workload-identity access token from the GCE metadata server.
async fn get_access_token(client: &reqwest::Client) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        access_token: String,
    }

    let resp: TokenResponse = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(resp.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn business_resource_has_required_labels() {
        let r = business_resource("my-proj", "us-central1");
        assert_eq!(r.resource_type, "generic_task");
        assert_eq!(
            r.labels.get("project_id").map(String::as_str),
            Some("my-proj")
        );
        assert_eq!(
            r.labels.get("location").map(String::as_str),
            Some("us-central1")
        );
        assert_eq!(
            r.labels.get("namespace").map(String::as_str),
            Some("overslash")
        );
        assert_eq!(
            r.labels.get("job").map(String::as_str),
            Some("metrics-exporter")
        );
    }

    #[test]
    fn make_gauge_emits_double_point() {
        let r = business_resource("p", "us-central1");
        let ts = make_gauge("custom.googleapis.com/foo", &[("k", "v")], 3.5, "t", &r);
        assert_eq!(ts.metric.metric_type, "custom.googleapis.com/foo");
        assert_eq!(ts.metric.labels.get("k").map(String::as_str), Some("v"));
        assert_eq!(ts.points[0].value.double_value, Some(3.5));
        assert_eq!(ts.points[0].value.int64_value, None);
    }

    #[test]
    fn make_gauge_int_emits_int64_string() {
        let r = business_resource("p", "us-central1");
        let ts = make_gauge_int("custom.googleapis.com/bar", &[], 42, "t", &r);
        assert_eq!(ts.points[0].value.double_value, None);
        assert_eq!(
            ts.points[0].value.int64_value.as_deref(),
            Some("42"),
            "Cloud Monitoring requires int64 as a string"
        );
    }

    #[test]
    fn point_value_constructors_are_disjoint() {
        let d = PointValue::double(1.5);
        assert_eq!(d.double_value, Some(1.5));
        assert_eq!(d.int64_value, None);
        let i = PointValue::int64(7);
        assert_eq!(i.double_value, None);
        assert_eq!(i.int64_value.as_deref(), Some("7"));
    }

    #[test]
    fn make_gauge_int_handles_negative_values() {
        let r = business_resource("p", "us-central1");
        let ts = make_gauge_int("custom.googleapis.com/x", &[], -5, "t", &r);
        assert_eq!(ts.points[0].value.int64_value.as_deref(), Some("-5"));
    }

    #[test]
    fn make_gauge_attaches_multiple_labels() {
        let r = business_resource("p", "us-central1");
        let ts = make_gauge(
            "custom.googleapis.com/x",
            &[("a", "1"), ("b", "2")],
            0.0,
            "t",
            &r,
        );
        assert_eq!(ts.metric.labels.len(), 2);
        assert_eq!(ts.metric.labels.get("a").map(String::as_str), Some("1"));
        assert_eq!(ts.metric.labels.get("b").map(String::as_str), Some("2"));
    }

    #[tokio::test]
    async fn write_time_series_noop_on_empty_input() {
        // Empty input must short-circuit before contacting the metadata
        // server (which is unreachable from CI) — otherwise the test
        // binary couldn't run this assertion at all.
        let client = reqwest::Client::new();
        write_time_series("dry-run-project", Vec::new(), &client)
            .await
            .expect("empty input must succeed without a network call");
    }

    #[test]
    fn time_series_serializes_to_camel_case_for_gcm() {
        // Cloud Monitoring REST API expects camelCase JSON keys. If serde
        // ever drops the rename attributes by mistake, this test catches
        // it at unit-test time rather than as a 400 from the live API.
        let r = business_resource("p", "us-central1");
        let ts = make_gauge_int(
            "custom.googleapis.com/x",
            &[],
            1,
            "2026-04-29T00:00:00Z",
            &r,
        );
        let req = TimeSeriesRequest {
            time_series: vec![ts],
        };
        let body = serde_json::to_string(&req).unwrap();
        assert!(body.contains("\"timeSeries\""));
        assert!(body.contains("\"endTime\""));
        assert!(body.contains("\"int64Value\""));
    }
}
