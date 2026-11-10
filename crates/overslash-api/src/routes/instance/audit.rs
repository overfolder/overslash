//! `GET /v1/instance/audit` and its export: every action taken with
//! instance-admin rights, across all orgs (`instance_audit_log`).

use axum::{
    Json,
    extract::{Query, State},
    http::header,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::instance_admin::{self, InstanceAuditFilter, InstanceAuditRow};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{InstanceAdminAuth, ReqExt},
    routes::audit::{deserialize_optional_datetime, filename_stamp, write_csv_cell},
};

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
/// The export is built in memory: instance-admin actions are rare, so this
/// is years of history, and a bigger trail is a sign to paginate the API.
const EXPORT_CAP: i64 = 10_000;

#[derive(Deserialize)]
pub(super) struct ListQuery {
    admin: Option<String>,
    action: Option<String>,
    org: Option<String>,
    /// Inclusive lower bound, RFC 3339.
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    since: Option<OffsetDateTime>,
    /// Exclusive upper bound, RFC 3339.
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    until: Option<OffsetDateTime>,
    /// Opaque cursor from a previous page's `next_cursor`.
    cursor: Option<String>,
    limit: Option<i64>,
}

fn nonempty(v: &Option<String>) -> Option<String> {
    v.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl ListQuery {
    fn filter(&self) -> Result<InstanceAuditFilter> {
        Ok(InstanceAuditFilter {
            admin: nonempty(&self.admin),
            action: nonempty(&self.action),
            org: nonempty(&self.org),
            before: self.cursor.as_deref().map(parse_cursor).transpose()?,
            since: self.since,
            until: self.until,
        })
    }
}

/// `<unix-nanos>_<uuid>`.
fn parse_cursor(raw: &str) -> Result<(OffsetDateTime, Uuid)> {
    let bad = || AppError::BadRequest("invalid cursor".into());
    let (ts, id) = raw.split_once('_').ok_or_else(bad)?;
    let nanos: i128 = ts.parse().map_err(|_| bad())?;
    let at = OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| bad())?;
    let id = Uuid::parse_str(id).map_err(|_| bad())?;
    Ok((at, id))
}

fn cursor_of(row: &InstanceAuditRow) -> String {
    format!("{}_{}", row.created_at.unix_timestamp_nanos(), row.id)
}

#[derive(Serialize)]
pub(super) struct Entry {
    id: Uuid,
    /// RFC 3339.
    created_at: String,
    actor_user_id: Option<Uuid>,
    actor_email: String,
    action: String,
    org_id: Option<Uuid>,
    org_slug: Option<String>,
    detail: serde_json::Value,
    ip_address: Option<String>,
}

impl From<InstanceAuditRow> for Entry {
    fn from(r: InstanceAuditRow) -> Self {
        Self {
            id: r.id,
            created_at: r
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            actor_user_id: r.actor_user_id,
            actor_email: r.actor_email,
            action: r.action,
            org_id: r.org_id,
            org_slug: r.org_slug,
            detail: r.detail,
            ip_address: r.ip_address,
        }
    }
}

#[derive(Serialize)]
pub(super) struct ListResponse {
    entries: Vec<Entry>,
    next_cursor: Option<String>,
}

pub(super) async fn list(
    _admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResponse>> {
    let filter = q.filter()?;
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    // One extra row tells whether another page exists.
    let mut rows = instance_admin::list_audit(state.db(&ext), &filter, limit + 1).await?;
    let next_cursor = if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        rows.last().map(cursor_of)
    } else {
        None
    };
    Ok(Json(ListResponse {
        entries: rows.into_iter().map(Entry::from).collect(),
        next_cursor,
    }))
}

/// Same filters as the list, minus paging: an export always starts at the
/// newest row. Spelled out rather than `#[serde(flatten)]`-ing `ListQuery`,
/// because flatten buffers query values as strings and then rejects numeric
/// fields like `limit`, turning `?limit=50` into a 400.
#[derive(Deserialize)]
pub(super) struct ExportQuery {
    admin: Option<String>,
    action: Option<String>,
    org: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    since: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "deserialize_optional_datetime")]
    until: Option<OffsetDateTime>,
    format: Option<String>,
}

pub(super) async fn export(
    _admin: InstanceAdminAuth,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Query(q): Query<ExportQuery>,
) -> Result<axum::response::Response> {
    let jsonl = match q.format.as_deref().unwrap_or("csv") {
        "csv" => false,
        "jsonl" => true,
        _ => {
            return Err(AppError::BadRequest(
                "format must be 'csv' or 'jsonl'".into(),
            ));
        }
    };
    // Pin the upper bound, so the file covers exactly the window it is
    // named after even when no `until` was sent.
    let until = q.until.unwrap_or_else(OffsetDateTime::now_utc);
    let filter = InstanceAuditFilter {
        admin: nonempty(&q.admin),
        action: nonempty(&q.action),
        org: nonempty(&q.org),
        before: None,
        since: q.since,
        until: Some(until),
    };
    let rows = instance_admin::list_audit(state.db(&ext), &filter, EXPORT_CAP).await?;

    let mut buf = Vec::new();
    if jsonl {
        for row in rows {
            serde_json::to_writer(&mut buf, &Entry::from(row))?;
            buf.push(b'\n');
        }
    } else {
        buf.extend_from_slice(b"created_at,actor_email,action,org_slug,detail,ip_address\n");
        for row in rows {
            let e = Entry::from(row);
            let detail = e.detail.to_string();
            let cells = [
                e.created_at.as_str(),
                e.actor_email.as_str(),
                e.action.as_str(),
                e.org_slug.as_deref().unwrap_or(""),
                detail.as_str(),
                e.ip_address.as_deref().unwrap_or(""),
            ];
            for (i, cell) in cells.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                write_csv_cell(&mut buf, cell);
            }
            buf.push(b'\n');
        }
    }
    let (ctype, ext_name) = if jsonl {
        ("application/x-ndjson", "jsonl")
    } else {
        ("text/csv; charset=utf-8", "csv")
    };
    Ok((
        [
            (header::CONTENT_TYPE, ctype.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"instance-audit-{}_{}.{ext_name}\"",
                    filename_stamp(q.since),
                    filename_stamp(Some(until)),
                ),
            ),
        ],
        buf,
    )
        .into_response())
}
