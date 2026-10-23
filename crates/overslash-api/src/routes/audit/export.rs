//! `GET /v1/audit/export` — the whole filtered range, streamed as CSV or JSONL.
//!
//! The dashboard's table only ever holds the pages a reader scrolled through;
//! an export has to cover everything the filters match. So the server walks
//! the range itself in keyset batches through the same `query_audit_log` the
//! table pages with — one WHERE clause, constant cost per batch at any depth —
//! and streams each batch out as it lands. Memory stays flat whatever the
//! range holds.

use axum::{
    body::{Body, Bytes},
    extract::{Query, RawQuery},
    http::header,
    response::Response,
};
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::{AuditEntry as AuditLogEntry, AuditFilter};

use super::{AuditEntry, AuditQuery, Enricher, parse_filter};
use crate::error::Result;
use crate::extractors::{ClientIp, UserOrKeyAuth};

/// Rows per round trip. Large enough that a big export is a few hundred
/// queries rather than thousands, small enough that one batch of enriched
/// rows — `detail` can carry a captured response body (D18) — stays modest.
const BATCH: i64 = 1000;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ExportFormat {
    Csv,
    Jsonl,
}

impl ExportFormat {
    fn as_str(self) -> &'static str {
        match self {
            ExportFormat::Csv => "csv",
            ExportFormat::Jsonl => "jsonl",
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            ExportFormat::Csv => "text/csv; charset=utf-8",
            ExportFormat::Jsonl => "application/x-ndjson",
        }
    }
}

/// Read alongside [`AuditQuery`] from the same query string; serde ignores the
/// keys each one doesn't know. An unknown `format` is rejected here, before a
/// byte of the body is committed.
#[derive(Deserialize)]
pub(super) struct ExportParams {
    format: ExportFormat,
}

pub(super) async fn export_audit(
    auth: UserOrKeyAuth,
    scope: OrgScope,
    ip: ClientIp,
    RawQuery(raw_query): RawQuery,
    Query(ExportParams { format }): Query<ExportParams>,
    Query(params): Query<AuditQuery>,
) -> Result<Response> {
    let now = OffsetDateTime::now_utc();
    let filter = parse_filter(&scope, params).await?.map(|mut f| {
        // Pin the upper bound before the first batch, so rows written while
        // the download runs can't slide into a range the reader asked for at
        // `now`. Paging is the export's job: whatever paging the caller sent
        // is dropped.
        f.until.get_or_insert(now);
        f.limit = BATCH;
        f.offset = 0;
        f.before = None;
        f.before_id = None;
        f
    });
    let filename = format!(
        "audit-{}_{}.{}",
        filename_stamp(filter.as_ref().and_then(|f| f.since)),
        filename_stamp(Some(filter.as_ref().and_then(|f| f.until).unwrap_or(now))),
        format.as_str(),
    );

    let state = ExportState {
        scope,
        filter,
        enricher: Enricher::default(),
        format,
        header_written: false,
        done: false,
        failed: false,
        rows: 0,
        audit: Some(ExportAudit {
            identity_id: auth.identity_id,
            ip: ip.0,
            query: raw_query.unwrap_or_default(),
        }),
    };
    let stream = futures_util::stream::unfold(state, |mut st| async move {
        st.next_chunk().await.map(|chunk| (chunk, st))
    });

    Ok(Response::builder()
        .header(header::CONTENT_TYPE, format.content_type())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        // A proxy that buffers would hold the whole range in memory, which is
        // the thing this endpoint exists not to do.
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(stream))
        .expect("static headers always build a valid response"))
}

/// `20261023T140000Z`, or `start` for an open lower bound.
fn filename_stamp(t: Option<OffsetDateTime>) -> String {
    match t {
        None => "start".into(),
        Some(t) => {
            let t = t.to_offset(time::UtcOffset::UTC);
            format!(
                "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        }
    }
}

struct ExportAudit {
    identity_id: Option<Uuid>,
    ip: Option<String>,
    query: String,
}

struct ExportState {
    scope: OrgScope,
    /// `None` when the filter can match nothing (an email naming nobody):
    /// the export is then a header and no rows.
    filter: Option<AuditFilter>,
    enricher: Enricher,
    format: ExportFormat,
    header_written: bool,
    done: bool,
    /// A batch errored: `done`, but the file is short.
    failed: bool,
    rows: u64,
    /// Taken by `Drop`, which writes the `audit.exported` row.
    audit: Option<ExportAudit>,
}

impl ExportState {
    async fn next_chunk(&mut self) -> Option<std::result::Result<Bytes, std::io::Error>> {
        if self.done {
            return None;
        }
        let mut buf = Vec::new();
        if !self.header_written {
            self.header_written = true;
            if self.format == ExportFormat::Csv {
                write_csv_header(&mut buf);
            }
        }
        let Some(filter) = self.filter.as_mut() else {
            self.done = true;
            return Some(Ok(Bytes::from(buf)));
        };
        let rows = match self.scope.query_audit_log(filter.clone()).await {
            Ok(rows) => rows,
            Err(e) => {
                // The status line is long gone; erroring the body is the only
                // way left to tell the client, and it shows as a truncated
                // download instead of a file that is silently short.
                tracing::error!(rows_written = self.rows, "audit export aborted: {e}");
                self.done = true;
                self.failed = true;
                return Some(Err(std::io::Error::other("audit export failed")));
            }
        };
        if (rows.len() as i64) < BATCH {
            self.done = true;
        }
        if let Some(last) = rows.last() {
            filter.before = Some(last.created_at);
            filter.before_id = Some(last.id);
        }
        let entries = self.enricher.enrich(&self.scope, rows).await;
        self.rows += entries.len() as u64;
        for entry in &entries {
            match self.format {
                ExportFormat::Csv => write_csv_row(&mut buf, entry),
                ExportFormat::Jsonl => {
                    // `AuditEntry` is plain data; serializing it cannot fail.
                    serde_json::to_writer(&mut buf, entry).expect("audit entry serializes");
                    buf.push(b'\n');
                }
            }
        }
        Some(Ok(Bytes::from(buf)))
    }
}

/// Exporting the audit log is itself an auditable act. Written on drop rather
/// than after the last batch, so an export the client abandons half-way is
/// recorded too — with `completed: false` and the rows it got. So is one cut
/// short by a failed batch.
impl Drop for ExportState {
    fn drop(&mut self) {
        let Some(audit) = self.audit.take() else {
            return;
        };
        let scope = self.scope.clone();
        let detail = serde_json::json!({
            "format": self.format.as_str(),
            "query": audit.query,
            "since": self.filter.as_ref().and_then(|f| f.since).and_then(|t| t.format(&Rfc3339).ok()),
            "until": self.filter.as_ref().and_then(|f| f.until).and_then(|t| t.format(&Rfc3339).ok()),
            "row_count": self.rows,
            "completed": self.done && !self.failed,
        });
        let description = format!(
            "Exported {} audit events as {}",
            self.rows,
            self.format.as_str().to_uppercase()
        );
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        rt.spawn(async move {
            let result = scope
                .log_audit(AuditLogEntry {
                    org_id: scope.org_id(),
                    identity_id: audit.identity_id,
                    action: "audit.exported",
                    resource_type: None,
                    resource_id: None,
                    detail,
                    description: Some(&description),
                    ip_address: audit.ip.as_deref(),
                })
                .await;
            if let Err(e) = result {
                tracing::warn!(error = %e, "audit export audit log failed");
            }
        });
    }
}

// ── CSV ──────────────────────────────────────────────────────────────────
//
// Columns match the dashboard's former client-side export, so a sheet built on
// the old file keeps working. Names are the ones *recorded on the row* (D59),
// falling back to the live chain for rows written before those columns
// existed: an exported audit log is a record, and should say who acted under
// the name they acted under.

const CSV_COLUMNS: [&str; 11] = [
    "timestamp",
    "identity_id",
    "user",
    "agent",
    "action",
    "resource_type",
    "resource_id",
    "description",
    "ip_address",
    "tags",
    "detail",
];

fn write_csv_header(buf: &mut Vec<u8>) {
    buf.extend_from_slice(CSV_COLUMNS.join(",").as_bytes());
    buf.extend_from_slice(b"\r\n");
}

fn write_csv_row(buf: &mut Vec<u8>, e: &AuditEntry) {
    let (path_user, path_leaf) = path_units(e.identity_path.as_deref());
    let cells: [String; 11] = [
        e.created_at.format(&Rfc3339).unwrap_or_default(),
        e.identity_id.map(|id| id.to_string()).unwrap_or_default(),
        e.owner_user_name
            .clone()
            .or(path_user.map(str::to_string))
            .unwrap_or_default(),
        e.identity_name
            .clone()
            .or(path_leaf.map(str::to_string))
            .unwrap_or_default(),
        e.action.clone(),
        e.resource_type.clone().unwrap_or_default(),
        e.resource_id.map(|id| id.to_string()).unwrap_or_default(),
        e.description.clone().unwrap_or_default(),
        e.ip_address.clone().unwrap_or_default(),
        // Space-separated: tags never contain whitespace (the minter collapses
        // it), so this stays one cell that splits cleanly downstream.
        e.tags.join(" "),
        e.detail.to_string(),
    ];
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        write_csv_cell(buf, cell);
    }
    buf.extend_from_slice(b"\r\n");
}

/// RFC 4180 quoting, plus a guard against formula injection: a spreadsheet
/// runs a cell that starts with `=`, `+`, `-` or `@` as a formula, and
/// descriptions, names and `detail` are all user-influenced. A leading `'`
/// makes the cell plain text in Excel, Sheets and LibreOffice alike.
fn write_csv_cell(buf: &mut Vec<u8>, value: &str) {
    let formula = value.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let quote = formula || value.contains([',', '"', '\r', '\n']);
    if quote {
        buf.push(b'"');
    }
    if formula {
        buf.push(b'\'');
    }
    if quote {
        buf.extend_from_slice(value.replace('"', "\"\"").as_bytes());
        buf.push(b'"');
    } else {
        buf.extend_from_slice(value.as_bytes());
    }
}

/// The owning user unit and the leaf agent unit of a SPIFFE path — the server
/// twin of the dashboard's `identityUnits`. A user-only path (a human acting
/// directly) has no leaf.
fn path_units(path: Option<&str>) -> (Option<&str>, Option<&str>) {
    let Some(path) = path else {
        return (None, None);
    };
    let parts: Vec<&str> = path
        .trim_start_matches("spiffe://")
        .split('/')
        .filter(|p| !p.is_empty())
        .skip(1) // org slug
        .collect();
    let units: Vec<(&str, &str)> = parts
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[kind, name]| (*kind, *name))
        .collect();
    let user = units.iter().find(|(k, _)| *k == "user").map(|(_, n)| *n);
    let leaf = units.last().filter(|(k, _)| *k != "user").map(|(_, n)| *n);
    (user, leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(v: &str) -> String {
        let mut buf = Vec::new();
        write_csv_cell(&mut buf, v);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn csv_cells_quote_only_when_needed() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(cell(""), "");
    }

    #[test]
    fn csv_cells_neutralize_formulas() {
        assert_eq!(cell("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(cell("+1"), "\"'+1\"");
        assert_eq!(cell("-1"), "\"'-1\"");
        assert_eq!(cell("@SUM(A1)"), "\"'@SUM(A1)\"");
        // Only a *leading* trigger is a formula.
        assert_eq!(cell("a=b"), "a=b");
    }

    #[test]
    fn path_units_split_user_and_leaf() {
        let p = "spiffe://acme/user/alice@acme.com/agent/henry/agent/researcher";
        assert_eq!(
            path_units(Some(p)),
            (Some("alice@acme.com"), Some("researcher"))
        );
        assert_eq!(
            path_units(Some("spiffe://acme/user/alice@acme.com")),
            (Some("alice@acme.com"), None)
        );
        assert_eq!(path_units(None), (None, None));
    }

    #[test]
    fn filename_stamp_is_compact_utc() {
        let t = OffsetDateTime::from_unix_timestamp(1_761_228_000).unwrap();
        assert_eq!(filename_stamp(Some(t)), "20251023T140000Z");
        assert_eq!(filename_stamp(None), "start");
    }
}
