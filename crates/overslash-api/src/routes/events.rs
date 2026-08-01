//! `GET /v1/events/stream` — the real-time event stream (SPEC.md §10).
//!
//! A connection lives for a fixed 30 seconds and then closes. That is not a
//! limitation to work around, it is the design: clients must reconnect with
//! `Last-Event-ID`, so the resume path is exercised constantly instead of
//! being discovered broken during an incident, idle connections cost nothing
//! for long, and no proxy in the path gets to decide the timeout for us.
//!
//! Delivery combines two sources. On reconnect, rows after the client's cursor
//! are replayed from Postgres, where visibility is enforced in SQL. Then the
//! connection tails the in-process bus, where the same visibility predicate is
//! applied in memory. The bus subscription is taken *before* the replay query
//! runs, so an event committed between the two cannot slip through the gap;
//! the resulting overlap is removed by a per-connection set of already-sent
//! cursors.

use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::stream;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::event::EventRow;

use crate::AppState;
use crate::error::{AppError, Result};
use crate::extractors::{AuthContext, ReqExt};
use crate::services::events::{ConnPermit, Topic, parse_topics};

/// Wire-format version, carried on the `stream.open` frame. Clients (notably
/// the widget SDK, which auto-detects this stream as its push upgrade) use it
/// to decide whether they understand the framing before relying on it.
const STREAM_PROTOCOL_VERSION: u32 = 1;

/// Buffer between the producer task and the HTTP response body. Only has to
/// absorb a replay burst; the bus has its own, larger buffer upstream.
const CHANNEL_CAPACITY: usize = 64;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/events/stream", get(events_stream))
}

#[derive(Deserialize)]
pub struct StreamQuery {
    /// Comma-separated topic names. Absent means every topic.
    topics: Option<String>,
}

/// Everything the delivery predicate needs, resolved once at connect.
struct Subscriber {
    org_id: Uuid,
    identity_id: Uuid,
    /// Org admins can already read every resource in the org over REST, so the
    /// stream would be an odd place to be stricter. Resolved once — worst-case
    /// staleness is one connection lifetime.
    is_org_admin: bool,
    topics: Vec<Topic>,
}

impl Subscriber {
    /// The single delivery rule, applied identically to replayed and live
    /// events. Replay additionally enforces the org and audience halves in
    /// SQL; re-checking here is cheap and keeps the invariant local.
    fn may_see(&self, event: &EventRow) -> bool {
        event.org_id == self.org_id
            && self.topics.iter().any(|t| t.as_str() == event.topic)
            && (self.is_org_admin || event.audience.contains(&self.identity_id))
    }

    fn topic_strings(&self) -> Vec<String> {
        self.topics.iter().map(|t| t.as_str().to_string()).collect()
    }
}

async fn events_stream(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Result<Response> {
    let topics = parse_topics(query.topics.as_deref()).map_err(|unknown| {
        AppError::BadRequest(format!(
            "unknown topic '{unknown}': expected any of 'approvals', 'connections', 'secrets'"
        ))
    })?;

    // Without an identity there is no audience membership to evaluate, so
    // there is no correct answer to "what may this caller see" — refuse rather
    // than fall back to something org-wide.
    let identity_id = auth.identity_id.ok_or_else(|| {
        AppError::Forbidden(
            "the event stream requires an identity-bound credential (agent or user)".into(),
        )
    })?;

    let is_org_admin = scope
        .get_identity(identity_id)
        .await?
        .map(|i| i.is_org_admin)
        .unwrap_or(false);

    let subscriber = Subscriber {
        org_id: auth.org_id,
        identity_id,
        is_org_admin,
        topics,
    };

    let bus = state.event_bus(&ext).clone();
    let permit = bus.try_acquire(subscriber.org_id, subscriber.identity_id)?;

    // Subscribe before reading the backlog: an event committed between the
    // replay query and the start of the live tail would otherwise be lost by
    // both halves.
    let receiver = bus.subscribe();

    let cursor = parse_last_event_id(&headers);
    let replay = match cursor {
        Some(cursor) => {
            scope
                .replay_events(
                    cursor,
                    subscriber.identity_id,
                    subscriber.is_org_admin,
                    &subscriber.topic_strings(),
                )
                .await?
        }
        None => Vec::new(),
    };

    // The resume point *as of this frame* — where the client already is, or the
    // org's high-water mark for a fresh subscriber so its first reconnect
    // resumes from now rather than replaying all of history.
    //
    // Deliberately NOT the last id in the replay batch. `stream.open` is
    // emitted before the replayed rows, and `EventSource` updates its
    // `lastEventId` per frame as it arrives — so advertising the end of the
    // batch up front would mean a connection dying mid-replay leaves the client
    // believing it consumed rows it never received, and its next reconnect
    // would skip straight past them. Each replayed row advances the cursor on
    // its own as it lands.
    let open_cursor = match cursor {
        Some(cursor) => cursor,
        None => scope.latest_event_cursor().await?,
    };

    let max_secs = state.config.events_stream_max_connection_secs;
    let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
    tokio::spawn(produce(
        tx,
        receiver,
        subscriber,
        replay,
        open_cursor,
        max_secs,
        permit,
    ));

    // Turn the receiver into the response body. The stream ends when the
    // producer drops its sender, which is how the deadline closes the
    // connection.
    let body = stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|event| (Ok::<_, Infallible>(event), rx))
    });

    // 15s is not here to defeat proxy idle timeouts: at the default 30s
    // ceiling we hang up long before any common proxy would (nginx and ALB
    // both idle at 60s), and `stream.open` guarantees a byte at t=0 so nothing
    // upstream sits buffering for first output either.
    //
    // What it earns at 30s is a single mid-connection write, which is how a
    // client that vanished without a FIN gets noticed — halving the worst-case
    // time its slot stays booked against the per-identity cap. A fixed
    // interval rather than one derived from the ceiling, because if an
    // operator raises `EVENTS_STREAM_MAX_CONNECTION_SECS` the same 15s becomes
    // a genuine proxy keepalive without needing to be re-tuned.
    Ok(Sse::new(body)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response())
}

/// Drive one connection: opening frame, replay, then live tail until the
/// deadline or the client goes away.
async fn produce(
    tx: mpsc::Sender<Event>,
    mut receiver: tokio::sync::broadcast::Receiver<Arc<EventRow>>,
    subscriber: Subscriber,
    replay: Vec<EventRow>,
    open_cursor: i64,
    max_secs: u64,
    permit: ConnPermit,
) {
    // Held for the connection's life; releases the per-identity and per-org
    // slots when this task ends, including on client disconnect.
    let _permit = permit;

    let open = Event::default()
        .event("stream.open")
        .id(open_cursor.to_string())
        .json_data(serde_json::json!({
            "cursor": open_cursor,
            "v": STREAM_PROTOCOL_VERSION,
        }));
    let open = match open {
        Ok(open) => open,
        Err(e) => {
            tracing::error!("event stream: failed to build stream.open: {e}");
            return;
        }
    };
    if tx.send(open).await.is_err() {
        return;
    }

    // Cursors already delivered on this connection, so the replay/live overlap
    // is not sent twice. Bounded by one connection's traffic.
    let mut sent: HashSet<i64> = HashSet::new();
    for row in replay {
        sent.insert(row.id);
        // A row we cannot serialize is undeliverable on any connection, so
        // ending the stream would only make the client reconnect, hit the same
        // row, and end again — an unbreakable loop that locks it out of every
        // later event. Skip it and keep the cursor moving.
        let Some(event) = to_sse_event(&row) else {
            continue;
        };
        if tx.send(event).await.is_err() {
            return;
        }
    }

    let deadline = tokio::time::sleep(Duration::from_secs(max_secs));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => return,
            // Client hung up. Without this the task would idle until the
            // deadline still holding a connection slot.
            _ = tx.closed() => return,
            received = receiver.recv() => match received {
                Ok(event) => {
                    if !subscriber.may_see(&event) || !sent.insert(event.id) {
                        continue;
                    }
                    // Same reasoning as the replay loop: skip, don't disconnect.
                    let Some(frame) = to_sse_event(&event) else {
                        continue;
                    };
                    if tx.send(frame).await.is_err() {
                        return;
                    }
                }
                // Fell too far behind the bus. Ending the connection is the
                // repair: the client reconnects with its cursor and the
                // backlog is served durably from Postgres instead.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!("event stream: subscriber lagged {missed} events, closing");
                    return;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}

/// Render a row as an SSE frame. The `data` field is the same envelope the
/// webhook transport sends (SPEC.md §10) so a client can handle either
/// without a second parser.
fn to_sse_event(row: &EventRow) -> Option<Event> {
    let created_at = row.created_at.format(&Rfc3339).unwrap_or_default();
    let envelope = serde_json::json!({
        "id": row.event_id,
        "type": row.r#type,
        "created_at": created_at,
        "data": row.payload,
    });
    match Event::default()
        .id(row.id.to_string())
        .event(&row.r#type)
        .json_data(envelope)
    {
        Ok(event) => Some(event),
        Err(e) => {
            tracing::error!("event stream: failed to serialize event {}: {e}", row.id);
            None
        }
    }
}

/// `Last-Event-ID` is set automatically by `EventSource` on reconnect. A
/// malformed value is treated as absent — better a fresh stream than a 400 the
/// browser will retry forever.
fn parse_last_event_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|cursor| *cursor >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn row(org_id: Uuid, topic: &str, audience: Vec<Uuid>) -> EventRow {
        EventRow {
            id: 1,
            event_id: Uuid::new_v4(),
            org_id,
            r#type: "approval.created".into(),
            topic: topic.into(),
            payload: serde_json::json!({}),
            audience,
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn subscriber(org_id: Uuid, identity_id: Uuid, is_org_admin: bool) -> Subscriber {
        Subscriber {
            org_id,
            identity_id,
            is_org_admin,
            topics: vec![Topic::Approvals],
        }
    }

    #[test]
    fn audience_membership_gates_delivery() {
        let org = Uuid::new_v4();
        let me = Uuid::new_v4();
        let sub = subscriber(org, me, false);

        assert!(sub.may_see(&row(org, "approvals", vec![me])));
        assert!(!sub.may_see(&row(org, "approvals", vec![Uuid::new_v4()])));
        assert!(!sub.may_see(&row(org, "approvals", vec![])));
    }

    #[test]
    fn another_orgs_event_is_never_delivered_even_to_an_admin() {
        let me = Uuid::new_v4();
        let sub = subscriber(Uuid::new_v4(), me, true);
        // Audience match plus admin — org is the only thing keeping this out.
        assert!(!sub.may_see(&row(Uuid::new_v4(), "approvals", vec![me])));
    }

    #[test]
    fn admins_see_events_they_are_not_an_audience_of() {
        let org = Uuid::new_v4();
        let sub = subscriber(org, Uuid::new_v4(), true);
        assert!(sub.may_see(&row(org, "approvals", vec![Uuid::new_v4()])));
    }

    #[test]
    fn unsubscribed_topics_are_filtered_out() {
        let org = Uuid::new_v4();
        let me = Uuid::new_v4();
        let sub = subscriber(org, me, true);
        assert!(!sub.may_see(&row(org, "connections", vec![me])));
    }

    #[test]
    fn last_event_id_parses_or_degrades_to_none() {
        let mut headers = HeaderMap::new();
        assert_eq!(parse_last_event_id(&headers), None);

        headers.insert("last-event-id", HeaderValue::from_static("42"));
        assert_eq!(parse_last_event_id(&headers), Some(42));

        headers.insert("last-event-id", HeaderValue::from_static(" 7 "));
        assert_eq!(parse_last_event_id(&headers), Some(7));

        headers.insert("last-event-id", HeaderValue::from_static("garbage"));
        assert_eq!(parse_last_event_id(&headers), None);

        headers.insert("last-event-id", HeaderValue::from_static("-1"));
        assert_eq!(parse_last_event_id(&headers), None);
    }
}
