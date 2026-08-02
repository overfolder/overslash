-- Durable event log backing the real-time SSE stream (`GET /v1/events/stream`).
--
-- SPEC.md §10 specifies a stream whose connections die every 30 seconds and
-- whose clients resume with `Last-Event-ID`. Resume is only meaningful against
-- a replayable log, and nothing replayable existed: webhook_deliveries rows are
-- per-subscription (an org with no webhook configured produced no rows at all)
-- and carry no notion of who was allowed to see the event. So the stream needs
-- its own table, and that table doubles as the cross-replica fan-out substrate:
-- writers NOTIFY the row's cursor, every replica's listener fetches it and
-- pushes to its locally-connected subscribers. Only the id travels over NOTIFY,
-- so the 8KB payload ceiling is irrelevant and no event data lands in
-- pg_stat_activity.
--
-- `id` is BIGSERIAL rather than the uuid PK we use elsewhere because it *is*
-- the resume cursor: `Last-Event-ID` needs a total order that a client can send
-- back as an opaque token and the server can turn into `WHERE id > $cursor`.
-- `event_id` keeps a stable uuid for the wire envelope, which mirrors the
-- webhook envelope's `id` field (SPEC.md:1288 — same payload every transport).
--
-- `audience` is the access-control decision, frozen at emit time. The emitting
-- code path already holds the approval row and the identity chains it needs, so
-- resolving "who may see this" once at write time is both cheaper and more
-- correct than re-deriving it per subscriber: an event is a historical fact, and
-- re-parenting an identity tomorrow must not retroactively widen who could see
-- what happened today. Org admins bypass the array entirely (checked in the
-- query), so admin promotion does not require backfilling rows.
CREATE TABLE events (
    id         BIGSERIAL PRIMARY KEY,
    event_id   UUID NOT NULL DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    topic      TEXT NOT NULL,
    payload    JSONB NOT NULL,
    audience   UUID[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The replay query is always `org_id = $1 AND id > $cursor ORDER BY id`, so
-- this composite index answers it as a range scan. The audience overlap (`&&`)
-- and topic filter run as cheap recheck predicates on the handful of rows a
-- 30-second reconnect window can produce — a GIN index on audience would cost
-- more to maintain on every insert than it saves on a sub-100-row rescan.
CREATE INDEX events_org_replay_idx ON events (org_id, id);

-- Supports the retention sweep only.
CREATE INDEX events_prune_idx ON events (created_at);

-- Fan-out. A trigger rather than a `pg_notify` bolted onto the INSERT
-- statement: it makes the notification an invariant of the table instead of a
-- convention every writer has to remember, and it keeps the Rust insert a
-- plain `INSERT ... RETURNING`. Notifications are queued transactionally and
-- delivered on commit, so a listener can never see a cursor whose row is not
-- yet visible to a SELECT.
CREATE FUNCTION events_notify() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('overslash_events', NEW.id::text);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER events_notify_trigger
    AFTER INSERT ON events
    FOR EACH ROW EXECUTE FUNCTION events_notify();

COMMENT ON TABLE events IS
    'Durable event log for the SSE stream (GET /v1/events/stream). Also the '
    'fan-out substrate: inserts pg_notify the row id on the overslash_events '
    'channel and each replica fetches + forwards to its subscribers.';
COMMENT ON COLUMN events.id IS
    'Resume cursor. Sent to clients as the SSE id: field and returned by them '
    'as Last-Event-ID.';
COMMENT ON COLUMN events.event_id IS
    'Stable uuid for the wire envelope, mirroring the webhook envelope id.';
COMMENT ON COLUMN events.audience IS
    'Identity ids permitted to receive this event, frozen at emit time. Org '
    'admins bypass this check. Empty means admins-only.';
