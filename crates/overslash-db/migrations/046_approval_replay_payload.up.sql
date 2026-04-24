-- Raw replay payload stored alongside the (possibly-redacted / projection-
-- shaped) `action_detail`. `action_detail` is what the UI renders to
-- reviewers and may be redacted via x-overslash-redact. `replay_payload`
-- is the full ActionRequest + side-channel fields (filter, prefer_stream)
-- needed to faithfully reproduce the original request when
-- POST /v1/approvals/{id}/execute fires.
--
-- NULL on pre-feature rows, on MCP-runtime approvals (no HTTP replay yet),
-- and on approvals created before this migration.

ALTER TABLE approvals
    ADD COLUMN replay_payload JSONB;
