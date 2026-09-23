-- Elicitation approvals become the default. See
-- docs/design/mcp-elicitation-approvals.md (Flow A, adopted) and the D-NEXT
-- decision entry.
--
-- The column is replaced rather than re-defaulted, because the old one could
-- not express the thing that matters. `elicitation_enabled` conflated "the
-- user turned this off" with "nobody has said anything yet", and the second
-- was by far the common case: `oauth_mcp_clients.capabilities` is written only
-- by `initialize`, which needs a token, which is issued *after* consent — so a
-- freshly-registered client_id always looks incapable at consent time and a
-- default keyed on capability would never fire.
--
-- Storing only the explicit opt-out removes the ambiguity. The platform
-- default lives in code, the capability check moves entirely to request time
-- (`elicitation_eligible`, where capabilities are genuinely known), and this
-- column answers exactly one question: did the user say no?
ALTER TABLE mcp_client_agent_bindings
    ADD COLUMN elicitation_opted_out BOOLEAN NOT NULL DEFAULT false;

-- Carry every existing binding over unchanged: they are all `false` today
-- (nothing could set them true without a declared capability), so they all
-- become opted-out and keep behaving exactly as they do now. This is the
-- deliberate "no backfill" decision — a stored `false` cannot be told apart
-- from a considered opt-out, and a migration should not turn a live
-- connection's approval surface inside out on a guess. The installed base
-- opts in from the dashboard.
UPDATE mcp_client_agent_bindings
   SET elicitation_opted_out = NOT elicitation_enabled;

ALTER TABLE mcp_client_agent_bindings
    DROP COLUMN elicitation_enabled;

-- Supports the post-cancel cooldown in `elicitation_eligible`
-- (`mcp_elicitation::cancelled_recently_for_agent`): after an unanswered
-- dialog we stop eliciting that agent for a short window, which is what keeps
-- a headless client from being re-prompted on every retry. Partial, because
-- the only rows the query ever looks at are the cancelled ones.
CREATE INDEX idx_pending_mcp_elicit_agent_cancelled
    ON pending_mcp_elicitations (agent_identity_id, completed_at)
 WHERE status = 'cancelled';
