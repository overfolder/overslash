-- `execution: "hybrid"` starts on the caller's connection and hands off to a
-- background job if it outruns the handoff threshold. See DECISIONS D68.
--
-- A gated hybrid call records what the caller actually asked for rather than
-- collapsing to 'async' at stamp time. Both replay triggers still treat it as
-- async (see `ApprovalRow::is_async`) — the handoff race is a property of the
-- original connection, and a replay is triggered either by a resolver's
-- browser or by `spawn_auto_call`, which has no connection at all. But a lossy
-- stamp cannot be un-lost later, and the approval card should be able to say
-- which of the two off-connection modes was requested.
ALTER TABLE approvals DROP CONSTRAINT approvals_execution_mode_check;
ALTER TABLE approvals
    ADD CONSTRAINT approvals_execution_mode_check
        CHECK (execution_mode IN ('sync', 'async', 'hybrid'));
