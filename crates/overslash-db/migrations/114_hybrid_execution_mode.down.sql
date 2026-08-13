-- Fold hybrid into async before narrowing: both triggers already treat the two
-- identically, so an in-flight gated hybrid approval keeps working. Narrowing
-- first would fail on any existing row.
UPDATE approvals SET execution_mode = 'async' WHERE execution_mode = 'hybrid';
ALTER TABLE approvals DROP CONSTRAINT approvals_execution_mode_check;
ALTER TABLE approvals
    ADD CONSTRAINT approvals_execution_mode_check
        CHECK (execution_mode IN ('sync', 'async'));
