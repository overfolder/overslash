-- Configurable detail disclosure.
--
-- `disclosed_fields` holds the curated, labeled summary extracted from the
-- resolved request via the template's `x-overslash-disclose` jq filters. It
-- survives the 100KB raw-payload truncation on `action_detail` and is shown
-- as a prominent "Summary" block above the raw blob on the approval review
-- page. NULL on approvals for templates that don't declare disclosure.
ALTER TABLE approvals
    ADD COLUMN disclosed_fields JSONB;
