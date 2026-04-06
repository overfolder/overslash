-- Hierarchical approval bubbling: track the current resolver of an approval
-- separately from the requesting identity, plus a per-org auto-bubble timeout.

ALTER TABLE approvals
    ADD COLUMN current_resolver_identity_id UUID REFERENCES identities(id) ON DELETE CASCADE,
    ADD COLUMN resolver_assigned_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Backfill: existing approvals are owned by the requesting identity's owner user
-- (or the identity itself if it is a user / has no owner).
UPDATE approvals a
   SET current_resolver_identity_id = COALESCE(
       (SELECT owner_id FROM identities WHERE id = a.identity_id),
       a.identity_id
   );

ALTER TABLE approvals
    ALTER COLUMN current_resolver_identity_id SET NOT NULL;

CREATE INDEX idx_approvals_resolver_pending
    ON approvals(current_resolver_identity_id)
    WHERE status = 'pending';

ALTER TABLE orgs
    ADD COLUMN approval_auto_bubble_secs INTEGER NOT NULL DEFAULT 300
        CHECK (approval_auto_bubble_secs >= 0);
