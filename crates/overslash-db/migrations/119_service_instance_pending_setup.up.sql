-- A fourth lifecycle value for a service instance: created by a setup flow,
-- credentials not yet proven to work.
--
-- D83 gave setup a credential probe but left it diagnostic — the instance was
-- live before anyone asked whether its key worked. `pending_setup` is the state
-- an instance sits in between "created" and "its probe came back green".
--
-- Deliberately NOT a reuse of `draft`. `draft` is a state a user parks an
-- instance in on purpose, via PATCH /v1/services/{id}/status, and it is offered
-- as a filter facet on the services list. Reusing it would mean the sweeper
-- below could not tell a setup nobody finished from an instance somebody
-- deliberately shelved, and a blanket age purge would start eating the latter.
--
-- The separation is enforced at the API rather than here: `pending_setup` is
-- absent from the status allow-list that PATCH /status and update_service
-- validate against, so it is a valid *source* status (park it, or activate it)
-- and never a valid *target*. Every row in this state is therefore one this
-- feature created, which is what makes the purge predicate safe without a
-- second marker column.
ALTER TABLE service_instances DROP CONSTRAINT service_instances_status_check;

ALTER TABLE service_instances ADD CONSTRAINT service_instances_status_check
    CHECK (status IN ('draft', 'active', 'archived', 'pending_setup'));

COMMENT ON COLUMN service_instances.status IS
    'Lifecycle: active (callable), draft (deliberately parked), archived (retired), pending_setup (created by a setup flow, probe not yet green — swept after ~24h). Only active resolves by name or appears in search.';

-- The sweeper's only predicate. Partial and keyed on created_at, because that
-- is the column the age test reads: `updated_at` is bumped by every credential
-- rebind, so a human pasting a third wrong key would push the deadline out
-- forever and the sweep would never bound the table.
CREATE INDEX idx_service_instances_pending_setup
    ON service_instances(created_at)
    WHERE status = 'pending_setup';
