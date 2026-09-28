-- Re-activates what the up migration disabled. The dispatcher's own scheme
-- check still refuses those endpoints, so they fail rather than deliver.
UPDATE webhook_subscriptions
   SET active = true
 WHERE disabled_reason = 'needs_https';

ALTER TABLE webhook_subscriptions DROP COLUMN disabled_reason;
