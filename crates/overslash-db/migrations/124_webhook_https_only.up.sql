-- Webhooks are HTTPS-only (CASA 7.1.1). Registration now refuses `http://`,
-- but rows written before that check existed can still carry one, and the
-- requirement is that we *refuse to deliver* to them — not keep signing
-- payloads onto the wire in the clear because the row predates the rule.
--
-- Such a row is disabled, not deleted: the owner still sees it in
-- `GET /v1/webhooks` with `disabled_reason` saying why, and can replace it
-- with an `https://` subscription. `active = false` keeps it out of dispatch,
-- the retry sweep and the failure digest.
--
-- `http://` to a loopback host is left alone. It is only ever dialed when the
-- operator allow-lists loopback in OVERSLASH_SSRF_ALLOWED_CIDRS (local dev,
-- tests, a receiver on the same box), and the dispatcher re-checks the
-- resolved address on every attempt, so nothing it sends can leave the host.
--
-- Census at authoring time: overslash-dev held one subscription, `https`.
-- Production was not readable from the authoring environment.
ALTER TABLE webhook_subscriptions ADD COLUMN disabled_reason TEXT;

COMMENT ON COLUMN webhook_subscriptions.disabled_reason IS
    'Why the platform disabled this subscription (needs_https). NULL for a subscription the platform has not disabled.';

UPDATE webhook_subscriptions
   SET active = false,
       disabled_reason = 'needs_https'
 WHERE url !~* '^https://'
   AND url !~* '^http://(localhost|127\.[0-9.]+|\[::1\])([:/?#]|$)';
