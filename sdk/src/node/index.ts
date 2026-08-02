/**
 * Server-side helpers.
 *
 * Nothing here needs Node specifically — it is WebCrypto and `fetch` — but the
 * subpath keeps webhook verification out of a browser bundle that has no use
 * for it.
 *
 * ```ts
 * // A tool that must block until a human decides, in a run loop that cannot pause:
 * const res = await overslash.actions.call({ service, action, params });
 * if (res.status === 'pending_approval') {
 *   surfaceToUser(res);                                        // your UI
 *   const final = await waitForApproval(overslash, res.approval_id);
 *   if (final.execution?.status === 'executed') {
 *     return overslash.approvals.execution(final.id);          // marks output_read
 *   }
 * }
 * ```
 */

export { parseWebhookEvent, verifyWebhookSignature } from './webhook-verify.js';
export type { VerifyWebhookOptions } from './webhook-verify.js';

export { waitForApproval } from '../controllers/wait-for-approval.js';
export type { WaitForApprovalOptions } from '../controllers/wait-for-approval.js';

export { SseEvents } from '../controllers/events.js';
export type { EventsTransport } from '../controllers/events.js';
