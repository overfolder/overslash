/**
 * Headless state machines.
 *
 * Everything here is framework-free and observable through the same `Store`
 * contract, which is `useSyncExternalStore`'s signature verbatim (D46). The
 * custom elements in `@overslash/sdk/elements` are built on exactly these — a
 * host rendering its own markup is not on a lesser path.
 */

export type { Store } from './store.js';
export { createStore } from './store.js';

export { PollScheduler } from './poll.js';
export type { PollSchedulerOptions } from './poll.js';

export { SseParser, readSseStream } from './sse-parse.js';
export type { SseFrame } from './sse-parse.js';

export { PollingEvents, SseEvents } from './events.js';
export type { EventsTransport, SseEventsOptions, StreamStatus } from './events.js';

export { createApprovalController, fromPendingCall } from './approval.js';
export type {
  ApprovalController,
  ApprovalControllerOptions,
  ApprovalState,
} from './approval.js';

export { createApprovalListController } from './approval-list.js';
export type {
  ApprovalListController,
  ApprovalListOptions,
  ApprovalListState,
} from './approval-list.js';

export { createProvideController } from './provide.js';
export type {
  ProvideController,
  ProvideControllerOptions,
  ProvideState,
  ProvideStatus,
} from './provide.js';

export { createSecretRequestController } from './secret-request.js';
export type {
  SecretRequestController,
  SecretRequestOptions,
  SecretRequestState,
} from './secret-request.js';

export { createConnectController } from './connect.js';
export type { ConnectController, ConnectOptions, ConnectState, ConnectStatus } from './connect.js';

export { waitForApproval } from './wait-for-approval.js';
export type { WaitForApprovalOptions } from './wait-for-approval.js';
