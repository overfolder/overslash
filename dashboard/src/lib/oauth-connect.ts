/**
 * Shared OAuth "link an account" popup + poll mechanics.
 *
 * Every connect flow (Create Service wizard, Connections view, service page)
 * opens the gated authorize URL in a popup, then polls the flow itself
 * (`GET /v1/oauth/flows/{id}`) until the callback stamps it completed or
 * failed — the e2e fake-AS harness drives exactly this, so it works without
 * depending on a `return_url` host allow-list. The flow is the only reliable
 * signal: a reconnect keeps the connection's id, and a background token
 * refresh moves `updated_at` just as a reconnect does, so diffing the
 * connections list cannot tell them apart. Keeping the loop in one place
 * avoids the near-verbatim copies these call sites used to carry.
 */
import { getOAuthFlow, listConnections } from '#lib/api/services.ts';
import type { ConnectionSummary } from '#lib/types.ts';

/** Thrown when the browser blocks the OAuth popup (window.open returns null). */
export class PopupBlockedError extends Error {
	constructor() {
		super('Pop-up blocked. Allow pop-ups and try again.');
		this.name = 'PopupBlockedError';
	}
}

/** Thrown when the provider or the callback refused the flow. */
export class OAuthFlowFailedError extends Error {
	constructor(reason: string | undefined) {
		super(reason ? `OAuth failed: ${reason}` : 'OAuth failed');
		this.name = 'OAuthFlowFailedError';
	}
}

/**
 * Open `authUrl` in a popup and poll flow `flowId` until it completes, then
 * close the popup and return the connection it produced. Returns `null` when
 * the deadline passes, the flow expires, the popup is closed first, or the flow
 * is aborted (callers check `signal.aborted` to decide whether to surface a
 * timeout message). Throws {@link PopupBlockedError} when the popup is blocked
 * and {@link OAuthFlowFailedError} when the flow failed.
 *
 * @param ownerIdentityId whose connections to list once it lands (an admin on
 *   another user's service); defaults to the caller's own.
 * @param onPoll called with the connections once the flow lands, so a caller
 *   can refresh its own connection-list state (e.g. the Create Service reuse
 *   picker).
 */
export async function connectViaPopup(opts: {
	authUrl: string;
	flowId: string;
	signal: AbortSignal;
	ownerIdentityId?: string;
	onPoll?: (rows: ConnectionSummary[]) => void;
	timeoutMs?: number;
	pollMs?: number;
}): Promise<ConnectionSummary | null> {
	const { authUrl, flowId, signal, onPoll } = opts;
	const timeoutMs = opts.timeoutMs ?? 90_000;
	const pollMs = opts.pollMs ?? 1500;

	const popup = window.open(authUrl, 'oss_oauth', 'width=520,height=680');
	if (!popup) throw new PopupBlockedError();

	const closePopup = () => {
		try {
			popup.close();
		} catch {
			/* ignore */
		}
	};

	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (signal.aborted) {
			closePopup();
			return null;
		}
		await new Promise((r) => setTimeout(r, pollMs));
		if (signal.aborted) {
			closePopup();
			return null;
		}
		// Read before checking `closed`: the callback page may close itself
		// the moment it has stamped the flow.
		const wasClosed = popup.closed;
		let flow;
		try {
			flow = await getOAuthFlow(flowId, signal);
		} catch {
			if (signal.aborted) {
				closePopup();
				return null;
			}
			continue;
		}
		if (flow.status === 'completed' && flow.connection_id) {
			closePopup();
			const rows = await listConnections({ ownerIdentityId: opts.ownerIdentityId }, signal);
			onPoll?.(rows);
			return rows.find((c) => c.id === flow.connection_id) ?? null;
		}
		if (flow.status === 'failed') {
			closePopup();
			throw new OAuthFlowFailedError(flow.failure);
		}
		if (flow.status === 'expired' || wasClosed) break;
	}
	closePopup();
	return null;
}
