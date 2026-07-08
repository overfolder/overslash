/**
 * Shared OAuth "link an account" popup + poll mechanics.
 *
 * Every connect flow (Create Service wizard, Connections view) opens the gated
 * authorize URL in a popup, then polls `GET /v1/connections` until a row that
 * wasn't there before shows up — the e2e fake-AS harness drives exactly this,
 * so it works without depending on a `return_url` host allow-list. Keeping the
 * loop in one place avoids the near-verbatim copies these call sites used to
 * carry.
 */
import { listConnections } from '$lib/api/services';
import type { ConnectionSummary } from '$lib/types';

/** Thrown when the browser blocks the OAuth popup (window.open returns null). */
export class PopupBlockedError extends Error {
	constructor() {
		super('Pop-up blocked. Allow pop-ups and try again.');
		this.name = 'PopupBlockedError';
	}
}

/**
 * Open `authUrl` in a popup and poll until a connection for `provider` whose id
 * isn't in `beforeIds` appears, then close the popup and return it. Returns
 * `null` when the deadline passes, the popup is closed first, or the flow is
 * aborted (callers check `signal.aborted` to decide whether to surface a
 * timeout message). Throws {@link PopupBlockedError} when the popup is blocked.
 *
 * @param onPoll called with the latest rows each poll, so a caller can refresh
 *   its own connection-list state (e.g. the Create Service reuse picker).
 */
export async function connectViaPopup(opts: {
	authUrl: string;
	provider: string;
	beforeIds: Set<string>;
	signal: AbortSignal;
	onPoll?: (rows: ConnectionSummary[]) => void;
	timeoutMs?: number;
	pollMs?: number;
}): Promise<ConnectionSummary | null> {
	const { authUrl, provider, beforeIds, signal, onPoll } = opts;
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
		let rows: ConnectionSummary[];
		try {
			rows = await listConnections({}, signal);
		} catch {
			if (signal.aborted) {
				closePopup();
				return null;
			}
			continue;
		}
		onPoll?.(rows);
		const fresh = rows.find((c) => !beforeIds.has(c.id) && c.provider_key === provider);
		if (fresh) {
			closePopup();
			return fresh;
		}
		if (popup.closed) break;
	}
	return null;
}
