/**
 * Shared OAuth "link an account" popup + poll mechanics.
 *
 * Every connect flow (Create Service wizard, Connections view) opens the gated
 * authorize URL in a popup, then polls `GET /v1/connections` until a row that
 * wasn't there before shows up, or an existing one is re-authorized in place
 * (its `updated_at` moves: a reconnect, or the callback recognising an account
 * that is already connected) — the e2e fake-AS harness drives exactly this,
 * so it works without depending on a `return_url` host allow-list. Keeping the
 * loop in one place avoids the near-verbatim copies these call sites used to
 * carry.
 */
import { listConnections } from '#lib/api/services.ts';
import type { ConnectionSummary } from '#lib/types.ts';

/** Thrown when the browser blocks the OAuth popup (window.open returns null). */
export class PopupBlockedError extends Error {
	constructor() {
		super('Pop-up blocked. Allow pop-ups and try again.');
		this.name = 'PopupBlockedError';
	}
}

/**
 * Open `authUrl` in a popup and poll until a connection for `provider` that is
 * not in `before`, or whose `updated_at` has moved since, shows up; then close
 * the popup and return it. Returns
 * `null` when the deadline passes, the popup is closed first, or the flow is
 * aborted (callers check `signal.aborted` to decide whether to surface a
 * timeout message). Throws {@link PopupBlockedError} when the popup is blocked.
 *
 * @param before the connections as they were before the flow started.
 * @param ownerIdentityId whose connections to poll (an admin on another
 *   user's service); defaults to the caller's own.
 * @param onPoll called with the latest rows each poll, so a caller can refresh
 *   its own connection-list state (e.g. the Create Service reuse picker).
 */
export async function connectViaPopup(opts: {
	authUrl: string;
	provider: string;
	before: ConnectionSummary[];
	signal: AbortSignal;
	ownerIdentityId?: string;
	onPoll?: (rows: ConnectionSummary[]) => void;
	timeoutMs?: number;
	pollMs?: number;
}): Promise<ConnectionSummary | null> {
	const { authUrl, provider, signal, onPoll } = opts;
	const seen = new Map(opts.before.map((c) => [c.id, c.updated_at]));
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
			rows = await listConnections({ ownerIdentityId: opts.ownerIdentityId }, signal);
		} catch {
			if (signal.aborted) {
				closePopup();
				return null;
			}
			continue;
		}
		onPoll?.(rows);
		const fresh = rows.find(
			(c) => c.provider_key === provider && seen.get(c.id) !== c.updated_at
		);
		if (fresh) {
			closePopup();
			return fresh;
		}
		if (popup.closed) break;
	}
	return null;
}
