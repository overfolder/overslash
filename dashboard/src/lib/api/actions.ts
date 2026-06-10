/**
 * API client wrappers for the API Explorer: calling actions and fetching
 * per-action parameter schemas.
 */
import { session } from '$lib/session';
import type { ActionDetail, CallRequest, CallResponse } from '$lib/types';

// `?wrap=true` makes the gateway return its own auth errors
// (needs_authentication / reauth_required) as a 200 envelope with the status
// inside, instead of a 401 the session layer would mistake for an expired
// session and bounce to /login. The "try it" panel renders that state inline.
export const callAction = (req: CallRequest, signal?: AbortSignal) =>
	session.post<CallResponse>('/v1/actions/call?wrap=true', req, signal);

export const getTemplateActionDetail = (
	key: string,
	actionKey: string,
	signal?: AbortSignal
) =>
	session.get<ActionDetail>(
		`/v1/templates/${encodeURIComponent(key)}/actions/${encodeURIComponent(actionKey)}`,
		signal
	);
