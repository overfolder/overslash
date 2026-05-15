/**
 * API client wrappers for the API Explorer: calling actions and fetching
 * per-action parameter schemas.
 */
import { session } from '$lib/session';
import type { ActionDetail, CallRequest, CallResponse } from '$lib/types';

export const callAction = (req: CallRequest, signal?: AbortSignal) =>
	session.post<CallResponse>('/v1/actions/call', req, signal);

export const getTemplateActionDetail = (
	key: string,
	actionKey: string,
	signal?: AbortSignal
) =>
	session.get<ActionDetail>(
		`/v1/templates/${encodeURIComponent(key)}/actions/${encodeURIComponent(actionKey)}`,
		signal
	);
