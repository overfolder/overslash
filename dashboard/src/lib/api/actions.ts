/**
 * API client wrappers for the API Explorer: executing actions and fetching
 * per-action parameter schemas.
 */
import { session } from '$lib/session';
import type { ActionDetail, ExecuteRequest, ExecuteResponse } from '$lib/types';

export const executeAction = (req: ExecuteRequest, signal?: AbortSignal) =>
	session.post<ExecuteResponse>('/v1/actions/execute', req, signal);

export const getTemplateActionDetail = (
	key: string,
	actionKey: string,
	signal?: AbortSignal
) =>
	session.get<ActionDetail>(
		`/v1/templates/${encodeURIComponent(key)}/actions/${encodeURIComponent(actionKey)}`,
		signal
	);
