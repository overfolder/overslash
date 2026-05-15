import { session, ApiError, type ApprovalResponse } from '$lib/session';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

export const load: PageLoad = async () => {
	try {
		const [approvals, pendingExecutions] = await Promise.all([
			session.get<ApprovalResponse[]>('/v1/approvals?scope=assigned'),
			session.get<ApprovalResponse[]>('/v1/approvals?scope=mine&status=allowed')
		]);
		return {
			approvals,
			pendingExecutions,
			error: null as null | string
		};
	} catch (e) {
		const message =
			e instanceof ApiError
				? `Failed to load approvals (${e.status}).`
				: 'Network error loading approvals.';
		return {
			approvals: [] as ApprovalResponse[],
			pendingExecutions: [] as ApprovalResponse[],
			error: message
		};
	}
};
