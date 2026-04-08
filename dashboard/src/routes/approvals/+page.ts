import { session, ApiError, type ApprovalResponse } from '$lib/session';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

export const load: PageLoad = async () => {
	try {
		const approvals = await session.get<ApprovalResponse[]>(
			'/v1/approvals?scope=assigned'
		);
		return { approvals, error: null as null | string };
	} catch (e) {
		const message =
			e instanceof ApiError
				? `Failed to load approvals (${e.status}).`
				: 'Network error loading approvals.';
		return { approvals: [] as ApprovalResponse[], error: message };
	}
};
