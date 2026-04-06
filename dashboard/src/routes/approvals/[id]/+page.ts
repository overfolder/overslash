import { session, ApiError, type ApprovalResponse } from '$lib/session';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

export const load: PageLoad = async ({ params }) => {
	try {
		const approval = await session.get<ApprovalResponse>(`/v1/approvals/${params.id}`);
		return { approval, error: null as null | { status: number; message: string } };
	} catch (e) {
		if (e instanceof ApiError) {
			const message =
				e.status === 404
					? 'This approval does not exist or has been deleted.'
					: `Failed to load approval (${e.status}).`;
			return { approval: null, error: { status: e.status, message } };
		}
		return {
			approval: null,
			error: { status: 0, message: 'Network error loading approval.' }
		};
	}
};
