import { session, ApiError, type ApprovalResponse } from '$lib/session';
import type { PageLoad } from './$types';

export const ssr = false;
export const prerender = false;

// Full-page approval detail. This route doubles as the stable deep-link target
// for agent-emitted URLs and platform integrations, so it must handle the
// `?org=<id>` hint the API mints into those links: when the approval belongs to
// a different org than the active session, an org-scoped fetch would 404 and
// read as "deleted". Switch into that org first, then hard-redirect back here
// (subdomain/apex may change, so `redirect()` can't do it — mirror the
// OrgSwitcher's `redirect_to` handling with a full navigation).
export const load: PageLoad = async ({ params, url, parent }) => {
	const parentData = (await parent()) as { user?: { org_id?: string } };
	const activeOrg = parentData.user?.org_id ?? null;
	const org = url.searchParams.get('org');

	if (org && org !== activeOrg && typeof window !== 'undefined') {
		try {
			const res = await session.post<{ redirect_to?: string }>('/auth/switch-org', {
				org_id: org
			});
			const dest = new URL(res?.redirect_to ?? window.location.origin);
			dest.pathname = `/approvals/${params.id}`;
			dest.search = '';
			window.location.href = dest.toString();
			// Navigation is underway — halt so we don't flash the (wrong-org) page.
			await new Promise(() => {});
		} catch (e) {
			const message =
				e instanceof ApiError && e.status === 403
					? "You don't have access to this approval's organization."
					: e instanceof ApiError
						? `Failed to open approval (${e.status}).`
						: 'Network error loading approval.';
			return { approval: null as ApprovalResponse | null, error: message };
		}
	}

	try {
		const approval = await session.get<ApprovalResponse>(`/v1/approvals/${params.id}`);
		return { approval, error: null as string | null };
	} catch (e) {
		const message =
			e instanceof ApiError
				? e.status === 404
					? 'This approval does not exist or has been deleted.'
					: `Failed to load approval (${e.status}).`
				: 'Network error loading approval.';
		return { approval: null as ApprovalResponse | null, error: message };
	}
};
