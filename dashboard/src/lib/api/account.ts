/**
 * Account-level, cross-org endpoints: org switching, leaving an org and the
 * invitations addressed to the signed-in user.
 *
 * Source of truth: `crates/overslash-api/src/routes/account_invitations.rs`
 * and `crates/overslash-api/src/routes/auth/session.rs` (switch-org).
 */
import { session } from '$lib/session';

/** One pending invitation from an org the caller is not yet a member of. */
export interface PendingInvitation {
	/** The pending identity's id — an opaque handle for accept/decline. */
	id: string;
	org_id: string;
	org_name: string;
	org_slug: string;
	/** Role the invitee will hold once they accept. */
	role: 'admin' | 'member' | string;
	created_at: string;
	/** `false` when the org runs its own IdP — accepting has to happen on
	 *  that org's own sign-in page, so the UI links to `sign_in_url`. */
	can_accept_in_place: boolean;
	sign_in_url: string;
}

export const listInvitations = (signal?: AbortSignal) =>
	session.get<PendingInvitation[]>('/v1/account/invitations', signal);

export const acceptInvitation = (id: string) =>
	session.post<{ org_id: string; slug: string }>(
		`/v1/account/invitations/${encodeURIComponent(id)}/accept`
	);

export const declineInvitation = (id: string) =>
	session.post<{ declined: boolean }>(
		`/v1/account/invitations/${encodeURIComponent(id)}/decline`
	);

/**
 * Switch the session to `orgId` and hard-navigate there.
 *
 * The server mints a new cookie and answers with the absolute URL to land on
 * — a different subdomain for corp orgs, which is why this can't be a
 * client-side `goto()`. Self-hosted single-host deployments return no URL, so
 * we reload in place to pick up the new cookie. Never resolves on success:
 * the navigation tears the page down.
 */
export async function switchOrg(orgId: string): Promise<void> {
	const res = await session.post<{ redirect_to?: string }>('/auth/switch-org', {
		org_id: orgId
	});
	if (res?.redirect_to) {
		window.location.href = res.redirect_to;
	} else {
		window.location.reload();
	}
}

/**
 * Leave an org. The server archives the caller's identity there (their
 * agents go with it, API keys revoked) and drops the membership.
 *
 * Leaving the org the session is scoped to re-points the session at the
 * personal org; the server answers with the URL to land on and we
 * hard-navigate there (never resolves in that case). Without a personal org
 * the session simply ends, so we reload onto the sign-in page.
 */
export async function leaveOrg(orgId: string, isCurrent: boolean): Promise<void> {
	const res = await session.delete<{ status: string; org_id: string; redirect_to?: string }>(
		`/v1/account/memberships/${encodeURIComponent(orgId)}`
	);
	if (res?.redirect_to) {
		window.location.href = res.redirect_to;
		return new Promise(() => {});
	}
	if (isCurrent) {
		window.location.reload();
		return new Promise(() => {});
	}
}

/** One live dashboard session of the signed-in human (a browser sign-in). */
export interface AccountSession {
	id: string;
	/** The org this session is currently scoped to. */
	org_id: string;
	org_name: string;
	created_at: string;
	last_seen_at: string;
	expires_at: string;
	user_agent: string | null;
	ip_address: string | null;
	/** The session this page is running in. */
	current: boolean;
}

export const listSessions = (signal?: AbortSignal) =>
	session.get<{ sessions: AccountSession[] }>('/v1/account/sessions', signal);

export const revokeSession = (id: string) =>
	session.delete<{ revoked: number }>(`/v1/account/sessions/${encodeURIComponent(id)}`);

export const revokeOtherSessions = () =>
	session.post<{ revoked: number }>('/v1/account/sessions/revoke-others');
