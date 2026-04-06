import type { PageLoad } from './$types';
import { session, ApiError, type MeIdentity } from '$lib/session';

export const ssr = false;
export const prerender = false;

export interface EnrollmentInfo {
	enrollment_id: string;
	suggested_name: string;
	platform: string | null;
	metadata: unknown;
	status: string;
	expires_at: string;
	created_at: string;
	requester_ip: string | null;
}

export interface IdentityNode {
	id: string;
	org_id: string;
	name: string;
	kind: string;
	parent_id: string | null;
	depth: number;
}

type LoadResult =
	| { state: 'pending'; token: string; enrollment: EnrollmentInfo; identities: IdentityNode[]; me: MeIdentity }
	| { state: 'expired'; token: string }
	| { state: 'already_resolved'; token: string; status: string }
	| { state: 'error'; token: string; message: string };

export const load: PageLoad = async ({ params, parent }): Promise<LoadResult> => {
	const { token } = params;
	const { user } = (await parent()) as { user: MeIdentity | null };
	if (!user) {
		return {
			state: 'error',
			token,
			message: 'Could not load your user profile. Refresh to try again.'
		};
	}

	try {
		const enrollment = await session.get<EnrollmentInfo>(`/enroll/approve/${token}`);
		if (enrollment.status && enrollment.status !== 'pending') {
			return { state: 'already_resolved', token, status: enrollment.status };
		}
		const identities = await session.get<IdentityNode[]>('/v1/identities');
		return { state: 'pending', token, enrollment, identities, me: user };
	} catch (e) {
		if (e instanceof ApiError) {
			if (e.status === 410) return { state: 'expired', token };
			if (e.status === 404) return { state: 'error', token, message: 'Enrollment not found.' };
			return { state: 'error', token, message: `Request failed (${e.status}).` };
		}
		return { state: 'error', token, message: 'Unexpected error loading enrollment.' };
	}
};
