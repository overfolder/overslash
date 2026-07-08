import { session } from '$lib/session';
import type { Identity, ApiKeySummary } from './types';

export const ssr = false;

export const load = async ({ parent }) => {
	const [{ user }, identities, apiKeys] = await Promise.all([
		parent(),
		session.get<Identity[]>('/v1/identities'),
		session.get<ApiKeySummary[]>('/v1/api-keys')
	]);
	// The layout resolves the current session identity: only admins see the
	// promote/demote controls, and `viewerIdentityId` lets the drawer flag a
	// self-demotion (allowed when other admins remain; the backend still
	// refuses demoting the last admin).
	return {
		identities,
		apiKeys,
		viewerIsAdmin: user?.is_org_admin === true,
		viewerIdentityId: user?.identity_id ?? null
	};
};
