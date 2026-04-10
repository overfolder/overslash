import type { PageLoad } from './$types';
import { ApiError, session, type MeIdentity } from '$lib/session';
import type { IdpConfig, OrgInfo, Webhook } from '$lib/types';

export const ssr = false;
export const prerender = false;

export interface MeAcl {
	identity_id: string;
	org_id: string;
	email: string;
	acl_level: 'Admin' | 'Write' | 'Read' | null;
}

export interface OrgPageData {
	me: MeAcl | null;
	org: OrgInfo | null;
	idpConfigs: IdpConfig[];
	webhooks: Webhook[];
	error: { status: number; message: string } | null;
}

export const load: PageLoad = async ({ parent }): Promise<OrgPageData> => {
	const layoutData = (await parent()) as { user: MeIdentity | null };
	const orgId = layoutData.user?.org_id;
	const isOrgAdmin = layoutData.user?.is_org_admin === true;

	try {
		const me = await session.get<MeAcl>('/auth/me');
		// Allow access if either the ACL endpoint says Admin or the identity
		// endpoint says is_org_admin (covers Dev Login users whose overslash
		// grants may not be set up but who are in the Admins group).
		if (me.acl_level !== 'Admin' && !isOrgAdmin) {
			return {
				me,
				org: null,
				idpConfigs: [],
				webhooks: [],
				error: { status: 403, message: 'Admin access required to view org settings.' }
			};
		}

		const [org, idpConfigs, webhooks] = await Promise.all([
			orgId
				? session.get<OrgInfo>(`/v1/orgs/${orgId}`)
				: Promise.resolve(null as unknown as OrgInfo),
			session.get<IdpConfig[]>('/v1/org-idp-configs'),
			session.get<Webhook[]>('/v1/webhooks')
		]);
		return { me, org, idpConfigs, webhooks, error: null };
	} catch (e) {
		const status = e instanceof ApiError ? e.status : 0;
		const message =
			e instanceof ApiError ? `Failed to load org settings (${e.status}).` : 'Network error.';
		return { me: null, org: null, idpConfigs: [], webhooks: [], error: { status, message } };
	}
};
