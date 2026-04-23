import type { PageLoad } from './$types';
import { ApiError, session, type MeIdentity } from '$lib/session';
import type {
	IdpConfig,
	McpClient,
	OAuthCredential,
	OrgInfo,
	SecretRequestSettings,
	Webhook
} from '$lib/types';

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
	oauthCredentials: OAuthCredential[];
	mcpClients: McpClient[];
	webhooks: Webhook[];
	secretRequestSettings: SecretRequestSettings | null;
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
				oauthCredentials: [],
				mcpClients: [],
				webhooks: [],
				secretRequestSettings: null,
				error: { status: 403, message: 'Admin access required to view org settings.' }
			};
		}

		const [org, idpConfigs, oauthCredentials, mcpClientsResp, webhooks, secretRequestSettings] =
			await Promise.all([
				orgId
					? session.get<OrgInfo>(`/v1/orgs/${orgId}`)
					: Promise.resolve(null as unknown as OrgInfo),
				session.get<IdpConfig[]>('/v1/org-idp-configs'),
				session.get<OAuthCredential[]>('/v1/org-oauth-credentials'),
				session.get<{ clients: McpClient[] }>('/v1/oauth/mcp-clients'),
				session.get<Webhook[]>('/v1/webhooks'),
				orgId
					? session.get<SecretRequestSettings>(`/v1/orgs/${orgId}/secret-request-settings`)
					: Promise.resolve(null)
			]);
		return {
			me,
			org,
			idpConfigs,
			oauthCredentials,
			mcpClients: mcpClientsResp.clients,
			webhooks,
			secretRequestSettings,
			error: null
		};
	} catch (e) {
		const status = e instanceof ApiError ? e.status : 0;
		const message =
			e instanceof ApiError ? `Failed to load org settings (${e.status}).` : 'Network error.';
		return {
			me: null,
			org: null,
			idpConfigs: [],
			oauthCredentials: [],
			mcpClients: [],
			webhooks: [],
			secretRequestSettings: null,
			error: { status, message }
		};
	}
};
