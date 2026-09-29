/**
 * Loader for the single `/org/[[section]]` route (which also serves bare
 * `/org`). It never reads `params`, so SvelteKit does not re-run it when the
 * user moves between settings sections — the 12-call fan-out happens once per
 * visit, not once per click. Keep every section on that one route: a second
 * route would remount the page and refetch on every crossing.
 */
import { ApiError, session, type MeIdentity } from '$lib/session';
import type {
	AuditSettings,
	ExecutionSettings,
	IdpConfig,
	ManagedSigninSettings,
	McpClient,
	OAuthCredential,
	OrgInfo,
	OrgInvite,
	SecretRequestSettings,
	ServiceKeySummary,
	TemplateSettings,
	Webhook
} from '$lib/types';

export interface MeAcl {
	identity_id: string;
	org_id: string;
	email: string;
	acl_level: 'Admin' | 'Write' | 'Read' | null;
}

export interface OrgSubscription {
	org_id: string;
	plan: string;
	seats: number;
	status: string;
	currency: string;
	current_period_end: number | null;
	cancel_at_period_end: boolean;
}

export interface OrgPageData {
	me: MeAcl | null;
	org: OrgInfo | null;
	idpConfigs: IdpConfig[];
	oauthCredentials: OAuthCredential[];
	mcpClients: McpClient[];
	serviceKeys: ServiceKeySummary[];
	webhooks: Webhook[];
	secretRequestSettings: SecretRequestSettings | null;
	executionSettings: ExecutionSettings | null;
	auditSettings: AuditSettings | null;
	managedSigninSettings: ManagedSigninSettings | null;
	templateSettings: TemplateSettings | null;
	invites: OrgInvite[];
	subscription: OrgSubscription | null;
	error: { status: number; message: string } | null;
}

export const loadOrgSettings = async ({
	parent,
	untrack
}: {
	parent: () => Promise<Record<string, unknown>>;
	untrack: <T>(fn: () => T) => T;
}): Promise<OrgPageData> => {
	// The root layout load reads `url`, so it re-runs on every navigation and a
	// tracked `parent()` would drag this loader along with it. The identity it
	// provides only changes on an org switch, which hard-reloads the page.
	const layoutData = (await untrack(() => parent())) as { user: MeIdentity | null };
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
				serviceKeys: [],
				webhooks: [],
				secretRequestSettings: null,
				executionSettings: null,
				auditSettings: null,
				managedSigninSettings: null,
				templateSettings: null,
				invites: [],
				subscription: null,
				error: { status: 403, message: 'Admin access required to view org settings.' }
			};
		}

		const [
			org,
			idpConfigs,
			oauthCredentials,
			mcpClientsResp,
			serviceKeys,
			webhooks,
			secretRequestSettings,
			executionSettings,
			auditSettings,
			managedSigninSettings,
			templateSettings,
			invites
		] = await Promise.all([
			orgId
				? session.get<OrgInfo>(`/v1/orgs/${orgId}`)
				: Promise.resolve(null as unknown as OrgInfo),
			session.get<IdpConfig[]>('/v1/org-idp-configs'),
			session.get<OAuthCredential[]>('/v1/org-oauth-credentials'),
			session.get<{ clients: McpClient[] }>('/v1/oauth/mcp-clients'),
			session.get<ServiceKeySummary[]>('/v1/org-service-keys'),
			session.get<Webhook[]>('/v1/webhooks'),
			orgId
				? session.get<SecretRequestSettings>(`/v1/orgs/${orgId}/secret-request-settings`)
				: Promise.resolve(null),
			orgId
				? session.get<ExecutionSettings>(`/v1/orgs/${orgId}/execution-settings`)
				: Promise.resolve(null),
			orgId
				? session.get<AuditSettings>(`/v1/orgs/${orgId}/audit-settings`)
				: Promise.resolve(null),
			orgId
				? session.get<ManagedSigninSettings>(`/v1/orgs/${orgId}/managed-signin`)
				: Promise.resolve(null),
			orgId
				? session.get<TemplateSettings>(`/v1/orgs/${orgId}/template-settings`)
				: Promise.resolve(null),
			session.get<OrgInvite[]>('/v1/org-invites')
		]);

		// Load subscription for non-personal Team orgs (404 = no subscription, silently null).
		let subscription: OrgSubscription | null = null;
		if (orgId && !org?.is_personal) {
			try {
				subscription = await session.get<OrgSubscription>(`/v1/orgs/${orgId}/subscription`);
			} catch (e) {
				if (!(e instanceof ApiError && e.status === 404)) throw e;
			}
		}

		return {
			me,
			org,
			idpConfigs,
			oauthCredentials,
			mcpClients: mcpClientsResp.clients,
			serviceKeys,
			webhooks,
			secretRequestSettings,
			executionSettings,
			auditSettings,
			managedSigninSettings,
			templateSettings,
			invites,
			subscription,
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
			serviceKeys: [],
			webhooks: [],
			secretRequestSettings: null,
			executionSettings: null,
			auditSettings: null,
			managedSigninSettings: null,
			templateSettings: null,
			invites: [],
			subscription: null,
			error: { status, message }
		};
	}
};
