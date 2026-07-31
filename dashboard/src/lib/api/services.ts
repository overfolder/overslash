/**
 * API client wrappers for the Services view: templates, service instances,
 * and OAuth connections.
 */
import { ApiError, session } from '$lib/session';
import type {
	ActionSummary,
	ByocCredentialSummary,
	ConnectionDetail,
	ConnectionSummary,
	CreateByocCredentialRequest,
	CreateServiceRequest,
	CreateTemplateRequest,
	Delta,
	DraftTemplateDetail,
	ImportTemplateRequest,
	InitiateConnectionRequest,
	InitiateConnectionResponse,
	OAuthProviderInfo,
	ServiceGroupRef,
	ServiceInstanceDetail,
	ServiceInstanceSummary,
	ServiceStatus,
	AdminTemplateSummary,
	TemplateDetail,
	TemplateSettings,
	TemplateSummary,
	TemplateVar,
	UpdateDraftRequest,
	UpdateByocCredentialRequest,
	UpdateServiceRequest,
	UpdateTemplateRequest,
	ValidationResult
} from '$lib/types';

// -- Templates --

export const listTemplates = () => session.get<TemplateSummary[]>('/v1/templates');

export const searchTemplates = (q: string) =>
	session.get<TemplateSummary[]>(`/v1/templates/search?q=${encodeURIComponent(q)}`);

export const getTemplate = (key: string, signal?: AbortSignal) =>
	session.get<TemplateDetail>(`/v1/templates/${encodeURIComponent(key)}`, signal);

export const getTemplateActions = (key: string, signal?: AbortSignal) =>
	session.get<ActionSummary[]>(`/v1/templates/${encodeURIComponent(key)}/actions`, signal);

// -- Template CRUD --

export const createTemplate = (req: CreateTemplateRequest) =>
	session.post<TemplateDetail>('/v1/templates', req);

export const updateTemplate = (id: string, patch: UpdateTemplateRequest) =>
	session.put<TemplateDetail>(`/v1/templates/${id}/manage`, patch);

export const deleteTemplate = (id: string) =>
	session.delete<{ deleted: boolean }>(`/v1/templates/${id}/manage`);

// -- Catalog curation (org-admin) --

/** Read the org's template/catalog settings. */
export const getTemplateSettings = (orgId: string, signal?: AbortSignal) =>
	session.get<TemplateSettings>(`/v1/orgs/${orgId}/template-settings`, signal);

/** Update the org's template/catalog settings. */
export const updateTemplateSettings = (orgId: string, patch: Partial<TemplateSettings>) =>
	session.patch<TemplateSettings>(`/v1/orgs/${orgId}/template-settings`, patch);

/**
 * Admin compliance view: every template across all tiers, with an `enabled`
 * flag on global rows reflecting the org's curated-catalog allow-list.
 */
export const listAdminTemplates = (signal?: AbortSignal) =>
	session.get<AdminTemplateSummary[]>('/v1/templates/admin', signal);

/** Global template keys explicitly enabled for this org (the curated allow-list). */
export const listEnabledGlobals = (signal?: AbortSignal) =>
	session.get<string[]>('/v1/templates/enabled-globals', signal);

/** Add a global template to the org's curated catalog. */
export const enableGlobalTemplate = (key: string) =>
	session.post<{ enabled: boolean; template_key: string }>('/v1/templates/enabled-globals', {
		template_key: key
	});

/** Remove a global template from the org's curated catalog. */
export const disableGlobalTemplate = (key: string) =>
	session.delete<{ disabled: boolean; template_key: string }>(
		`/v1/templates/enabled-globals/${encodeURIComponent(key)}`
	);

// -- OpenAPI import / drafts --

export const importTemplate = (req: ImportTemplateRequest) =>
	session.post<DraftTemplateDetail>('/v1/templates/import', req);

export const listDrafts = (signal?: AbortSignal) =>
	session.get<DraftTemplateDetail[]>('/v1/templates/drafts', signal);

export const getDraft = (id: string, signal?: AbortSignal) =>
	session.get<DraftTemplateDetail>(`/v1/templates/drafts/${encodeURIComponent(id)}`, signal);

export const updateDraft = (id: string, patch: UpdateDraftRequest) =>
	session.put<DraftTemplateDetail>(`/v1/templates/drafts/${encodeURIComponent(id)}`, patch);

export const promoteDraft = (id: string) =>
	session.post<TemplateDetail>(
		`/v1/templates/drafts/${encodeURIComponent(id)}/promote`,
		{}
	);

export const discardDraft = (id: string) =>
	session.delete<{ deleted: boolean }>(`/v1/templates/drafts/${encodeURIComponent(id)}`);

// -- MCP tools resync --

export interface McpResyncResponse {
	service_id: string;
	tool_count: number;
	discovered_at: string;
}

// Resync runs against a service *instance* (which carries the url/secret or
// OAuth connection needed to reach the MCP server); the result is stored per
// instance. An OAuth instance with no connection yields a `needs_authentication`
// envelope (ApiError) the caller drives through the connect flow.
export const resyncMcpService = (id: string) =>
	session.post<McpResyncResponse>(
		`/v1/services/${encodeURIComponent(id)}/mcp/resync`,
		{}
	);

// -- Template variables (D44) --

/** The `${VAR}` references a template authored on this deployment can resolve.
 * Graceful 404 for the same reason `validateTemplate` has one: the editor must
 * still work against an API that predates the endpoint. */
export async function listTemplateVars(): Promise<TemplateVar[] | null> {
	try {
		return await session.get<TemplateVar[]>('/v1/templates/vars');
	} catch (e) {
		if (e instanceof ApiError && (e.status === 404 || e.status === 501)) return null;
		throw e;
	}
}

// -- Template validation (pending endpoint, graceful 404) --

export async function validateTemplate(yaml: string): Promise<ValidationResult | null> {
	try {
		return await session.postText<ValidationResult>('/v1/templates/validate', yaml);
	} catch (e) {
		if (e instanceof ApiError && (e.status === 404 || e.status === 501)) return null;
		throw e;
	}
}

/** Lint a derived-layer delta against its resolved base (live editor feedback).
 * `userLevel` must match the scope the layer will be created at so the preview
 * folds over the same base the server will. */
export async function validateDelta(
	extendsKey: string,
	delta: Delta,
	userLevel = false
): Promise<ValidationResult | null> {
	try {
		return await session.post<ValidationResult>('/v1/templates/validate-delta', {
			extends: extendsKey,
			delta,
			user_level: userLevel
		});
	} catch (e) {
		if (e instanceof ApiError && (e.status === 404 || e.status === 501)) return null;
		throw e;
	}
}

// -- Service instances --

export const listServices = (
	opts: { includeUserLevel?: boolean; user?: string; connection?: string } = {}
) => {
	const p = new URLSearchParams();
	// `user=` (admin-only) lists the target user's accessible set and takes
	// precedence over `include_user_level` on the backend; send only one.
	if (opts.user) p.set('user', opts.user);
	else if (opts.includeUserLevel) p.set('include_user_level', 'true');
	// `connection=` subsets the listing to instances bound to that connection —
	// the Connections view's "Used by" cross-link.
	if (opts.connection) p.set('connection', opts.connection);
	const qs = p.toString();
	return session.get<ServiceInstanceSummary[]>(`/v1/services${qs ? `?${qs}` : ''}`);
};

export const getService = (name: string, signal?: AbortSignal) =>
	session.get<ServiceInstanceDetail>(
		`/v1/services/${encodeURIComponent(name)}?include_inactive=true`,
		signal
	);

export const createService = (req: CreateServiceRequest) =>
	session.post<ServiceInstanceDetail>('/v1/services', req);

export const updateService = (id: string, patch: UpdateServiceRequest) =>
	session.put<ServiceInstanceDetail>(`/v1/services/${id}/manage`, patch);

export const setServiceStatus = (id: string, status: ServiceStatus) =>
	session.patch<ServiceInstanceDetail>(`/v1/services/${id}/status`, { status });

/**
 * Delete a service instance. Always pass the instance UUID — never the name —
 * because the backend's name-based resolution uses user-shadows-org semantics
 * and would delete a user-owned instance that happens to share a name with the
 * org-level row the user actually clicked.
 *
 * By default the OAuth connection the service was bound to is also cleaned up
 * when it becomes orphaned (no other service uses it and it isn't marked
 * `keep`). Pass `{ keepConnection: true }` to preserve the connection.
 */
export const deleteService = (id: string, opts: { keepConnection?: boolean } = {}) =>
	session.delete<{ deleted: boolean; connection_deleted: boolean }>(
		`/v1/services/${id}${opts.keepConnection ? '?keep_connection=true' : ''}`
	);

export const getServiceActions = (name: string, signal?: AbortSignal) =>
	session.get<ActionSummary[]>(`/v1/services/${encodeURIComponent(name)}/actions`, signal);

export const listServiceGroups = (serviceId: string, signal?: AbortSignal) =>
	session.get<ServiceGroupRef[]>(`/v1/services/${serviceId}/groups`, signal);

// -- OAuth connections --

export const listConnections = (
	opts: { includeUserLevel?: boolean; ownerIdentityId?: string } = {},
	signal?: AbortSignal
) => {
	// `include_user_level=true` (admin-only) lists every user's connections
	// across the org; silently ignored for non-admins by the backend.
	// `owner_identity_id` lists a specific owner's connections (self always
	// allowed, another identity is admin-only); the service detail page passes
	// the service's owner so an admin sees that user's bindable connections.
	const params = new URLSearchParams();
	if (opts.includeUserLevel) params.set('include_user_level', 'true');
	if (opts.ownerIdentityId) params.set('owner_identity_id', opts.ownerIdentityId);
	const qs = params.toString() ? `?${params}` : '';
	return session.get<ConnectionSummary[]>(`/v1/connections${qs}`, signal);
};

export const getConnection = (id: string, signal?: AbortSignal) =>
	session.get<ConnectionDetail>(`/v1/connections/${id}`, signal);

export const initiateOAuth = (req: InitiateConnectionRequest, signal?: AbortSignal) =>
	session.post<InitiateConnectionResponse>('/v1/connections', req, signal);

export const deleteConnection = (id: string) => session.delete<void>(`/v1/connections/${id}`);

/**
 * Promote a connection to be the default for its provider. Low-risk + idempotent
 * — the list radio and detail toggle fire this with no confirmation.
 */
export const setConnectionDefault = (id: string) =>
	session.post<{ is_default: boolean }>(`/v1/connections/${id}/set_default`, {});

/**
 * Set (or clear) the `keep` flag on a connection. When `keep` is true the
 * connection is preserved from the service-deletion auto-cleanup even when no
 * service references it. Owner-or-admin gated; fired from the detail toggle.
 */
export const setConnectionKeep = (id: string, keep: boolean) =>
	session.post<{ keep: boolean }>(`/v1/connections/${id}/keep`, { keep });

export interface UpgradeScopesResponse {
	auth_url: string;
	state: string;
	connection_id: string;
	requested_scopes: string[];
}

/**
 * Start an incremental-scope OAuth flow for an existing connection. The
 * returned auth URL re-runs OAuth and the callback updates the connection
 * row in place — services bound to this connection stay bound.
 */
export const upgradeConnectionScopes = (
	connectionId: string,
	scopes: string[],
	signal?: AbortSignal
) =>
	session.post<UpgradeScopesResponse>(
		`/v1/connections/${connectionId}/upgrade_scopes`,
		{ scopes },
		signal
	);

// -- OAuth providers (read-only catalog) --

export const listOAuthProviders = (signal?: AbortSignal) =>
	session.get<OAuthProviderInfo[]>('/v1/oauth-providers', signal);

// -- BYOC credentials (user self-service) --

export const listByocCredentials = (signal?: AbortSignal) =>
	session.get<ByocCredentialSummary[]>('/v1/byoc-credentials', signal);

export const createByocCredential = (req: CreateByocCredentialRequest) =>
	session.post<ByocCredentialSummary>('/v1/byoc-credentials', req);

// Replace an existing credential's client id/secret in place. The credential id
// (and every connection pinned to it) survives; pinned connections are marked
// `reauth_required` server-side.
export const updateByocCredential = (id: string, req: UpdateByocCredentialRequest) =>
	session.put<ByocCredentialSummary>(`/v1/byoc-credentials/${id}`, req);

export const deleteByocCredential = (id: string) =>
	session.delete<{ deleted: boolean }>(`/v1/byoc-credentials/${id}`);
