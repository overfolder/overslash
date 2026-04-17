/**
 * API client wrappers for the Services view: templates, service instances,
 * and OAuth connections.
 */
import { ApiError, session } from '$lib/session';
import type {
	ActionSummary,
	ByocCredentialSummary,
	ConnectionSummary,
	CreateByocCredentialRequest,
	CreateServiceRequest,
	CreateTemplateRequest,
	InitiateConnectionRequest,
	InitiateConnectionResponse,
	OAuthProviderInfo,
	ServiceInstanceDetail,
	ServiceInstanceSummary,
	ServiceStatus,
	TemplateDetail,
	TemplateSummary,
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

// -- Template validation (pending endpoint, graceful 404) --

export async function validateTemplate(yaml: string): Promise<ValidationResult | null> {
	try {
		return await session.postText<ValidationResult>('/v1/templates/validate', yaml);
	} catch (e) {
		if (e instanceof ApiError && (e.status === 404 || e.status === 501)) return null;
		throw e;
	}
}

// -- Service instances --

export const listServices = () => session.get<ServiceInstanceSummary[]>('/v1/services');

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
 */
export const deleteService = (id: string) =>
	session.delete<{ deleted: boolean }>(`/v1/services/${id}`);

export const getServiceActions = (name: string, signal?: AbortSignal) =>
	session.get<ActionSummary[]>(`/v1/services/${encodeURIComponent(name)}/actions`, signal);

// -- OAuth connections --

export const listConnections = (signal?: AbortSignal) =>
	session.get<ConnectionSummary[]>('/v1/connections', signal);

export const initiateOAuth = (req: InitiateConnectionRequest, signal?: AbortSignal) =>
	session.post<InitiateConnectionResponse>('/v1/connections', req, signal);

export const deleteConnection = (id: string) => session.delete<void>(`/v1/connections/${id}`);

// -- OAuth providers (read-only catalog) --

export const listOAuthProviders = (signal?: AbortSignal) =>
	session.get<OAuthProviderInfo[]>('/v1/oauth-providers', signal);

// -- BYOC credentials (user self-service) --

export const listByocCredentials = (signal?: AbortSignal) =>
	session.get<ByocCredentialSummary[]>('/v1/byoc-credentials', signal);

export const createByocCredential = (req: CreateByocCredentialRequest) =>
	session.post<ByocCredentialSummary>('/v1/byoc-credentials', req);

export const deleteByocCredential = (id: string) =>
	session.delete<{ deleted: boolean }>(`/v1/byoc-credentials/${id}`);
