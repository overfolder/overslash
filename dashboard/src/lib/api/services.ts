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
	DraftTemplateDetail,
	ImportTemplateRequest,
	InitiateConnectionRequest,
	InitiateConnectionResponse,
	OAuthProviderInfo,
	ServiceGroupRef,
	ServiceInstanceDetail,
	ServiceInstanceSummary,
	ServiceStatus,
	TemplateDetail,
	TemplateSummary,
	UpdateDraftRequest,
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

// -- MCP runtime control (per-service instance) --

export interface McpStatusResponse {
	state: 'stopped' | 'starting' | 'ready' | 'paused' | 'error';
	pid: number | null;
	last_used: string | null;
	since: string | null;
	memory_mb: number | null;
	env_hash: string | null;
	package: string | null;
	version: string | null;
	last_error: string | null;
}

export interface McpLogLine {
	ts: string;
	level: 'stderr' | 'stdio' | 'event';
	text: string;
}

export const getMcpStatus = (serviceId: string) =>
	session.get<McpStatusResponse>(`/v1/services/${encodeURIComponent(serviceId)}/mcp-status`);

export const getMcpLogs = (serviceId: string, lines = 100, level = 'stderr,stdio,event') =>
	session.get<{ lines: McpLogLine[] }>(
		`/v1/services/${encodeURIComponent(serviceId)}/mcp-logs?lines=${lines}&level=${encodeURIComponent(level)}`
	);

export const wakeMcp = (serviceId: string) =>
	session.post<{ state: string; pid: number | null; since: string | null }>(
		`/v1/services/${encodeURIComponent(serviceId)}/mcp/wake`,
		{}
	);

export const stopMcp = (serviceId: string) =>
	session.post<null>(`/v1/services/${encodeURIComponent(serviceId)}/mcp/stop`, {});

export const restartMcp = (serviceId: string) =>
	session.post<{ state: string; pid: number | null; since: string | null }>(
		`/v1/services/${encodeURIComponent(serviceId)}/mcp/restart`,
		{}
	);

// -- MCP introspection --

export type McpEnvBinding =
	| { from: 'secret'; default_secret_name?: string | null }
	| { from: 'oauth_token'; provider: string }
	| { from: 'literal'; value: string };

export interface IntrospectedMcpTool {
	name: string;
	description: string | null;
	input_schema: unknown;
	suggested_risk: 'read' | 'write' | 'delete';
}

export interface IntrospectMcpRequest {
	package?: string;
	version?: string;
	command?: string[];
	env?: Record<string, string>;
}

export const introspectMcp = (req: IntrospectMcpRequest) =>
	session.post<{ tools: IntrospectedMcpTool[] }>('/v1/templates/mcp/introspect', req);

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

export const listServiceGroups = (serviceId: string, signal?: AbortSignal) =>
	session.get<ServiceGroupRef[]>(`/v1/services/${serviceId}/groups`, signal);

// -- OAuth connections --

export const listConnections = (signal?: AbortSignal) =>
	session.get<ConnectionSummary[]>('/v1/connections', signal);

export const initiateOAuth = (req: InitiateConnectionRequest, signal?: AbortSignal) =>
	session.post<InitiateConnectionResponse>('/v1/connections', req, signal);

export const deleteConnection = (id: string) => session.delete<void>(`/v1/connections/${id}`);

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

export const deleteByocCredential = (id: string) =>
	session.delete<{ deleted: boolean }>(`/v1/byoc-credentials/${id}`);
