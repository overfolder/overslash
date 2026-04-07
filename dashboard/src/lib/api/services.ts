/**
 * API client wrappers for the Services view: templates, service instances,
 * and OAuth connections.
 */
import { session } from '$lib/session';
import type {
	ActionSummary,
	ConnectionSummary,
	CreateServiceRequest,
	InitiateConnectionRequest,
	InitiateConnectionResponse,
	ServiceInstanceDetail,
	ServiceInstanceSummary,
	ServiceStatus,
	TemplateDetail,
	TemplateSummary,
	UpdateServiceRequest
} from '$lib/types';

// -- Templates --

export const listTemplates = () => session.get<TemplateSummary[]>('/v1/templates');

export const searchTemplates = (q: string) =>
	session.get<TemplateSummary[]>(`/v1/templates/search?q=${encodeURIComponent(q)}`);

export const getTemplate = (key: string) =>
	session.get<TemplateDetail>(`/v1/templates/${encodeURIComponent(key)}`);

export const getTemplateActions = (key: string) =>
	session.get<ActionSummary[]>(`/v1/templates/${encodeURIComponent(key)}/actions`);

// -- Service instances --

export const listServices = () => session.get<ServiceInstanceSummary[]>('/v1/services');

export const getService = (name: string) =>
	session.get<ServiceInstanceDetail>(`/v1/services/${encodeURIComponent(name)}`);

export const createService = (req: CreateServiceRequest) =>
	session.post<ServiceInstanceDetail>('/v1/services', req);

export const updateService = (id: string, patch: UpdateServiceRequest) =>
	session.put<ServiceInstanceDetail>(`/v1/services/${id}/manage`, patch);

export const setServiceStatus = (id: string, status: ServiceStatus) =>
	session.patch<ServiceInstanceDetail>(`/v1/services/${id}/status`, { status });

export const deleteService = (name: string) =>
	session.delete<{ deleted: boolean }>(`/v1/services/${encodeURIComponent(name)}`);

export const getServiceActions = (name: string) =>
	session.get<ActionSummary[]>(`/v1/services/${encodeURIComponent(name)}/actions`);

// -- OAuth connections --

export const listConnections = (signal?: AbortSignal) =>
	session.get<ConnectionSummary[]>('/v1/connections', signal);

export const initiateOAuth = (req: InitiateConnectionRequest, signal?: AbortSignal) =>
	session.post<InitiateConnectionResponse>('/v1/connections', req, signal);

export const deleteConnection = (id: string) => session.delete<void>(`/v1/connections/${id}`);
