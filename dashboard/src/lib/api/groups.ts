/**
 * Typed client for /v1/groups endpoints (PR #45).
 * See crates/overslash-api/src/routes/groups.rs for the source of truth.
 */
import { session } from '$lib/session';

export interface Group {
	id: string;
	org_id: string;
	name: string;
	description: string;
	allow_raw_http: boolean;
	created_at: string;
	updated_at: string;
}

export interface CreateGroupRequest {
	name: string;
	description?: string;
	allow_raw_http?: boolean;
}

export type UpdateGroupRequest = CreateGroupRequest;

export interface GroupGrant {
	id: string;
	group_id: string;
	service_instance_id: string;
	service_name: string;
	access_level: string; // "read" | "write" | "admin"
	auto_approve_reads: boolean;
	created_at: string;
}

export interface AddGrantRequest {
	service_instance_id: string;
	access_level: string;
	auto_approve_reads?: boolean;
}

export interface ServiceInstanceSummary {
	id: string;
	name: string;
	template_source: string;
	template_key: string;
	status: string;
	owner_identity_id?: string | null;
	connection_id?: string | null;
	secret_name?: string | null;
}

export interface Identity {
	id: string;
	org_id: string;
	name: string;
	kind: string; // "user" | "agent" | "sub_agent"
	external_id?: string | null;
	parent_id?: string | null;
	depth: number;
	owner_id?: string | null;
	inherit_permissions: boolean;
}

export const groupsApi = {
	list: (signal?: AbortSignal) => session.get<Group[]>('/v1/groups', signal),
	get: (id: string) => session.get<Group>(`/v1/groups/${id}`),
	create: (body: CreateGroupRequest) => session.post<Group>('/v1/groups', body),
	update: (id: string, body: UpdateGroupRequest) => session.put<Group>(`/v1/groups/${id}`, body),
	delete: (id: string) => session.delete<{ deleted: boolean }>(`/v1/groups/${id}`),

	listGrants: (id: string) => session.get<GroupGrant[]>(`/v1/groups/${id}/grants`),
	addGrant: (id: string, body: AddGrantRequest) =>
		session.post<GroupGrant>(`/v1/groups/${id}/grants`, body),
	removeGrant: (id: string, grantId: string) =>
		session.delete<{ deleted: boolean }>(`/v1/groups/${id}/grants/${grantId}`),

	listMembers: (id: string) => session.get<string[]>(`/v1/groups/${id}/members`),
	addMember: (id: string, identityId: string) =>
		session.post<unknown>(`/v1/groups/${id}/members`, { identity_id: identityId }),
	removeMember: (id: string, identityId: string) =>
		session.delete<{ deleted: boolean }>(`/v1/groups/${id}/members/${identityId}`)
};

export const identitiesApi = {
	list: () => session.get<Identity[]>('/v1/identities')
};

export const servicesApi = {
	list: () => session.get<ServiceInstanceSummary[]>('/v1/services')
};
