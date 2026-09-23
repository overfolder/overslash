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
	is_system: boolean;
	/** "everyone" | "admins" | "self" for system groups; absent otherwise. */
	system_kind?: 'everyone' | 'admins' | 'self';
	/** Set iff system_kind === 'self' — the user-identity this Myself group is for. */
	owner_identity_id?: string;
	/**
	 * Whether the calling identity belongs to this group (resolved through
	 * their ceiling user). Only present on the list endpoint. Creating an
	 * org-level service requires a group where this is `true`.
	 */
	is_member?: boolean;
	created_at: string;
	updated_at: string;
}

/** One group grant as picked in the UI, before it is persisted. */
export interface GroupGrantPick {
	group_id: string;
	access_level: 'read' | 'write' | 'admin';
	/** Never above `access_level` — the API rejects the pair with a 400. */
	auto_approve_level: 'none' | 'read' | 'write' | 'admin';
}

export interface CreateGroupRequest {
	name: string;
	description?: string;
}

export type UpdateGroupRequest = CreateGroupRequest;

export interface GroupGrant {
	id: string;
	group_id: string;
	service_instance_id: string;
	service_name: string;
	access_level: string; // "read" | "write" | "admin"
	auto_approve_level: string; // "none" | "read" | "write" | "admin", <= access_level
	/** @deprecated derived from `auto_approve_level !== 'none'`. */
	auto_approve_reads: boolean;
	created_at: string;
}

export interface AddGrantRequest {
	service_instance_id: string;
	access_level: string;
	auto_approve_level?: string;
}

export interface PatchGrantRequest {
	access_level?: string;
	auto_approve_level?: string;
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
	email?: string | null;
	parent_id?: string | null;
	depth: number;
	owner_id?: string | null;
	inherit_permissions: boolean;
}

/**
 * A group as an external directory reports it.
 *
 * Not a ceiling: it carries no grants and confers nothing until an admin maps
 * it onto a real group. See crates/overslash-api/src/routes/directory_groups.rs.
 */
export interface DirectoryGroup {
	id: string;
	org_id: string;
	/** The IdP config that reported it, when it came from a login. */
	idp_config_id?: string;
	/** 'oidc_claim' today; widened as Admin SDK / SCIM sources land. */
	source: string;
	/** The claim value — a name from Okta, an object GUID from Entra. */
	external_id: string;
	display_name: string;
	first_seen_at: string;
	last_seen_at: string;
}

export interface DirectoryGroupSummary extends DirectoryGroup {
	/** Humans the directory currently places in this group. */
	member_count: number;
	/** Groups it feeds. Empty means discovered but inert. */
	mapped_group_ids: string[];
}

/** One member of a group and how they got there. A member can be both. */
export interface MemberOrigin {
	identity_id: string;
	/** An admin put them here, and an admin can take them out. */
	direct: boolean;
	/** Directory groups routing them in. Non-empty with `direct: false` means
	 *  there is no manual row to remove — the mapping has to go instead. */
	via_directory_group_ids: string[];
}

export const groupsApi = {
	list: (signal?: AbortSignal) => session.get<Group[]>('/v1/groups', signal),
	/**
	 * Like `list`, but includes per-user "Myself" system groups
	 * (`system_kind === 'self'`). The default listing hides them so the org
	 * admin's group view doesn't get flooded by one row per user; the service
	 * detail page calls this variant so an owner can see and manage their own
	 * Myself grant inline.
	 */
	listIncludingSelf: (signal?: AbortSignal) =>
		session.get<Group[]>('/v1/groups?include_self=true', signal),
	get: (id: string) => session.get<Group>(`/v1/groups/${id}`),
	create: (body: CreateGroupRequest) => session.post<Group>('/v1/groups', body),
	update: (id: string, body: UpdateGroupRequest) => session.put<Group>(`/v1/groups/${id}`, body),
	delete: (id: string) => session.delete<{ deleted: boolean }>(`/v1/groups/${id}`),

	listGrants: (id: string) => session.get<GroupGrant[]>(`/v1/groups/${id}/grants`),
	addGrant: (id: string, body: AddGrantRequest) =>
		session.post<GroupGrant>(`/v1/groups/${id}/grants`, body),
	patchGrant: (id: string, grantId: string, body: PatchGrantRequest) =>
		session.patch<GroupGrant>(`/v1/groups/${id}/grants/${grantId}`, body),
	removeGrant: (id: string, grantId: string) =>
		session.delete<{ deleted: boolean }>(`/v1/groups/${id}/grants/${grantId}`),

	listMembers: (id: string) => session.get<string[]>(`/v1/groups/${id}/members`),
	addMember: (id: string, identityId: string) =>
		session.post<unknown>(`/v1/groups/${id}/members`, { identity_id: identityId }),
	removeMember: (id: string, identityId: string) =>
		session.delete<{ deleted: boolean }>(`/v1/groups/${id}/members/${identityId}`),

	/** Members tagged direct / via-directory. Companion to `listMembers`, which
	 *  returns a bare id list and is left unchanged. */
	listMemberOrigins: (id: string) =>
		session.get<MemberOrigin[]>(`/v1/groups/${id}/member-origins`),

	listDirectorySources: (id: string) =>
		session.get<DirectoryGroup[]>(`/v1/groups/${id}/directory-sources`),
	/** Map a directory group in. This is the act that grants something. */
	addDirectorySource: (id: string, directoryGroupId: string) =>
		session.post<{ created: boolean }>(`/v1/groups/${id}/directory-sources`, {
			directory_group_id: directoryGroupId
		}),
	removeDirectorySource: (id: string, directoryGroupId: string) =>
		session.delete<{ deleted: boolean }>(
			`/v1/groups/${id}/directory-sources/${directoryGroupId}`
		)
};

export const directoryGroupsApi = {
	list: (signal?: AbortSignal) =>
		session.get<DirectoryGroupSummary[]>('/v1/directory-groups', signal)
};

export const identitiesApi = {
	list: () => session.get<Identity[]>('/v1/identities')
};

export const servicesApi = {
	list: () => session.get<ServiceInstanceSummary[]>('/v1/services')
};
