/**
 * Typed client for the Instance Admin panel (`/v1/instance/*`), plus the
 * existing per-org plan and trial endpoints it drives.
 * See crates/overslash-api/src/routes/instance/ for the source of truth.
 */
import { session } from '#lib/session.ts';

export type OrgPlan = 'standard' | 'trial' | 'free_unlimited';

export interface InstanceOrg {
	id: string;
	name: string;
	slug: string;
	plan: OrgPlan | string;
	/** Unix seconds; set only while on a trial. */
	trial_ends_at: number | null;
	is_personal: boolean;
	member_count: number;
	/** Unix seconds. */
	last_activity_at: number | null;
	/** Unix seconds. */
	created_at: number;
}

export interface InstanceOrgList {
	orgs: InstanceOrg[];
	trial_default_duration_days: number;
	allow_org_creation: boolean;
}

export interface InstanceAdmin {
	user_id: string;
	email: string | null;
	name: string | null;
	provider: string | null;
	/** Unix seconds; null = bootstrapped out-of-band. */
	granted_at: number | null;
	granted_by_email: string | null;
	last_seen_at: number | null;
	is_you: boolean;
}

export interface UserSearchResult {
	id: string;
	email: string | null;
	name: string | null;
	provider: string | null;
	is_instance_admin: boolean;
	eligible: boolean;
	reason: string | null;
}

export type ConfigValue =
	| { kind: 'text'; value: string }
	| { kind: 'list'; values: string[] }
	| { kind: 'secret'; set: boolean }
	| { kind: 'unset'; note: string | null };

export type ConfigRow = ConfigValue & { key: string; note?: string; is_default: boolean };

export interface ConfigGroup {
	title: string;
	rows: ConfigRow[];
}

export interface InstanceAuditEntry {
	id: string;
	/** RFC 3339. */
	created_at: string;
	actor_user_id: string | null;
	actor_email: string;
	action: string;
	org_id: string | null;
	org_slug: string | null;
	detail: Record<string, unknown>;
	ip_address: string | null;
}

export interface InstanceAuditFilters {
	admin?: string;
	action?: string;
	org?: string;
}

function query(params: Record<string, string | undefined>): string {
	const q = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) if (v) q.set(k, v);
	const s = q.toString();
	return s ? `?${s}` : '';
}

export const listInstanceOrgs = (includePersonal: boolean, signal?: AbortSignal) =>
	session.get<InstanceOrgList>(
		`/v1/instance/orgs${includePersonal ? '?include_personal=true' : ''}`,
		signal
	);

export const createInstanceOrg = (body: {
	name: string;
	slug: string;
	plan: OrgPlan;
	trial_days?: number;
}) => session.post<{ id: string; slug: string }>('/v1/instance/orgs', body);

export const setOrgPlan = (orgId: string, plan: 'standard' | 'free_unlimited') =>
	session.patch(`/v1/orgs/${orgId}/plan`, { plan });

export const startTrial = (orgId: string, durationDays: number) =>
	session.post(`/v1/orgs/${orgId}/trial`, { duration_days: durationDays });

export const extendTrial = (orgId: string, extendDays: number) =>
	session.patch(`/v1/orgs/${orgId}/trial`, { extend_days: extendDays });

export const listInstanceAdmins = (signal?: AbortSignal) =>
	session.get<InstanceAdmin[]>('/v1/instance/admins', signal);

export const searchInstanceUsers = (q: string, signal?: AbortSignal) =>
	session.get<UserSearchResult[]>(`/v1/instance/users${query({ q })}`, signal);

export const grantInstanceAdmin = (userId: string) =>
	session.post('/v1/instance/admins', { user_id: userId });

export const revokeInstanceAdmin = (userId: string) =>
	session.delete(`/v1/instance/admins/${userId}`);

export const getInstanceConfig = (signal?: AbortSignal) =>
	session.get<{ groups: ConfigGroup[] }>('/v1/instance/config', signal);

export const listInstanceAudit = (
	filters: InstanceAuditFilters,
	cursor?: string,
	signal?: AbortSignal
) =>
	session.get<{ entries: InstanceAuditEntry[]; next_cursor: string | null }>(
		`/v1/instance/audit${query({ ...filters, cursor })}`,
		signal
	);

export function instanceAuditExportUrl(
	filters: InstanceAuditFilters,
	format: 'csv' | 'jsonl'
): string {
	return `/v1/instance/audit/export${query({ ...filters, format })}`;
}
