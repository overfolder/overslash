export interface AuditEntry {
	id: string;
	identity_id: string | null;
	action: string;
	resource_type: string | null;
	resource_id: string | null;
	detail: Record<string, unknown>;
	ip_address: string | null;
	created_at: string;
}

export interface Identity {
	id: string;
	org_id: string;
	name: string;
	kind: string;
	external_id: string | null;
}

export interface ServiceSummary {
	key: string;
	display_name: string;
	hosts: string[];
	action_count: number;
}

export type EventCategory =
	| 'action_executed'
	| 'approval_resolved'
	| 'secret_accessed'
	| 'connection_changed';

export const EVENT_CATEGORY_MAP: Record<EventCategory, string[]> = {
	action_executed: ['action.executed', 'action.streamed'],
	approval_resolved: ['approval.resolved', 'approval.created'],
	secret_accessed: ['secret.put', 'secret.deleted'],
	connection_changed: ['connection.created', 'connection.deleted']
};

export const EVENT_CATEGORY_LABELS: Record<EventCategory, string> = {
	action_executed: 'Action Executed',
	approval_resolved: 'Approval Resolved',
	secret_accessed: 'Secret Accessed',
	connection_changed: 'Connection Changed'
};

export interface AuditFilters {
	identity_id?: string;
	category?: EventCategory;
	service?: string;
	since?: string;
	until?: string;
	page: number;
	limit: number;
}
