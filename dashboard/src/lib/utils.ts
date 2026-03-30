import { EVENT_CATEGORY_MAP, type EventCategory } from './types';

export function formatTimestamp(iso: string): string {
	const d = new Date(iso);
	return d.toLocaleString('en-US', {
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
		second: '2-digit',
		hour12: false
	});
}

export function formatFullTimestamp(iso: string): string {
	return new Date(iso).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

export function getRelativeTime(iso: string): string {
	const now = Date.now();
	const then = new Date(iso).getTime();
	const diffSec = Math.floor((now - then) / 1000);

	if (diffSec < 60) return `${diffSec}s ago`;
	const diffMin = Math.floor(diffSec / 60);
	if (diffMin < 60) return `${diffMin}m ago`;
	const diffHr = Math.floor(diffMin / 60);
	if (diffHr < 24) return `${diffHr}h ago`;
	const diffDay = Math.floor(diffHr / 24);
	return `${diffDay}d ago`;
}

export function humanizeAction(action: string): string {
	return action
		.split('.')
		.map((s) => s.charAt(0).toUpperCase() + s.slice(1))
		.join(' ');
}

export function resolveCategory(action: string): EventCategory | null {
	for (const [category, actions] of Object.entries(EVENT_CATEGORY_MAP)) {
		if (actions.includes(action)) return category as EventCategory;
	}
	return null;
}

export function categoryColor(category: EventCategory | null): string {
	switch (category) {
		case 'action_executed':
			return 'bg-blue-100 text-blue-800';
		case 'approval_resolved':
			return 'bg-amber-100 text-amber-800';
		case 'secret_accessed':
			return 'bg-red-100 text-red-800';
		case 'connection_changed':
			return 'bg-green-100 text-green-800';
		default:
			return 'bg-gray-100 text-gray-700';
	}
}

export function kindBadgeColor(kind: string): string {
	switch (kind) {
		case 'user':
			return 'bg-purple-100 text-purple-800';
		case 'agent':
			return 'bg-cyan-100 text-cyan-800';
		default:
			return 'bg-gray-100 text-gray-700';
	}
}

export function extractResultSummary(entry: { action: string; detail: Record<string, unknown> }): string {
	const d = entry.detail;
	switch (entry.action) {
		case 'action.executed':
			return `${d.status_code ?? '—'} (${d.duration_ms ?? '?'}ms)`;
		case 'action.streamed':
			return `${d.status_code ?? '—'}`;
		case 'approval.resolved':
			return String(d.decision ?? d.status ?? '—');
		case 'secret.put':
			return `v${d.version ?? '?'}`;
		case 'identity.created':
			return String(d.kind ?? '—');
		case 'permission_rule.created':
			return String(d.effect ?? '—');
		default:
			return '—';
	}
}
