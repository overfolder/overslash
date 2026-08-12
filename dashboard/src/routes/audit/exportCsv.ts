import { identityUnits } from '$lib/identityPath';
import type { AuditEntry } from './types';

// Names are the ones *recorded on the row* (D59), falling back to the live
// chain for rows written before those columns existed. An exported audit log is
// a record: it should say who acted under the name they acted under.
const COLUMNS: Array<{ key: string; get: (e: AuditEntry) => string }> = [
	{ key: 'timestamp', get: (e) => e.created_at },
	{ key: 'identity_id', get: (e) => e.identity_id ?? '' },
	{
		key: 'user',
		get: (e) =>
			e.owner_user_name ?? identityUnits(e.identity_path, e.identity_path_ids).user?.name ?? ''
	},
	{
		key: 'agent',
		get: (e) =>
			e.identity_name ?? identityUnits(e.identity_path, e.identity_path_ids).leaf?.name ?? ''
	},
	{ key: 'action', get: (e) => e.action },
	// Empty, not a placeholder dash: a CSV cell is read by a spreadsheet, and
	// "not a gated call" is better spelled as absence than as an em dash.
	{ key: 'risk', get: (e) => e.risk ?? '' },
	{ key: 'resource_type', get: (e) => e.resource_type ?? '' },
	{ key: 'resource_id', get: (e) => e.resource_id ?? '' },
	{ key: 'description', get: (e) => e.description ?? '' },
	{ key: 'ip_address', get: (e) => e.ip_address ?? '' },
	// Space-separated: tags never contain whitespace (the minter collapses it),
	// so this stays one CSV cell that splits cleanly downstream.
	{ key: 'tags', get: (e) => (e.tags ?? []).join(' ') },
	{ key: 'detail', get: (e) => JSON.stringify(e.detail ?? {}) }
];

function quote(value: string): string {
	if (/[",\r\n]/.test(value)) {
		return `"${value.replace(/"/g, '""')}"`;
	}
	return value;
}

export function toCsv(entries: AuditEntry[]): string {
	const header = COLUMNS.map((c) => c.key).join(',');
	const rows = entries.map((e) => COLUMNS.map((c) => quote(c.get(e))).join(','));
	return [header, ...rows].join('\r\n');
}

export function downloadCsv(entries: AuditEntry[]): void {
	const csv = toCsv(entries);
	const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	const date = new Date().toISOString().slice(0, 10);
	a.href = url;
	a.download = `audit-${date}.csv`;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	// Firefox initiates the download asynchronously after click(); revoking
	// the blob URL synchronously can race with that and cancel the download.
	// Defer revocation so the browser has time to start the transfer.
	setTimeout(() => URL.revokeObjectURL(url), 100);
}
