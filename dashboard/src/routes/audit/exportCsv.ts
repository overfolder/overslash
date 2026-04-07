import type { AuditEntry } from './types';

const COLUMNS: Array<{ key: string; get: (e: AuditEntry) => string }> = [
	{ key: 'timestamp', get: (e) => e.created_at },
	{ key: 'identity_id', get: (e) => e.identity_id ?? '' },
	{ key: 'identity', get: (e) => e.identity_name ?? '' },
	{ key: 'action', get: (e) => e.action },
	{ key: 'resource_type', get: (e) => e.resource_type ?? '' },
	{ key: 'resource_id', get: (e) => e.resource_id ?? '' },
	{ key: 'description', get: (e) => e.description ?? '' },
	{ key: 'ip_address', get: (e) => e.ip_address ?? '' },
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
