import { get } from 'svelte/store';
import { timeFormat } from '$lib/stores/shell';

export function relativeTime(iso: string): string {
	const t = Date.parse(iso);
	if (!Number.isFinite(t)) return iso;
	const diffMs = t - Date.now();
	const abs = Math.abs(diffMs);
	const sec = Math.round(abs / 1000);
	const min = Math.round(sec / 60);
	const hr = Math.round(min / 60);
	const day = Math.round(hr / 24);
	let phrase: string;
	if (sec < 60) phrase = `${sec}s`;
	else if (min < 60) phrase = `${min}m`;
	else if (hr < 24) phrase = `${hr}h`;
	else phrase = `${day}d`;
	return diffMs < 0 ? `${phrase} ago` : `in ${phrase}`;
}

export function absoluteTime(iso: string): string {
	const t = Date.parse(iso);
	if (!Number.isFinite(t)) return iso;
	return new Date(t).toLocaleString();
}

export function formatTime(iso: string | null | undefined): string {
	if (!iso) return '—';
	return get(timeFormat) === 'absolute' ? absoluteTime(iso) : relativeTime(iso);
}

/** Render TTL until `expiresAt`. Returns "forever", "expired", or a short like "3d 4h". */
export function ttlRemaining(expiresAt: string | null | undefined): string {
	if (!expiresAt) return 'forever';
	const t = Date.parse(expiresAt);
	if (!Number.isFinite(t)) return expiresAt;
	const diff = t - Date.now();
	if (diff <= 0) return 'expired';
	const sec = Math.floor(diff / 1000);
	const day = Math.floor(sec / 86400);
	const hr = Math.floor((sec % 86400) / 3600);
	const min = Math.floor((sec % 3600) / 60);
	if (day > 0) return `${day}d ${hr}h`;
	if (hr > 0) return `${hr}h ${min}m`;
	return `${min}m`;
}
