import { writable, type Writable } from 'svelte/store';
import { session } from '$lib/session';

function persisted<T>(key: string, initial: T): Writable<T> {
	let stored = initial;
	if (typeof localStorage !== 'undefined') {
		const raw = localStorage.getItem(key);
		if (raw !== null) {
			try {
				stored = JSON.parse(raw) as T;
			} catch {
				/* ignore */
			}
		}
	}
	const store = writable<T>(stored);
	store.subscribe((val) => {
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem(key, JSON.stringify(val));
		}
	});
	return store;
}

function initialTheme(): 'light' | 'dark' {
	if (typeof localStorage !== 'undefined' && localStorage.getItem('ovs_theme') !== null) {
		try {
			return JSON.parse(localStorage.getItem('ovs_theme') as string);
		} catch {
			/* fallthrough */
		}
	}
	if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches) {
		return 'dark';
	}
	return 'light';
}

export const sidebarCollapsed = persisted<boolean>('ovs_sidebar_collapsed', false);
export const theme = persisted<'light' | 'dark'>('ovs_theme', initialTheme());

export const notificationsStore = writable<{ count: number }>({ count: 0 });

interface ApprovalLite {
	status?: string;
	created_at?: string;
}

let pollTimer: ReturnType<typeof setInterval> | null = null;

async function pollOnce() {
	try {
		const res = await session.get<{ approvals?: ApprovalLite[] } | ApprovalLite[]>(
			'/v1/approvals?status=pending'
		);
		const list: ApprovalLite[] = Array.isArray(res) ? res : (res?.approvals ?? []);
		const cutoff = Date.now() - 60_000;
		const count = list.filter((a) => {
			if (a.status && a.status !== 'pending') return false;
			if (!a.created_at) return true;
			const t = Date.parse(a.created_at);
			return Number.isFinite(t) ? t <= cutoff : true;
		}).length;
		notificationsStore.set({ count });
	} catch {
		/* swallow */
	}
}

export function startNotificationPolling() {
	if (pollTimer !== null) return;
	pollOnce();
	pollTimer = setInterval(pollOnce, 30_000);
}

export function stopNotificationPolling() {
	if (pollTimer !== null) {
		clearInterval(pollTimer);
		pollTimer = null;
	}
}
