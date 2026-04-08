import { writable, type Writable } from 'svelte/store';
import { session, type UserPreferences } from '$lib/session';

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
export const timeFormat = persisted<'relative' | 'absolute'>('ovs_time_format', 'relative');

let preferencesHydrated = false;
let suppressSync = false;

/** Pull user preferences from the backend and apply to local stores. Idempotent. */
export async function hydrateUserPreferences(): Promise<void> {
	if (preferencesHydrated) return;
	let prefs: UserPreferences;
	try {
		prefs = await session.get<UserPreferences>('/auth/me/preferences');
	} catch {
		/* not authenticated or backend down — keep local values, allow retry */
		return;
	}
	// Only mark hydrated once the fetch has actually succeeded, otherwise a
	// transient backend error would lock the user out of their saved prefs
	// for the rest of the session.
	preferencesHydrated = true;
	suppressSync = true;
	try {
		if (prefs.theme === 'light' || prefs.theme === 'dark') {
			theme.set(prefs.theme);
		}
		if (prefs.time_display === 'relative' || prefs.time_display === 'absolute') {
			timeFormat.set(prefs.time_display);
		}
	} finally {
		// `persisted()` writes to localStorage in its subscriber, which can
		// throw (quota exceeded, private-mode Safari). Use `finally` so a
		// throw can't strand `suppressSync = true` and silently disable all
		// future preference syncing for the session.
		suppressSync = false;
	}
}

async function pushPreferences(patch: UserPreferences) {
	if (suppressSync || !preferencesHydrated) return;
	try {
		await session.put('/auth/me/preferences', patch);
	} catch {
		/* ignore — local store still updated */
	}
}

theme.subscribe((val) => {
	void pushPreferences({ theme: val });
});
timeFormat.subscribe((val) => {
	void pushPreferences({ time_display: val });
});

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
