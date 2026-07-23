// Transient bottom-of-page feedback.
//
// Approval rows resolve and then vanish, so the row itself can't report what
// happened — the toast is the only confirmation the operator gets. Kept
// deliberately tiny: a module-level rune array, no subscriptions, no queueing
// policy beyond "newest last, auto-dismiss".

export type ToastKind = 'success' | 'error' | 'info';

export interface Toast {
	id: number;
	kind: ToastKind;
	message: string;
}

const DEFAULT_TTL_MS = 3600;

let nextId = 0;
const items = $state<Toast[]>([]);

/** Reactive list of live toasts, oldest first. */
export const toasts = {
	get items() {
		return items;
	}
};

export function pushToast(kind: ToastKind, message: string, ttlMs = DEFAULT_TTL_MS): number {
	const id = ++nextId;
	items.push({ id, kind, message });
	if (typeof window !== 'undefined') {
		setTimeout(() => dismissToast(id), ttlMs);
	}
	return id;
}

export function dismissToast(id: number): void {
	const i = items.findIndex((t) => t.id === id);
	if (i !== -1) items.splice(i, 1);
}
