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

// A resolution's toast is the *only* confirmation the operator gets — the row
// it describes is already gone — and the messages run long ("Allowed &
// remembered — <key> · also resolved 3 related requests"). 5s is the usual
// accessibility floor for a message that must be read rather than glanced at;
// clicking dismisses sooner.
const DEFAULT_TTL_MS = 5000;

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
