// The pending step-up, if any.
//
// An admin-class mutation in a shared org, or revealing a secret there, needs
// a recent sign-in through one of the org's IdPs; otherwise the API answers
// 403 `step_up_required`. The session client hands that body here, and
// `StepUpModal` (mounted once in the root layout) offers the sign-ins that
// would satisfy it. The failed request still throws, so the page that made it
// shows its usual error too.
//
// The sign-in is a full-page redirect, so nothing in memory survives it. A
// caller that can repeat its action by itself says so with `describeStepUp`.
// The modal then records a `StepUpResume` as the human leaves, and the page
// picks it up with `takeStepUpResume` on the way back. The record is written
// only on that click, never from a URL, so a link cannot trigger the action.

export type StepUpReason =
	| 'idp_required'
	| 'provider_not_allowed'
	| 'stale'
	| 'auth_time_missing';

export interface StepUpProvider {
	key: string;
	display_name: string;
	/** `/auth/login/{key}?step_up=true[&org=…]`; the modal appends `next`. */
	login_path: string;
}

export interface StepUpChallenge {
	reason: StepUpReason;
	providers: StepUpProvider[];
	max_age_secs: number;
}

/** What the prompt says when the action is not an admin change. */
export interface StepUpContext {
	/** Subject of "… needs a sign-in", e.g. `Revealing a secret`. */
	subject: string;
	/** Replaces "Then repeat the change." */
	after: string;
	/** Which action to repeat on return; absent if the human must redo it. */
	resume?: StepUpResume;
}

/** An action to repeat once the human is back. No value, only an address. */
export interface StepUpResume {
	kind: 'secret-reveal';
	version: number;
}

/** Local, not session, storage: an email link opens in a new tab. */
const RESUME_KEY = 'overslash.step-up.resume';
/** Long enough for an IdP's MFA challenge; a walk-away should not fire. */
const RESUME_TTL_MS = 10 * 60 * 1000;

let pending = $state<StepUpChallenge | null>(null);
let context = $state<StepUpContext | null>(null);

export const stepUp = {
	get pending() {
		return pending;
	},
	get context() {
		return context;
	}
};

/** True when `body` is a `step_up_required` answer; records it if so. */
export function requestStepUp(body: unknown): boolean {
	if (!body || typeof body !== 'object') return false;
	const b = body as { error?: unknown } & Partial<StepUpChallenge>;
	if (b.error !== 'step_up_required') return false;
	context = null;
	pending = {
		reason: (b.reason ?? 'idp_required') as StepUpReason,
		providers: Array.isArray(b.providers) ? b.providers : [],
		max_age_secs: typeof b.max_age_secs === 'number' ? b.max_age_secs : 3600
	};
	return true;
}

/** Called from the catch of a request that `requestStepUp` just recorded. */
export function describeStepUp(c: StepUpContext): void {
	context = c;
}

export function dismissStepUp(): void {
	pending = null;
	context = null;
}

/** True when `e` is the 403 that raised the prompt. */
export function isStepUpError(e: unknown): boolean {
	const body = (e as { body?: unknown } | null)?.body;
	return (body as { error?: unknown } | null)?.error === 'step_up_required';
}

/** The human is leaving for the sign-in: remember what to repeat, and where. */
export function persistStepUpResume(): void {
	if (!context?.resume) return;
	localStorage.setItem(
		RESUME_KEY,
		JSON.stringify({
			...context.resume,
			path: window.location.pathname + window.location.search,
			at: Date.now()
		})
	);
}

/**
 * The action of `kind` to repeat on this page, once. An expired record, or one
 * for this kind on another page, is dropped; another kind's is left alone.
 */
export function takeStepUpResume(kind: StepUpResume['kind']): StepUpResume | null {
	const raw = localStorage.getItem(RESUME_KEY);
	if (!raw) return null;
	let saved: StepUpResume & { path?: unknown; at?: unknown };
	try {
		saved = JSON.parse(raw);
	} catch {
		localStorage.removeItem(RESUME_KEY);
		return null;
	}
	if (saved.kind !== kind) return null;
	localStorage.removeItem(RESUME_KEY);
	const here = window.location.pathname + window.location.search;
	const fresh = typeof saved.at === 'number' && Date.now() - saved.at < RESUME_TTL_MS;
	if (saved.path !== here || !fresh) return null;
	return { kind: saved.kind, version: saved.version };
}
