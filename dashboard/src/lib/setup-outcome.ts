/**
 * What the service setup page says after a successful submit.
 *
 * Pulled out of the template because it is a seven-way decision over five
 * inputs, two of which are tri-state — and the branch that matters most is
 * the one that is easiest to lose. The server distinguishes "I do not know
 * what is left" (an absent `remaining_slots`) from "nothing is left" (`[]`),
 * degrading rather than failing a write it has already committed; a page that
 * collapses the two announces a service ready on a shrug. It did, once.
 */
import { probeRejected } from '$lib/public-request';
import type { ServiceStatus, ServiceTestResponse } from '$lib/types';

export type SetupOutcome =
	/** Saved to the vault, but never attached to the instance. */
	| 'bind_failed'
	/** The probe is in flight. Nothing conclusive to say yet. */
	| 'testing'
	/** The upstream rejected the credential. */
	| 'rejected'
	/** Bound, but the server could not say what remains. Likely ready. */
	| 'unknown'
	/** Bound, and at least one sibling slot is still unfilled. */
	| 'incomplete'
	/** Bound, nothing outstanding, no rejection — and still not callable. */
	| 'not_live'
	/** Bound, nothing outstanding, and live. */
	| 'connected';

export function setupOutcome(state: {
	bindFailed: boolean;
	testing: boolean;
	testResult: ServiceTestResponse | null;
	/** `null` means the server did not say. */
	remainingSlots: string[] | null;
	/**
	 * The instance's lifecycle status. `null` means this surface does not
	 * know — treated as live, so a surface that never learned the field (or an
	 * older API that does not send it) cannot regress every page to
	 * `not_live`. Failing open here is right because the *other* six cases
	 * already cover every way setup can visibly go wrong.
	 */
	status: ServiceStatus | null;
}): SetupOutcome {
	// Order is the point. Each earlier case is a stronger statement than the
	// ones below it, so a failed bind outranks a probe verdict, and a probe
	// verdict outranks a slot count.
	if (state.bindFailed) return 'bind_failed';
	if (state.testing) return 'testing';
	if (probeRejected(state.testResult)) return 'rejected';
	if (state.remainingSlots === null) return 'unknown';
	if (state.remainingSlots.length > 0) return 'incomplete';
	// Directly above `connected`, and nowhere higher. Above `rejected` it
	// would replace "Resend did not accept this key" with "not live yet" —
	// dropping both the reason and the fix. Above `incomplete` it would
	// replace "two more credentials to go" with "not live yet", when the slot
	// count is precisely what *explains* why it is not live.
	if (state.status !== null && state.status !== 'active') return 'not_live';
	return 'connected';
}

/** Which kind of red verdict this is. `null` unless the probe came back `failed`. */
export type FailureKind =
	/** Nothing answered at that address. */
	| 'unreachable'
	/** The upstream answered with a status that can only mean the credential. */
	| 'rejected'
	/**
	 * The upstream answered with some other error.
	 *
	 * Note this is *not* "the credential is probably fine": Resend rejects a
	 * bad API key with a `400`, not a `401`. It means only that the status
	 * alone does not say, so the copy for this case must defer to the
	 * truncated upstream error the verdict already carries rather than
	 * reassuring anyone.
	 */
	| 'upstream';

/**
 * Split `failed` three ways, so the copy can stop saying "the key was
 * rejected" about a service that was merely down.
 *
 * The discriminator is `http_status`, and it works because the backend
 * deliberately leaves it unset on a transport failure: `transport_verdict`
 * builds a bare `failed` with no status, and `probe::run` folds connect errors
 * *and* timeouts into `failed` rather than answering 502/504 — because a 502
 * tells the operator Overslash is broken when what happened is that their
 * service could not be reached.
 *
 * Lives beside `setupOutcome` so the wizard, the setup page and the service
 * detail page cannot word the same failure three different ways.
 */
export function failureKind(r: ServiceTestResponse | null | undefined): FailureKind | null {
	if (!probeRejected(r)) return null;
	if (r?.http_status == null) return 'unreachable';
	return r.http_status === 401 || r.http_status === 403 ? 'rejected' : 'upstream';
}

/**
 * What to call a credential slot in front of a person.
 *
 * `x-overslash-label` is optional and most shipped templates omit it, so a
 * slot's authored label is usually empty and the raw key is what reaches the
 * screen — "token" above the box someone is about to paste an API key into.
 *
 * The fallback mirrors `humanize` in `routes/secret_requests.rs`, which does
 * the same job for the public setup page: sentence case, and a short *leading*
 * word read as an acronym (`api_key` → "API key", `sql_dsn` → "SQL dsn").
 * Restricting the acronym rule to the first word is what keeps "key" from
 * becoming "KEY".
 *
 * Deliberately tiny, and deliberately never the vault secret name: that is an
 * org-chosen identifier and tells the person pasting a value nothing.
 */
export function credentialLabel(slot: { key: string; label?: string }): string {
	const authored = (slot.label ?? '').trim();
	if (authored) return authored;
	const words = slot.key.split(/[_-]/).filter(Boolean);
	if (words.length === 0) return slot.key;
	const rendered = words.map((w, i) =>
		i === 0 && words.length > 1 && w.length <= 3 && /^[a-z]+$/i.test(w)
			? w.toUpperCase()
			: w.toLowerCase()
	);
	const out = rendered.join(' ');
	return out.charAt(0).toUpperCase() + out.slice(1);
}
