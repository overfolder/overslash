/**
 * What the service setup page says after a successful submit.
 *
 * Pulled out of the template because it is a six-way decision over four
 * inputs, two of which are tri-state — and the branch that matters most is
 * the one that is easiest to lose. The server distinguishes "I do not know
 * what is left" (an absent `remaining_slots`) from "nothing is left" (`[]`),
 * degrading rather than failing a write it has already committed; a page that
 * collapses the two announces a service ready on a shrug. It did, once.
 */
import { probeRejected } from '$lib/public-request';
import type { ServiceTestResponse } from '$lib/types';

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
	/** Bound, nothing outstanding. */
	| 'connected';

export function setupOutcome(state: {
	bindFailed: boolean;
	testing: boolean;
	testResult: ServiceTestResponse | null;
	/** `null` means the server did not say. */
	remainingSlots: string[] | null;
}): SetupOutcome {
	// Order is the point. Each earlier case is a stronger statement than the
	// ones below it, so a failed bind outranks a probe verdict, and a probe
	// verdict outranks a slot count.
	if (state.bindFailed) return 'bind_failed';
	if (state.testing) return 'testing';
	if (probeRejected(state.testResult)) return 'rejected';
	if (state.remainingSlots === null) return 'unknown';
	if (state.remainingSlots.length > 0) return 'incomplete';
	return 'connected';
}
