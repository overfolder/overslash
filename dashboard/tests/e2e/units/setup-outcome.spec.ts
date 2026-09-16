// What the service setup page says after a submit.
//
// Six states over four inputs, and the one worth guarding is the distinction
// the server goes out of its way to draw: an absent `remaining_slots` means
// "I could not work out what is left", not "nothing is left". The page
// collapsed the two once and announced a service connected on a shrug, which
// is why this decision now lives in a function with a test rather than in six
// inline branches.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import { setupOutcome } from '../../../src/lib/setup-outcome';

const base = {
	bindFailed: false,
	testing: false,
	testResult: null,
	remainingSlots: [] as string[] | null
};

test('nothing outstanding reads as connected', () => {
	expect(setupOutcome(base)).toBe('connected');
});

test('an absent remaining_slots is unknown, not connected', () => {
	// The whole point. `null` is what the server sends when the template would
	// not resolve to answer, and it is *not* the same answer as `[]`.
	expect(setupOutcome({ ...base, remainingSlots: null })).toBe('unknown');
});

test('outstanding slots outrank a clean state', () => {
	expect(setupOutcome({ ...base, remainingSlots: ['mailbox_pass'] })).toBe('incomplete');
});

test('a failed bind outranks everything', () => {
	// The credential never reached the service, so no slot count and no probe
	// verdict can make this page say anything better.
	expect(
		setupOutcome({
			bindFailed: true,
			testing: false,
			testResult: { status: 'ok' },
			remainingSlots: []
		})
	).toBe('bind_failed');
});

test('an in-flight probe outranks a slot count', () => {
	// "Connected" above a panel that is about to turn red is worse than silence.
	expect(setupOutcome({ ...base, testing: true })).toBe('testing');
});

test('only an upstream rejection reads as rejected', () => {
	expect(setupOutcome({ ...base, testResult: { status: 'failed' } })).toBe('rejected');
	// The upstream was never asked in these three, so none of them is a
	// rejection — they render amber in TestResult and must not claim the
	// service refused the credential.
	for (const status of ['pending_approval', 'needs_authentication', 'denied'] as const) {
		expect(setupOutcome({ ...base, testResult: { status } })).toBe('connected');
	}
	// …and a template with no probe is not a rejection either.
	expect(setupOutcome({ ...base, testResult: { status: 'not_supported' } })).toBe('connected');
});
