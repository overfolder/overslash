// Pure-logic checks for the two public, token-gated pages
// (`/secrets/provide/[req_id]` and `/services/setup/[req_id]`).
//
// Neither page can be reached without a live signed token, so the states a
// visitor actually hits — expired, spent, tampered — are the ones hardest to
// see in a browser and easiest to get subtly wrong. The 410 split in
// particular carries the whole difference between "ask for a new link" and
// "someone already did this", and both pages branch on it.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import {
	fmtCountdown,
	mapPublicRequestError,
	submitErrorMessage
} from '../../../src/lib/public-request';

test('410 splits on the error code, not the status', () => {
	expect(mapPublicRequestError(410, { error: 'already_fulfilled' })).toBe('already_fulfilled');
	expect(mapPublicRequestError(410, { error: 'expired' })).toBe('expired');
	// A 410 with no body at all still has to land somewhere sensible.
	expect(mapPublicRequestError(410, null)).toBe('expired');
});

test('a tampered token and a missing service both read as an invalid link', () => {
	expect(mapPublicRequestError(400, { error: 'invalid_token' })).toBe('invalid');
	// The setup route 404s a request that names no service. From the
	// visitor's seat that is the same dead link as a bad id.
	expect(mapPublicRequestError(404, { error: 'not_found' })).toBe('invalid');
});

test('a server error is distinguished from a bad link', () => {
	// "Try again in a moment" vs "this link is broken" are different
	// instructions, so 5xx must not collapse into `invalid`.
	expect(mapPublicRequestError(500, null)).toBe('server_error');
	expect(mapPublicRequestError(503, null)).toBe('server_error');
});

test('the countdown pads seconds and reads expired past the deadline', () => {
	const t0 = Date.parse('2026-01-01T00:00:00Z');
	expect(fmtCountdown('2026-01-01T00:59:04Z', t0)).toBe('59m 04s');
	expect(fmtCountdown('2026-01-01T00:00:00Z', t0)).toBe('expired');
	expect(fmtCountdown('2025-12-31T23:59:00Z', t0)).toBe('expired');
	// An unparseable timestamp shows itself rather than `NaNm`.
	expect(fmtCountdown('not a date', t0)).toBe('not a date');
});

test('submit errors name the recoverable case', () => {
	expect(submitErrorMessage(410, 'already_fulfilled')).toContain('already fulfilled');
	expect(submitErrorMessage(410, 'expired')).toContain('expired');
	expect(submitErrorMessage(401, 'user_session_required')).toContain('signed in');
	expect(submitErrorMessage(400, 'invalid_token')).toContain('invalid');
	// An unrecognised failure must still be actionable.
	expect(submitErrorMessage(502, '')).toContain('try again');
});
