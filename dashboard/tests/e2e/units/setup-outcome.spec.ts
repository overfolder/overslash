// What the service setup page says after a submit.
//
// Seven states over five inputs, and the ones worth guarding are the two
// distinctions the server goes out of its way to draw. An absent
// `remaining_slots` means "I could not work out what is left", not "nothing is
// left" — the page collapsed those once and announced a service connected on a
// shrug. And every slot being filled is not the same claim as the service
// being callable: the probe runs after the submit, so `status` is what
// separates "saved" from "live".
//
// The *ordering* is the contract, so most of these tests are about which case
// outranks which rather than about any one case in isolation.
//
// Imported by relative path: `$lib` is a SvelteKit alias that Playwright's
// transform does not resolve.
import { test, expect } from '@playwright/test';
import { credentialLabel, failureKind, setupOutcome } from '../../../src/lib/setup-outcome';
import type { ServiceStatus } from '../../../src/lib/types';

const base = {
	bindFailed: false,
	testing: false,
	testResult: null,
	remainingSlots: [] as string[] | null,
	status: 'active' as ServiceStatus | null
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
			remainingSlots: [],
			status: 'active' as ServiceStatus
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

test('a gated instance with nothing outstanding is not_live, not connected', () => {
	// The headline case. Every credential is present and nothing was rejected,
	// and the service still cannot be called — which is the state a visitor who
	// is not the instance's owner always lands in, because the probe runs as
	// them and they have no grant on it.
	expect(setupOutcome({ ...base, status: 'pending_setup' })).toBe('not_live');
});

test('an absent status does not regress an older API to not_live', () => {
	// `null` is "this surface does not know", and failing open is right: the
	// other six cases already cover every way setup visibly goes wrong.
	expect(setupOutcome({ ...base, status: null })).toBe('connected');
});

test('not_live sits directly above connected and nowhere higher', () => {
	const gated = { ...base, status: 'pending_setup' as ServiceStatus };
	// A rejection carries both the reason and the fix; "not live yet" carries
	// neither.
	expect(setupOutcome({ ...gated, testResult: { status: 'failed' } })).toBe('rejected');
	// The slot count is precisely what *explains* why it is not live.
	expect(setupOutcome({ ...gated, remainingSlots: ['mailbox_pass'] })).toBe('incomplete');
	expect(setupOutcome({ ...gated, remainingSlots: null })).toBe('unknown');
	expect(setupOutcome({ ...gated, testing: true })).toBe('testing');
	expect(setupOutcome({ ...gated, bindFailed: true })).toBe('bind_failed');
});

// `failureKind` — the copy's discriminator, and it rests entirely on the
// backend deliberately leaving `http_status` unset on a transport failure
// (`transport_verdict` in routes/actions/probe.rs builds a bare `failed`).
// Without that, "couldn't reach it" and "the key was rejected" are the same
// verdict wearing the same words.
test('only a failed verdict has a failure kind', () => {
	expect(failureKind(null)).toBe(null);
	for (const status of [
		'ok',
		'pending_approval',
		'needs_authentication',
		'denied',
		'not_supported'
	] as const) {
		expect(failureKind({ status })).toBe(null);
	}
});

test('a failed verdict with no http_status is unreachable', () => {
	expect(failureKind({ status: 'failed' })).toBe('unreachable');
});

test('401 and 403 are a rejected credential; anything else is the upstream', () => {
	expect(failureKind({ status: 'failed', http_status: 401 })).toBe('rejected');
	expect(failureKind({ status: 'failed', http_status: 403 })).toBe('rejected');
	// A 500 says nothing about the key — offering "the key was rejected" here
	// would send someone hunting for a new credential over an upstream blip.
	expect(failureKind({ status: 'failed', http_status: 500 })).toBe('upstream');
	expect(failureKind({ status: 'failed', http_status: 404 })).toBe('upstream');
	// Real case, and the reason `upstream`'s copy must not reassure: Resend
	// answers a bad API key with a 400, so this bucket is "the status alone
	// does not say", not "the credential is probably fine".
	expect(failureKind({ status: 'failed', http_status: 400 })).toBe('upstream');
});

// `credentialLabel` — the fallback that keeps "token" off the box someone is
// about to paste an API key into. Mirrors `humanize` in
// routes/secret_requests.rs, which does the same job server-side for the
// public setup page; these cases are the ones that file's doc comment names.
test('an authored label always wins', () => {
	expect(credentialLabel({ key: 'mailbox_user', label: 'Mailbox username' })).toBe(
		'Mailbox username'
	);
	// Whitespace is not a label. Most shipped templates omit `x-overslash-label`
	// entirely, which is why the fallback exists at all.
	expect(credentialLabel({ key: 'token', label: '  ' })).toBe('Token');
});

test('a short leading word is read as an acronym, and only the leading one', () => {
	expect(credentialLabel({ key: 'api_key' })).toBe('API key');
	expect(credentialLabel({ key: 'sql_dsn' })).toBe('SQL dsn');
	// The rule is restricted to the first word precisely so this stays "key".
	expect(credentialLabel({ key: 'mailbox_key' })).toBe('Mailbox key');
});

test('a single word is sentence-cased, not shouted', () => {
	expect(credentialLabel({ key: 'token' })).toBe('Token');
	// One word, so the acronym rule does not apply even though it is short.
	expect(credentialLabel({ key: 'key' })).toBe('Key');
});
