import { test, expect } from '@playwright/test';

import {
	attachToContext,
	deleteOrg,
	freshOrgSlug,
	listMailboxMessages,
	login,
	purgeMail,
	resolveEnv,
	seedMailbox,
	seedSecret
} from '../../scenarios/index.mjs';

// Full user story, driven through the UI against the real stack:
//
//   A user configures a service from the `email.yaml` template, points it at
//   their own gateway, sets their mailbox credentials, then uses "Try It" and
//   successfully lists their email.
//
// Nothing here is faked. The mail lives in GreenMail (a real IMAP/SMTP
// server); the request reaches it through overfwd, the real gateway
// `services/email.yaml` was written against. The only thing standing in for
// production is *whose* mailbox it is.
//
// The org is created for this spec and deleted afterwards, so the services,
// secrets and mail asserted on below cannot have been left behind by another
// spec — and cannot leak into one.

const MESSAGES = [
	{
		from: 'billing@vendor.test',
		subject: 'Q3 invoice attached',
		body: 'Payment is due on Friday.'
	},
	{
		from: 'standup@team.test',
		subject: 'Standup notes for Thursday',
		body: 'Gateway work landed; screenshots next.'
	}
];

test('user configures the email template against their own gateway and lists mail via Try It', async ({
	page
}) => {
	const env = resolveEnv();
	// The harness hard-fails without the mail stack, so reaching a run with
	// these unset means someone booted the API by hand — say so rather than
	// failing later on an inscrutable selector timeout.
	expect(
		env.overfwdUrl,
		'OVERFWD_URL unset — run via `make e2e-up`, which starts the mail stack'
	).toBeTruthy();
	expect(env.mailboxImap, 'MAILBOX_IMAP unset — run via `make e2e-up`').toBeTruthy();

	const orgSlug = freshOrgSlug('e2e-email');
	const session = await login('admin', { org: orgSlug });

	try {
		await attachToContext(page.context(), session);

		// Mail state is global to the GreenMail container (it is not org-scoped
		// the way the Overslash side is), so clear it before seeding rather than
		// trusting that no earlier run left messages behind.
		await purgeMail();
		const seeded = await seedMailbox(MESSAGES);

		// The mailbox login has two halves, joined by the template's jq
		// expression into `X-Mailbox-Auth: Basic base64(user:pass)` at send
		// time. Only the password is a secret: the username is a plain
		// per-instance config value typed straight into the form below. The
		// gateway key is the org-wide one; this overfwd runs keyless, so storing
		// it proves the org-vault path resolves without making the call depend
		// on it.
		await seedSecret(session, { name: 'mailbox_pass', value: env.mailboxPassword! });
		await seedSecret(session, { name: 'overfwd_gateway_key', value: 'e2e-gateway-key' });

		// ── Configure the service through the wizard ────────────────────
		await page.goto('/services/new');
		// Pick step: choosing a card only previews it; a second click commits.
		await page.getByRole('button', { name: /Email \(Mailbox Gateway\)/i }).click();
		await page.getByRole('button', { name: 'Use this template' }).click();

		const gatewayUrl = page.getByLabel('Gateway URL');
		await expect(gatewayUrl).toBeVisible();
		await gatewayUrl.fill(env.overfwdUrl!);

		// The instance-config fields exist because `email.yaml` marks these
		// params `x-overslash-instance-config`. Without them overfwd falls back
		// to autoconfig, which cannot resolve a container hostname — so these
		// two fields are what make a self-hosted gateway reachable at all.
		await page.getByLabel('X-Mailbox-Imap').fill(env.mailboxImap!);
		await page.getByLabel('X-Mailbox-Smtp').fill(env.mailboxSmtp!);

		// The username is an ordinary config field, so it takes the login
		// itself; the password is a secret picker, so it takes the NAME of the
		// vault secret seeded above. Both feed the one `X-Mailbox-Auth` header.
		await page.getByLabel(/Mailbox username/i).fill(env.mailboxLogin!);
		await page.getByLabel(/Mailbox password/i).fill('mailbox_pass');

		await page.screenshot({ path: 'screenshots/email-story-1-configure.png' });

		await page.getByRole('button', { name: /^Create service$/i }).click();

		// The wizard routes to the instance detail page on success.
		await page.waitForURL(/\/services\/[0-9a-f-]{36}$/, { timeout: 15_000 });
		const serviceId = page.url().split('/').pop()!;
		await page.screenshot({ path: 'screenshots/email-story-2-created.png' });

		// ── Try It ──────────────────────────────────────────────────────
		await page.getByRole('button', { name: /Try it/i }).click();
		await page.waitForURL(/tab=api-explorer/, { timeout: 15_000 });

		// Scope to the Request card: the sidebar's "Services" nav link also
		// carries an aria-label that matches a bare getByLabel('Service').
		const request = page.getByRole('region', { name: 'Request' });
		await request.getByLabel('Service').selectOption(serviceId);
		await request.getByLabel('Action').selectOption('search');

		// `search` is `risk: read`, and the creating user's Myself group grant
		// carries auto-approve-reads — so this executes inline rather than
		// parking as a pending approval.
		await page.getByRole('button', { name: /^Call$/ }).click();

		const response = page.getByRole('region', { name: 'Response' });
		await expect(response.getByText('200', { exact: true })).toBeVisible({ timeout: 30_000 });

		// The actual assertion of the user story: the mail is on screen.
		for (const m of seeded) {
			await expect(response.getByText(m.subject, { exact: false })).toBeVisible();
		}

		await page.screenshot({ path: 'screenshots/email-story-3-try-it.png' });

		// ── Out-of-band proof ───────────────────────────────────────────
		//
		// Everything above could in principle be satisfied by a gateway that
		// echoed our own request back. Ask GreenMail directly what it holds:
		// if the subjects match, the dashboard rendered real mail that really
		// traversed IMAP.
		const stored = await listMailboxMessages();
		const storedSubjects = stored.map((m) => String(m.subject ?? ''));
		for (const m of seeded) {
			expect(storedSubjects, JSON.stringify(storedSubjects)).toContain(m.subject);
		}
	} finally {
		await teardownOrg(orgSlug);
	}
});

test('the same template without a pinned mailbox endpoint cannot reach a self-hosted gateway', async ({
	page
}) => {
	// The negative half of the story. If this passes while the test above also
	// passes, the pinned config is doing the work — not some incidental default
	// that would make the fields decorative.
	const env = resolveEnv();
	test.skip(!env.overfwdUrl, 'OVERFWD_URL unset — run via `make e2e-up`');

	const orgSlug = freshOrgSlug('e2e-email-neg');
	const session = await login('admin', { org: orgSlug });

	try {
		await attachToContext(page.context(), session);
		await seedSecret(session, { name: 'mailbox_pass', value: env.mailboxPassword! });

		const svc = await createEmailServiceViaApi(session, {
			name: 'email-unpinned',
			url: env.overfwdUrl!,
			mailboxLogin: env.mailboxLogin!
			// deliberately no endpoint pins — the helper still supplies the
			// mailbox username, since without it the credential would not
			// resolve and the call would fail for the wrong reason.
		});

		await page.goto('/services?tab=api-explorer');
		const request = page.getByRole('region', { name: 'Request' });
		await request.getByLabel('Service').selectOption(svc.id);
		await request.getByLabel('Action').selectOption('search');
		await page.getByRole('button', { name: /^Call$/ }).click();

		// overfwd runs with autoconfig disabled, so a call with no endpoint
		// headers is a hard `bad_request` rather than a silent DNS lookup.
		const response = page.getByRole('region', { name: 'Response' });
		await expect(response.getByText(/400|bad_request|X-Mailbox-Imap/i).first()).toBeVisible({
			timeout: 30_000
		});
	} finally {
		await teardownOrg(orgSlug);
	}
});

/**
 * Delete a run-private org without letting teardown eat the real failure.
 *
 * `deleteOrg` throws on a non-2xx, and a throw from `finally` *replaces* the
 * in-flight exception — so on the most likely reason a spec failed (the API is
 * down or wedged) the report would show "delete dev org failed: HTTP 5xx" and
 * discard the assertion that actually failed.
 */
async function teardownOrg(slug: string) {
	try {
		await deleteOrg(slug);
	} catch (e) {
		console.warn(`teardown: could not delete org ${slug}:`, e);
	}
}

/**
 * Create an `email` instance straight through the API.
 *
 * The happy path above goes through the wizard because the wizard is part of
 * the story being tested. This one only needs an instance in a particular
 * shape, so it skips the UI.
 */
async function createEmailServiceViaApi(
	session: Awaited<ReturnType<typeof login>>,
	opts: { name: string; url: string; mailboxLogin: string; config?: Record<string, string> }
): Promise<{ id: string }> {
	const res = await fetch(`${session.apiUrl}/v1/services`, {
		method: 'POST',
		headers: { 'content-type': 'application/json', cookie: session.cookieHeader },
		body: JSON.stringify({
			template_key: 'email',
			name: opts.name,
			url: opts.url,
			credentials: { mailbox_pass: 'mailbox_pass' },
			// The username rides `config` alongside any endpoint pins.
			config: { mailbox_user: opts.mailboxLogin, ...(opts.config ?? {}) },
			status: 'active'
		})
	});
	if (!res.ok) {
		throw new Error(`create email service failed: HTTP ${res.status} ${await res.text()}`);
	}
	return res.json();
}
