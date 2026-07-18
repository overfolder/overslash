// Helpers for the e2e mail stack: GreenMail (a real IMAP/SMTP server) behind
// the real overfwd gateway that `services/email.yaml` targets.
//
// Mail is delivered over SMTP rather than inserted through GreenMail's REST
// API, for the same reason `seedApproval` walks the action gateway instead of
// writing rows: a message that arrived the way real mail arrives is the only
// one that proves the IMAP read path end-to-end.

import { createConnection } from 'node:net';

import { resolveEnv } from './env.mjs';

/**
 * A message to deliver. `to` defaults to the mailbox the compose file declares,
 * so callers normally omit it.
 *
 * @typedef {{ from: string, to?: string, subject: string, body: string }} SeedMessage
 */

/** Throwing accessor — every mail helper needs the stack to be up. */
function mailEnv() {
	const env = resolveEnv();
	if (!env.greenmailApiUrl || !env.greenmailSmtpPort) {
		throw new Error(
			'scenarios/mail: GREENMAIL_API_URL / GREENMAIL_SMTP_PORT not resolved. ' +
				'Run `make e2e-up` (it starts the mail stack and writes .e2e/dashboard.env).'
		);
	}
	return env;
}

/**
 * Empty every mailbox, keeping the declared users.
 *
 * This is `POST /api/mail/purge`, not `/api/service/reset` — reset restarts
 * GreenMail and drops any user not in `-Dgreenmail.users`, which costs seconds
 * and a readiness re-poll. Purge is the right granularity between specs: the
 * users are fixed by compose, only the mail varies.
 */
export async function purgeMail() {
	const { greenmailApiUrl } = mailEnv();
	const res = await fetch(`${greenmailApiUrl}/api/mail/purge`, { method: 'POST' });
	if (!res.ok) {
		throw new Error(`greenmail purge failed: HTTP ${res.status} ${await res.text()}`);
	}
}

/**
 * Deliver messages over SMTP, in order, and return them.
 *
 * GreenMail's IMAP SEARCH returns newest-first, so the last message seeded is
 * the first one a `search` action reports.
 *
 * @param {SeedMessage[]} messages
 * @param {{ to?: string }} [opts]
 * @returns {Promise<SeedMessage[]>}
 */
export async function seedMailbox(messages, opts = {}) {
	const env = mailEnv();
	const recipient = opts.to ?? env.mailboxLogin ?? 'e2e@example.com';
	/** @type {SeedMessage[]} */
	const sent = [];
	for (const m of messages) {
		const msg = { ...m, to: m.to ?? recipient };
		await smtpSend(Number(env.greenmailSmtpPort), msg);
		sent.push(msg);
	}
	return sent;
}

/**
 * List what a mailbox actually holds, straight from GreenMail's admin API.
 *
 * This deliberately does not go through overfwd or Overslash — it is the
 * out-of-band check that a message the UI displayed is a message that really
 * exists in the mail store, rather than something the gateway synthesised.
 *
 * @param {string} [emailOrId]
 * @param {string} [folder]
 */
export async function listMailboxMessages(emailOrId, folder = 'INBOX') {
	const env = mailEnv();
	const who = emailOrId ?? env.mailboxLogin ?? 'e2e@example.com';
	const res = await fetch(
		`${env.greenmailApiUrl}/api/user/${encodeURIComponent(who)}/messages/${folder}`
	);
	if (!res.ok) {
		throw new Error(`greenmail list failed: HTTP ${res.status} ${await res.text()}`);
	}
	return /** @type {Array<Record<string, unknown>>} */ (await res.json());
}

/**
 * Minimal SMTP submission over a plain socket.
 *
 * GreenMail's plaintext port speaks no STARTTLS and the image runs with
 * `auth.disabled`, so the exchange is just EHLO/MAIL/RCPT/DATA. Hand-rolling
 * it keeps the dashboard's dependency tree free of a mail client for one
 * eight-line conversation.
 *
 * @param {number} port
 * @param {SeedMessage} msg
 */
function smtpSend(port, msg) {
	return new Promise((resolve, reject) => {
		const sock = createConnection({ host: '127.0.0.1', port });
		sock.setEncoding('utf8');
		sock.setTimeout(15_000);

		const body = [
			`From: ${msg.from}`,
			`To: ${msg.to}`,
			`Subject: ${msg.subject}`,
			'Content-Type: text/plain; charset=utf-8',
			'',
			// A leading dot would terminate DATA early; dot-stuff per RFC 5321.
			msg.body.replace(/^\./gm, '..'),
			'.'
		].join('\r\n');

		const steps = [
			'EHLO overslash-e2e',
			`MAIL FROM:<${msg.from}>`,
			`RCPT TO:<${msg.to}>`,
			'DATA',
			body,
			'QUIT'
		];
		let step = -1; // -1 = waiting for the server greeting
		let buf = '';
		let settled = false;

		/** @param {unknown} e */
		const fail = (e) => {
			if (settled) return;
			settled = true;
			sock.destroy();
			reject(e instanceof Error ? e : new Error(String(e)));
		};

		sock.on('data', (chunk) => {
			buf += chunk;
			// Responses are line-based; a multi-line reply uses `250-` for all
			// but its final line, which uses `250 `. Only act on the final one.
			if (!/\r\n$/.test(buf)) return;
			const lines = buf.trimEnd().split('\r\n');
			const last = lines[lines.length - 1];
			if (/^\d{3}-/.test(last)) return;
			buf = '';

			const code = Number(last.slice(0, 3));
			if (code >= 400) return fail(new Error(`smtp ${steps[step] ?? 'greeting'}: ${last}`));

			step += 1;
			if (step >= steps.length) return;
			sock.write(steps[step] + '\r\n');
			if (steps[step] === 'QUIT') {
				settled = true;
				sock.end();
				resolve(undefined);
			}
		});

		sock.on('timeout', () => fail(new Error('smtp timeout')));
		sock.on('error', fail);
		// A server that accepts the connection and then drops it (still booting,
		// mid-restart, connection limit) clears the inactivity timer on close, so
		// `timeout` never fires and the promise would hang until Playwright's
		// global timeout with nothing pointing at SMTP. `settled` is set by the
		// QUIT path; anything else reaching close is a failure.
		sock.on('close', () => {
			if (!settled) fail(new Error('smtp connection closed before QUIT'));
		});
	});
}
