// Real-stack screenshots — and an end-to-end proof — for email attachments
// sent through gateway-staged uploads.
//
// An agent stages a PDF with `overslash:upload_file`, PUTs the bytes to the
// minted URL, and sends it as an attachment through an `email` instance wired
// to the e2e mail stack (real overfwd ≥ 0.6.0 in front of GreenMail). The send
// is a write, so it parks behind an approval, which is what gets screenshotted:
// the Attachments row names the file as the gateway stored it. The script then
// approves, dispatches, and reads GreenMail out of band to prove the message
// arrived carrying the attachment.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/email-attachments-approval.png
//   dashboard/screenshots/email-attachments-sent.png

import { createHash } from 'node:crypto';

import {
	api,
	deleteOrg,
	freshOrgSlug,
	listMailboxMessages,
	login,
	makeSnapper,
	purgeMail,
	resolveEnv,
	seedAgent,
	seedAgentApiKey,
	seedApprovalResolution,
	seedSecret,
	seedService
} from '../tests/scenarios/index.mjs';

const env = resolveEnv();
const orgSlug = freshOrgSlug('email-attach');
const session = await login('admin', { org: orgSlug });

// A tiny but genuine PDF, so the recipient's client would render it.
const pdf = Buffer.from(
	'%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n' +
		'2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n' +
		'3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 100]>>endobj\n' +
		'trailer<</Root 1 0 R>>\n%%EOF\n'
);
const sha256 = createHash('sha256').update(pdf).digest('hex');

try {
	await purgeMail();
	await seedSecret(session, { name: 'mailbox_pass', value: env.mailboxPassword ?? 'e2e' });
	await seedService(session, {
		templateKey: 'email',
		name: 'email',
		url: env.overfwdUrl,
		credentials: { mailbox_pass: 'mailbox_pass' },
		config: {
			mailbox_user: env.mailboxLogin,
			'X-Mailbox-Imap': env.mailboxImap,
			'X-Mailbox-Smtp': env.mailboxSmtp
		}
	});

	// A gated agent: its send parks behind an approval. Staging is granted up
	// front, the way a user would with "Allow & Remember" the first time.
	const agent = await seedAgent(session, { name: 'reporting-bot', inheritPermissions: false });
	const { key } = await seedAgentApiKey(session, agent.id);
	await api(session, '/v1/permissions', {
		method: 'POST',
		body: { identity_id: agent.id, action_pattern: 'overslash:upload_file:*' }
	});

	const call = (body, expect = [200, 202]) =>
		api(session, '/v1/actions/call', { method: 'POST', bearer: key, body, expect });

	const minted = JSON.parse(
		(
			await call({
				service: 'overslash',
				action: 'upload_file',
				params: {
					filename: 'q3-board-deck.pdf',
					size_bytes: pdf.length,
					content_type: 'application/pdf',
					sha256
				}
			})
		).result.body
	);
	const pushed = await fetch(minted.upload_url, { method: 'PUT', body: pdf });
	if (pushed.status !== 201) throw new Error(`push failed: ${pushed.status} ${await pushed.text()}`);

	const pending = await call({
		service: 'email',
		action: 'send',
		params: {
			from: env.mailboxLogin,
			to: [env.mailboxLogin],
			subject: 'Q3 board deck',
			text: 'Deck attached — numbers on slide 4.',
			attachments: [{ upload_id: minted.upload_id }]
		}
	});
	if (pending.status !== 'pending_approval') {
		throw new Error(`expected an approval, got ${JSON.stringify(pending)}`);
	}
	const approvalId = pending.approval_id;

	const snap = await makeSnapper(session);
	try {
		const shot = await snap.navigateAndSnap('email-attachments-approval', `/approvals/${approvalId}`, {
			viewport: { width: 1200, height: 1000 },
			waitFor: async (p) => {
				await p.getByText('q3-board-deck.pdf', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		});
		await shot.ctx.close();

		// A new agent auto-calls on approve, so resolving is what dispatches the
		// replay — the path that inlines the staged bytes. Poll for its result.
		await seedApprovalResolution(session, approvalId, 'allow');
		let execution;
		for (let i = 0; i < 40; i++) {
			execution = await api(session, `/v1/approvals/${approvalId}/execution`, { bearer: key });
			if (!['pending', 'executing'].includes(execution.status)) break;
			await new Promise((r) => setTimeout(r, 250));
		}
		if (execution?.status !== 'executed') {
			throw new Error(`replay did not execute: ${JSON.stringify(execution)}`);
		}

		// Out of band: the mail store itself, not anything the gateway echoed.
		const messages = await listMailboxMessages(env.mailboxLogin);
		const delivered = messages.find((m) => String(m.subject ?? '').includes('Q3 board deck'));
		if (!delivered) throw new Error('message never reached GreenMail');
		const raw = JSON.stringify(delivered);
		if (!raw.includes('q3-board-deck.pdf')) {
			throw new Error(`delivered message carries no attachment: ${raw.slice(0, 500)}`);
		}
		console.log('[email-attachments] delivered with attachment ✔');

		const sent = await snap.navigateAndSnap('email-attachments-sent', `/approvals/${approvalId}`, {
			viewport: { width: 1200, height: 1000 },
			waitFor: async (p) => {
				await p.getByText('q3-board-deck.pdf', { exact: false }).first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(500);
			}
		});
		await sent.ctx.close();
	} finally {
		await snap.close();
	}
	console.log('[email-attachments] done');
} finally {
	await deleteOrg(orgSlug);
}
