// Real-stack screenshots for a multi-key approval — the shape #481 made
// common, where one action derives one permission key per recipient.
//
// An email send to three addresses raises an approval whose `permission_keys`
// and tier-0 keys all carry three entries; the broader tiers collapse onto a
// single key. These captures are the proof that the detail page shows every
// key it is asking the approver to grant (no "+1"), and that the collapsed
// tiers read once.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/{multikey-detail,
// multikey-tiers,multikey-queue}.png.

import { login, makeSnapper, seedApproval, seedSecret, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

await seedSecret(session, { name: 'ada_mailbox_password', value: 'app-password' });
await seedService(session, {
	templateKey: 'email',
	name: 'email',
	url: 'https://mailbox.acme-corp.example',
	// mailbox_user is non-secret instance config — not a credential.
	config: { mailbox_user: 'ada@migadu.example' },
	credentials: { mailbox_pass: 'ada_mailbox_password' }
});

// Three recipients across `to` and `cc` — the email template scopes them all
// under one `recipient` label, so this derives three distinct keys.
const approval = await seedApproval(session, {
	templateKey: 'email',
	action: 'send',
	params: {
		from: 'ada@migadu.example',
		to: ['ada@example.com', 'grace@example.com'],
		cc: ['margaret@example.com'],
		subject: 'Q3 rollout plan',
		text: 'Sharing the rollout plan ahead of Thursday.'
	}
});
console.log(`[multikey] approval ${approval.id} keys: ${approval.permission_keys.join(' ')}`);

const snap = await makeSnapper(session);
try {
	// Detail page: sticky "Remember as" bar + REQUEST DETAILS permission list.
	const { page, ctx } = await snap.navigateAndSnap('multikey-detail', `/approvals/${approval.id}`, {
		viewport: { width: 1280, height: 900 },
		waitFor: async (p) => {
			await p.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});

	// The tier ladder lives further down the right rail on this viewport.
	const tiers = page.locator('.aq-scope');
	await tiers.scrollIntoViewIfNeeded();
	await page.waitForTimeout(200);
	await snap.snap(page, 'multikey-tiers');
	await ctx.close();

	// Queue row: the scope summary names every recipient, not just the first.
	const queue = await snap.navigateAndSnap('multikey-queue', '/approvals', {
		viewport: { width: 1280, height: 800 },
		waitFor: async (p) => {
			await p.getByText('grace@example.com').first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});
	await queue.ctx.close();

	console.log('[multikey] done');
} finally {
	await snap.close();
}
