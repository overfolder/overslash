// Real-stack screenshots for the instance form's "Show more options" split.
//
// Every template's endpoint and config pins are overridable. The instance form
// shows the ones an instance cannot work without, plus the ones a template
// promotes (`x-overslash-promoted`), up front; everything else waits behind
// "Show more options", each field naming the default it falls back to.
//
// Captures:
//   1. /services/new for Langfuse: the promoted endpoint, up front, with the
//      EU-cloud default spelled out.
//   2. /services/new for Resend: no promoted field, so the endpoint is collapsed.
//   3. The same form with the disclosure open, showing Resend's default.
//   4. A Langfuse instance pointed at the US region: the override on the
//      detail page.
//   5. A Resend instance with a custom endpoint: the disclosure opens on its own
//      so the override is not hidden.
//
// Prereq: `make e2e-up`. Output under dashboard/screenshots/.

import { login, makeSnapper, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

const langfuse = await seedService(session, {
	templateKey: 'langfuse',
	name: 'langfuse_us',
	url: 'https://us.cloud.langfuse.com'
});
const resend = await seedService(session, {
	templateKey: 'resend',
	name: 'resend_proxy',
	url: 'https://resend-proxy.acme.example'
});

const snap = await makeSnapper(session);
const shot = async (name, path, waitFor, after) => {
	const { page, ctx } = await snap.navigateAndSnap(name, path, {
		viewport: { width: 1200, height: 1100 },
		waitFor
	});
	if (after) await after(page);
	await ctx.close();
};
try {
	await shot('more-options-langfuse-new', '/services/new?template=langfuse', async (p) => {
		await p.getByLabel('Endpoint URL').waitFor({ timeout: 15_000 });
		await p.getByText('https://cloud.langfuse.com').first().waitFor({ timeout: 5_000 });
		await p.waitForTimeout(300);
	});

	await shot('more-options-resend-collapsed', '/services/new?template=resend', async (p) => {
		await p.getByRole('button', { name: /Show more options/ }).waitFor({ timeout: 15_000 });
		await p.waitForTimeout(300);
	});

	await shot('more-options-resend-expanded', '/services/new?template=resend', async (p) => {
		await p.getByRole('button', { name: /Show more options/ }).click({ timeout: 15_000 });
		await p.getByLabel('Endpoint URL').waitFor({ timeout: 5_000 });
		await p.waitForTimeout(300);
	});

	await shot('more-options-langfuse-instance', `/services/${langfuse.id}`, async (p) => {
		await p.getByLabel('Endpoint URL').waitFor({ timeout: 15_000 });
		await p.waitForTimeout(400);
	});

	await shot('more-options-resend-instance', `/services/${resend.id}`, async (p) => {
		await p.getByRole('button', { name: /Hide more options/ }).waitFor({ timeout: 15_000 });
		await p.waitForTimeout(400);
	});

	console.log('[more-options] done');
} finally {
	await snap.close();
}
