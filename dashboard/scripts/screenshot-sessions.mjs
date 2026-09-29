// Real-stack screenshots for the Account page's Sessions card (CASA 2.2.x).
//
// Signs the same human in four times from four "devices" (each dev login is a
// fresh server-side session, labelled by its User-Agent), captures the list,
// then signs out all the others and captures what is left.
//
// Runs in a private dev org so earlier scripts' sessions in the shared org
// don't clutter the list. Prereq: `make e2e-up`. Output: dashboard/
// screenshots/sessions-{light,dark}.png and sessions-after-revoke.png.

import { resolve } from 'node:path';
import { deleteOrg, freshOrgSlug, login, makeSnapper } from '../tests/scenarios/index.mjs';

const UA = {
	mac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
	iphone:
		'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
	windows:
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0',
	linux: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
};

const org = freshOrgSlug('sessions');
try {
	// The other devices first, so this one is the most recent.
	for (const ua of [UA.linux, UA.windows, UA.iphone]) {
		await login('admin', { org, userAgent: ua });
	}
	const session = await login('admin', { org, userAgent: UA.mac });
	const snap = await makeSnapper(session);
	const waitFor = async (/** @type {import('playwright').Page} */ p) => {
		await p.getByTestId('sessions-card').getByText('This session').waitFor({ timeout: 15_000 });
	};
	try {
		for (const theme of /** @type {const} */ (['light', 'dark'])) {
			const { ctx } = await snap.navigateAndSnap(`sessions-${theme}`, '/account', {
				viewport: { width: 1280, height: 1000 },
				theme,
				fullPage: true,
				waitFor
			});
			await ctx.close();
		}

		// Sign out all other sessions through the UI, then capture the result.
		const { page, ctx } = await snap.page({ viewport: { width: 1280, height: 1000 } });
		await page.goto(`${session.dashboardUrl}/account`, { waitUntil: 'domcontentloaded' });
		await waitFor(page);
		await page.getByRole('button', { name: 'Sign out all other sessions' }).click();
		await page.getByRole('button', { name: 'Sign out others' }).click();
		await page.getByRole('button', { name: 'Sign out all other sessions' }).waitFor({
			state: 'detached',
			timeout: 15_000
		});
		await snap.snap(page, 'sessions-after-revoke');
		await ctx.close();
		console.log('[sessions] done — screenshots in', resolve('screenshots'));
	} finally {
		await snap.close();
	}
} finally {
	await deleteOrg(org);
}
