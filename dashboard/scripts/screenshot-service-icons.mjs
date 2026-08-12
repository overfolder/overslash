// Real-stack screenshots for service icons.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/service-icons-*.png.
//
// Every fixture here goes through the real API, so the marks in these shots
// are the ones the gateway actually resolved: the shipped templates declare no
// `icon:` at all and still come back with an `icon_url`, which is the whole
// point of the implicit `builtin:<key>` rule.
//
// The catalog deliberately contains templates from both halves. `github`,
// `stripe`, `notion` and the Google set ship a mark; `slack` and `linkedin`
// ship none (neither has an entry in simple-icons — both brands asked to be
// removed) and render the letter tile. A shot with only the working half
// would hide the fallback, which is half the feature.

import { setTimeout as wait } from 'node:timers/promises';
import {
	deleteOrg,
	enableGlobalTemplate,
	freshOrgSlug,
	login,
	makeSnapper,
	seedService
} from '../tests/scenarios/index.mjs';

// A private org per run: the shared Dev Org accumulates instances across runs
// and the table shot would drift (same reasoning as screenshot-avatars).
const ORG = freshOrgSlug('service-icons');
const session = await login('admin', { org: ORG });

// Templates with a shipped mark, and two without — the fallback has to be in
// frame or the shot oversells the feature.
const TEMPLATES = [
	'github',
	'stripe',
	'notion',
	'gmail',
	'google_calendar',
	'google_drive',
	'hubspot',
	'telegram',
	'slack',
	'linkedin'
];

for (const key of TEMPLATES) {
	await enableGlobalTemplate(session, key).catch(() => {});
}

// Instances for the table shot. Secret-based templates instantiate without a
// connection; the OAuth ones would need a dance we do not need for a mark.
const INSTANCES = [
	{ templateKey: 'github', name: 'github' },
	{ templateKey: 'stripe', name: 'stripe' },
	{ templateKey: 'notion', name: 'notion' },
	{ templateKey: 'telegram', name: 'telegram' },
	{ templateKey: 'slack', name: 'slack' }
];
/** @type {string | undefined} */
let detailId;
for (const input of INSTANCES) {
	try {
		const svc = await seedService(session, input);
		detailId ??= svc.id;
	} catch (err) {
		console.warn(`[service-icons] skipped ${input.templateKey}: ${err.message}`);
	}
}

const snap = await makeSnapper(session);
try {
	// 1. Template catalog, light and dark. Dark is not optional here: a brand
	//    mark carries its own colours and several of the shipped ones are
	//    near-black, so the light ground behind the image is exactly what this
	//    shot is checking.
	//
	//    Seeding `ovs_theme` rather than using the snapper's `theme` option —
	//    the app's theme boot reads localStorage and stamps over a dataset set
	//    in an init script (see screenshot-avatars for the run that proved it).
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		const { ctx, page } = await snap.page({ viewport: { width: 1440, height: 900 } });
		await page.addInitScript((t) => {
			try {
				localStorage.setItem('ovs_theme', JSON.stringify(t));
			} catch {}
		}, theme);
		await page.goto(`${session.dashboardUrl}/services/new`);
		await page.locator('.card').first().waitFor({ timeout: 20_000 });
		await wait(700);
		await snap.snap(page, `service-icons-catalog-${theme}`, { fullPage: false });
		await ctx.close();
	}

	// 2. The instances table — 20px marks in a dense row, with `slack` on the
	//    letter tile a few rows down.
	{
		const { ctx } = await snap.navigateAndSnap('service-icons-list', '/services', {
			fullPage: false,
			viewport: { width: 1440, height: 900 },
			waitFor: async (p) => {
				await p.locator('table tbody tr').first().waitFor({ timeout: 20_000 });
				await wait(500);
			}
		});
		await ctx.close();
	}

	// 3. Service detail header — the 40px mark.
	if (detailId) {
		const { ctx } = await snap.navigateAndSnap('service-icons-detail', `/services/${detailId}`, {
			fullPage: false,
			viewport: { width: 1440, height: 900 },
			waitFor: async (p) => {
				await p.locator('h1').first().waitFor({ timeout: 20_000 });
				await wait(500);
			}
		});
		await ctx.close();
	}
} finally {
	await snap.close();
	await deleteOrg(ORG);
}
