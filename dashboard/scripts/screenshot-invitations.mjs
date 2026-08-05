// Real-stack screenshot of the sidebar's "Pending invitations" section: a
// user signed into their own org who has been invited to others.
//
// Two run-private orgs invite the dev `member` profile — one with Overslash-
// managed sign-in on (Accept / Decline in place) and one with it off (the
// org runs its own IdP, so the card links out instead). Both orgs are deleted
// in teardown, which takes the invitations with them.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/invitations-*.png.

import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	setManagedSignin
} from '../tests/scenarios/index.mjs';

const managedSlug = freshOrgSlug('acme');
const idpSlug = freshOrgSlug('initech');

// The invitee: an ordinary member of the shared dev org. The sidebar section
// is rendered from `/auth/me/identity.invitations[]`, which is keyed on this
// user's IdP-verified email — not on the org they're currently viewing.
const invitee = await login('member');

const snap = await makeSnapper(invitee);

/** Sidebar locator that also proves the invitations section rendered. */
async function waitForInvites(page) {
	await page.locator('section[aria-label="Pending invitations"]').waitFor({ timeout: 15_000 });
}

async function snapSidebar(page, name) {
	const sidebar = page.locator('aside.sidebar').first();
	await sidebar.screenshot({ path: `screenshots/${name}.png` });
	console.log(`[scenarios] wrote screenshots/${name}.png`);
}

try {
	// Org A — managed sign-in on (the default for orgs created through
	// `POST /v1/orgs`), so the invitation can be accepted in place.
	const acme = await login('admin', { org: managedSlug });
	await api(acme, '/v1/org-invites', {
		method: 'POST',
		body: { email: invitee.email, role: 'admin' }
	});

	// Org B — the org runs its own IdP; the card must link out rather than
	// offering Accept.
	const initech = await login('admin', { org: idpSlug });
	await api(initech, '/v1/org-invites', {
		method: 'POST',
		body: { email: invitee.email, role: 'member' }
	});
	await setManagedSignin(initech, { allow_overslash_managed_signin: false });

	// Expanded sidebar, light theme.
	let { page, ctx } = await snap.navigateAndSnap('invitations-sidebar', '/agents', {
		viewport: { width: 1400, height: 900 },
		fullPage: false,
		waitFor: waitForInvites
	});
	await snapSidebar(page, 'invitations-sidebar-crop');
	await ctx.close();

	// Same, dark theme — the cards inherit surface/border tokens, so this is
	// the cheapest proof they don't go invisible.
	({ page, ctx } = await snap.navigateAndSnap('invitations-sidebar-dark', '/agents', {
		viewport: { width: 1400, height: 900 },
		theme: 'dark',
		fullPage: false,
		waitFor: waitForInvites
	}));
	await snapSidebar(page, 'invitations-sidebar-dark-crop');
	await ctx.close();

	// Collapsed rail — 64px, so the section becomes an envelope + count.
	// `sidebarCollapsed` is a localStorage-persisted store; seed it before
	// the app boots.
	({ ctx, page } = await snap.page({ viewport: { width: 1400, height: 900 } }));
	await page.addInitScript(() => {
		try {
			window.localStorage.setItem('ovs_sidebar_collapsed', 'true');
		} catch {}
	});
	await page.goto(`${invitee.dashboardUrl}/agents`, { waitUntil: 'networkidle' });
	await page.locator('aside.sidebar.collapsed').waitFor({ timeout: 15_000 });
	await snapSidebar(page, 'invitations-sidebar-collapsed');
	await ctx.close();

	console.log('[invitations] done');
} finally {
	await snap.close();
	// Removing the orgs removes the pending identities, so the shared dev
	// member doesn't carry stale invitations into other scripts.
	await deleteOrg(managedSlug).catch(() => {});
	await deleteOrg(idpSlug).catch(() => {});
}
