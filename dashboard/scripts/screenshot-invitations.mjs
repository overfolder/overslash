// Real-stack screenshot of the sidebar's "Pending invitations" section: a
// user signed into their own org who has been invited to others.
//
// Three run-private orgs: the invitee's own, plus two that invite them — one
// with Overslash-managed sign-in on (Accept / Decline in place) and one with
// it off (the org runs its own IdP, so the card links out instead). All three
// are deleted in teardown, which takes the invitations with them.
//
// The invitee signs in FIRST, before any invitation exists. `/auth/dev/token`
// resolves a profile through a *global* email lookup, so a pending identity
// carrying that same email in another org can be picked instead of the real
// one; minting the session up front sidesteps it, and it's also why this
// script never invites the shared `dev-org` profiles.
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

const homeSlug = freshOrgSlug('home');
const managedSlug = freshOrgSlug('acme');
const idpSlug = freshOrgSlug('initech');

// The invitee, in their own org. The sidebar section is rendered from
// `/auth/me/identity.invitations[]`, which is keyed on this user's
// IdP-verified email — not on the org they happen to be viewing.
const invitee = await login('admin', { org: homeSlug });

const snap = await makeSnapper(invitee);

/**
 * Open the shell and wait for the invitations section.
 *
 * Deliberately not `snap.navigateAndSnap`: the layout holds an SSE
 * connection open, so `networkidle` never fires anywhere in the dashboard.
 * The section itself is the readiness signal.
 */
async function openShell(opts = {}) {
	const { ctx, page } = await snap.page({ viewport: { width: 1400, height: 900 } });
	if (opts.theme === 'dark') {
		// `snap.page({ theme })` stamps `data-theme` before load, but the shell's
		// own `ovs_theme` store re-stamps it on hydration and wins. Seed the
		// store instead.
		await page.addInitScript(() => {
			try {
				window.localStorage.setItem('ovs_theme', '"dark"');
			} catch {}
		});
	}
	if (opts.collapsed) {
		// `sidebarCollapsed` is a localStorage-persisted store; seed it
		// before the app boots.
		await page.addInitScript(() => {
			try {
				window.localStorage.setItem('ovs_sidebar_collapsed', 'true');
			} catch {}
		});
	}
	await page.goto(`${invitee.dashboardUrl}/agents`, { waitUntil: 'domcontentloaded' });
	await page.locator(opts.collapsed ? 'aside.sidebar.collapsed' : 'aside.sidebar').waitFor({
		timeout: 20_000
	});
	await page
		.locator(opts.collapsed ? 'button.rail' : 'section[aria-label="Pending invitations"]')
		.waitFor({ timeout: 20_000 });
	return { ctx, page };
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

	// Org B — runs its own IdP; the card must link out rather than offering
	// Accept. Invite first, then flip the flag: invite creation itself is
	// unaffected by it, and flipping first would only obscure that.
	const initech = await login('admin', { org: idpSlug });
	await api(initech, '/v1/org-invites', {
		method: 'POST',
		body: { email: invitee.email, role: 'member' }
	});
	await setManagedSignin(initech, { allow_overslash_managed_signin: false });

	// Expanded sidebar, light theme — full page for context, then a crop of
	// the sidebar itself.
	let { page, ctx } = await openShell();
	await snap.snap(page, 'invitations-sidebar', { fullPage: false });
	await snapSidebar(page, 'invitations-sidebar-crop');
	await ctx.close();

	// Same, dark theme — the cards inherit surface/border tokens, so this is
	// the cheapest proof they don't go invisible.
	({ page, ctx } = await openShell({ theme: 'dark' }));
	await snap.snap(page, 'invitations-sidebar-dark', { fullPage: false });
	await snapSidebar(page, 'invitations-sidebar-dark-crop');
	await ctx.close();

	// Collapsed rail — 64px, so the section becomes an envelope + count.
	({ page, ctx } = await openShell({ collapsed: true }));
	await snapSidebar(page, 'invitations-sidebar-collapsed');
	await ctx.close();

	console.log('[invitations] done');
} finally {
	await snap.close();
	// Removing the orgs removes the pending identities with them.
	await deleteOrg(managedSlug).catch(() => {});
	await deleteOrg(idpSlug).catch(() => {});
	await deleteOrg(homeSlug).catch(() => {});
}
