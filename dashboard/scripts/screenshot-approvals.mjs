// Capture three screenshots of the standalone /approvals/[id] page:
//   1. logged-out-redirect.png — visiting the deep link without a session
//      bounces through /login?return_to=...
//   2. pending.png             — authenticated view with the resolver card
//   3. resolved.png            — post-Deny banner state
//
// Driven by dashboard/scripts/screenshot-approvals.sh, which boots the
// podman-compose stack, mints a dev session cookie, and seeds an approval row.

import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const DASH_URL = process.env.DASH_URL ?? 'http://localhost:5173';
const APPROVAL_ID = process.env.APPROVAL_ID;
const SESSION_COOKIE = process.env.SESSION_COOKIE;
const OUT_DIR = resolve('screenshots');

if (!APPROVAL_ID || !SESSION_COOKIE) {
	console.error('APPROVAL_ID and SESSION_COOKIE env vars are required');
	process.exit(1);
}

mkdirSync(OUT_DIR, { recursive: true });

const browser = await chromium.launch();
const cookieHost = new URL(DASH_URL).hostname;
const sessionCookie = {
	name: 'oss_session',
	value: SESSION_COOKIE,
	domain: cookieHost,
	path: '/',
	httpOnly: true,
	secure: false,
	sameSite: 'Lax'
};

async function shot(page, name) {
	const out = resolve(OUT_DIR, `${name}.png`);
	await page.screenshot({ path: out, fullPage: true });
	console.log(`wrote ${out}`);
}

try {
	// 1. Logged-out: fresh context with no cookies. The auth guard in
	//    +layout.ts should redirect to /login?return_to=/approvals/<id>.
	{
		const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
		const page = await ctx.newPage();
		await page.goto(`${DASH_URL}/approvals/${APPROVAL_ID}`, { waitUntil: 'networkidle' });
		await page.waitForURL(/\/login\?return_to=/, { timeout: 10_000 });
		await shot(page, 'logged-out-redirect');
		await ctx.close();
	}

	// 2. Pending: authenticated context, resolver card visible.
	const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
	await ctx.addCookies([sessionCookie]);
	const page = await ctx.newPage();
	await page.goto(`${DASH_URL}/approvals/${APPROVAL_ID}`, { waitUntil: 'networkidle' });
	await page.getByRole('button', { name: 'Deny' }).waitFor({ timeout: 10_000 });
	await shot(page, 'pending');

	// 3. Resolved: click Deny, wait for banner, screenshot.
	await page.getByRole('button', { name: 'Deny' }).click();
	await page.getByText(/this approval is/i).waitFor({ timeout: 10_000 });
	await shot(page, 'resolved');

	await ctx.close();
} finally {
	await browser.close();
}
