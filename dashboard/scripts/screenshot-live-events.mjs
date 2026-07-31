// Real-stack screenshots for the SSE event stream (`GET /v1/events/stream`).
//
// The point of these captures is the thing a static screenshot cannot assert
// on its own: the queue changes *without a navigation*. Every shot below is
// taken on a page that was loaded once and never reloaded — an approval is
// seeded through the real action gateway after load, and the row that appears
// got there over the stream.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/{stream-live-empty,
// stream-live-arrived,stream-fallback}.png.

import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { login, seedApproval } from '../tests/scenarios/index.mjs';
import { attachToContext } from '../tests/scenarios/auth.mjs';

const OUT = resolve('screenshots');
const session = await login('admin');

const browser = await chromium.launch();
try {
	const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
	await attachToContext(ctx, session);
	const page = await ctx.newPage();

	// Deliberately not `networkidle`: the stream holds a connection open for
	// its whole 30s lifetime, so the network is never idle by design and that
	// wait would always time out.
	await page.goto(`${session.dashboardUrl}/approvals`, { waitUntil: 'domcontentloaded' });

	// The chip flips to `live` on the stream.open frame, which is the visible
	// proof the connection is established rather than merely attempted.
	await page.locator('.aq-live:not(.is-fallback)').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(300);
	await page.screenshot({ path: resolve(OUT, 'stream-live-empty.png'), fullPage: true });
	console.log('[live-events] wrote stream-live-empty.png');

	const before = await page.locator('.aq-list .aq-slot').count();

	// Seed through the real gateway *after* the page is loaded. Nothing on the
	// client asks for this; it arrives over the stream.
	await seedApproval(session, {
		method: 'POST',
		url: 'https://api.example.com/messages',
		body: '{"text":"pushed over SSE"}'
	});

	await page
		.locator('.aq-list .aq-slot')
		.nth(before)
		.waitFor({ timeout: 15_000 });
	await page.waitForTimeout(400);
	await page.screenshot({ path: resolve(OUT, 'stream-live-arrived.png'), fullPage: true });
	console.log(`[live-events] wrote stream-live-arrived.png (${before} -> ${before + 1} rows, no reload)`);

	// Fallback presentation: with the stream refused, the queue keeps working
	// on its polling path and says so rather than claiming to be live.
	const offline = await browser.newContext({ viewport: { width: 1280, height: 800 } });
	await attachToContext(offline, session);
	await offline.route('**/v1/events/stream*', (route) => route.abort());
	const offlinePage = await offline.newPage();
	await offlinePage.goto(`${session.dashboardUrl}/approvals`, { waitUntil: 'domcontentloaded' });
	await offlinePage.locator('.aq-live.is-fallback').waitFor({ timeout: 15_000 });
	await offlinePage.waitForTimeout(300);
	await offlinePage.screenshot({ path: resolve(OUT, 'stream-fallback.png'), fullPage: true });
	console.log('[live-events] wrote stream-fallback.png');
} finally {
	await browser.close();
}
