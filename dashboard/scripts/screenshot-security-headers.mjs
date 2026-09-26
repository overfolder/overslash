// Real-stack check for the security-headers PR: the dashboard has to keep
// working under its new Content-Security-Policy, and the HTML pages the API
// renders itself have to keep rendering (and running their one hashed
// script) under the API's.
//
//   1. Walks the main dashboard surfaces — including CodeMirror (injects
//      <style>), avatars and service icons (cross-origin images), the SSE
//      stream and the OAuth connect popup — and fails on any CSP violation,
//      page error, or console error that mentions the policy.
//   2. Opens the API's admin-override consent page the way a real user
//      reaches it — a popup — and clicks Cancel. The popup only closes if the
//      page's hash-allowed inline script ran.
//   3. Captures the API's plain "link unavailable" page: inline styles only.
//
// `vite preview` renders the SPA shell through SvelteKit, which sends the
// `kit.csp` policy as a header with a per-response nonce (as on Vercel), and
// vite.config.ts adds vercel.json's header block — the production header set.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/security-headers-*.png.

import {
	api,
	connectGithubService,
	login,
	makeSnapper,
	promoteToOrgAdmin,
	seedService
} from '../tests/scenarios/index.mjs';

const admin = await login('admin');
const member = await login('member');
// The stock dev admin lacks the per-identity `is_org_admin` flag the
// connect gate's admin override checks.
await promoteToOrgAdmin(admin);
const snap = await makeSnapper(admin);

/** @type {string[]} */
const problems = [];

/**
 * Record every CSP violation, uncaught error and policy-related console
 * error on `page`, tagged with `label`.
 *
 * @param {import('playwright').Page} page
 * @param {string} label
 */
async function watch(page, label) {
	await page.addInitScript(() => {
		/** @type {any} */ (window).__csp = [];
		document.addEventListener('securitypolicyviolation', (e) => {
			/** @type {any} */ (window).__csp.push(`${e.effectiveDirective} blocked ${e.blockedURI}`);
		});
	});
	page.on('pageerror', (e) => problems.push(`[${label}] pageerror: ${e.message}`));
	page.on('console', (m) => {
		if (m.type() === 'error' && /content security policy|refused to/i.test(m.text())) {
			problems.push(`[${label}] console: ${m.text()}`);
		}
	});
}

/** @param {import('playwright').Page} page @param {string} label */
async function collectViolations(page, label) {
	const v = await page.evaluate(() => /** @type {any} */ (window).__csp ?? []);
	for (const line of v) problems.push(`[${label}] violation: ${line}`);
}

// ── Response headers on the SPA shell ──────────────────────────────────────
{
	const res = await fetch(`${admin.dashboardUrl}/agents`);
	const h = Object.fromEntries(res.headers);
	console.log('[security-headers] dashboard shell headers:');
	for (const k of [
		'strict-transport-security',
		'x-content-type-options',
		'x-frame-options',
		'referrer-policy',
		'permissions-policy',
		'content-security-policy'
	]) {
		console.log(`  ${k}: ${h[k] ?? '(missing)'}`);
		if (!h[k]) problems.push(`[shell] missing ${k}`);
	}
	if (!/frame-ancestors 'none'/.test(h['content-security-policy'] ?? '')) {
		problems.push('[shell] CSP lacks frame-ancestors');
	}
	if (/script-src[^;]*'unsafe-inline'/.test(h['content-security-policy'] ?? '')) {
		problems.push("[shell] script-src allows 'unsafe-inline'");
	}
}

// ── Dashboard surfaces ─────────────────────────────────────────────────────
const github = await seedService(admin, {
	templateKey: 'github',
	name: `github-csp-${Date.now().toString(36)}`
});

const routes = [
	['agents', '/agents'],
	['services', '/services'],
	['service-detail', `/services/${github.id}`],
	['template-editor', '/services/templates/new'],
	['secrets', '/secrets'],
	['approvals', '/approvals'],
	['audit', '/audit'],
	['members', '/members'],
	['org', '/org'],
	['profile', '/profile'],
	['map', '/map']
];

for (const [name, path] of routes) {
	const { page } = await snap.page();
	await watch(page, name);
	await page.goto(`${admin.dashboardUrl}${path}`, { waitUntil: 'domcontentloaded' });
	await page.locator('main, .login-page').first().waitFor({ timeout: 15_000 });
	await page.waitForTimeout(1_500);
	await collectViolations(page, name);
	if (['agents', 'service-detail', 'template-editor', 'members'].includes(name)) {
		await snap.snap(page, `security-headers-${name}`, { fullPage: false });
	}
	await page.context().close();
}

// The OAuth connect popup: dashboard → /connect-authorize → fake AS → API
// callback, then the dashboard polls the new connection in.
{
	const { page } = await snap.page();
	await watch(page, 'oauth-connect');
	page.on('popup', (p) => void watch(p, 'oauth-connect-popup'));
	await connectGithubService(admin, page, { suffix: 'csp' });
	await collectViolations(page, 'oauth-connect');
	await snap.snap(page, 'security-headers-oauth-connected', { fullPage: false });
	await page.context().close();
}

// Logged out: the login page renders outside the app shell.
{
	const browserCtx = await snap.browser.newContext({ viewport: { width: 1280, height: 800 } });
	const page = await browserCtx.newPage();
	await watch(page, 'login');
	await page.goto(`${admin.dashboardUrl}/login`, { waitUntil: 'domcontentloaded' });
	await page.locator('.login-page').waitFor({ timeout: 15_000 });
	await page.waitForTimeout(1_000);
	await collectViolations(page, 'login');
	await snap.snap(page, 'security-headers-login', { fullPage: false });
	await browserCtx.close();
}

// ── API-rendered HTML: admin-override consent (hashed inline script) ───────
{
	// The member starts a GitHub connection; the admin — same org, not the
	// owner — opening that link gets the loud consent interstitial.
	/** @type {{ auth_url: string }} */
	const flow = await api(member, '/v1/connections', {
		method: 'POST',
		body: { provider: 'github' }
	});
	const { page } = await snap.page();
	await watch(page, 'consent-opener');
	await page.goto(`${admin.dashboardUrl}/agents`, { waitUntil: 'domcontentloaded' });
	const [popup] = await Promise.all([
		page.waitForEvent('popup'),
		page.evaluate((u) => window.open(u, '_blank', 'width=640,height=720'), flow.auth_url)
	]);
	await watch(popup, 'consent');
	// The popup's init script only lands on its next navigation, so reload.
	await popup.reload({ waitUntil: 'load' });
	await popup.getByRole('button', { name: 'Cancel' }).waitFor({ timeout: 10_000 });
	const csp = (await popup.evaluate(async () => {
		const r = await fetch(location.href, { credentials: 'include' });
		return r.headers.get('content-security-policy');
	})) ?? '(missing)';
	console.log(`[security-headers] consent page CSP: ${csp}`);
	await popup.setViewportSize({ width: 640, height: 720 });
	await snap.snap(popup, 'security-headers-api-consent', { fullPage: false });
	await collectViolations(popup, 'consent');
	await Promise.all([
		popup.waitForEvent('close', { timeout: 5_000 }).catch(() => {
			problems.push('[consent] Cancel did not close the popup — hashed script blocked?');
		}),
		popup.getByRole('button', { name: 'Cancel' }).click()
	]);
	await page.context().close();
}

// ── API-rendered HTML: a page with inline styles and no script ─────────────
{
	const { page } = await snap.page({ viewport: { width: 800, height: 400 } });
	await watch(page, 'gone');
	await page.goto(`${admin.apiUrl}/connect-authorize?id=${crypto.randomUUID()}`);
	await page.getByRole('heading', { name: 'Link unavailable' }).waitFor();
	await collectViolations(page, 'gone');
	await snap.snap(page, 'security-headers-api-gone', { fullPage: false });
	await page.context().close();
}

await snap.close();

if (problems.length) {
	console.error(`[security-headers] ${problems.length} problem(s):`);
	for (const p of problems) console.error(`  ${p}`);
	process.exit(1);
}
console.log('[security-headers] no CSP violations, page errors or policy console errors');
