// Smoke test for `overslash web`: load the root page in a real browser,
// assert the SvelteKit app boots, and save a screenshot.
//
// Usage: URL=http://127.0.0.1:18080 node scripts/smoke-web.mjs
import { chromium } from 'playwright';
import { fileURLToPath } from 'node:url';

const url = process.env.URL || 'http://127.0.0.1:18080';
const outDir = fileURLToPath(new URL('../screenshots/', import.meta.url));
const shotPath = fileURLToPath(new URL('smoke-web.png', new URL('../screenshots/', import.meta.url)));

async function main() {
	const browser = await chromium.launch();
	const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
	const page = await ctx.newPage();

	const errors = [];
	page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
	page.on('console', (msg) => {
		if (msg.type() === 'error') errors.push(`console: ${msg.text()}`);
	});

	console.log(`→ navigating ${url}`);
	const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 20000 });
	console.log(`  status=${resp?.status()}`);
	if (!resp || !resp.ok()) throw new Error(`non-2xx from ${url}`);

	// Wait for SvelteKit to hydrate — once hydrated, <html> gets a data-* attr
	// and the <body> is no longer empty.
	await page.waitForFunction(() => document.body && document.body.children.length > 0, {
		timeout: 20000
	});
	const title = await page.title();
	const bodyText = (await page.textContent('body'))?.slice(0, 200) ?? '';
	console.log(`  title=${JSON.stringify(title)}`);
	console.log(`  body[0..200]=${JSON.stringify(bodyText)}`);

	await import('node:fs').then((fs) => fs.mkdirSync(outDir, { recursive: true }));
	await page.screenshot({ path: shotPath, fullPage: true });
	console.log(`  screenshot=${shotPath}`);

	if (errors.length) {
		console.warn(`warnings (${errors.length}):`);
		for (const e of errors) console.warn(`  - ${e}`);
	}

	// Also smoke the API from the same origin.
	const health = await page.evaluate(async () => {
		const r = await fetch('/health');
		return { status: r.status, body: await r.text() };
	});
	console.log(`  /health=${JSON.stringify(health)}`);
	if (health.status !== 200 || !health.body.includes('ok')) {
		throw new Error(`/health unexpected: ${JSON.stringify(health)}`);
	}

	await browser.close();
	console.log('✓ smoke passed');
}

main().catch((e) => {
	console.error('✗ smoke failed:', e);
	process.exit(1);
});
