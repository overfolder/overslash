// Renders the welcome / first-login email template with realistic
// placeholder values and screenshots the result so PRs can show what
// the recipient inbox actually sees. Self-contained — no API stack
// needed; the template is pure HTML.
//
// Output: dashboard/screenshots/welcome-email.png

import { readFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const templatePath = resolve(
	repoRoot,
	'crates/overslash-core/templates/email/welcome.html'
);
const outDir = resolve(repoRoot, 'dashboard/screenshots');
mkdirSync(outDir, { recursive: true });

// Substitute `{var}` placeholders exactly like
// `overslash_core::email::render` (no `[optional]` segments in this
// template, so a plain replace is faithful).
const raw = readFileSync(templatePath, 'utf8');
const params = {
	display_name: 'Ada',
	dashboard_url: 'https://app.overslash.com/',
	unsubscribe_url:
		'https://api.overslash.com/v1/unsubscribe?token=8e5b7d2c-1c4a-4d6e-9b3c-6a1f2e9c4d12'
};
const rendered = raw.replace(/\{(\w+)\}/g, (_, k) =>
	params[k] !== undefined ? params[k] : `{${k}}`
);

const browser = await chromium.launch();
try {
	// 640px column is what Gmail web renders in; transactional emails
	// are designed for ~560px content, so this leaves the cushion the
	// template uses around its rounded card.
	const ctx = await browser.newContext({
		viewport: { width: 640, height: 800 },
		deviceScaleFactor: 2
	});
	const page = await ctx.newPage();
	await page.setContent(rendered, { waitUntil: 'load' });
	// Clip to the email card itself so the screenshot is the *email*,
	// not a full page with most of it empty. The template wraps content
	// in an outer table with a .max-width of 560 + 40px outer padding.
	const card = await page.locator('table[width="560"]').first();
	const box = await card.boundingBox();
	const out = resolve(outDir, 'welcome-email.png');
	if (box) {
		await page.screenshot({
			path: out,
			clip: {
				x: Math.max(0, box.x - 24),
				y: Math.max(0, box.y - 24),
				width: box.width + 48,
				height: box.height + 48
			}
		});
	} else {
		await page.screenshot({ path: out, fullPage: true });
	}
	console.log(`[scenarios] wrote ${out}`);
	await ctx.close();
} finally {
	await browser.close();
}
