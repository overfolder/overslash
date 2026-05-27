// One-off helper: screenshot a handful of Storybook stories (light + dark) from
// the static build for PR proof-of-work. Not wired into CI.
//
//   npm run build-storybook
//   node scripts/screenshot-storybook.mjs
//
// Outputs PNGs to dashboard/screenshots/storybook/.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, extname, resolve } from 'node:path';
import { chromium } from 'playwright';

const ROOT = resolve(import.meta.dirname, '..');
const STATIC = join(ROOT, 'storybook-static');
const OUT = join(ROOT, 'screenshots', 'storybook');

const MIME = {
	'.html': 'text/html',
	'.js': 'text/javascript',
	'.mjs': 'text/javascript',
	'.css': 'text/css',
	'.json': 'application/json',
	'.svg': 'image/svg+xml',
	'.woff2': 'font/woff2',
	'.woff': 'font/woff',
	'.png': 'image/png',
	'.map': 'application/json'
};

const server = createServer(async (req, res) => {
	try {
		const url = new URL(req.url, 'http://localhost');
		let p = join(STATIC, decodeURIComponent(url.pathname));
		if (url.pathname === '/' || url.pathname === '') p = join(STATIC, 'index.html');
		if (!existsSync(p)) {
			res.writeHead(404);
			res.end('not found');
			return;
		}
		const body = await readFile(p);
		res.writeHead(200, { 'content-type': MIME[extname(p)] ?? 'application/octet-stream' });
		res.end(body);
	} catch (e) {
		res.writeHead(500);
		res.end(String(e));
	}
});

await new Promise((r) => server.listen(0, r));
const port = server.address().port;
const base = `http://localhost:${port}`;

// Story IDs are `kebab(title)--kebab(name)`.
const shots = [
	['approval-riskbadge--all', 'riskbadge'],
	['services-statusbadge--all-variants', 'statusbadge'],
	['api-explorer-httpmethodbadge--all-methods', 'httpmethodbadge'],
	['controls-toggleswitch--interactive', 'toggleswitch'],
	['controls-searchbar--with-filter-chips', 'searchbar'],
	['shell-navitem--sidebar-group', 'navitem'],
	['shell-logo--both', 'logo'],
	['secrets-ownercell--agent-owner', 'ownercell']
];

const browser = await chromium.launch();
const { mkdir } = await import('node:fs/promises');
await mkdir(OUT, { recursive: true });

for (const theme of ['light', 'dark']) {
	const page = await browser.newPage({ viewport: { width: 720, height: 360 }, deviceScaleFactor: 2 });
	for (const [id, label] of shots) {
		const url = `${base}/iframe.html?id=${id}&globals=theme:${theme}&viewMode=story`;
		await page.goto(url, { waitUntil: 'load' });
		// Wait until Storybook has mounted the requested story into the root.
		await page.waitForFunction(
			() => {
				const root = document.querySelector('#storybook-root') ?? document.querySelector('#root');
				return !!root && root.children.length > 0 && root.textContent.trim().length > 0;
			},
			{ timeout: 15000 }
		);
		await page.waitForTimeout(500);
		const file = join(OUT, `${label}-${theme}.png`);
		await page.screenshot({ path: file });
		console.log('saved', file);
	}
	await page.close();
}

await browser.close();
server.close();
