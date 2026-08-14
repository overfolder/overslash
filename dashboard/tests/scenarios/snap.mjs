// Boots a Playwright browser, attaches the session, navigates to a route,
// and writes a screenshot to `dashboard/screenshots/<name>.png`. Designed
// for screenshot scripts (mjs CLIs) — Playwright tests should use the
// `test()` fixture and `page.screenshot()` directly.

import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
import { attachToContext } from './auth.mjs';

/**
 * @typedef {{ width: number, height: number }} ViewportSize
 * @typedef {'light' | 'dark'} ColorScheme
 *
 * @typedef {{
 *   browser: import('playwright').Browser,
 *   close: () => Promise<void>,
 *   page: (opts?: { viewport?: ViewportSize, theme?: ColorScheme }) => Promise<{
 *     ctx: import('playwright').BrowserContext,
 *     page: import('playwright').Page,
 *   }>,
 *   snap: (page: import('playwright').Page, name: string, opts?: { fullPage?: boolean }) => Promise<string>,
 *   navigateAndSnap: (
 *     name: string,
 *     path: string,
 *     opts?: {
 *       viewport?: ViewportSize,
 *       theme?: ColorScheme,
 *       fullPage?: boolean,
 *       waitFor?: (page: import('playwright').Page) => Promise<void>,
 *     }
 *   ) => Promise<{
 *     ctx: import('playwright').BrowserContext,
 *     page: import('playwright').Page,
 *     out: string,
 *   }>,
 * }} Snapper
 */

/**
 * @param {import('./auth.mjs').Session} session
 * @param {string} [outDir]
 * @returns {Promise<Snapper>}
 */
export async function makeSnapper(session, outDir = resolve('screenshots')) {
	mkdirSync(outDir, { recursive: true });
	const browser = await chromium.launch();

	/** @param {{ viewport?: ViewportSize, theme?: ColorScheme }} [opts] */
	async function newPage(opts = {}) {
		const dark = opts.theme === 'dark';
		const ctx = await browser.newContext({
			viewport: opts.viewport ?? { width: 1280, height: 800 },
			// `initialTheme()` in `$lib/stores/shell` falls back to
			// `prefers-color-scheme` when nothing is stored, so this alone
			// already produces a dark render. Belt to the braces below.
			colorScheme: dark ? 'dark' : 'light'
		});
		await attachToContext(ctx, session);
		const page = await ctx.newPage();
		if (dark) {
			// Seed the *store's* key, not `data-theme`. The theme is a
			// `persisted` store reading `localStorage.ovs_theme`; it writes
			// `data-theme` itself on hydration, so setting that attribute here
			// was silently overwritten a tick later and every "dark" screenshot
			// in this repo came out light.
			await page.addInitScript(() => {
				try {
					localStorage.setItem('ovs_theme', JSON.stringify('dark'));
				} catch {}
			});
		}
		return { ctx, page };
	}

	/**
	 * @param {import('playwright').Page} page
	 * @param {string} name
	 * @param {{ fullPage?: boolean }} [opts]
	 */
	async function snap(page, name, opts = {}) {
		const out = resolve(outDir, `${name}.png`);
		await page.screenshot({ path: out, fullPage: opts.fullPage ?? true });
		console.log(`[scenarios] wrote ${out}`);
		return out;
	}

	/**
	 * @param {string} name
	 * @param {string} path
	 * @param {{
	 *   viewport?: ViewportSize,
	 *   theme?: ColorScheme,
	 *   fullPage?: boolean,
	 *   waitFor?: (page: import('playwright').Page) => Promise<void>,
	 * }} [opts]
	 */
	async function navigateAndSnap(name, path, opts = {}) {
		const { ctx, page } = await newPage({ viewport: opts.viewport, theme: opts.theme });
		const url = path.startsWith('http') ? path : `${session.dashboardUrl}${path}`;
		// NOT `networkidle`: every authenticated page holds an open SSE
		// connection to /v1/events/stream (added in #504), so the network is
		// never idle and `goto` times out after 30s. Callers pass `waitFor` to
		// pin the element that actually matters; the settle below covers the
		// handful that don't.
		await page.goto(url, { waitUntil: 'domcontentloaded' });
		if (opts.waitFor) await opts.waitFor(page);
		else await page.waitForLoadState('load');
		const out = await snap(page, name, { fullPage: opts.fullPage });
		return { ctx, page, out };
	}

	return {
		browser,
		close: () => browser.close(),
		page: newPage,
		snap,
		navigateAndSnap
	};
}
