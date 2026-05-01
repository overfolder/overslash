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
		const ctx = await browser.newContext({
			viewport: opts.viewport ?? { width: 1280, height: 800 }
		});
		await attachToContext(ctx, session);
		const page = await ctx.newPage();
		if (opts.theme === 'dark') {
			await page.addInitScript(() => {
				try {
					document.documentElement.dataset.theme = 'dark';
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
		await page.goto(url, { waitUntil: 'networkidle' });
		if (opts.waitFor) await opts.waitFor(page);
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
