// Generate the non-prod ("dev") favicon variants by tinting the brand mark
// green, so a dev/preview/local tab is distinguishable from prod at a glance.
//
// This is the reproducible source-of-truth for the committed
// `static/favicon-dev-*.png` / `static/apple-touch-icon-dev.png` assets — the
// dashboard serves those static files directly (no build step), and the
// runtime favicon swap in `+layout.svelte` points the <link> tags at them in
// non-prod environments.
//
// We tint in a headless Chromium canvas (Playwright is already a devDependency
// used by every screenshot-*.mjs; sharp/ImageMagick are not installed). A
// `source-atop` fill only paints the mark's opaque pixels, preserving the
// transparent background.
//
// Run: `node scripts/gen-dev-favicons.mjs` (from the dashboard/ dir).

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { chromium } from 'playwright';

const STATIC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'static');
const TINT = '#21b86b'; // --success-500
const TINT_ALPHA = 0.45;

// [source, output] pairs — one per <link> the swap repoints.
const ICONS = [
	['favicon-16.png', 'favicon-dev-16.png'],
	['favicon-32.png', 'favicon-dev-32.png'],
	['apple-touch-icon.png', 'apple-touch-icon-dev.png']
];

async function tint(page, srcPath) {
	const buf = await readFile(srcPath);
	const dataUrl = `data:image/png;base64,${buf.toString('base64')}`;
	const out = await page.evaluate(
		async ({ dataUrl, tint, alpha }) => {
			const img = new Image();
			await new Promise((resolve, reject) => {
				img.onload = resolve;
				img.onerror = reject;
				img.src = dataUrl;
			});
			const canvas = document.createElement('canvas');
			canvas.width = img.naturalWidth;
			canvas.height = img.naturalHeight;
			const ctx = canvas.getContext('2d');
			ctx.drawImage(img, 0, 0);
			// Paint the tint only where the mark is opaque, keeping transparency.
			ctx.globalCompositeOperation = 'source-atop';
			ctx.globalAlpha = alpha;
			ctx.fillStyle = tint;
			ctx.fillRect(0, 0, canvas.width, canvas.height);
			return canvas.toDataURL('image/png');
		},
		{ dataUrl, tint: TINT, alpha: TINT_ALPHA }
	);
	return Buffer.from(out.split(',')[1], 'base64');
}

const browser = await chromium.launch();
try {
	const page = await browser.newPage();
	for (const [src, dst] of ICONS) {
		const png = await tint(page, join(STATIC_DIR, src));
		await writeFile(join(STATIC_DIR, dst), png);
		console.log(`✓ ${dst} (${png.length} bytes)`);
	}
} finally {
	await browser.close();
}
