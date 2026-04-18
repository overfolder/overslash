import adapterAuto from '@sveltejs/adapter-auto';
import adapterStatic from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// Cloud (Vercel) builds use adapter-auto. Self-hosted single-binary builds
// run with `ADAPTER=static` (see `npm run build:static`) so the result can
// be embedded into the Rust `overslash` binary and served same-origin by
// `overslash web`. SPA fallback to index.html keeps client-side routing.
const useStatic = process.env.ADAPTER === 'static';

// With SVELTE_STRICT=true, promote every Svelte compiler warning (a11y, unused
// CSS, state_referenced_locally, etc.) to a build error so precommit/CI fail
// if new warnings sneak in. Dev builds keep the default handler.
const strict = process.env.SVELTE_STRICT === 'true';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
	onwarn: (warning, handler) => {
		if (strict) {
			const loc = warning.filename
				? `${warning.filename}:${warning.start?.line ?? '?'}:${warning.start?.column ?? '?'}`
				: '';
			throw new Error(`[svelte ${warning.code}] ${loc} ${warning.message}`);
		}
		handler(warning);
	},
	kit: {
		adapter: useStatic
			? adapterStatic({
					pages: 'build',
					assets: 'build',
					fallback: 'index.html',
					precompress: false,
					strict: false
				})
			: adapterAuto()
	}
};

export default config;
