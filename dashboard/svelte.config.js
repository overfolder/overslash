import adapterAuto from '@sveltejs/adapter-auto';
import adapterStatic from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// Cloud (Vercel) builds use adapter-auto. Self-hosted single-binary builds
// run with `ADAPTER=static` (see `npm run build:static`) so the result can
// be embedded into the Rust `overslash` binary and served same-origin by
// `overslash web`. SPA fallback to index.html keeps client-side routing.
const useStatic = process.env.ADAPTER === 'static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	preprocess: vitePreprocess(),
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
