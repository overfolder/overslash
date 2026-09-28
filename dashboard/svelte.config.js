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

// Vercel injects its feedback toolbar into preview deployments only; allow its
// origins there and nowhere else. `VERCEL_ENV` is read at build time.
const vercelToolbar = process.env.VERCEL_ENV === 'preview';
// Off Vercel (local dev, e2e, the self-hosted binary) the API may be plain
// http on loopback, and service icons are absolute URLs into it.
const loopbackApi = !process.env.VERCEL ? ['http://localhost:*', 'http://127.0.0.1:*'] : [];

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
			: adapterAuto(),
		// The dashboard's Content-Security-Policy. It lives here rather than in
		// vercel.json because the SPA shell carries an inline bootstrap <script>
		// whose content changes every build: SvelteKit allows it by nonce when
		// it renders the shell (on Vercel, as a response header) and by hash
		// when it prerenders one (the `build:static` fallback, as a <meta> tag,
		// which drops `frame-ancestors` — browsers ignore it there). A static
		// header would need 'unsafe-inline' for scripts. The rest of the header
		// baseline (HSTS, X-Frame-Options, ...) is in vercel.json, which sets no
		// CSP of its own so the two can never collide on one header name.
		csp: {
			mode: 'auto',
			directives: {
				'default-src': ['self'],
				'script-src': ['self', ...(vercelToolbar ? ['https://vercel.live'] : [])],
				// CodeMirror and Svelte transitions inject <style> elements, and
				// markup carries style="" attributes.
				'style-src': ['self', 'unsafe-inline', ...(vercelToolbar ? ['https://vercel.live'] : [])],
				// Avatars come from whichever IdP the user signed in with, and
				// custom templates may point their icon at any https URL.
				'img-src': ['self', 'data:', 'blob:', 'https:', ...loopbackApi],
				'font-src': [
					'self',
					'data:',
					...(vercelToolbar ? ['https://vercel.live', 'https://assets.vercel.com'] : [])
				],
				// Every API call is same-origin: vercel.json (and the dev/preview
				// proxy) forwards /v1, /auth, /public and friends to the API.
				'connect-src': [
					'self',
					...(vercelToolbar ? ['https://vercel.live', 'wss://ws-us3.pusher.com'] : [])
				],
				'frame-src': vercelToolbar ? ['https://vercel.live'] : ['none'],
				'worker-src': ['self', 'blob:'],
				'object-src': ['none'],
				'base-uri': ['self'],
				'form-action': ['self'],
				'frame-ancestors': ['none']
			}
		}
	}
};

export default config;
