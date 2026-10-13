import adapterAuto from '@sveltejs/adapter-auto';
import adapterStatic from '@sveltejs/adapter-static';
import type { Config as SvelteKitConfig } from '@sveltejs/kit/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig, loadEnv, type Plugin } from 'vite';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// With SVELTE_STRICT=true, promote every Svelte compiler warning (a11y, unused
// CSS, state_referenced_locally, etc.) to a build error so precommit/CI fail
// if new warnings sneak in. Dev builds keep the default handler.
const strict = process.env.SVELTE_STRICT === 'true';

// Cloud (Vercel) builds use adapter-auto. Self-hosted single-binary builds
// run with `ADAPTER=static` (see `npm run build:static`) so the result can
// be embedded into the Rust `overslash` binary and served same-origin by
// `overslash web`. SPA fallback to index.html keeps client-side routing.
const useStatic = process.env.ADAPTER === 'static';

// Vercel injects its feedback toolbar into preview deployments only; allow its
// origins there and nowhere else. `VERCEL_ENV` is read at build time.
const vercelToolbar = process.env.VERCEL_ENV === 'preview';
// Off Vercel (local dev, e2e, the self-hosted binary) the API may be plain
// http on loopback, and service icons are absolute URLs into it.
const loopbackApi = !process.env.VERCEL ? (['http://localhost:*', 'http://127.0.0.1:*'] as const) : [];

// SvelteKit's own config. Kit 3 no longer reads svelte.config.js; everything
// that lived under `kit:` there is passed to the plugin, flattened.
const svelteKitConfig: SvelteKitConfig = {
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
			'script-src': ['self', ...(vercelToolbar ? (['https://vercel.live'] as const) : [])],
			// CodeMirror and Svelte transitions inject <style> elements, and
			// markup carries style="" attributes.
			'style-src': ['self', 'unsafe-inline', ...(vercelToolbar ? (['https://vercel.live'] as const) : [])],
			// Avatars come from whichever IdP the user signed in with, and
			// custom templates may point their icon at any https URL.
			'img-src': ['self', 'data:', 'blob:', 'https:', ...loopbackApi],
			'font-src': [
				'self',
				'data:',
				...(vercelToolbar ? (['https://vercel.live', 'https://assets.vercel.com'] as const) : [])
			],
			// Every API call is same-origin: vercel.json (and the dev/preview
			// proxy) forwards /v1, /auth, /public and friends to the API.
			'connect-src': [
				'self',
				...(vercelToolbar ? (['https://vercel.live', 'wss://ws-us3.pusher.com'] as const) : [])
			],
			'frame-src': vercelToolbar ? (['https://vercel.live'] as const) : ['none'],
			'worker-src': ['self', 'blob:'],
			'object-src': ['none'],
			'base-uri': ['self'],
			'form-action': ['self'],
			'frame-ancestors': ['none']
		}
	}
};

// Resolve the dev proxy target. Precedence (first match wins):
//   1. API_URL env var (explicit override, highest priority)
//   2. OVERSLASH_WEB_PORT from repo-root .env.local (worktree's standalone
//      `overslash web` binary; see bin/worktree-env.sh)
//   3. API_HOST_PORT from repo-root .env.local (worktree's Docker API
//      container, per docker-compose.dev.yml)
//   4. http://localhost:3000 fallback (main-repo default)
//
// Vite's loadEnv reads .env and .env.local from the given dir. We point it at
// the repo root so both the Rust backend and dashboard dev server stay in sync
// without a second copy of the port config.
function resolveApiTarget(mode: string): string {
	if (process.env.API_URL) return process.env.API_URL;
	const rootEnv = loadEnv(mode, resolve(import.meta.dirname, '..'), '');
	if (rootEnv.OVERSLASH_WEB_PORT) return `http://localhost:${rootEnv.OVERSLASH_WEB_PORT}`;
	if (rootEnv.API_HOST_PORT) return `http://localhost:${rootEnv.API_HOST_PORT}`;
	return 'http://localhost:3000';
}

// Serve vercel.json's catch-all header block from `vite preview` — what
// `make e2e-up` runs — so e2e runs and screenshots load under the production
// header set. A plugin rather than `preview.headers`: SvelteKit's preview
// middleware answers the SPA shell before Vite's own header middleware runs,
// and this one registers ahead of it (it is listed before `sveltekit()`).
function vercelHeadersInPreview(): Plugin {
	const cfg = JSON.parse(readFileSync(resolve(import.meta.dirname, 'vercel.json'), 'utf8')) as {
		headers?: { source: string; headers: { key: string; value: string }[] }[];
	};
	const block = cfg.headers?.find((h) => h.source === '/(.*)')?.headers ?? [];
	return {
		name: 'overslash:vercel-headers-in-preview',
		configurePreviewServer(server) {
			server.middlewares.use((_req, res, next) => {
				for (const { key, value } of block) res.setHeader(key, value);
				next();
			});
		}
	};
}

export default defineConfig(({ mode }) => {
	const apiTarget = resolveApiTarget(mode);
	return {
		plugins: [vercelHeadersInPreview(), sveltekit(svelteKitConfig)],
		build: {
			// Emit client source maps on Vercel preview / dev deploys so DevTools
			// can map minified chunks back to original Svelte/TS sources. Production
			// (app.overslash.com) and the embedded-binary release build keep the
			// default of no maps — VERCEL_ENV is unset in those builds.
			sourcemap:
				process.env.VERCEL_ENV === 'preview' || process.env.VERCEL_ENV === 'development',
			rollupOptions: {
				// In strict mode, any Rollup warning fails the build. Paired with the
				// post-build chunk-size check in scripts/check-chunk-sizes.mjs this
				// gives full warning coverage for CI / precommit.
				onwarn: strict
					? (warning) => {
							throw new Error(`[rollup ${warning.code ?? 'WARNING'}] ${warning.message}`);
						}
					: undefined
			}
		},
		server: {
			port: 5173,
			proxy: {
				// Proxy API and auth requests to Rust backend
				'/v1': {
					target: apiTarget,
					changeOrigin: true
				},
				'/auth': {
					target: apiTarget,
					changeOrigin: true
				},
				'/health': {
					target: apiTarget,
					changeOrigin: true
				},
				// The MCP endpoint. Proxied so the `claude mcp add …` command the
				// Agents view renders (dashboard origin + /mcp, for any host we
				// don't recognise as the managed cloud) actually works locally.
				'/mcp': {
					target: apiTarget,
					changeOrigin: true
				},
				// Agent-facing enrollment instructions, served by the API at /SKILL.md.
				'/SKILL.md': {
					target: apiTarget,
					changeOrigin: true
				},
				// The unauthenticated, JWT-scoped standalone pages: "Provide
				// Secret" and its service-shaped sibling. Matched on the whole
				// `/public` namespace rather than per-page: it belongs entirely
				// to the API, and a per-page rule means the next public
				// endpoint resolves against the dashboard's own origin and
				// 404s with nothing to point at. Mirrored in vercel.json.
				'/public': {
					target: apiTarget,
					changeOrigin: true
				}
			}
		}
	};
});
