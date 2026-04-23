import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig, loadEnv } from 'vite';
import { resolve } from 'node:path';

const strict = process.env.SVELTE_STRICT === 'true';

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
	const rootEnv = loadEnv(mode, resolve(__dirname, '..'), '');
	if (rootEnv.OVERSLASH_WEB_PORT) return `http://localhost:${rootEnv.OVERSLASH_WEB_PORT}`;
	if (rootEnv.API_HOST_PORT) return `http://localhost:${rootEnv.API_HOST_PORT}`;
	return 'http://localhost:3000';
}

export default defineConfig(({ mode }) => {
	const apiTarget = resolveApiTarget(mode);
	return {
		plugins: [sveltekit()],
		build: {
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
				// Backend enrollment approval endpoints (consumed by /enroll/consent SvelteKit page)
				'/enroll/approve': {
					target: apiTarget,
					changeOrigin: true
				},
				// Standalone "Provide Secret" page (unauthenticated, JWT-scoped)
				'/public/secrets': {
					target: apiTarget,
					changeOrigin: true
				}
			}
		}
	};
});
