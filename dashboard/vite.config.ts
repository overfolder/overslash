import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const apiTarget = process.env.API_URL || 'http://localhost:3000';
const strict = process.env.SVELTE_STRICT === 'true';

export default defineConfig({
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
});
