import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

const apiTarget = process.env.API_URL || 'http://localhost:3000';

export default defineConfig({
	plugins: [sveltekit()],
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
			}
		}
	}
});
