import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: {
		port: 5173,
		proxy: {
			// Proxy API and auth requests to Rust backend
			'/v1': {
				target: 'http://localhost:3000',
				changeOrigin: true
			},
			'/auth': {
				target: 'http://localhost:3000',
				changeOrigin: true
			},
			'/health': {
				target: 'http://localhost:3000',
				changeOrigin: true
			}
		}
	}
});
