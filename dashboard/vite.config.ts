import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const API_URL = process.env.API_URL ?? 'http://localhost:3000';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		port: parseInt(process.env.DASHBOARD_PORT ?? '5173'),
		proxy: {
			'/v1': API_URL,
			'/auth': API_URL,
		},
	},
});
