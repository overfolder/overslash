import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
	testDir: 'e2e',
	timeout: 30000,
	projects: [
		{
			name: 'chromium',
			use: { ...devices['Desktop Chrome'] }
		}
	],
	use: {
		baseURL: 'http://localhost:5173',
		screenshot: 'only-on-failure'
	},
	webServer: {
		command: 'npm run dev -- --port 5173',
		port: 5173,
		reuseExistingServer: true
	}
});
