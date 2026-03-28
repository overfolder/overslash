import { defineConfig, devices } from '@playwright/test';

const PORT = parseInt(process.env.DASHBOARD_PORT ?? '5173');

export default defineConfig({
	testDir: './e2e',
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	workers: process.env.CI ? 1 : undefined,
	reporter: 'html',
	use: {
		baseURL: `http://localhost:${PORT}`,
		trace: 'on-first-retry',
		screenshot: 'only-on-failure',
	},
	projects: [
		{
			name: 'chromium',
			use: { ...devices['Desktop Chrome'] },
		},
	],
	webServer: {
		command: `bun run dev -- --port ${PORT}`,
		port: PORT,
		reuseExistingServer: !process.env.CI,
	},
});
