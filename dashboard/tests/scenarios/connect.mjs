// OAuth-Connect dance against the fake AS, exposed as a scenarios helper
// so Playwright specs and screenshot scripts can both bind a real
// `connections` row to a service without re-implementing the popup flow.
//
// The dance is page-driven (the dashboard opens a popup that hits
// `/oauth/authorize` on the fake AS, which auto-approves and 307s into the
// API callback), so unlike the rest of the seed helpers this one needs a
// Playwright `Page` — not just a `Session`. Everything else (service row,
// connection row read-back) goes through the real API.

import { expect } from '@playwright/test';

import { api } from './api.mjs';
import { seedService } from './seed.mjs';

/**
 * @typedef {{
 *   id: string,
 *   name: string,
 *   template_key: string,
 *   connection_id: string,
 * }} ConnectedGithubService
 */

/**
 * Create a fresh user-level GitHub service and bind a real OAuth
 * connection to it via the dashboard's Connect UI. Returns the bound
 * service detail.
 *
 * The harness reuses Postgres across runs, so the service name is
 * suffixed with the current timestamp to avoid colliding with leftover
 * rows from prior runs.
 *
 * @param {import('./auth.mjs').Session} session
 * @param {import('@playwright/test').Page} page
 * @param {{ suffix?: string }} [opts]
 * @returns {Promise<ConnectedGithubService>}
 */
export async function connectGithubService(session, page, opts = {}) {
	const suffix = opts.suffix ?? 'connect';
	const name = `github-e2e-${suffix}-${Date.now().toString(36)}`;
	await seedService(session, { templateKey: 'github', name });

	await page.goto(`${session.dashboardUrl}/services/${encodeURIComponent(name)}`);
	await page.getByRole('button', { name: 'credentials' }).click();
	await expect(page.getByText('needs setup')).toBeVisible();

	const [popup] = await Promise.all([
		page.waitForEvent('popup'),
		page.getByRole('button', { name: 'Connect new' }).click()
	]);
	await popup.waitForEvent('close', { timeout: 15_000 });

	await page.getByRole('button', { name: 'Save', exact: true }).click();
	await expect(page.getByText('connected')).toBeVisible({ timeout: 10_000 });

	/** @type {ConnectedGithubService} */
	const detail = await api(
		session,
		`/v1/services/${encodeURIComponent(name)}?include_inactive=true`
	);
	if (!detail.connection_id) {
		throw new Error(`connectGithubService: ${name} has no connection_id after save`);
	}
	return detail;
}
