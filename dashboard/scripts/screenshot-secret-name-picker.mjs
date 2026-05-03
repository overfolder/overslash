// Real-stack screenshots for the SecretNamePicker UX on services pages.
//
// Seeds two vault secrets via PUT /v1/secrets/{name} and an api-key service
// instance pre-bound to one of them, then captures:
//
//   1. services-new-secret-picker-open  — create-service wizard at the
//      Resend (api-key) template, dropdown open showing seeded secrets
//   2. services-edit-secret-picker      — edit page, picker pre-filled with
//      the existing secret_name and the dropdown open showing alternatives
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/{services-new-secret-
// picker-open,services-edit-secret-picker}.png.
//
// Note: uses the `resend` shipped template (default_secret_name: resend_key,
// apiKey scheme) — it's the simplest api-key-only template that exercises
// the picker on both pages.

import { setTimeout as wait } from 'node:timers/promises';
import {
	login,
	makeSnapper,
	seedSecrets,
	seedService
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

const stamp = Date.now();
const SECRETS = [
	`resend_demo_${stamp}`,
	`stripe_demo_${stamp}`,
	`sendgrid_demo_${stamp}`
];
await seedSecrets(
	session,
	SECRETS.map((name) => ({ name, value: `demo-${name}` }))
);

// Pre-bind a service to one of the seeded secrets so the edit-page picker
// has a meaningful pre-filled value. Resend ships as an api-key template
// with default_secret_name=resend_key, so creating it without args works.
const svc = await seedService(session, {
	templateKey: 'resend',
	name: `resend_demo_${stamp}`,
	secretName: SECRETS[0]
});

const snap = await makeSnapper(session);
try {
	// 1. Create-service wizard: navigate, pick the Resend template, advance to
	//    the configure step, focus the picker so the dropdown is open.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'services-new-secret-picker-closed',
			'/services/new',
			{
				fullPage: false,
				waitFor: async (p) => {
					await p.locator('text=Choose a template').waitFor({ timeout: 15_000 });
				}
			}
		);

		// The TemplateCard list is keyed off the template `key`. Click the Resend
		// card, then the "Use this template" button to advance to step 2.
		await page.locator('text=Resend').first().click();
		await page.locator('button:has-text("Use this template")').waitFor({ timeout: 10_000 });
		await page.locator('button:has-text("Use this template")').click();
		await page.locator('label:has-text("API key secret name")').waitFor({ timeout: 10_000 });

		// Focus the picker — its <input> is the only one in the secret-name field.
		// The dropdown opens on focus and shows the seeded secrets.
		const pickerInput = page.locator('#new-service-secret');
		await pickerInput.click();
		// Give the listSecrets() fetch + render a beat to settle.
		await page.locator('[role="listbox"] button').first().waitFor({ timeout: 10_000 });
		await wait(300);
		await snap.snap(page, 'services-new-secret-picker-open', { fullPage: false });
		await ctx.close();
	}

	// 2. Edit page: navigate to the seeded service. The picker pre-fills with
	//    the bound secret name; click to open the dropdown so the alternatives
	//    are visible too.
	{
		const { page, ctx } = await snap.navigateAndSnap(
			'services-edit-secret-picker-prefill',
			`/services/${encodeURIComponent(svc.name)}`,
			{
				fullPage: false,
				waitFor: async (p) => {
					await p
						.locator('label:has-text("API key secret name")')
						.waitFor({ timeout: 15_000 });
				}
			}
		);

		// The picker correctly suppresses its dropdown when the prefilled value
		// exactly matches a vault secret (no suggestions to make). To capture
		// the "dropdown open with alternatives" state on the edit page, clear
		// the value first via the ✕ button, then re-focus.
		await page.locator('button[aria-label="Clear secret name"]').first().click();
		const pickerInput = page.locator('#edit-service-secret');
		await pickerInput.click();
		await page.locator('[role="listbox"] button').first().waitFor({ timeout: 10_000 });
		await wait(300);
		await snap.snap(page, 'services-edit-secret-picker-open', { fullPage: false });
		await ctx.close();
	}

	console.log('[secret-name-picker] done');
} finally {
	await snap.close();
}
