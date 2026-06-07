// Real-stack screenshot for the service detail "Try it" → API Explorer fix.
//
// Seeds a user-level service, opens its detail page, clicks "⌘ Try it",
// and verifies the explorer URL carries the service UUID (not the name)
// and that the explorer resolves/selects the service. Captures the detail
// page and the explorer state.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/try-it-uuid-detail.png
//   dashboard/screenshots/try-it-uuid-explorer.png

import { login, makeSnapper, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

const svcName = `google_calendar_${Date.now()}`;
const svc = await seedService(session, { templateKey: 'google_calendar', name: svcName });
console.log(`[try-it-uuid] seeded service ${svcName} id=${svc.id}`);

const snap = await makeSnapper(session);
try {
	const { page, ctx } = await snap.navigateAndSnap('try-it-uuid-detail', `/services/${svc.id}`, {
		viewport: { width: 1280, height: 800 },
		waitFor: async (p) => {
			await p.locator(`text=${svcName}`).first().waitFor({ timeout: 15_000 });
		}
	});
	try {
		await page.getByRole('button', { name: /try it/i }).click();
		await page.waitForURL(/tab=api-explorer/, { timeout: 15_000 });

		const url = new URL(page.url());
		const serviceParam = url.searchParams.get('service');
		if (serviceParam !== svc.id) {
			throw new Error(`expected ?service=${svc.id}, got ?service=${serviceParam}`);
		}
		console.log(`[try-it-uuid] explorer URL carries UUID: ${page.url()}`);

		// The explorer should resolve the UUID to the seeded service: the
		// service <select> must end up with the UUID as its value. (<option>
		// elements are hidden, so assert the select's value instead.)
		await page
			.locator(`select:has(option[value="${svc.id}"])`)
			.first()
			.waitFor({ timeout: 15_000 });
		const selected = await page
			.locator(`select:has(option[value="${svc.id}"])`)
			.first()
			.inputValue();
		if (selected !== svc.id) {
			throw new Error(`explorer did not select the service: select value=${selected}`);
		}
		console.log(`[try-it-uuid] explorer selected ${svcName} (${selected})`);
		await page.waitForLoadState('networkidle');
		await snap.snap(page, 'try-it-uuid-explorer');
		console.log('[try-it-uuid] done');
	} finally {
		await ctx.close();
	}
} finally {
	await snap.close();
}
