// Real-stack screenshot for the endpoint field's org-secret note.
//
// A personal service of a template with an org-source slot (`email`'s
// `overfwd_gateway_key`) only receives that org secret at the endpoint the
// org's template declares. Typing a custom endpoint into the create form
// shows a note saying the org secret stays behind.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/endpoint-org-secrets-note.png

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');

const snap = await makeSnapper(session);
try {
	await snap.navigateAndSnap('endpoint-org-secrets-note', '/services/new?template=email', {
		viewport: { width: 1280, height: 1100 },
		waitFor: async (p) => {
			const field = p.locator('#new-service-url');
			if (!(await field.isVisible().catch(() => false))) {
				// The endpoint sits under "Show more options" unless promoted.
				await p.getByRole('button', { name: /more options/i }).first().click();
			}
			await field.waitFor({ timeout: 15_000 });
			await field.fill('https://gateway.my-own-host.example');
			await p.getByTestId('endpoint-org-secrets-note').waitFor({ timeout: 15_000 });
			await p.getByTestId('endpoint-org-secrets-note').scrollIntoViewIfNeeded();
		}
	});
	console.log('[endpoint-org-secrets] done');
} finally {
	await snap.close();
}
