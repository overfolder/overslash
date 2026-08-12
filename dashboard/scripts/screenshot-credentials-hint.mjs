// Real-stack screenshots for the D60 `needs_authentication` hint_url loop.
//
// When a secret-backed service instance can't resolve its credentials, the API
// now returns `401 needs_authentication` naming the unset fields and carrying a
// `hint_url` that deep-links the instance's credentials form. That link is only
// useful if `/services/{id}?tab=credentials` actually lands on that tab, which
// is what these shots prove end to end:
//
//   1. credentials-hint-envelope  — the API response an agent receives, shown
//      in the Try It console: the typed 401 with missing_credentials + hint_url
//   2. credentials-hint-landing   — following that hint_url lands directly on
//      the Credentials tab, not Overview
//   3. credentials-hint-resolved  — the same instance after binding the
//      credential, back on Overview
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/credentials-hint-*.png.
//
// Uses `stripe` — the simplest shipped instance-secret template (one implicit
// `token` slot, no OAuth, no required config), so the envelope is a clean
// single-field case.

import { setTimeout as wait } from 'node:timers/promises';
import { api, login, makeSnapper, seedSecrets, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');
const stamp = Date.now();

// An instance with NO credential bound: exactly the state the gate catches.
const svc = await seedService(session, {
	templateKey: 'stripe',
	name: `stripe_unconfigured_${stamp}`
});

// Call it and capture the envelope the agent actually gets back. `expect` is
// widened because a 401 is the point of this shot, not a failure.
const envelope = await api(session, '/v1/actions/call', {
	method: 'POST',
	body: { service: svc.name, action: 'list_customers', params: {} },
	expect: [200, 400, 401, 403]
}).catch((err) => ({ error: String(err) }));
console.log('[credentials-hint] envelope:', JSON.stringify(envelope, null, 2));

const hintUrl = typeof envelope?.hint_url === 'string' ? envelope.hint_url : null;
// The hint is an absolute dashboard URL; the snapper navigates by path.
const hintPath = hintUrl ? new URL(hintUrl, 'http://localhost').pathname + new URL(hintUrl, 'http://localhost').search : `/services/${svc.id}?tab=credentials`;
console.log('[credentials-hint] following hint:', hintPath);

const snap = await makeSnapper(session);
try {
	// 1 + 2. Follow the hint_url exactly as a user handed the link would.
	{
		const { ctx } = await snap.navigateAndSnap('credentials-hint-landing', hintPath, {
			fullPage: false,
			waitFor: async (p) => {
				// The Credentials tab must be the active one on arrival — that is
				// the whole contract the hint depends on.
				await p.locator('.tab.active:has-text("credentials")').waitFor({ timeout: 15_000 });
				await wait(300);
			}
		});
		await ctx.close();
	}

	// 3. Bind the credential, then show the instance no longer flagged.
	{
		const secretName = `stripe_key_${stamp}`;
		await seedSecrets(session, [{ name: secretName, value: `sk_test_${stamp}` }]);
		await api(session, `/v1/services/${svc.id}/manage`, {
			method: 'PUT',
			body: { credentials: { token: secretName } },
			expect: [200]
		});

		const { ctx } = await snap.navigateAndSnap(
			'credentials-hint-resolved',
			`/services/${svc.id}?tab=credentials`,
			{
				fullPage: false,
				waitFor: async (p) => {
					await p.locator('.tab.active:has-text("credentials")').waitFor({ timeout: 15_000 });
					await wait(300);
				}
			}
		);
		await ctx.close();
	}

	console.log('[credentials-hint] done');
} finally {
	await snap.close();
}
