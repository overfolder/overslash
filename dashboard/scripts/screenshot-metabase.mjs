// Real-stack screenshots for the Metabase template + D42/D43 SQL policy.
//
// Three captures:
//   metabase-service      — the service detail page: 7 actions with
//                           run_query/export_query at risk `dynamic`
//   metabase-approval     — an INSERT classified write by the gateway parser,
//                           bubbling an approval whose permission key names
//                           exactly the referenced table
//                           (metabase:run_query:table=pagila/public.film)
//                           with the raw SQL disclosed as the primary field
//   metabase-queue        — the approvals queue row for the same call
//
// Prereq: `make e2e-up` (the stack now builds with sql_policy, so the
// classifier runs like prod). Output: dashboard/screenshots/metabase-*.png.

import { login, makeSnapper, seedApproval, seedSecret, seedService } from '../tests/scenarios/index.mjs';

const session = await login('admin');

await seedSecret(session, { name: 'metabase_api_key', value: 'mb_screenshot_key' });
const service = await seedService(session, {
	templateKey: 'metabase',
	name: 'metabase',
	// Never dialled — the write bubbles an approval before any upstream call.
	url: 'https://metabase.acme-corp.example',
	config: { sql_databases: '{"5": {"dialect": "postgres", "label": "pagila"}}' },
	credentials: { token: 'metabase_api_key' }
});

const approval = await seedApproval(session, {
	templateKey: 'metabase',
	action: 'run_query',
	params: {
		database: 5,
		query: "INSERT INTO public.film (title) VALUES ('Chaos Monkey II')"
	}
});
console.log(`[metabase] approval ${approval.id} keys: ${approval.permission_keys.join(' ')}`);

const snap = await makeSnapper(session);
try {
	// Service detail, Actions tab: the actions table with the `dynamic`
	// risk class on run_query/export_query.
	const svc = await snap.navigateAndSnap('metabase-service', `/services/${service.id}`, {
		viewport: { width: 1280, height: 900 },
		waitFor: async (p) => {
			await p.getByRole('button', { name: 'Actions' }).click({ timeout: 15_000 });
			await p.getByText('dynamic').first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});
	await svc.ctx.close();

	// Approval detail: table-scoped key + disclosed SQL.
	const detail = await snap.navigateAndSnap('metabase-approval', `/approvals/${approval.id}`, {
		viewport: { width: 1280, height: 900 },
		waitFor: async (p) => {
			await p.getByRole('button', { name: /^Deny$/ }).waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});
	await detail.ctx.close();

	// Queue row.
	const queue = await snap.navigateAndSnap('metabase-queue', '/approvals', {
		viewport: { width: 1280, height: 800 },
		waitFor: async (p) => {
			await p.getByText('pagila').first().waitFor({ timeout: 15_000 });
			await p.waitForTimeout(400);
		}
	});
	await queue.ctx.close();

	console.log('[metabase] done');
} finally {
	await snap.close();
}
