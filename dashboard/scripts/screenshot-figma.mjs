// Real-stack screenshots for the Figma service template.
//
// Three things a reviewer should see, all driven through the real API and the
// real dashboard so nothing here is a hand-built fixture:
//   1. Figma in the service catalog — the card, the new Design category and
//      the vendor mark this PR vendors.
//   2. The curated action list on the service detail page: 24 actions and
//      their risk classes, including the three deletes.
//   3. The approval a comment raises. This is the substance of the template:
//      a comment on a shared design file notifies the whole file and cannot be
//      edited afterwards, so the card has to carry the file and the exact text
//      — and the permission key it offers has to name the one file, not all of
//      them.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/figma-*.png.

import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	seedApproval,
	seedService
} from '../tests/scenarios/index.mjs';

const FILE_KEY = 'kPTWz3QhL9xN4bVcR8dYsM';

// A fresh org per run, so the BYOC client and the connection below are
// always the first of their kind and the script is re-runnable against a
// long-lived stack. Not named `figma`: the slug shows in the org switcher,
// and Playwright's `hasText` is case-insensitive substring matching, so a
// `figma-*` slug would match the card filter below.
const org = freshOrgSlug('design');
const session = await login('admin', { org });
const snap = await makeSnapper(session);

try {
	// ── 1. The catalog card ─────────────────────────────────────────────
	const { page, ctx } = await snap.navigateAndSnap('figma-catalog', '/services/new', {
		viewport: { width: 1400, height: 1000 },
		fullPage: false,
		waitFor: async (p) => {
			// The catalog is 20-odd templates deep, so Figma's card starts
			// below the fold. Search for it the way a human would, which also
			// makes it the only card in frame.
			await p.getByPlaceholder(/Search templates/i).fill('figma');
			await p.getByText('Figma', { exact: true }).first().waitFor({ timeout: 20_000 });
			await p.waitForTimeout(400);
		}
	});
	// Target the exact display-name node: the button's accessible name folds in
	// the key and description, so a loose match is ambiguous.
	const card = page
		.locator('button, a, article, .card')
		.filter({ has: page.getByText('Figma', { exact: true }) })
		.last();
	await card.screenshot({ path: 'screenshots/figma-catalog-card.png' });
	console.log('[scenarios] wrote screenshots/figma-catalog-card.png');
	await ctx.close();

	// ── 2. The service, its connection, and the action list ─────────────
	//
	// Figma is an OAuth template, so `create_service` would normally mint a
	// connect link and stop. `skipConnect` takes that branch off, and the
	// connection arrives instead through the real import endpoint — the same
	// one a partner uses when it has already run its own OAuth. The token is a
	// fixture: every read below is against the gateway, not api.figma.com.
	const svc = await seedService(session, {
		templateKey: 'figma',
		name: 'figma',
		skipConnect: true
	});
	// An imported connection self-refreshes against a pinned client, so the
	// gateway refuses one with no BYOC credential behind it — the same rule
	// that makes a Figma connection able to survive its 90-day token.
	const byoc = await api(session, '/v1/byoc-credentials', {
		method: 'POST',
		body: {
			provider: 'figma',
			client_id: 'figma-fixture-client-id',
			client_secret: 'figma-fixture-client-secret',
			identity_id: session.identityId
		},
		expect: [200, 201]
	});
	await api(session, '/v1/connections/import', {
		method: 'POST',
		body: {
			provider: 'figma',
			byoc_credential_id: byoc.id,
			access_token: 'figd_fixture_not_a_real_token',
			// Every scope the template declares, so the detail page reads
			// "Full Scopes" rather than showing the partial-coverage badge —
			// that badge is its own screenshot, not this one.
			scopes: [
				'current_user:read',
				'file_content:read',
				'file_metadata:read',
				'file_versions:read',
				'file_comments:read',
				'file_comments:write',
				'file_dev_resources:read',
				'file_dev_resources:write',
				'file_variables:read',
				'library_content:read',
				'team_library_content:read',
				'projects:read'
			],
			account_email: 'design@acme.example',
			pin_service_ids: [svc.id]
		},
		expect: [200, 201]
	});

	const { page: dPage, ctx: dCtx } = await snap.navigateAndSnap(
		'figma-actions',
		`/services/${svc.id}`,
		{
			viewport: { width: 1400, height: 1400 },
			fullPage: true,
			waitFor: async (p) => {
				// The detail page opens on Overview; the curated action list
				// lives behind the Actions tab. Rows are method/path/summary,
				// not operation ids, so wait on a summary.
				await p.getByRole('button', { name: 'Actions' }).click({ timeout: 20_000 });
				await p
					.getByText('Comment on file {file_key}')
					.first()
					.waitFor({ timeout: 20_000 });
				await p.waitForTimeout(500);
			}
		}
	);
	void dPage;
	await dCtx.close();

	// ── 3. The approval a comment raises ────────────────────────────────
	//
	// A real ungranted call: the agent asks, the gateway builds the disclosure
	// and raises the approval. The `file_key` resolver reaches the live
	// api.figma.com with the fixture token, is refused, and the disclosure
	// falls back to the raw key — the same fallback the template declares for
	// a connection without `file_metadata:read`.
	const approval = await seedApproval(session, {
		templateKey: 'figma',
		action: 'post_comment',
		params: {
			file_key: FILE_KEY,
			message:
				'The spacing between these cards is 12px here but the token says 16px — ' +
				'which one is right? Implementing against 16px for now.'
		}
	});
	const { page: aPage, ctx: aCtx } = await snap.navigateAndSnap(
		'figma-approval',
		`/approvals/${approval.id}`,
		{
			viewport: { width: 1400, height: 1200 },
			fullPage: true,
			waitFor: async (p) => {
				await p.getByText(FILE_KEY).first().waitFor({ timeout: 20_000 });
			}
		}
	);
	void aPage;
	await aCtx.close();

	console.log('[scenarios] done');
} finally {
	await snap.close();
	await deleteOrg(session).catch(() => {});
}
