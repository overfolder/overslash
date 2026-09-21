// Real-stack screenshots for `x-overslash-additional-properties`.
//
// The feature's dashboard half is the API Explorer, and the whole point of the
// pair of shots is the *contrast*: the same shape of action, once strict and
// once relaxed, so a reviewer can see exactly what the flag changes — a closed
// `<select>` becoming an open combobox, and an "Additional arguments" section
// appearing below the declared fields.
//
// Runs in a fresh org so the service picker holds only these rows, and deletes
// it on the way out.
//
// Prereq: `make e2e-up`. Run from `dashboard/`.
// Output: dashboard/screenshots/additional-properties-*.png.

import {
	api,
	deleteOrg,
	freshOrgSlug,
	login,
	makeSnapper,
	promoteToOrgAdmin,
	seedService
} from '../tests/scenarios/index.mjs';

const TEMPLATE_YAML = `openapi: "3.1.0"
info:
  title: "Docs Search"
  key: "relaxdemo"
servers:
  - url: "https://api.relaxdemo.test"
paths:
  /search:
    get:
      operationId: search_strict
      summary: "Search (strict)"
      description: "Only the parameters below are accepted."
      risk: read
      parameters:
        - name: query
          in: query
          required: true
          schema: {type: string}
          description: "Full-text query."
        - name: sort
          in: query
          schema:
            type: string
            enum: [relevance, newest, oldest]
          description: "Ordering for the result set."
        - name: limit
          in: query
          schema: {type: integer}
          description: "Maximum rows to return."
  /search/advanced:
    get:
      operationId: search_relaxed
      summary: "Search (relaxed)"
      description: "Accepts the upstream's full filter surface, which this template does not enumerate."
      risk: read
      additional-properties: true
      parameters:
        - name: query
          in: query
          required: true
          schema: {type: string}
          description: "Full-text query."
        - name: sort
          in: query
          schema:
            type: string
            enum: [relevance, newest, oldest]
          description: "Ordering. The upstream accepts values beyond these."
        - name: limit
          in: query
          schema: {type: integer}
          description: "Maximum rows to return."
`;

const org = freshOrgSlug('addprops');
const session = await login('admin', { org });

try {
	// The dev `admin` profile is in the Admins group but its `is_org_admin`
	// column is false, and registering an org template is admin-only.
	const identities = await api(session, '/v1/identities');
	const me = identities.find((i) => i.kind === 'user');
	if (me) await promoteToOrgAdmin(session, me.id);

	const tpl = await api(session, '/v1/templates', {
		method: 'POST',
		body: { openapi: TEMPLATE_YAML, user_level: false },
		expect: [200, 201]
	});
	console.log(`[addprops] template ${tpl.key}`);

	await seedService(session, { templateKey: 'relaxdemo', name: 'docs-search' });

	const snap = await makeSnapper(session);

	// The form is rendered from `GET /v1/templates/{key}/actions/{action}`, so
	// it is not on screen until that resolves — a shot taken on navigation
	// alone catches "Loading schema…" and shows nothing of the feature.
	const pickAction = (label) => async (page) => {
		await page.waitForSelector('.params');
		await page.getByRole('button', { name: label }).click();
		await page.waitForSelector('.form');
	};

	try {
		// Strict: the enum is a closed <select>, and there is nowhere to put an
		// argument the template did not declare.
		const strict = await snap.navigateAndSnap(
			'additional-properties-strict',
			'/services?tab=api-explorer&service=docs-search',
			{ waitFor: pickAction('Search (strict)') }
		);
		await strict.ctx.close();

		// Relaxed: same three declared params, plus the extra-args rows, and
		// `sort` is now an <input list> combobox.
		const relaxed = await snap.navigateAndSnap(
			'additional-properties-relaxed',
			'/services?tab=api-explorer&service=docs-search',
			{
				waitFor: async (page) => {
					await pickAction('Search (relaxed)')(page);
					await page.waitForSelector('.extras');
					// Two filled rows and one blank, so the shot shows both the
					// filled state and the affordance that adds another.
					await page.getByRole('button', { name: '+ Add argument' }).click();
					await page.getByLabel('Additional argument 1 name').fill('filter[status]');
					await page.getByLabel('Additional argument 1 value').fill('published');
					await page.getByRole('button', { name: '+ Add argument' }).click();
					await page.getByLabel('Additional argument 2 name').fill('include_archived');
					await page.getByLabel('Additional argument 2 value').fill('true');
					await page.getByRole('button', { name: '+ Add argument' }).click();
					// An off-list enum value, which the strict form cannot express.
					await page.getByLabel('Additional argument 3 name').fill('');
					await page.locator('#param-sort').fill('trending');
					await page.locator('#param-query').fill('rate limits');
				}
			}
		);
		await relaxed.ctx.close();
	} finally {
		await snap.close();
	}

	console.log('[addprops] wrote dashboard/screenshots/additional-properties-*.png');
} finally {
	await deleteOrg(session, org);
}
