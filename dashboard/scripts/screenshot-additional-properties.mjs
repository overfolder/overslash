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

import { resolve } from 'node:path';

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
	// `getByLabel` is ambiguous on this page — the nav tab, the "show all
	// users" switch and the picker all answer to /Service/ — so scope to the
	// two selects inside the request card's `.fields`, which are the service
	// and action pickers in that order.
	const pickAction = (key) => async (page) => {
		const fields = page.locator('section.request .fields');
		const service = fields.locator('select').first();
		await service.waitFor();
		// The `?service=` param does not always resolve by name, so select
		// explicitly rather than assuming it landed.
		// `selectOption({label})` takes only a plain string, and the option text
		// carries owner/status decoration, so resolve the value by substring.
		const serviceValue = await service.evaluate(
			(el) => [...el.options].find((o) => o.text.includes('docs-search'))?.value
		);
		if (!serviceValue) throw new Error('docs-search is not in the service picker');
		await service.selectOption(serviceValue);
		const action = fields.locator('select').nth(1);
		await action.waitFor();
		// The options only populate once the actions list resolves.
		await page.waitForFunction(
			(k) =>
				[...document.querySelectorAll('section.request .fields select')]
					.flatMap((s) => [...s.options])
					.some((o) => o.value === k),
			key
		);
		await action.selectOption(key);
		await page.waitForSelector('.form');
	};

	// Element shots, not `navigateAndSnap`. A full-page capture of this route
	// stitches the sticky shell header over the form and buries the thing the
	// screenshot exists to show; the request card on its own is the feature.
	const shot = async (name, actionKey, extra) => {
		const { ctx, page } = await snap.page({ viewport: { width: 1280, height: 1400 } });
		try {
			await page.goto(`${session.dashboardUrl}/services?tab=api-explorer&service=docs-search`, {
				// NOT `networkidle`: the page holds an open SSE connection.
				waitUntil: 'domcontentloaded'
			});
			await pickAction(actionKey)(page);
			if (extra) await extra(page);
			const out = resolve('screenshots', `${name}.png`);
			await page.locator('section.request').screenshot({ path: out });
			console.log(`[addprops] wrote ${out}`);
		} finally {
			await ctx.close();
		}
	};

	try {
		// Strict: `sort` is a closed <select>, and there is nowhere to put an
		// argument the template did not declare.
		await shot('additional-properties-strict', 'search_strict', async (page) => {
			await page.locator('#param-query').fill('rate limits');
		});

		// Relaxed: same three declared params, plus the extra-args rows, and
		// `sort` is now an <input list> combobox holding an off-list value.
		await shot('additional-properties-relaxed', 'search_relaxed', async (page) => {
			await page.waitForSelector('.extras');
			await page.locator('#param-query').fill('rate limits');
			await page.locator('#param-sort').fill('trending');
			// Two filled rows and one blank, so the shot shows both the filled
			// state and the affordance that adds another.
			await page.getByRole('button', { name: '+ Add argument' }).click();
			await page.getByLabel('Additional argument 1 name').fill('filter[status]');
			await page.getByLabel('Additional argument 1 value').fill('published');
			await page.getByRole('button', { name: '+ Add argument' }).click();
			await page.getByLabel('Additional argument 2 name').fill('include_archived');
			await page.getByLabel('Additional argument 2 value').fill('true');
			await page.getByRole('button', { name: '+ Add argument' }).click();
		});
	} finally {
		await snap.close();
	}

	console.log('[addprops] wrote dashboard/screenshots/additional-properties-*.png');
} finally {
	await deleteOrg(session, org);
}
