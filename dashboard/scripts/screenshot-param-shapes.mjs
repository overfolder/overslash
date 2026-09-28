// Real-stack screenshots for nested parameter schemas in the API Explorer.
//
// Three shots, and the point of the set is what each one removes from the
// reviewer's guesswork:
//
//  1. `before` — an `object` param whose template declares no shape. A blank
//     textarea and a sentence of prose, which is what the whole corpus looked
//     like. Kept as the contrast; nothing about this shot is a regression.
//  2. `shape` — the same shape of action with `properties` declared: a JSON
//     skeleton of the required fields as the placeholder, and the field list
//     underneath naming every declared field with its type, enum and
//     description.
//  3. `invalid` — the same form with a value that misses a required field and
//     names one that does not exist, reporting exactly what the gateway would
//     have said, before the round trip.
//
// Runs in a fresh org so the service picker holds only these rows, and deletes
// it on the way out.
//
// Prereq: `make e2e-up`. Run from `dashboard/`.
// Output: dashboard/screenshots/param-shapes-*.png.

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

// Modelled on HubSpot's `manage_crm_objects`, which is the real case: the
// contract used to live entirely in a `description` string, and got it wrong —
// `objectType` sits on each object, not on the request.
const TEMPLATE_YAML = `openapi: "3.1.0"
info:
  title: "CRM Demo"
  key: "shapedemo"
servers:
  - url: "https://api.shapedemo.test"
paths:
  /records/opaque:
    post:
      operationId: create_records_opaque
      summary: "Create records (undeclared shape)"
      description: "The payload's contract lives in the description, and nowhere else."
      risk: write
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [createRequest]
              properties:
                createRequest:
                  type: object
                  description: >-
                    Create payload: {objects: [{objectType, properties}]}.
  /records:
    post:
      operationId: create_records
      summary: "Create records"
      description: "Create one or more CRM records."
      risk: write
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [createRequest]
              properties:
                createRequest:
                  type: object
                  description: "Records to create. Max 10 per request."
                  required: [objects]
                  properties:
                    objects:
                      type: array
                      items:
                        type: object
                        required: [objectType]
                        properties:
                          objectType:
                            type: string
                            enum: [contacts, companies, deals, tickets]
                            description: "The CRM object type to create."
                          properties:
                            type: object
                            additionalProperties: true
                            description: "Property keys and values to set on the new record."
                          associations:
                            type: array
                            items:
                              type: object
                              required: [targetObjectId, targetObjectType]
                              properties:
                                targetObjectId:
                                  type: integer
                                targetObjectType:
                                  type: string
`;

const org = freshOrgSlug('shapes');
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
	console.log(`[shapes] template ${tpl.key}`);

	await seedService(session, { templateKey: 'shapedemo', name: 'crm-demo' });

	const snap = await makeSnapper(session);

	// The form renders from `GET /v1/templates/{key}/actions/{action}`, so it is
	// not on screen until that resolves — a shot taken on navigation alone
	// catches "Loading schema…". `getByLabel` is ambiguous on this page, so
	// scope to the two selects inside the request card's `.fields`.
	const pickAction = (key) => async (page) => {
		const fields = page.locator('section.request .fields');
		const service = fields.locator('select').first();
		await service.waitFor();
		const serviceValue = await service.evaluate(
			(el) => [...el.options].find((o) => o.text.includes('crm-demo'))?.value
		);
		if (!serviceValue) throw new Error('crm-demo is not in the service picker');
		await service.selectOption(serviceValue);
		const action = fields.locator('select').nth(1);
		await action.waitFor();
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

	// Element shots: a full-page capture stitches the sticky shell header over
	// the form and buries the thing the screenshot exists to show.
	const shot = async (name, actionKey, extra) => {
		const { ctx, page } = await snap.page({ viewport: { width: 1280, height: 1400 } });
		try {
			await page.goto(`${session.dashboardUrl}/services?tab=api-explorer&service=crm-demo`, {
				// NOT `networkidle`: the page holds an open SSE connection.
				waitUntil: 'domcontentloaded'
			});
			await pickAction(actionKey)(page);
			if (extra) await extra(page);
			const out = resolve('screenshots', `${name}.png`);
			await page.locator('section.request').screenshot({ path: out });
			console.log(`[shapes] wrote ${out}`);
		} finally {
			await ctx.close();
		}
	};

	try {
		await shot('param-shapes-before', 'create_records_opaque');

		await shot('param-shapes-declared', 'create_records', async (page) => {
			// The field list is collapsed by default so the control stays the
			// first thing on screen; open it, because it is the subject.
			await page.locator('details.shape').first().evaluate((el) => {
				el.open = true;
			});
		});

		await shot('param-shapes-invalid', 'create_records', async (page) => {
			await page
				.locator('#param-createRequest')
				.fill('{\n  "objects": [\n    { "propertes": {} }\n  ]\n}');
			// The messages render as the value changes; wait for the list
			// rather than for a timeout.
			await page.waitForSelector('.errors li');
		});
	} finally {
		await snap.close();
	}

	console.log('[shapes] wrote dashboard/screenshots/param-shapes-*.png');
} finally {
	await deleteOrg(session, org);
}
