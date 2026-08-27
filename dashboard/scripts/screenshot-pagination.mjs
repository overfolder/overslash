// Real-stack screenshot for `x-overslash-pagination` (D-NEXT): an action that
// returns one page of a larger collection, and says so before anyone calls it.
//
// One surface, and the contrast on it is the point. A catalog service with two
// list actions — one annotated, one not — so the "pages" pill reads as a
// property of *that* action rather than decoration on every row. It sits beside
// D73's `wait_mode` pill, which the third action carries, because the two say
// different things about the same subject: how the result arrives, and how much
// of it arrives at once.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/pagination-actions.png.

import { api, login, makeSnapper, resolveEnv, seedService } from '../tests/scenarios/index.mjs';

const env = resolveEnv();

const TEMPLATE_YAML = `openapi: 3.1.0
info:
  title: Catalog
  key: catalog
servers:
  - url: ${env.openapiUrl}
paths:
  /paged/cursor:
    get:
      operationId: list_records
      summary: List records
      description: >-
        Returns records newest first. One page at a time — pass pageToken from
        the previous response to continue.
      risk: read
      pagination:
        page_size:
          param: maxResults
          default: 100
          max: 500
        next:
          style: cursor
          param: pageToken
          from: nextPageToken
        items: items
      parameters:
        - name: maxResults
          in: query
          schema: { type: integer }
        - name: pageToken
          in: query
          schema: { type: string }
  /echo:
    get:
      operationId: list_categories
      summary: List categories
      description: Returns every category. A short, fixed list.
      risk: read
  /slow:
    get:
      operationId: export_records
      summary: Export every record as CSV
      description: Builds the full export. Minutes, not seconds, on a large account.
      risk: read
      wait-mode: hybrid
      handoff_after_ms: 2000
      parameters:
        - name: ms
          in: query
          schema: { type: string }
`;

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	await api(session, '/v1/templates', {
		method: 'POST',
		body: { openapi: TEMPLATE_YAML, user_level: false },
		expect: [200, 201, 409]
	});
	const svc = await seedService(session, { templateKey: 'catalog', name: 'catalog' });

	const actions = await snap.navigateAndSnap(
		'pagination-actions',
		// `?tab=` rather than a click — the tab is deep-linkable on purpose.
		`/services/${svc.id}?tab=actions`,
		{
			viewport: { width: 1280, height: 960 },
			waitFor: async (p) => {
				// The HTTP table renders method/path/summary/risk, so pin the
				// summary rather than the action key.
				await p.locator('text=List records').first().waitFor({ timeout: 15_000 });
				await p.locator('.pill-page').first().waitFor({ timeout: 15_000 });
			}
		}
	);
	await actions.ctx.close();
} finally {
	await snap.close();
}
