// Real-stack screenshots for the action wait-mode rung (D73): an action
// declaring the execution mode a call falls back to when the caller names none.
//
// Two surfaces, both new:
//   1. the service's action list, where the declaration is visible *before*
//      anyone calls the action — the only place a caller can learn that a
//      request naming no `execution` may come back 202 rather than a result;
//   2. the approval detail for a gated *hybrid* call, which used to claim
//      nothing about backgrounding because the page tested
//      `execution_mode === 'async'` alone while the server queues both.
//
// Prereq: `make e2e-up` (ASYNC_EXECUTION_ENABLED=1 — without it a hybrid call
// is a 400 and the second shot has nothing to show). Output:
//   dashboard/screenshots/wait-mode-actions.png
//   dashboard/screenshots/wait-mode-gated-hybrid.png

import {
	api,
	login,
	makeSnapper,
	resolveEnv,
	seedApproval,
	seedService
} from '../tests/scenarios/index.mjs';

const env = resolveEnv();

// A reporting service whose export genuinely cannot answer inside the
// synchronous ceiling, which is the whole motivating case: without the
// declaration a caller who does not know that rides into a 504.
const TEMPLATE_YAML = `openapi: 3.1.0
info:
  title: Reporting
  key: reporting
servers:
  - url: ${env.openapiUrl}
paths:
  /slow:
    get:
      operationId: export_rows
      summary: Export every row as CSV
      description: Builds the full export. Minutes, not seconds, on a large account.
      risk: read
      wait-mode: hybrid
      handoff_after_ms: 2000
      parameters:
        - name: ms
          in: query
          schema: { type: string }
  /echo:
    get:
      operationId: list_reports
      summary: List saved reports
      description: Returns the report index.
      risk: read
`;

const session = await login('admin');
const snap = await makeSnapper(session);

try {
	await api(session, '/v1/templates', {
		method: 'POST',
		body: { openapi: TEMPLATE_YAML, user_level: false },
		expect: [200, 201, 409]
	});
	// `seedService`, not a raw POST with `expect: [.., 409]` — a 409 body is an
	// error, not a service, so a re-run against the same stack would carry an
	// undefined id into the URL. The helper finds and reuses the existing row.
	const svc = await seedService(session, { templateKey: 'reporting', name: 'reporting' });

	// 1. The action list. `export_rows` carries the badge and `list_reports`,
	//    declaring nothing, carries none — the contrast is the point, since a
	//    badge on every row would say nothing at all.
	const actions = await snap.navigateAndSnap(
		'wait-mode-actions',
		// `?tab=` rather than a click: the tab is deep-linkable on purpose, and
		// addressing it directly keeps the shot from depending on which control
		// happens to render the tab strip.
		`/services/${svc.id}?tab=actions`,
		{
			viewport: { width: 1280, height: 960 },
			waitFor: async (p) => {
				// The HTTP action table renders method/path/summary/risk — there is
				// no key column — so pin the summary, not `export_rows`.
				await p.locator('text=Export every row as CSV').first().waitFor({ timeout: 15_000 });
				await p.locator('.pill-defer').first().waitFor({ timeout: 15_000 });
			}
		}
	);
	await actions.ctx.close();

	// 2. A gated hybrid call. The reviewer is told approving starts something
	//    that runs in the background — true for hybrid exactly as for async,
	//    because a replay has no connection to race and is queued either way.
	const approval = await seedApproval(session, {
		method: 'GET',
		url: `${env.openapiUrl}/slow?ms=12000`,
		execution: 'hybrid'
	});
	const gated = await snap.navigateAndSnap(
		'wait-mode-gated-hybrid',
		`/approvals/${approval.id}`,
		{
			viewport: { width: 1280, height: 960 },
			waitFor: (p) =>
				p
					.getByText(/runs? in the background/i)
					.first()
					.waitFor({ timeout: 15_000 })
		}
	);
	await gated.ctx.close();
} finally {
	await snap.close();
}
