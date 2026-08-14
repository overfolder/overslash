// Real-stack screenshots for the D66 extension lint — the keys a template
// declares that the compiler silently ignores.
//
// Both surfaces are new: the YAML editor's footer used to read "✓ Valid" over a
// list of warnings, and the draft page rendered `import_warnings` while dropping
// `validation.warnings` entirely.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/extension-lint-editor.png
//   dashboard/screenshots/extension-lint-draft.png

import { api, login, makeSnapper } from '../tests/scenarios/index.mjs';

// One document, one finding per rule: a bare key at a position whose fields we
// enumerate (`response_type` — the bug that opened #539), a real extension that
// is MCP-only (`x-overslash-download`), and a typo that earns a suggestion.
const LINTY_YAML = `openapi: 3.1.0
info:
  title: Reporting
  key: reporting
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    token:
      type: apiKey
      in: header
      name: Authorization
      x-overslash-template:
        lang: jq
        expr: '"Bearer " + .token'
      default_secret_name: reporting_token
paths:
  /exports:
    get:
      operationId: export_rows
      summary: Export rows
      risk: read
      response_type: binary
      x-overslash-download:
        url: .url
      x-overslash-disclsoe:
        - label: Rows
          filter: .rows
`;

const adminSession = await login('admin');
const snap = await makeSnapper(adminSession);

try {
	// 1. The editor the author is typing in. The footer names each ignored key
	//    with its dot-path, and the header no longer claims an unqualified
	//    "Valid" over them.
	const { page, ctx } = await snap.navigateAndSnap(
		'extension-lint-editor',
		'/services/templates/new',
		{
			viewport: { width: 1280, height: 1000 },
			waitFor: async (p) => {
				const editor = p.locator('.cm-content');
				await editor.waitFor({ timeout: 15_000 });
				// Replace the seeded skeleton wholesale.
				await editor.click();
				await p.keyboard.press('ControlOrMeta+a');
				await p.keyboard.press('Delete');
				await editor.fill(LINTY_YAML);
				// The panel debounces validation at 400ms, then round-trips.
				await p.locator('text=is ignored on an operation').first().waitFor({
					timeout: 15_000
				});
			}
		}
	);
	await ctx.close();

	// 2. The draft page. Import persists a draft with its report, so the
	//    findings ride along and now render as their own card.
	const draft = await api(adminSession, '/v1/templates/import', {
		method: 'POST',
		body: {
			source: { type: 'body', content_type: 'application/yaml', body: LINTY_YAML },
			key: 'reporting-draft'
		}
	});
	const draftShot = await snap.navigateAndSnap(
		'extension-lint-draft',
		`/services/templates/drafts/${draft.id}`,
		{
			viewport: { width: 1280, height: 1000 },
			waitFor: async (p) => {
				await p.locator('text=Ignored declarations').first().waitFor({ timeout: 15_000 });
			}
		}
	);
	await draftShot.ctx.close();
} finally {
	await snap.close();
}
