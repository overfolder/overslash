// Real-stack screenshots for deployment template variables (D44).
//
// The template editor gains a "Deployment variables" panel listing the
// `${VAR}` references this deployment can resolve — the set configured via
// `OVERSLASH_TEMPLATE_VAR_*`, and nothing else. Clicking a name inserts the
// reference at the cursor. An unresolvable reference is a validation error,
// not a silently empty host, so it lands in the same inline panel as any
// other template error.
//
// The e2e stack sets OVERSLASH_TEMPLATE_VAR_MAILBOX_HOST (see
// scripts/e2e-up.sh), so no seeding is needed — the panel renders straight
// from /v1/templates/vars.
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/template-vars-panel.png
//   dashboard/screenshots/template-vars-unset-error.png
//   dashboard/screenshots/template-vars-email-source.png
//   dashboard/screenshots/template-vars-metabase-endpoint.png

import { login, makeSnapper } from '../tests/scenarios/index.mjs';

const session = await login('admin');

/** A minimal template that references a variable, for the editor shots. */
const yamlWith = (ref) => `openapi: 3.1.0
info:
  title: Varred API
  key: varred
servers:
  - url: https://${ref}
paths:
  /items:
    get:
      operationId: list_items
      summary: List items
      risk: read
`;

/** Replace the CodeMirror document via the editor's own input path so the
 * debounced validate round-trip runs exactly as it does for a real user.
 *
 * `insertText` rather than `pressSequentially`: CodeMirror's `indentOnInput`
 * re-indents on every typed newline, so character-by-character entry of
 * already-indented YAML compounds the leading whitespace into a document that
 * no longer parses — and `validateRemotely` bails on a parse error, so the
 * server-side result we came to photograph never renders. One insertText is a
 * single input event, which is also what a paste does. */
async function setEditorDoc(page, text) {
	const editor = page.locator('.cm-content');
	await editor.waitFor({ timeout: 15_000 });
	await editor.click();
	await page.keyboard.press('ControlOrMeta+a');
	await page.keyboard.press('Delete');
	await page.keyboard.insertText(text);
	// The editor debounces remote validation by 400ms.
	await page.waitForTimeout(1500);
}

const snap = await makeSnapper(session);
try {
	// 1. The reference panel, open, on the new-template editor.
	const { page, ctx } = await snap.navigateAndSnap(
		'template-vars-panel',
		'/services/templates/new',
		{
			viewport: { width: 1280, height: 900 },
			waitFor: async (p) => {
				await p.locator('.vars-panel').waitFor({ timeout: 15_000 });
				await p.locator('.vars-panel summary').click();
				await setEditorDoc(p, yamlWith('${MAILBOX_HOST}'));
			}
		}
	);

	// 2. A reference this deployment cannot resolve — `template_var_unset`
	//    inline, naming the env var an operator has to set.
	await setEditorDoc(page, yamlWith('${NOT_SET_ANYWHERE}'));
	await page.locator('.error-msg').first().waitFor({ timeout: 15_000 });
	await snap.snap(page, 'template-vars-unset-error');
	await ctx.close();

	// 3. The shipped `email` template as the catalog now serves it: `servers[0]`
	//    is `https://${MAILBOX_HOST}`, not a baked-in host. Viewport-sized
	//    (`fullPage: false`) because this template's source runs to several
	//    thousand pixels and a full-page capture is unreadable as a review
	//    artifact.
	await snap
		.navigateAndSnap('template-vars-email-source', '/services/templates/email', {
			viewport: { width: 1280, height: 900 },
			fullPage: false,
			waitFor: async (p) => {
				// Anchor on the reference itself, not on prose: `mailbox.overslash.com`
				// still appears in this template's comments, so matching that would
				// pass even if the substitution had been reverted.
				const ref = p.locator('.cm-content', { hasText: '${MAILBOX_HOST}' }).first();
				await ref.waitFor({ timeout: 15_000 });
				await p
					.getByText('url: https://${MAILBOX_HOST}', { exact: false })
					.first()
					.scrollIntoViewIfNeeded();
				await p.waitForTimeout(400);
			}
		})
		.then((r) => r.ctx.close());
	// 4. The `${VAR?}` half. The e2e stack sets no METABASE_URL, so the shipped
	//    metabase template compiles host-less rather than vanishing — and the
	//    create-service form asks for the endpoint instead of silently
	//    defaulting to somebody else's localhost.
	await snap
		.navigateAndSnap('template-vars-metabase-endpoint', '/services/new?template=metabase', {
			viewport: { width: 1280, height: 900 },
			fullPage: false,
			waitFor: async (p) => {
				// Anchor on the required-hint itself: the field is also shown for
				// templates that merely *allow* an override, so waiting on the
				// input alone would pass without proving the required case.
				await p
					.getByText('Required — this template has no default endpoint.')
					.first()
					.waitFor({ timeout: 20_000 });
				await p.waitForTimeout(300);
			}
		})
		.then((r) => r.ctx.close());
} finally {
	await snap.close();
}
