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
//   dashboard/screenshots/template-vars-email-host.png

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
 * debounced validate round-trip runs exactly as it does for a typing user. */
async function setEditorDoc(page, text) {
	const editor = page.locator('.cm-content');
	await editor.waitFor({ timeout: 15_000 });
	await editor.click();
	await page.keyboard.press('ControlOrMeta+a');
	await page.keyboard.press('Delete');
	await editor.pressSequentially(text, { delay: 1 });
	// The editor debounces remote validation by 400ms.
	await page.waitForTimeout(1200);
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

	// 3. The payoff: the shipped `email` template's host is the deployment's,
	//    resolved from ${MAILBOX_HOST} rather than baked into the YAML.
	await snap
		.navigateAndSnap('template-vars-email-host', '/services/templates/email', {
			viewport: { width: 1280, height: 900 },
			waitFor: async (p) => {
				await p.locator('text=mailbox.overslash.com').first().waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		})
		.then((r) => r.ctx.close());
} finally {
	await snap.close();
}
