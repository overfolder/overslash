// Real-stack screenshots for the Agents view.
//
// Replaces screenshot-agents-mocked.mjs (route-interception fakes). Drives
// the running e2e stack via the `tests/scenarios/` library: signs in via
// /auth/dev/token, seeds an identity tree by POSTing /v1/identities, and
// captures screenshots of the rendered tree + detail panels.
//
// Prereq: `make e2e-up` (writes .e2e/dashboard.env). Output: dashboard/
// screenshots/agents-{light,dark,*}.png.

import { resolve } from 'node:path';
import {
	login,
	listIdentities,
	makeSnapper,
	seedAgent,
	seedAgents
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// Build the same hierarchy the mocked version drew, but as real DB rows.
// idempotent: if a duplicate name 4xx's we just look up the existing row.
async function ensureAgent(name, parent) {
	try {
		return await seedAgent(session, {
			name,
			parentId: parent?.id,
			kind: parent?.kind === 'agent' ? 'sub_agent' : 'agent',
			inheritPermissions: true
		});
	} catch (err) {
		if (err instanceof Error && /409|already exists|duplicate/i.test(err.message)) {
			const all = await listIdentities(session);
			const match = all.find((i) => i.name === name);
			if (match) return match;
		}
		throw err;
	}
}

const research = await ensureAgent('research-agent');
const code = await ensureAgent('code-agent');
const _githubWorker = await ensureAgent('github-worker', code);
const _deployWorker = await ensureAgent('deploy-worker', code);
// Pull a fresh listing so any pre-existing tree (re-runs against the same
// stack) is fully reflected on the page. The screenshot just needs the
// hierarchy rendered — we don't assert on row count.
await listIdentities(session);

const snap = await makeSnapper(session);

try {
	for (const theme of /** @type {const} */ (['light', 'dark'])) {
		const { page, ctx } = await snap.navigateAndSnap(
			`agents-${theme}`,
			'/agents',
			{
				viewport: { width: 1440, height: 900 },
				theme,
				fullPage: false,
				waitFor: async (p) => {
					await p
						.getByRole('treeitem')
						.first()
						.waitFor({ timeout: 15_000 });
				}
			}
		).then((r) => ({ page: r.page, ctx: r.ctx }));

		// Detail panel: select the research agent.
		const agentNode = page.locator('button.tree-label', {
			hasText: research.name
		});
		if ((await agentNode.count()) > 0) {
			await agentNode.first().click();
			await page.waitForTimeout(800);
			await snap.snap(page, `agents-${theme}-detail`, { fullPage: false });
		}

		// Read-only user node detail (light only — same shape in dark).
		if (theme === 'light') {
			const userNode = page.locator('button.tree-label', {
				hasText: 'Dev User'
			});
			if ((await userNode.count()) > 0) {
				await userNode.first().click();
				await page.waitForTimeout(800);
				await snap.snap(page, `agents-${theme}-user-detail`, {
					fullPage: false
				});
			}
		}

		await ctx.close();
	}
	console.log('[agents] done — screenshots in', resolve('screenshots'));
} finally {
	await snap.close();
}
