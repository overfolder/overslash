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
	api,
	login,
	listIdentities,
	makeSnapper,
	seedAgent,
	seedAgents
} from '../tests/scenarios/index.mjs';

const session = await login('admin');

// A second user identity (not the logged-in admin) so we can show the
// admin-only "Remove from org" affordance + the non-self user copy.
async function ensureUser(name) {
	try {
		return await api(session, '/v1/identities', {
			method: 'POST',
			body: { name, kind: 'user' },
			expect: [200, 201]
		});
	} catch (err) {
		if (err instanceof Error && /409|already exists|duplicate/i.test(err.message)) {
			const all = await listIdentities(session);
			const match = all.find((i) => i.name === name && i.kind === 'user');
			if (match) return match;
		}
		throw err;
	}
}

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

// Seed a spread of permission-rule shapes so the detail panel's rule table
// shows the human-readable descriptions rendered server-side (the sentence on
// top, the raw key underneath). Idempotent: skip any pattern already present.
async function ensureRules(agent, patterns) {
	const existing = await api(session, `/v1/permissions?identity_id=${agent.id}`, {
		expect: [200]
	});
	const have = new Set(existing.map((r) => r.action_pattern));
	for (const action_pattern of patterns) {
		if (have.has(action_pattern)) continue;
		await api(session, '/v1/permissions', {
			method: 'POST',
			body: { identity_id: agent.id, action_pattern, effect: 'allow' },
			expect: [200, 201]
		});
	}
}

const research = await ensureAgent('research-agent');
await ensureRules(research, [
	'github:*:*',
	'github:create_pull_request:*',
	'email:send:recipient=*@acme.com',
	'http:POST:api.stripe.com/v1/**'
]);
const code = await ensureAgent('code-agent');
const _githubWorker = await ensureAgent('github-worker', code);
const _deployWorker = await ensureAgent('deploy-worker', code);
const teammate = await ensureUser('teammate');
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
		const agentNode = page.locator('.tree-label', {
			hasText: research.name
		});
		if ((await agentNode.count()) > 0) {
			await agentNode.first().click();
			await page.waitForTimeout(800);
			await snap.snap(page, `agents-${theme}-detail`, { fullPage: false });
		}

		// Read-only user node detail (light only — same shape in dark).
		// The logged-in user keeps the "read-only" copy and no Remove action.
		if (theme === 'light') {
			const userNode = page.locator('.tree-label', {
				hasText: 'Dev User'
			});
			if ((await userNode.count()) > 0) {
				await userNode.first().click();
				await page.waitForTimeout(800);
				await snap.snap(page, `agents-${theme}-user-detail`, {
					fullPage: false
				});
			}

			// A different user identity: neutral copy + admin "Remove from org".
			const otherUser = page.locator('.tree-label', {
				hasText: teammate.name
			});
			if ((await otherUser.count()) > 0) {
				await otherUser.first().click();
				await page.waitForTimeout(800);
				await snap.snap(page, `agents-${theme}-other-user-remove`, {
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
