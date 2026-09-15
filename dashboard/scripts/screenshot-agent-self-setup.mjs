// Real-stack screenshots for the agent self-setup default (D79): the org
// policy card, the disclosure on the agent create modal, and the permission
// rules a freshly-created first-level agent is actually born holding.
//
// The last one is the point of the feature, so it is captured from the real
// rules table rather than asserted in prose: seed an agent through the API and
// screenshot what the dashboard then renders for it.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/agent-self-setup-*.png.

import {
	login,
	makeSnapper,
	seedAgent,
	setAgentSelfSetup
} from '../tests/scenarios/index.mjs';

const session = await login('admin');
const snap = await makeSnapper(session);
const CARD = 'Agent defaults';

try {
	// ── 1. The org policy card ──────────────────────────────────────────
	await setAgentSelfSetup(session, true);

	const { page, ctx } = await snap.navigateAndSnap('agent-self-setup-org-page', '/org', {
		viewport: { width: 1400, height: 1100 },
		fullPage: false,
		waitFor: async (p) => {
			await p.locator('section.card', { hasText: CARD }).first().waitFor({ timeout: 20_000 });
			await p.locator('section.card', { hasText: CARD }).first().scrollIntoViewIfNeeded();
			await p.waitForTimeout(400);
		}
	});

	const card = page.locator('section.card', { hasText: CARD }).first();
	await card.screenshot({ path: 'screenshots/agent-self-setup-org-card.png' });
	console.log('[scenarios] wrote screenshots/agent-self-setup-org-card.png');
	await ctx.close();

	// ── 2. A first-level agent, and the rules it was born with ──────────
	const agent = await seedAgent(session, {
		name: `self-setup-demo-${Date.now()}`,
		inheritPermissions: false
	});

	const { page: agentsPage, ctx: agentsCtx } = await snap.navigateAndSnap(
		'agent-self-setup-rules-page',
		`/agents/${agent.id}`,
		{
			viewport: { width: 1400, height: 1100 },
			fullPage: false,
			waitFor: async (p) => {
				// The rules table is what we came for — wait on a seeded pattern
				// rather than a timeout, so a regression fails here loudly.
				await p
					.getByText('overslash:manage_services_own:*', { exact: false })
					.first()
					.waitFor({ timeout: 20_000 });
				await p.waitForTimeout(400);
			}
		}
	);
	await agentsPage.screenshot({ path: 'screenshots/agent-self-setup-seeded-rules.png' });
	console.log('[scenarios] wrote screenshots/agent-self-setup-seeded-rules.png');
	await agentsCtx.close();

	// ── 3. The disclosure on the create modal ───────────────────────────
	const { page: modalPage, ctx: modalCtx } = await snap.navigateAndSnap(
		'agent-self-setup-create-page',
		'/agents',
		{
			viewport: { width: 1400, height: 1000 },
			fullPage: false,
			waitFor: async (p) => {
				// The sidebar's "+ Add agent…" button; it seeds createParentId to
				// the selected node, or the signed-in user when nothing is selected —
				// which is the case the disclosure line renders for.
				await p.locator('button.add-row').first().click();
				await p.locator('.modal').first().waitFor({ timeout: 15_000 });
				// The hint renders only once the chosen parent is a user.
				await p.locator('.modal .create-note').waitFor({ timeout: 15_000 });
				await p.waitForTimeout(300);
			}
		}
	);
	await modalPage
		.locator('.modal')
		.first()
		.screenshot({ path: 'screenshots/agent-self-setup-create-modal.png' });
	console.log('[scenarios] wrote screenshots/agent-self-setup-create-modal.png');
	await modalCtx.close();

	console.log('[agent-self-setup] done');
} finally {
	// Leave the shared stack on the default, so other scripts see production
	// behaviour rather than whatever this one last set.
	await setAgentSelfSetup(session, true);
	await snap.close();
}
