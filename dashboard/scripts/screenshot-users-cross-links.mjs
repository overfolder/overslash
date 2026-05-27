// Real-stack screenshots for the Users-list cross-navigation feature.
//
// Seeds agents and services owned by the non-admin `member` user, then signs
// in as admin and captures the three surfaces this PR adds:
//   1. Users list (/members) — new "Services" column + clickable "Agents" count
//   2. Services page scoped to a user (?user=) — accessible-services list + banner
//   3. Agents page scoped to a user (?user=) — subtree + identity banner
//
// Prereq: `make e2e-up`. Output:
//   dashboard/screenshots/users-list-services-column.png
//   dashboard/screenshots/services-user-filter.png
//   dashboard/screenshots/agents-user-filter.png

import { login, makeSnapper, seedAgents, seedServices } from '../tests/scenarios/index.mjs';

const adminSession = await login('admin');
const memberSession = await login('member');
const memberId = memberSession.identityId;

const stamp = Date.now();

// Agents owned by the member user: a couple of root agents plus one sub-agent,
// so the Users list shows a non-zero Agents count and the scoped Agents tree
// has depth to render.
const [deployBot] = await seedAgents(memberSession, [
	{ name: `deploy-bot-${stamp}` },
	{ name: `analytics-bot-${stamp}` }
]);
await seedAgents(memberSession, [
	{ name: `metrics-collector-${stamp}`, parentId: deployBot.id, kind: 'sub_agent' }
]);

// Services owned by the member user — their accessible set when an admin
// drills in via ?user=.
const svcNames = [`github_${stamp}`, `slack_${stamp}`];
await seedServices(memberSession, [
	{ templateKey: 'github', name: svcNames[0] },
	{ templateKey: 'slack', name: svcNames[1] }
]);

const snap = await makeSnapper(adminSession);
try {
	// 1. Users list — new Services column + clickable Agents count.
	{
		const { ctx } = await snap.navigateAndSnap('users-list-services-column', '/members', {
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.getByRole('columnheader', { name: 'Services' }).waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	// 2. Services page scoped to the member user.
	{
		const { ctx } = await snap.navigateAndSnap(
			'services-user-filter',
			`/services?user=${memberId}`,
			{
				viewport: { width: 1280, height: 800 },
				waitFor: async (p) => {
					await p.locator('text=Showing services accessible to').waitFor({ timeout: 15_000 });
					await p.locator(`text=${svcNames[0]}`).first().waitFor({ timeout: 15_000 });
				}
			}
		);
		await ctx.close();
	}

	// 3. Agents page scoped to the member user.
	{
		const { ctx } = await snap.navigateAndSnap('agents-user-filter', `/agents?user=${memberId}`, {
			viewport: { width: 1280, height: 800 },
			waitFor: async (p) => {
				await p.locator('text=Viewing agents owned by').waitFor({ timeout: 15_000 });
			}
		});
		await ctx.close();
	}

	console.log('[users-cross-links] done');
} finally {
	await snap.close();
}
