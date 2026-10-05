// Real-stack screenshots for relationship-gated approval reads.
//
// One run-private org. The admin's agent makes a gated call; the member — a
// non-admin with no relationship to that agent — then looks at it. Captures:
//   1. Agents view, admin on the agent — its pending approval is listed
//   2. Agents view, member on the same agent — the "outside your tree" note
//   3. /approvals/{id} as the member — the 404 copy (not "deleted")
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/approval-visibility-*.png.

import { deleteOrg, freshOrgSlug, login, makeSnapper, seedApproval } from '../tests/scenarios/index.mjs';

const slug = freshOrgSlug('approval-vis');
const admin = await login('admin', { org: slug });
const member = await login('member', { org: slug });
const approval = await seedApproval(admin, { agentName: 'billing-agent' });

const adminSnap = await makeSnapper(admin);
const memberSnap = await makeSnapper(member);
const viewport = { width: 1400, height: 900 };

try {
	{
		const { ctx } = await adminSnap.navigateAndSnap(
			'approval-visibility-admin-agent',
			`/agents/${approval.identity_id}`,
			{
				viewport,
				waitFor: async (p) => {
					await p.getByText('Pending Approvals').waitFor({ timeout: 20_000 });
				}
			}
		);
		await ctx.close();
	}
	{
		const { ctx } = await memberSnap.navigateAndSnap(
			'approval-visibility-member-agent',
			`/agents/${approval.identity_id}`,
			{
				viewport,
				waitFor: async (p) => {
					await p.locator('.approvals-hidden').waitFor({ timeout: 20_000 });
				}
			}
		);
		await ctx.close();
	}
	{
		const { ctx } = await memberSnap.navigateAndSnap(
			'approval-visibility-member-detail',
			`/approvals/${approval.id}`,
			{
				viewport,
				waitFor: async (p) => {
					await p.getByText("you don't have access to it").waitFor({ timeout: 20_000 });
				}
			}
		);
		await ctx.close();
	}
	console.log('[approval-visibility] done');
} finally {
	await adminSnap.close();
	await memberSnap.close();
	await deleteOrg(slug);
}
