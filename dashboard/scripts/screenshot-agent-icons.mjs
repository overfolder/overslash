// Real-stack screenshots for agent icons (DECISIONS.md D70).
//
// The point of the feature is that the *logo* identifies the MCP client and the
// *stripe* identifies the agent, so the fixture is built to show exactly that:
// two agents enrolled against the same client — same mark, different bars —
// alongside agents on other clients and one with no MCP binding at all.
//
// Runs in a fresh org so the tree holds only these rows, and deletes it on the
// way out.
//
// Prereq: `make e2e-up`. Output: dashboard/screenshots/agent-icons-*.png.

import {
	api,
	deleteOrg,
	enrollMcpClient,
	freshOrgSlug,
	login,
	makeSnapper,
	seedAgent
} from '../tests/scenarios/index.mjs';

const org = freshOrgSlug('icons');
const session = await login('admin', { org });

try {
	// Two on the same client. This pair is the whole argument for the stripe:
	// identical marks, and still tellable apart at a glance.
	await enrollMcpClient(session, { clientName: 'Claude Code', agentName: 'releaser' });
	await enrollMcpClient(session, { clientName: 'Claude Code', agentName: 'reviewer' });

	// Different clients, to show the marks we ship.
	await enrollMcpClient(session, { clientName: 'Cursor', agentName: 'refactorer' });
	await enrollMcpClient(session, { clientName: 'Zed', agentName: 'navigator' });

	// A client we ship no mark for — falls back to the generic bot rather than
	// to nothing, the same way an unrecognised template falls to a letter tile.
	await enrollMcpClient(session, { clientName: 'Bespoke Internal Tool', agentName: 'in-house' });

	// No MCP binding at all: the API-key case. Also the bot.
	await seedAgent(session, { name: 'cron-runner', inheritPermissions: true });

	const identities = await api(session, '/v1/identities');
	for (const i of identities.filter((x) => x.kind !== 'user')) {
		console.log(
			`[agent-icons] ${i.name.padEnd(12)} ${(i.mcp_client_label ?? '(no client)').padEnd(22)} ` +
				`${(i.icon_url ?? '').split('/').pop()} ${(i.icon_stripe ?? []).join(' ')}`
		);
	}

	const snap = await makeSnapper(session);
	const waitForTree = async (page) => {
		await page.waitForSelector('.tree-node .agent-avatar');
		// The marks are `loading="lazy"` <img>s; a screenshot taken before they
		// decode catches the letter-tile fallback underneath and silently
		// misrepresents the feature.
		await page.waitForFunction(() =>
			[...document.querySelectorAll('.tree-node .agent-avatar img')].every((i) => i.complete)
		);
	};

	await snap.navigateAndSnap('agent-icons-light', '/agents', { waitFor: waitForTree });
	await snap.navigateAndSnap('agent-icons-dark', '/agents', {
		theme: 'dark',
		waitFor: waitForTree
	});

	// The detail header, where the mark renders at 32px next to the agent name.
	const agents = identities.filter((i) => i.kind === 'agent' || i.kind === 'sub_agent');
	const releaser = agents.find((a) => a.name === 'releaser');
	if (releaser) {
		await snap.navigateAndSnap('agent-icons-detail', `/agents/${releaser.id}`, {
			waitFor: waitForTree
		});
	}

	await snap.close();
	console.log('[agent-icons] done — screenshots in dashboard/screenshots');
} finally {
	await deleteOrg(session).catch(() => {});
}
