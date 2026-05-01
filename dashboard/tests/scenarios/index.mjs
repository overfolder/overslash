// Public entrypoint for the scenarios library.
//
// Use this from Playwright tests *and* from screenshot scripts to drive
// the running e2e stack:
//
//     import { login, seedAgents, makeSnapper } from '../tests/scenarios/index.mjs';
//     const session = await login('admin');
//     await seedAgents(session, [{ name: 'henry' }]);
//     const snap = await makeSnapper(session);
//     await snap.navigateAndSnap('agents', '/agents');
//     await snap.close();
//
// All helpers hit the real API at the URL the e2e harness wrote into
// `.e2e/dashboard.env`. No Playwright route interception — what you
// screenshot is what the dashboard actually renders against the real
// stack.

export { resolveEnv } from './env.mjs';
export { login, attachToContext } from './auth.mjs';
export { api } from './api.mjs';
export {
	seedAgent,
	seedAgents,
	listIdentities,
	seedAgentApiKey,
	seedSecret,
	seedSecrets,
	seedService,
	seedServices,
	seedGroup,
	seedGroupGrant,
	seedGroupMember,
	seedApproval
} from './seed.mjs';
export { makeSnapper } from './snap.mjs';
