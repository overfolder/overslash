# scenarios

Real-stack helpers for Playwright tests and PR-screenshot scripts.

The previous pattern was Playwright route-interception: each script hand-rolled a JSON fake of every API response the page touched, booted only the SvelteKit dev server, and snapshotted that. Screenshots looked plausible but drifted from production whenever the API shape, the auth flow, or the rendering changed — and reviewers had no signal that the page actually worked.

This library is the replacement. Helpers sign in via `/auth/dev/token` and seed fixtures (agents, secrets, services, groups, approvals) by POSTing to the real API. What you screenshot is what the dashboard actually renders against the running stack.

## Prerequisites

```bash
make e2e-up    # Postgres → overslash-fakes → API → dashboard preview, all on dynamic ports
```

That writes `.e2e/dashboard.env` with `DASHBOARD_URL`, `API_URL`, and the fake-upstream URLs. The scenarios library reads this file at import time. Tear down with `make e2e-down`.

## Using it from a screenshot script

```js
import {
  login,
  seedAgents,
  seedSecrets,
  seedApproval,
  makeSnapper
} from '../tests/scenarios/index.mjs';

const session = await login('admin');             // dev-auth user, admin role
await seedAgents(session, [{ name: 'henry' }]);   // POST /v1/identities
await seedSecrets(session, [{ name: 'gh', value: 'ghp-xxx' }]); // PUT /v1/secrets/gh
const approval = await seedApproval(session);     // triggers a real /v1/actions/call gap

const snap = await makeSnapper(session);
try {
  await snap.navigateAndSnap('agents', '/agents');
  await snap.navigateAndSnap('approval-pending', `/approvals/${approval.id}`);
} finally {
  await snap.close();
}
```

## Using it from a Playwright test

The same helpers work inside `tests/e2e/flows/*.spec.ts`. Import from `../scenarios/index.mjs` and pass `session` into Playwright contexts via `attachToContext(ctx, session)`.

## Available helpers

| Helper | What it does |
|---|---|
| `login(profile)` | POST `/auth/dev/token?profile=admin\|member\|readonly`, returns a `Session` with cookie + identity ids |
| `attachToContext(ctx, session)` | Mirrors the session cookie onto a Playwright BrowserContext (both API and dashboard hosts) |
| `seedAgent(s, input)` / `seedAgents(s, inputs[])` | POST `/v1/identities` |
| `listIdentities(s)` | GET `/v1/identities` |
| `seedAgentApiKey(s, identityId, name)` | POST `/v1/api-keys` (admin-scope, identity-bound) |
| `seedSecret(s, input)` / `seedSecrets(s, inputs[])` | PUT `/v1/secrets/{name}` |
| `seedService(s, input)` / `seedServices(s, inputs[])` | POST `/v1/services` (find-and-return on 409) |
| `seedGroup(s, input)` | POST `/v1/groups` |
| `seedGroupGrant(s, groupId, input)` | POST `/v1/groups/{id}/grants` |
| `seedGroupMember(s, groupId, identityId)` | POST `/v1/groups/{id}/members` |
| `seedApproval(s, input?)` | Mints an agent without permissions, calls `/v1/actions/call` to trigger a gap, returns the resulting approval row |
| `makeSnapper(session, outDir?)` | Returns `{ navigateAndSnap, page, snap, close }` for screenshot capture |
| `api(s, path, opts)` | Low-level typed `fetch` for routes the lib doesn't wrap yet |

## Conventions

- Helpers are **idempotent where the API allows it**. Service creation degrades to find-and-return on 409 so re-runs against a long-lived stack don't fail. Group creation does not (group names are unique per org); use `${name}-${Date.now()}` if you need multiple runs.
- Helpers return the **canonical API response shape**, not a hand-rolled subset. Chain freely.
- For approvals, never insert directly via psql or hand-roll `permission_keys` / `suggested_tiers`. `seedApproval` walks the real action gateway so all derived fields are populated.

## Adding a new helper

Pattern: add it to `seed.mjs`, mirror the API request shape, return the canonical response. Re-export from `index.mjs`. If the API doesn't have an endpoint for the thing you want to seed, that's a signal — either there is one and we missed it (check `crates/overslash-api/src/routes/`), or the seed should go through a chain of real calls (e.g. approvals via the action gateway), not a back-door insert.

## Migration status

Real-stack scripts (use this library):

- `screenshot-agents.mjs`
- `screenshot-approvals.mjs`
- `screenshot-audit.mjs`
- `screenshot-groups.mjs`
- `screenshot-secrets.mjs`

Still mocked (need follow-up; require richer fakes seeding):

- `screenshot-oauth-consent-mocked.mjs` — needs an OAuth-AS authorize flow to mint a real consent request
- `screenshot-oauth-connections-ux.mjs` — needs seeded OAuth connections through the real provider dance
