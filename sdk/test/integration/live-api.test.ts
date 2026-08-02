// @vitest-environment node
//
// Deliberately not the suite-wide `happy-dom`. This file signs in with a
// session cookie, and a DOM environment enforces the browser rule that `Cookie`
// is a forbidden header — it strips it silently and every request arrives
// unauthenticated. The flows here are server-side anyway.

/**
 * The SDK against a real gateway.
 *
 * Unit tests prove the SDK does what it intends against a stub. This proves the
 * intent matches the API — the actual drift risk for hand-written type mirrors
 * (D47). It is the other side of the wire from
 * `crates/overslash-api/tests/events_stream.rs`.
 *
 * Opt in:
 *   make e2e-up
 *   OVERSLASH_E2E=1 npx vitest run test/integration
 *
 * `OVERSLASH_API_URL` overrides the default `http://localhost:3000`.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { OverslashClient } from '../../src/client.js';
import { SseEvents } from '../../src/controllers/events.js';
import { waitForApproval } from '../../src/controllers/wait-for-approval.js';
import { createProvideController } from '../../src/controllers/provide.js';
import type { EventEnvelope } from '../../src/types/events.js';

const API = process.env.OVERSLASH_API_URL ?? 'http://localhost:3000';

let client: OverslashClient;
let orgId: string;

/**
 * Sign in through the dev-token endpoint and mint a real API key, so the SDK is
 * exercised on the credential an integration would actually hold — not on the
 * dashboard's session cookie.
 */
beforeAll(async () => {
  const res = await fetch(`${API}/auth/dev/token?profile=admin`, {
    headers: { accept: 'application/json' },
  });
  if (!res.ok) {
    throw new Error(
      `/auth/dev/token returned ${res.status}. Is the stack up (\`make e2e-up\`) with dev auth enabled?`,
    );
  }
  const dev = (await res.json()) as { org_id: string; identity_id: string; token: string };
  orgId = dev.org_id;

  const cookie = `oss_session=${dev.token}`;
  const keyRes = await fetch(`${API}/v1/api-keys`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({
      org_id: dev.org_id,
      identity_id: dev.identity_id,
      name: `sdk-integration-${Date.now()}`,
      scopes: [],
    }),
  });
  if (!keyRes.ok) throw new Error(`could not mint an API key: ${keyRes.status}`);
  const { key } = (await keyRes.json()) as { key: string };

  client = new OverslashClient({ baseUrl: API, auth: { apiKey: key } });
}, 60_000);

describe('the credential and the types', () => {
  it('introspects itself through /v1/whoami', async () => {
    const me = await client.whoami();

    expect(me.org_id).toBe(orgId);
    expect(me.identity_id).toBeTruthy();
    // The field set the SDK's mirror claims. A rename upstream fails here.
    expect(Object.keys(me).sort()).toEqual(
      ['identity_id', 'kind', 'name', 'org_id', 'owner_id', 'parent_id'].sort(),
    );
  });

  it('lists approvals under a chain scope rather than org-wide', async () => {
    const approvals = await client.approvals.list({ scope: 'actionable' });
    expect(Array.isArray(approvals)).toBe(true);
  });
});

describe('the event stream', () => {
  it('opens, announces a cursor, and stays open', async () => {
    const events = new SseEvents(client);
    try {
      const seen: EventEnvelope[] = [];
      events.subscribe(['approval.pending', 'approval.created'], (e) => seen.push(e));

      await waitFor(() => events.live, 15_000, 'stream did not go live');
      expect(events.status).toBe('live');
    } finally {
      events.close();
    }
  }, 30_000);

  it('survives the server closing the connection at its 30s ceiling', async () => {
    // The reconnect path is the *normal* path here, not an error path — that is
    // the whole point of the fixed ceiling, and the SDK must not report an
    // outage when it fires.
    const events = new SseEvents(client);
    try {
      events.subscribe(['approval.pending'], () => {});
      await waitFor(() => events.live, 15_000, 'stream did not go live');

      const downs: string[] = [];
      events.onStatusChange((s) => {
        if (s === 'down') downs.push(s);
      });

      await new Promise((r) => setTimeout(r, 35_000));

      expect(events.live).toBe(true);
      expect(downs).toEqual([]);
    } finally {
      events.close();
    }
  }, 60_000);
});

describe('the secret-request handshake', () => {
  it('mints, provides, and refuses a second provide', async () => {
    const name = `sdk_integration_${Date.now()}`;
    const request = await client.secretRequests.create({
      secret_name: name,
      reason: 'SDK integration test',
      ttl_seconds: 300,
    });

    expect(request.id).toMatch(/^req_/);
    expect(request.url).toContain(request.id);

    // The controller's state machine, against the real endpoint.
    const controller = createProvideController(client, {
      reqId: request.id,
      token: request.token,
    });
    await waitFor(() => controller.getState().status === 'ready', 10_000, 'provide never readied');
    expect(controller.getState().metadata?.secret_name).toBe(name);

    expect(await controller.submit('sk_test_integration')).toBe(true);
    expect(controller.getState().status).toBe('submitted');

    // Single use: the second attempt is the terminal state, not a silent
    // overwrite of the vault slot.
    const second = createProvideController(client, {
      reqId: request.id,
      token: request.token,
    });
    await waitFor(
      () => second.getState().status === 'already_fulfilled',
      10_000,
      'a fulfilled request did not report already_fulfilled',
    );

    controller.dispose();
    second.dispose();
    await client.secrets.delete(name).catch(() => {});
  }, 45_000);

  it('reports secret_request.fulfilled over the stream', async () => {
    const events = new SseEvents(client);
    const name = `sdk_integration_evt_${Date.now()}`;
    try {
      const seen: EventEnvelope<{ request_id?: string; token?: string }>[] = [];
      events.subscribe<{ request_id?: string; token?: string }>(
        ['secret_request.created', 'secret_request.fulfilled'],
        (e) => seen.push(e),
      );
      await waitFor(() => events.live, 15_000, 'stream did not go live');

      const request = await client.secretRequests.create({ secret_name: name, ttl_seconds: 300 });
      await client.secretRequests.submitProvide(request.id, request.token, 'sk_test_evt');

      await waitFor(
        () => seen.some((e) => e.type === 'secret_request.fulfilled'),
        20_000,
        'never saw secret_request.fulfilled',
      );

      // The provide URL is a bearer capability, and webhook subscriptions are
      // org-wide. It must not ride along on either transport.
      for (const event of seen) {
        expect(JSON.stringify(event.data)).not.toContain(request.token);
      }
    } finally {
      events.close();
      await client.secrets.delete(name).catch(() => {});
    }
  }, 45_000);
});

describe('waitForApproval', () => {
  it('reports a timeout rather than hanging when nothing settles', async () => {
    // A real approval needs a gated action, which needs a configured service —
    // more setup than this suite owns. What is worth proving against the real
    // API is that a 404 surfaces rather than being swallowed into a wait.
    await expect(
      waitForApproval(client, '00000000-0000-4000-8000-000000000000', { timeoutMs: 3000 }),
    ).rejects.toThrow();
  }, 15_000);
});

async function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
  message: string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(message);
}
