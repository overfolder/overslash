import { describe, expect, it } from 'vitest';
import {
  parseWebhookEvent,
  verifyWebhook,
  verifyWebhookSignature,
} from '../src/node/webhook-verify.js';

const SECRET = 'whsec_3f8a1c';

/** HMAC-SHA256, hex — both schemes use it. */
async function hmacHex(message: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Sign like the dispatcher's legacy header: over the raw bytes alone. */
async function sign(payload: string, secret = SECRET): Promise<string> {
  return `sha256=${await hmacHex(payload, secret)}`;
}

/** Sign like the dispatcher's `X-Overslash-Signature-V1`: over `<ts>.<body>`. */
async function signV1(payload: string, ts: number, secret = SECRET): Promise<string> {
  return `v1=${await hmacHex(`${ts}.${payload}`, secret)}`;
}

const NOW = 1_790_000_000;

const BODY = JSON.stringify({
  id: '2b7c1f5e-0000-4000-8000-000000000001',
  type: 'approval.resolved',
  created_at: '2026-08-01T10:00:00Z',
  data: { approval_id: 'a1', status: 'allowed' },
});

describe('verifyWebhookSignature', () => {
  it('accepts a signature the dispatcher would have produced', async () => {
    const signature = await sign(BODY);
    await expect(verifyWebhookSignature({ payload: BODY, signature, secret: SECRET })).resolves.toBe(
      true,
    );
  });

  it('rejects a body altered after signing', async () => {
    const signature = await sign(BODY);
    const tampered = BODY.replace('allowed', 'denied');
    await expect(
      verifyWebhookSignature({ payload: tampered, signature, secret: SECRET }),
    ).resolves.toBe(false);
  });

  it('rejects the wrong secret', async () => {
    const signature = await sign(BODY, 'whsec_someone_else');
    await expect(verifyWebhookSignature({ payload: BODY, signature, secret: SECRET })).resolves.toBe(
      false,
    );
  });

  it('rejects a header without the sha256= prefix', async () => {
    const signature = (await sign(BODY)).replace('sha256=', '');
    await expect(verifyWebhookSignature({ payload: BODY, signature, secret: SECRET })).resolves.toBe(
      false,
    );
  });

  it('rejects a non-hex digest instead of throwing', async () => {
    await expect(
      verifyWebhookSignature({ payload: BODY, signature: 'sha256=not-hex!', secret: SECRET }),
    ).resolves.toBe(false);
  });

  it('accepts raw bytes as readily as a string', async () => {
    const signature = await sign(BODY);
    const bytes = new TextEncoder().encode(BODY);
    await expect(
      verifyWebhookSignature({ payload: bytes, signature, secret: SECRET }),
    ).resolves.toBe(true);
  });

  it('fails a re-serialised body — the signature is over bytes', async () => {
    // The trap every webhook integration hits: JSON middleware parses the body,
    // the handler stringifies it back, and the whitespace no longer matches.
    const pretty = JSON.stringify(JSON.parse(BODY), null, 2);
    const signature = await sign(BODY);
    await expect(
      verifyWebhookSignature({ payload: pretty, signature, secret: SECRET }),
    ).resolves.toBe(false);
  });

  it('is case-insensitive about the hex digest', async () => {
    const signature = (await sign(BODY)).toUpperCase().replace('SHA256=', 'sha256=');
    await expect(verifyWebhookSignature({ payload: BODY, signature, secret: SECRET })).resolves.toBe(
      true,
    );
  });
});

describe('verifyWebhook', () => {
  const verify = (over: Partial<Parameters<typeof verifyWebhook>[0]> & { signature: string }) =>
    verifyWebhook({ payload: BODY, timestamp: String(NOW), secret: SECRET, now: NOW, ...over });

  it('accepts a v1 signature the dispatcher would have produced', async () => {
    await expect(verify({ signature: await signV1(BODY, NOW) })).resolves.toBe(true);
  });

  it('matches the dispatcher byte-for-byte (shared vector with the Rust unit test)', async () => {
    await expect(
      verifyWebhook({
        payload: '{"id":"x"}',
        timestamp: '1790000000',
        signature: 'v1=67533a13d71e2eb77b03c01b4fe125052bbf1417cff15203550ad39a75c4995b',
        secret: 'whsec_test',
        now: 1_790_000_000,
      }),
    ).resolves.toBe(true);
  });

  it('accepts a timestamp inside the tolerance either way', async () => {
    await expect(verify({ signature: await signV1(BODY, NOW), now: NOW + 300 })).resolves.toBe(true);
    await expect(verify({ signature: await signV1(BODY, NOW), now: NOW - 300 })).resolves.toBe(true);
  });

  it('rejects a replay outside the tolerance', async () => {
    await expect(verify({ signature: await signV1(BODY, NOW), now: NOW + 301 })).resolves.toBe(false);
    await expect(
      verify({ signature: await signV1(BODY, NOW), now: NOW + 60, toleranceSeconds: 30 }),
    ).resolves.toBe(false);
  });

  it('rejects a bumped timestamp — the timestamp is inside the MAC', async () => {
    const signature = await signV1(BODY, NOW - 3600);
    await expect(verify({ signature, timestamp: String(NOW) })).resolves.toBe(false);
  });

  it('rejects a missing or malformed timestamp', async () => {
    const signature = await signV1(BODY, NOW);
    await expect(verify({ signature, timestamp: undefined })).resolves.toBe(false);
    await expect(verify({ signature, timestamp: '' })).resolves.toBe(false);
    await expect(verify({ signature, timestamp: '1790000000.5' })).resolves.toBe(false);
  });

  it('rejects a tampered body and the wrong secret', async () => {
    const signature = await signV1(BODY, NOW);
    await expect(verify({ signature, payload: BODY.replace('allowed', 'denied') })).resolves.toBe(
      false,
    );
    await expect(verify({ signature: await signV1(BODY, NOW, 'whsec_other') })).resolves.toBe(false);
  });

  it('does not accept the legacy signature in place of v1', async () => {
    const legacyHex = (await sign(BODY)).slice('sha256='.length);
    await expect(verify({ signature: `v1=${legacyHex}` })).resolves.toBe(false);
    await expect(verify({ signature: await sign(BODY) })).resolves.toBe(false);
  });

  it('accepts when any of several v1 entries matches', async () => {
    const signature = `v1=${'0'.repeat(64)}, ${await signV1(BODY, NOW)}`;
    await expect(verify({ signature })).resolves.toBe(true);
  });

  it('accepts raw bytes as readily as a string', async () => {
    const signature = await signV1(BODY, NOW);
    await expect(verify({ signature, payload: new TextEncoder().encode(BODY) })).resolves.toBe(true);
  });
});

describe('parseWebhookEvent', () => {
  it('returns the envelope with a typed payload', () => {
    const event = parseWebhookEvent<{ approval_id: string }>(BODY);
    expect(event.type).toBe('approval.resolved');
    expect(event.data.approval_id).toBe('a1');
  });

  it('rejects something that is not an envelope', () => {
    expect(() => parseWebhookEvent('{"hello":"world"}')).toThrow(/envelope/);
  });
});
