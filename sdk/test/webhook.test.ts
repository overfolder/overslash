import { describe, expect, it } from 'vitest';
import { parseWebhookEvent, verifyWebhookSignature } from '../src/node/webhook-verify.js';

const SECRET = 'whsec_3f8a1c';

/** Sign like the dispatcher does: HMAC-SHA256 over the raw bytes, hex. */
async function sign(payload: string, secret = SECRET): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `sha256=${hex}`;
}

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
