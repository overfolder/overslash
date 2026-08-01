/**
 * Webhook verification.
 *
 * Mirrors `crates/overslash-api/src/services/webhook_dispatcher.rs`: HMAC-SHA256
 * over the **raw body bytes**, hex-encoded, sent as
 * `X-Overslash-Signature: sha256=<hex>`.
 *
 * WebCrypto rather than `node:crypto`, so the same code verifies in a Worker or
 * an edge runtime — and so the package keeps its "no Node built-ins" property.
 */

import type { EventEnvelope, WireEventType } from '../types/events.js';

export interface VerifyWebhookOptions {
  /**
   * The **raw** body, exactly as received.
   *
   * Not a re-serialised object: `JSON.stringify(JSON.parse(body))` reorders
   * nothing but reformats everything, and the signature is over bytes. Read the
   * body as text or a Buffer before any JSON middleware touches it.
   */
  payload: string | Uint8Array;
  /** The full header value, `sha256=` prefix included. */
  signature: string;
  /** The subscription secret, returned once when the webhook was created. */
  secret: string;
}

export async function verifyWebhookSignature(opts: VerifyWebhookOptions): Promise<boolean> {
  const expected = stripPrefix(opts.signature);
  if (!expected) return false;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(opts.secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const body = typeof opts.payload === 'string' ? new TextEncoder().encode(opts.payload) : opts.payload;
  const mac = await crypto.subtle.sign('HMAC', key, body as BufferSource);

  return timingSafeEqual(toHex(new Uint8Array(mac)), expected);
}

/**
 * Parse an envelope. Does **not** verify — call `verifyWebhookSignature` first,
 * on the raw bytes, and only then parse.
 */
export function parseWebhookEvent<T = Record<string, unknown>>(
  payload: string,
): EventEnvelope<T> & { type: WireEventType | string } {
  const parsed = JSON.parse(payload) as EventEnvelope<T>;
  if (!parsed || typeof parsed !== 'object' || typeof parsed.type !== 'string') {
    throw new Error('Not an Overslash event envelope');
  }
  return parsed;
}

function stripPrefix(signature: string): string | null {
  const trimmed = signature.trim();
  if (!trimmed.startsWith('sha256=')) return null;
  const hex = trimmed.slice('sha256='.length);
  return /^[0-9a-f]+$/i.test(hex) ? hex.toLowerCase() : null;
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/**
 * Constant-time compare.
 *
 * The lengths are both a SHA-256 hex digest in the honest case, so leaking the
 * length mismatch is harmless; what must not leak is *where* two same-length
 * digests diverge.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
