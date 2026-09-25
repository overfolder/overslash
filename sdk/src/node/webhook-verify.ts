/**
 * Webhook verification.
 *
 * Mirrors `crates/overslash-api/src/services/webhook_dispatcher.rs`. Every
 * attempt carries two signatures, both HMAC-SHA256 with the subscription
 * secret, hex-encoded:
 *
 * - `X-Overslash-Timestamp: <unix seconds>` and
 *   `X-Overslash-Signature-V1: v1=<hex>` over `"<timestamp>.<raw body>"` —
 *   what {@link verifyWebhook} checks. The timestamp is inside the MAC, so a
 *   captured delivery stops verifying once it falls outside the tolerance.
 * - `X-Overslash-Signature: sha256=<hex>` over the raw body alone — the
 *   legacy scheme, deprecated: it replays forever. {@link verifyWebhookSignature}
 *   still checks it for integrations that have not moved yet.
 *
 * WebCrypto rather than `node:crypto`, so the same code verifies in a Worker or
 * an edge runtime — and so the package keeps its "no Node built-ins" property.
 */

import type { EventEnvelope, WireEventType } from '../types/events.js';

/** Stripe's default, and what Overslash's own Stripe consumer uses. */
export const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 5 * 60;

export interface VerifyWebhookV1Options {
  /**
   * The **raw** body, exactly as received — see {@link VerifyWebhookOptions.payload}.
   */
  payload: string | Uint8Array;
  /** The `X-Overslash-Timestamp` header. A missing one fails verification. */
  timestamp: string | null | undefined;
  /** The `X-Overslash-Signature-V1` header: `v1=<hex>`, possibly several, comma-separated. */
  signature: string | null | undefined;
  /** The subscription secret, returned once when the webhook was created. */
  secret: string;
  /** How far the timestamp may be from `now`, either way. Default 300. */
  toleranceSeconds?: number;
  /** Current unix time in seconds; injectable for tests. */
  now?: number;
}

/**
 * Verify a delivery's timestamped `v1` signature. `false` when the timestamp
 * is missing, malformed or outside the tolerance, or no `v1` entry matches.
 */
export async function verifyWebhook(opts: VerifyWebhookV1Options): Promise<boolean> {
  const ts = opts.timestamp?.trim();
  if (!ts || !/^\d+$/.test(ts)) return false;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const tolerance = opts.toleranceSeconds ?? DEFAULT_WEBHOOK_TOLERANCE_SECONDS;
  if (Math.abs(now - Number(ts)) > tolerance) return false;

  const candidates = (opts.signature ?? '')
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.startsWith('v1='))
    .map((part) => part.slice('v1='.length))
    .filter((hex) => /^[0-9a-f]+$/i.test(hex))
    .map((hex) => hex.toLowerCase());
  if (candidates.length === 0) return false;

  const body = typeof opts.payload === 'string' ? new TextEncoder().encode(opts.payload) : opts.payload;
  const prefix = new TextEncoder().encode(`${ts}.`);
  const signed = new Uint8Array(prefix.length + body.length);
  signed.set(prefix);
  signed.set(body, prefix.length);
  const expected = await hmacHex(opts.secret, signed);

  // Compare against every candidate, no early exit.
  let ok = false;
  for (const candidate of candidates) ok = timingSafeEqual(expected, candidate) || ok;
  return ok;
}

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

/**
 * Verify the legacy body-only `X-Overslash-Signature: sha256=<hex>`.
 *
 * @deprecated It has no time component, so a captured delivery verifies
 * forever. Use {@link verifyWebhook}; this header will stop being sent.
 */
export async function verifyWebhookSignature(opts: VerifyWebhookOptions): Promise<boolean> {
  const expected = stripPrefix(opts.signature);
  if (!expected) return false;

  const body = typeof opts.payload === 'string' ? new TextEncoder().encode(opts.payload) : opts.payload;
  return timingSafeEqual(await hmacHex(opts.secret, body), expected);
}

async function hmacHex(secret: string, message: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, message as BufferSource);
  return toHex(new Uint8Array(mac));
}

/**
 * Parse an envelope. Does **not** verify — call `verifyWebhook` first,
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
