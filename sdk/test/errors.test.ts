import { describe, expect, it } from 'vitest';
import { ApiError, AuthActionError, pickApiError, toApiError } from '../src/errors.js';

describe('auth envelope lifting', () => {
  it('lifts needs_authentication with its gated URL', () => {
    const err = toApiError(401, {
      error: 'needs_authentication',
      service: 'gmail',
      provider: 'google',
      connection_id: 'c1',
      auth_url: 'https://api.overslash.com/connect-authorize?id=f1',
      short: 'https://oversla.sh/abc',
    });

    expect(err).toBeInstanceOf(AuthActionError);
    const auth = err as AuthActionError;
    expect(auth.kind).toBe('needs_authentication');
    expect(auth.headless).toBe(false);
    expect(auth.authUrl).toBe('https://api.overslash.com/connect-authorize?id=f1');
    expect(auth.provider).toBe('google');
    expect(auth.connectionId).toBe('c1');
  });

  it('lifts the headless variant, which carries no URL at all', () => {
    // A white-label org mints no gated link because its end users have no
    // Overslash session (D21). A caller that opens `authUrl` unguarded opens
    // `undefined`, so `headless` has to be checked first.
    const err = toApiError(401, {
      error: 'needs_authentication',
      headless: true,
      provider: 'google',
      required_scopes: ['gmail.send'],
      account_email: 'alice@acme.com',
    }) as AuthActionError;

    expect(err.headless).toBe(true);
    expect(err.authUrl).toBeUndefined();
    expect(err.short).toBeUndefined();
    expect(err.requiredScopes).toEqual(['gmail.send']);
    expect(err.accountEmail).toBe('alice@acme.com');
  });

  it('lifts reauth_required with its reason', () => {
    const err = toApiError(401, {
      error: 'reauth_required',
      connection_id: 'c9',
      reason: 'refresh token revoked',
      auth_url: 'https://gate',
    }) as AuthActionError;

    expect(err.kind).toBe('reauth_required');
    expect(err.connectionId).toBe('c9');
    expect(err.reason).toBe('refresh token revoked');
  });

  it('lifts missing_scopes with both the target set and the delta', () => {
    const err = toApiError(403, {
      error: 'missing_scopes',
      connection_id: 'c2',
      required: ['a', 'b', 'c'],
      missing: ['c'],
      upgrade_url: 'https://api.overslash.com/v1/connections/c2/upgrade_scopes',
    }) as AuthActionError;

    expect(err.kind).toBe('missing_scopes');
    expect(err.requiredScopes).toEqual(['a', 'b', 'c']);
    expect(err.missingScopes).toEqual(['c']);
    expect(err.upgradeUrl).toContain('/upgrade_scopes');
  });

  it('leaves ordinary errors as ApiError', () => {
    const err = toApiError(403, { error: 'admin access required' });

    expect(err).toBeInstanceOf(ApiError);
    expect(err).not.toBeInstanceOf(AuthActionError);
    expect(err.code).toBe('admin access required');
  });
});

describe('pickApiError', () => {
  it("prefers the gateway's own words over a status code", () => {
    expect(pickApiError(new ApiError(403, { error: 'admin access required' }))).toBe(
      'admin access required',
    );
  });

  it('falls back to a text body', () => {
    expect(pickApiError(new ApiError(502, 'bad gateway'))).toBe('bad gateway');
  });

  it('names the status when the body says nothing useful', () => {
    expect(pickApiError(new ApiError(500, {}), 'Network error')).toBe('Network error (500)');
  });

  it('handles plain errors and unknown throwables', () => {
    expect(pickApiError(new Error('boom'))).toBe('boom');
    expect(pickApiError('not an error', 'Fallback')).toBe('Fallback');
  });
});
