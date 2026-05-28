/**
 * Presentational metadata for OAuth providers shown in the Connections view.
 *
 * The API's `OAuthProviderInfo` carries the runtime data the dashboard needs
 * (`default_identity_scopes` for the scope chips, redirect/origin for BYOC),
 * so this module only owns brand colours — values that aren't worth a
 * round-trip and don't change per-tenant.
 */

import type { OAuthProviderInfo } from '$lib/types';

export interface ProviderBrand {
	/** Single glyph shown in the brand tile. */
	letter: string;
	/** Tile background (brand colour). */
	bg: string;
	/** Tile foreground (glyph colour). */
	fg: string;
}

const NEUTRAL_BRAND: ProviderBrand = { letter: '?', bg: 'var(--neutral-400)', fg: '#ffffff' };

const PROVIDER_BRAND: Record<string, ProviderBrand> = {
	google: { letter: 'G', bg: '#ea4335', fg: '#ffffff' },
	github: { letter: 'G', bg: '#24292f', fg: '#ffffff' },
	slack: { letter: 'S', bg: '#4a154b', fg: '#ffffff' },
	x: { letter: 'X', bg: '#0f1419', fg: '#ffffff' },
	eventbrite: { letter: 'E', bg: '#f05537', fg: '#ffffff' }
};

/** Brand tile metadata for a provider key, falling back to a neutral tile that
 * uses the first letter of the key for providers we don't have a colour for. */
export function brandFor(providerKey: string): ProviderBrand {
	const known = PROVIDER_BRAND[providerKey];
	if (known) return known;
	return {
		...NEUTRAL_BRAND,
		letter: (providerKey[0] ?? '?').toUpperCase()
	};
}

/**
 * Identity scopes the backend always injects for this provider (`openid email
 * profile` for Google, `read:user user:email` for GitHub, …). Sourced from
 * `GET /v1/oauth-providers` so the dashboard never drifts from the
 * `oauth_providers.default_identity_scopes` column.
 */
export function defaultScopesFor(provider: OAuthProviderInfo | null | undefined): string[] {
	return provider?.default_identity_scopes ?? [];
}
