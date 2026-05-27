/**
 * Presentational metadata for OAuth providers shown in the Connections view.
 *
 * The API's `OAuthProviderInfo` carries no brand colour or default scope set,
 * so the dashboard keeps a small static map for the provider tiles and for the
 * scopes a connection requests when it's created outside a service context
 * (the Connections "Connect account" flow has no template to derive scopes
 * from). Both are purely client-side; the backend remains the source of truth
 * for which providers actually exist (`GET /v1/oauth-providers`).
 */

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
 * Default scope set requested when linking an account from the Connections view
 * (no service/template is involved, so there's nothing to derive scopes from).
 * Mirrors the design prototype. Unknown providers request no extra scopes and
 * fall back to whatever the provider's OAuth app defaults to.
 */
export const DEFAULT_SCOPES: Record<string, string[]> = {
	google: ['openid', 'email', 'profile'],
	github: ['read:user'],
	slack: ['users:read'],
	x: ['users.read'],
	eventbrite: ['event_read']
};

export function defaultScopesFor(providerKey: string): string[] {
	return DEFAULT_SCOPES[providerKey] ?? [];
}
