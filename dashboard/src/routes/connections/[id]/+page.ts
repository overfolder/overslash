import type { MeIdentity } from '$lib/session';
import type { OAuthProviderInfo } from '$lib/types';
import { listOAuthProviders } from '$lib/api/services';

export const load = async ({ parent }) => {
	const layoutData = (await parent()) as { user: MeIdentity | null };
	// Provider catalog supplies the display name for the page title. The
	// connection itself loads client-side so Reconnect can refresh in place.
	let providers: OAuthProviderInfo[] = [];
	try {
		providers = await listOAuthProviders();
	} catch {
		// Non-fatal: fall back to the raw provider key in the title.
	}
	return {
		user: layoutData.user,
		providers
	};
};
