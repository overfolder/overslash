import type { MeIdentity } from '$lib/session';
import type { OAuthProviderInfo } from '$lib/types';
import { listOAuthProviders } from '$lib/api/services';

export const load = async ({ parent }) => {
	const layoutData = (await parent()) as { user: MeIdentity | null };
	// Provider catalog drives the Connect-account picker + BYOC hints. The
	// connection rows themselves load client-side so the page can refresh and
	// highlight a new row after the OAuth popup completes.
	let providers: OAuthProviderInfo[] = [];
	try {
		providers = await listOAuthProviders();
	} catch {
		// Non-fatal: an empty catalog just means the picker shows nothing and
		// the user can't link a new account until it's reachable.
	}
	return {
		user: layoutData.user,
		providers
	};
};
