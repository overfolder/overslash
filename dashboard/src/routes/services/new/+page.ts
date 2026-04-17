import type { MeIdentity } from '$lib/session';
import type { OAuthProviderInfo } from '$lib/types';
import { listOAuthProviders } from '$lib/api/services';

export const load = async ({ parent }) => {
	const layoutData = (await parent()) as { user: MeIdentity | null };
	let providers: OAuthProviderInfo[] = [];
	try {
		providers = await listOAuthProviders();
	} catch {
		// Non-fatal: Create Service falls back to the "no fallback" BYOC path
		// if we can't resolve the provider catalog.
	}
	return {
		user: layoutData.user,
		providers
	};
};
