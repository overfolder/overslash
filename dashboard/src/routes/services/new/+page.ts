import type { MeIdentity } from '$lib/session';
import type { OAuthProviderInfo } from '$lib/types';
import { listOAuthProviders } from '$lib/api/services';

export const load = async ({ parent }) => {
	const layoutData = (await parent()) as { user: MeIdentity | null };
	let providers: OAuthProviderInfo[] = [];
	let providersLoaded = false;
	try {
		providers = await listOAuthProviders();
		providersLoaded = true;
	} catch {
		// Non-fatal: when provider catalog is unavailable, we don't force
		// BYOC — the backend cascade will resolve credentials at connect
		// time. The UI just can't show accurate credential-source hints.
	}
	return {
		user: layoutData.user,
		providers,
		providersLoaded
	};
};
