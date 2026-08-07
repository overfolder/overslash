import type { MeIdentity } from '$lib/session';
import type { OAuthProviderInfo } from '$lib/types';
import { listOAuthProviders } from '$lib/api/services';
import { groupsApi, type Group } from '$lib/api/groups';

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
	// Needed only by the org-level path, where the API requires at least one
	// group the creator belongs to. Non-fatal: the form falls back to a
	// "create one first" hint if the listing is unavailable.
	let groups: Group[] = [];
	try {
		groups = await groupsApi.list();
	} catch {
		// ignore — see above
	}
	return {
		user: layoutData.user,
		providers,
		providersLoaded,
		groups
	};
};
