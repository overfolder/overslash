import type { PageLoad } from './$types';
import {
	session,
	type SecretMetadata,
	type PermissionRule,
	type UserPreferences
} from '$lib/session';
import { listByocCredentials, listOAuthProviders } from '$lib/api/services';
import type { ByocCredentialSummary, OAuthProviderInfo } from '$lib/types';

export const load: PageLoad = async () => {
	const [secrets, permissions, preferences, byoc, providers] = await Promise.all([
		session.get<SecretMetadata[]>('/v1/secrets').catch(() => [] as SecretMetadata[]),
		session.get<PermissionRule[]>('/v1/permissions').catch(() => [] as PermissionRule[]),
		session.get<UserPreferences>('/auth/me/preferences').catch(() => ({}) as UserPreferences),
		listByocCredentials().catch(() => [] as ByocCredentialSummary[]),
		listOAuthProviders().catch(() => [] as OAuthProviderInfo[])
	]);
	return { secrets, permissions, preferences, byoc, providers };
};
