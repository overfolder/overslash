import type { PageLoad } from './$types';
import {
	session,
	type SecretMetadata,
	type PermissionRule,
	type UserPreferences
} from '$lib/session';

export const load: PageLoad = async () => {
	const [secrets, permissions, preferences] = await Promise.all([
		session.get<SecretMetadata[]>('/v1/secrets').catch(() => [] as SecretMetadata[]),
		session.get<PermissionRule[]>('/v1/permissions').catch(() => [] as PermissionRule[]),
		session.get<UserPreferences>('/auth/me/preferences').catch(() => ({}) as UserPreferences)
	]);
	return { secrets, permissions, preferences };
};
