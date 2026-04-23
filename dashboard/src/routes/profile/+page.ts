import type { PageLoad } from './$types';
import {
	session,
	type SecretMetadata,
	type PermissionRule,
	type EnrollmentTokenItem,
	type UserPreferences
} from '$lib/session';

export const load: PageLoad = async () => {
	const [secrets, permissions, enrollmentTokens, preferences] = await Promise.all([
		session.get<SecretMetadata[]>('/v1/secrets').catch(() => [] as SecretMetadata[]),
		session.get<PermissionRule[]>('/v1/permissions').catch(() => [] as PermissionRule[]),
		session
			.get<EnrollmentTokenItem[]>('/v1/enrollment-tokens')
			.catch(() => [] as EnrollmentTokenItem[]),
		session.get<UserPreferences>('/auth/me/preferences').catch(() => ({}) as UserPreferences)
	]);
	return { secrets, permissions, enrollmentTokens, preferences };
};
