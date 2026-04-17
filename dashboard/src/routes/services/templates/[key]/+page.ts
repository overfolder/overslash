import type { PageLoad } from './$types';
import { getTemplate, listOAuthProviders } from '$lib/api/services';

export const load: PageLoad = async ({ params, parent }) => {
	const layoutData = await parent();
	const [template, providers] = await Promise.all([
		getTemplate(params.key),
		listOAuthProviders().catch(() => [])
	]);
	const isAdmin = (layoutData as any).user?.is_org_admin === true;
	const identityId = (layoutData as any).user?.identity_id as string | undefined;

	return { template, isAdmin, identityId, providers };
};
