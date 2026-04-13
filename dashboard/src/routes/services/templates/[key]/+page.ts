import type { PageLoad } from './$types';
import { getTemplate } from '$lib/api/services';

export const load: PageLoad = async ({ params, parent }) => {
	const layoutData = await parent();
	const template = await getTemplate(params.key);
	const isAdmin = (layoutData as any).user?.is_org_admin === true;
	const identityId = (layoutData as any).user?.identity_id as string | undefined;

	return { template, isAdmin, identityId };
};
