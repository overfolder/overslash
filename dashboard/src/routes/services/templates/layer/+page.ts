import type { PageLoad } from './$types';
import { getTemplate } from '$lib/api/services';
import type { TemplateDetail } from '$lib/types';

/**
 * Layer editor loader. Two modes:
 *   - create:  ?base=<key>            → derive a new layer from `base`.
 *   - edit:    ?edit=<derived key>    → edit an existing derived layer.
 * In edit mode the base is the layer's own `extends`.
 */
export const load: PageLoad = async ({ url, parent }) => {
	const layoutData = await parent();
	const isAdmin = (layoutData as any).user?.is_org_admin === true;

	const editKey = url.searchParams.get('edit');
	let layer: TemplateDetail | null = null;
	let baseKey = url.searchParams.get('base') ?? '';

	if (editKey) {
		layer = await getTemplate(editKey);
		baseKey = layer.extends ?? '';
	}

	const base = baseKey ? await getTemplate(baseKey) : null;

	return { isAdmin, baseKey, base, layer };
};
