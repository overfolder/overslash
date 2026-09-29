import type { ParamMatcher } from '@sveltejs/kit';
import { SETTINGS_SECTION_IDS } from '$lib/components/settings/sections';

// Only known Org Settings sections route to `/org/[section]`; anything else
// 404s instead of shadowing a future static `/org/<x>` route. The static
// `/org/groups` and `/org/directory-groups` routes win regardless.
export const match: ParamMatcher = (param) => SETTINGS_SECTION_IDS.has(param);
