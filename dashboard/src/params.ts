import { defineParams } from '@sveltejs/kit/params';
import { SETTINGS_SECTION_IDS } from '#lib/components/settings/sections.ts';

export const params = defineParams({
	// Only known Org Settings sections route to `/org/[[section]]`; anything else
	// 404s instead of shadowing a future static `/org/<x>` route. The static
	// `/org/groups` and `/org/directory-groups` routes win regardless.
	settingsSection: (param) => (SETTINGS_SECTION_IDS.has(param) ? param : undefined)
});
