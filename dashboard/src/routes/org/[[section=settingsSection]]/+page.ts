import type { PageLoad } from './$types';
import { loadOrgSettings } from '$lib/components/settings/org-settings-load';

export const ssr = false;
export const prerender = false;

export const load: PageLoad = loadOrgSettings;
