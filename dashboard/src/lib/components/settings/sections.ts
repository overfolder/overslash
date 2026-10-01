/**
 * Org Settings information architecture: groups of sections, one page per
 * section at `/org/<id>` (`/org` itself shows General). The route matcher in
 * `src/params/settingsSection.ts` accepts exactly these ids, so a new section
 * is a new entry here and nothing else in routing.
 */

export interface SettingsContext {
	isPersonalOrg: boolean;
	isInstanceAdmin: boolean;
	hasOrg: boolean;
	hasSubscription: boolean;
	hasManagedSignin: boolean;
}

export interface SettingsSection {
	id: string;
	label: string;
	/** Mirrors the `{#if}` gate the section's card has always had. */
	visible?: (ctx: SettingsContext) => boolean;
}

export interface SettingsGroup {
	id: string;
	label: string;
	sections: SettingsSection[];
}

const corpOnly = (ctx: SettingsContext) => !ctx.isPersonalOrg;

export const SETTINGS_GROUPS: SettingsGroup[] = [
	{
		id: 'org',
		label: 'Organization',
		sections: [
			{ id: 'general', label: 'General' },
			{
				id: 'billing',
				label: 'Billing',
				visible: (ctx) => !ctx.isPersonalOrg && ctx.hasSubscription
			},
			{
				id: 'trial',
				label: 'Trial',
				visible: (ctx) => ctx.isInstanceAdmin && !ctx.isPersonalOrg && ctx.hasOrg
			}
		]
	},
	{
		id: 'access',
		label: 'Access',
		sections: [
			{
				id: 'signin',
				label: 'Sign-in & members',
				visible: (ctx) => !ctx.isPersonalOrg && ctx.hasManagedSignin
			},
			{ id: 'idp', label: 'Identity Providers', visible: corpOnly },
			{ id: 'google-directory', label: 'Google Workspace', visible: corpOnly }
		]
	},
	{
		id: 'agents',
		label: 'Agents & policy',
		sections: [
			{ id: 'agent-defaults', label: 'Agent defaults' },
			{ id: 'catalog', label: 'Service catalog' },
			{ id: 'secret-requests', label: 'Secret requests' }
		]
	},
	{
		id: 'dev',
		label: 'Developer',
		sections: [
			{ id: 'oauth', label: 'OAuth App Credentials', visible: corpOnly },
			{ id: 'mcp', label: 'MCP Clients' },
			{ id: 'service-keys', label: 'Service keys' },
			{ id: 'webhooks', label: 'Webhooks' }
		]
	},
	{
		id: 'data',
		label: 'Audit & data',
		sections: [{ id: 'audit', label: 'Audit log' }]
	}
];

export const SETTINGS_SECTION_IDS: ReadonlySet<string> = new Set(
	SETTINGS_GROUPS.flatMap((g) => g.sections.map((s) => s.id))
);

export const DEFAULT_SETTINGS_SECTION = 'general';

/** Groups with their hidden sections dropped; empty groups are dropped too. */
export function visibleGroups(ctx: SettingsContext): SettingsGroup[] {
	return SETTINGS_GROUPS.map((g) => ({
		...g,
		sections: g.sections.filter((s) => s.visible?.(ctx) ?? true)
	})).filter((g) => g.sections.length > 0);
}

/** Pre-sub-nav deep links were `/org#<anchor>`; map them onto sections. */
export const LEGACY_ANCHORS: Record<string, string> = {
	billing: 'billing',
	'instance-admin-trial': 'trial',
	'oauth-app-credentials': 'oauth',
	'google-directory': 'google-directory'
};

export function settingsHref(id: string): string {
	return id === DEFAULT_SETTINGS_SECTION ? '/org' : `/org/${id}`;
}

/** True for `/org` and `/org/<section>` — not `/org/groups` and friends. */
export function isSettingsPath(pathname: string): boolean {
	if (pathname === '/org') return true;
	const m = /^\/org\/([^/]+)\/?$/.exec(pathname);
	return m !== null && SETTINGS_SECTION_IDS.has(m[1]);
}
