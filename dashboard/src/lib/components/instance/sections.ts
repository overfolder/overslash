// Sections of the Instance Admin panel (`/instance/<section>`), in dock order.

export interface InstanceSection {
	id: string;
	label: string;
	/** Shown in the dock as disabled with a "Later" pill. */
	later?: boolean;
}

export interface InstanceGroup {
	label: string;
	sections: InstanceSection[];
}

export const INSTANCE_GROUPS: InstanceGroup[] = [
	{ label: 'Tenancy', sections: [{ id: 'orgs', label: 'Orgs' }] },
	{ label: 'Access', sections: [{ id: 'admins', label: 'Instance admins' }] },
	{
		label: 'Deployment',
		sections: [
			{ id: 'config', label: 'Configuration' },
			{ id: 'registry', label: 'Service registry', later: true }
		]
	},
	{ label: 'Audit', sections: [{ id: 'audit', label: 'Instance audit' }] }
];

export const DEFAULT_INSTANCE_SECTION = 'orgs';

/** Routable sections: the `[[section=instanceSection]]` matcher's set. */
export const INSTANCE_SECTION_IDS: ReadonlySet<string> = new Set(
	INSTANCE_GROUPS.flatMap((g) => g.sections.filter((s) => !s.later).map((s) => s.id))
);

export function instanceHref(id: string): string {
	return id === DEFAULT_INSTANCE_SECTION ? '/instance' : `/instance/${id}`;
}

export function instanceGroupOf(id: string): InstanceGroup | undefined {
	return INSTANCE_GROUPS.find((g) => g.sections.some((s) => s.id === id));
}
