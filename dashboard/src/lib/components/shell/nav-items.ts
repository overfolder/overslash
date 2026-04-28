export interface NavItemDef {
	href: string;
	label: string;
	icon: string;
}

export const NAV_ITEMS: NavItemDef[] = [
	{ href: '/agents', label: 'Agents', icon: '⊟' },
	{ href: '/services', label: 'Services', icon: '◫' },
	{ href: '/secrets', label: 'Secrets', icon: '⚷' },
	{ href: '/approvals', label: 'Approvals', icon: '✓' },
	{ href: '/audit', label: 'Audit Log', icon: '☰' }
];

export const ADMIN_NAV_ITEMS: NavItemDef[] = [
	{ href: '/members', label: 'Users', icon: '◉' },
	{ href: '/org/groups', label: 'Groups', icon: '◈' }
];

/** Settings item shown at the bottom of the sidebar (admin only). */
export const SETTINGS_NAV_ITEM: NavItemDef = { href: '/org', label: 'Settings', icon: '⚙' };

export function isActive(pathname: string, href: string): boolean {
	return pathname === href || pathname.startsWith(href + '/');
}

export function pageTitleFromPath(pathname: string): string {
	for (const item of [...NAV_ITEMS, ...ADMIN_NAV_ITEMS, SETTINGS_NAV_ITEM]) {
		if (isActive(pathname, item.href)) return item.label;
	}
	if (pathname.startsWith('/profile')) return 'Profile';
	return 'Overslash';
}
