export interface NavItemDef {
	href: string;
	label: string;
	icon: string;
}

export const NAV_ITEMS: NavItemDef[] = [
	{ href: '/', label: 'Dashboard', icon: '⌂' },
	{ href: '/identities', label: 'Identities', icon: '⊟' },
	{ href: '/services', label: 'Services', icon: '◫' },
	{ href: '/approvals', label: 'Approvals', icon: '✓' },
	{ href: '/api-explorer', label: 'API Explorer', icon: '⌘' },
	{ href: '/audit', label: 'Audit Log', icon: '☰' }
];

export const ADMIN_NAV_ITEMS: NavItemDef[] = [
	{ href: '/members', label: 'Members', icon: '◉' },
	{ href: '/org/groups', label: 'Groups', icon: '◈' }
];

export function isActive(pathname: string, href: string): boolean {
	if (href === '/') return pathname === '/';
	return pathname === href || pathname.startsWith(href + '/');
}

export function pageTitleFromPath(pathname: string): string {
	for (const item of [...NAV_ITEMS, ...ADMIN_NAV_ITEMS]) {
		if (isActive(pathname, item.href)) return item.label;
	}
	if (pathname.startsWith('/profile')) return 'Profile';
	return 'Overslash';
}
