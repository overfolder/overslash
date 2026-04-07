export interface NavItemDef {
	href: string;
	label: string;
	icon: string;
}

export const NAV_ITEMS: NavItemDef[] = [
	{ href: '/', label: 'Dashboard', icon: '⌂' },
	{ href: '/identities', label: 'Identities', icon: '⊟' },
	{ href: '/services', label: 'Services', icon: '◫' },
	{ href: '/api-explorer', label: 'API Explorer', icon: '⌘' },
	{ href: '/audit', label: 'Audit Log', icon: '☰' }
];

export const ADMIN_NAV_ITEMS: NavItemDef[] = [
	{ href: '/org', label: 'Org Dashboard', icon: '⚙' },
	{ href: '/members', label: 'Members', icon: '◉' }
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
