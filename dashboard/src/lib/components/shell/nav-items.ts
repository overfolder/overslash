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

/**
 * Pick the single nav item whose href is the longest prefix of `pathname`.
 * Use this instead of calling `isActive` per-item when items can be prefixes
 * of one another (e.g. `/org` and `/org/groups`) — otherwise both light up.
 */
export function pickActiveHref(pathname: string, items: { href: string }[]): string | null {
	let best: string | null = null;
	for (const it of items) {
		if (!isActive(pathname, it.href)) continue;
		if (best === null || it.href.length > best.length) best = it.href;
	}
	return best;
}

export function pageTitleFromPath(pathname: string): string {
	for (const item of [...NAV_ITEMS, ...ADMIN_NAV_ITEMS, SETTINGS_NAV_ITEM]) {
		if (isActive(pathname, item.href)) return item.label;
	}
	if (pathname.startsWith('/profile')) return 'Profile';
	return 'Overslash';
}
