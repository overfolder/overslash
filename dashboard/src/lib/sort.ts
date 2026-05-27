export type SortDir = 'asc' | 'desc';

/**
 * Compare two items by an extracted value. Numbers compare numerically;
 * everything else compares as case-insensitive strings via localeCompare.
 * `dir === 'desc'` reverses the order.
 */
export function compareBy<T>(
	a: T,
	b: T,
	get: (x: T) => string | number,
	dir: SortDir
): number {
	const av = get(a);
	const bv = get(b);
	let cmp: number;
	if (typeof av === 'number' && typeof bv === 'number') {
		cmp = av - bv;
	} else {
		cmp = String(av).localeCompare(String(bv), undefined, { sensitivity: 'base' });
	}
	return dir === 'desc' ? -cmp : cmp;
}
