// Parsing for SPIFFE-style identity paths.
// Format: spiffe://<org>/<kind>/<name>/<kind>/<name>/...
//
// Each `kind/name` pair is one identity unit. The leading `spiffe://` scheme
// and the org slug are stripped/handled separately. `ids` carries one UUID per
// `(kind, name)` unit, aligned in order (no id for the org slug).
//
// Shared by IdentityPath.svelte (full clickable path) and the audit log row
// (which splits the path into separate User and Agent columns).

export type IdentitySegment =
	| { type: 'org'; name: string; href: string }
	| { type: 'unit'; kind: string; name: string; href: string };

export function parseIdentityPath(path: string, ids: string[] = []): IdentitySegment[] {
	const stripped = path.replace(/^spiffe:\/\//, '');
	const parts = stripped.split('/').filter(Boolean);
	if (parts.length === 0) return [];
	const out: IdentitySegment[] = [];
	// First part is the org slug.
	out.push({ type: 'org', name: parts[0], href: `/org` });
	// Remaining parts come in (kind, name) pairs aligned with `ids`
	// (one id per pair, no id for the org slug).
	let unitIndex = 0;
	for (let i = 1; i + 1 < parts.length; i += 2) {
		const kind = parts[i];
		const name = parts[i + 1];
		const id = ids[unitIndex];
		// Agent units link by id when available so /agents/<id> can resolve
		// directly without a name → id lookup. User units stay name-keyed to
		// match the /users/[name] route. If the caller hasn't supplied ids
		// (legacy), fall back to name-keyed agent links and accept the (rare)
		// name-collision risk.
		const href =
			kind === 'user'
				? `/users/${name}`
				: id
					? `/agents/${id}`
					: `/agents/${name}`;
		out.push({ type: 'unit', kind, name, href });
		unitIndex += 1;
	}
	return out;
}

export interface IdentityUnit {
	name: string;
	href: string;
}

/** Split a path into the owning user unit and the leaf actor unit.
 *  - `user`: first `user` unit (the owner), else null.
 *  - `leaf`: the last unit when it is an agent/sub-agent, else null (so a
 *    user-only path — a human acting directly — yields `leaf: null`). */
export function identityUnits(
	path: string | null,
	ids: string[] = []
): { user: IdentityUnit | null; leaf: IdentityUnit | null } {
	if (!path) return { user: null, leaf: null };
	const units = parseIdentityPath(path, ids).filter((s) => s.type === 'unit');
	const user = units.find((u) => u.kind === 'user') ?? null;
	const last = units.length > 0 ? units[units.length - 1] : null;
	const leaf = last && last.kind !== 'user' ? last : null;
	return {
		user: user ? { name: user.name, href: user.href } : null,
		leaf: leaf ? { name: leaf.name, href: leaf.href } : null
	};
}

/** Human-readable chain (`alice / henry / researcher`) for a hover title —
 *  drops the scheme, org slug, and `kind` tokens. */
export function formatIdentityPath(path: string | null): string {
	if (!path) return '';
	return parseIdentityPath(path)
		.filter((s) => s.type === 'unit')
		.map((s) => s.name)
		.join(' / ');
}
