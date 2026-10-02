// Secret paths: which vault a service binding points at.
//
// Secrets are namespaced per user, plus one org-wide vault, and a service
// binding stores a canonical path (crates/overslash-core/src/types/secret_path.rs):
//
//   org/<name>              the org-wide vault
//   <user identity id>/<name>  a user's vault
//
// The API also accepts `<handle>/<name>` (a user's email, or its local part,
// or name — when it names exactly one user), `user:<handle>/<name>` (for a
// user literally called "org"), and a bare `<name>`, which means the vault the
// binding is written into. The dashboard shows the shortest of those forms and
// sends the stored canonical value back untouched when the user didn't edit
// the field — so an unchanged binding to another admin's secret is kept.

import { formatIdentity, type IdentityLike } from '$lib/identityDisplay';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type ParsedSecretPath =
	| { scope: 'org'; name: string }
	| { scope: 'user'; ownerId: string; name: string }
	| { scope: 'bare'; name: string };

/** Parse a stored binding. Only `org/…` and `<uuid>/…` are qualified; anything
 *  else (a legacy name, a handle form) is reported as bare. */
export function parseSecretPath(raw: string): ParsedSecretPath {
	const slash = raw.indexOf('/');
	if (slash > 0 && slash < raw.length - 1) {
		const head = raw.slice(0, slash);
		const name = raw.slice(slash + 1);
		if (head === 'org') return { scope: 'org', name };
		if (UUID_RE.test(head)) return { scope: 'user', ownerId: head.toLowerCase(), name };
	}
	return { scope: 'bare', name: raw };
}

/** Display form of a stored binding.
 *
 *  `home` is the vault a bare name would land in — the service owner's, or the
 *  viewer's own on an org-level service — so bindings into it render as the
 *  plain name. Another user's vault renders as `<short handle>/<name>`, using
 *  the same email shortening as every other user field. An unresolvable owner
 *  keeps its id, which still round-trips. */
export function secretPathLabel(
	raw: string,
	home: string | null | undefined,
	identityById: Map<string, IdentityLike>,
	allowedDomains: string[]
): string {
	if (!raw) return raw;
	const p = parseSecretPath(raw);
	if (p.scope === 'bare') return p.name;
	if (p.scope === 'org') return `org/${p.name}`;
	// Plain name only when it reads back as one: a legacy name holding `/` or
	// starting `user:` would otherwise come back as another vault or a handle.
	if (home && p.ownerId === home.toLowerCase() && !p.name.includes('/') && !p.name.startsWith('user:'))
		return p.name;
	const ident = identityById.get(p.ownerId);
	if (!ident) return raw;
	const handle = formatIdentity(ident, allowedDomains).primary;
	if (!handle || handle.includes('/')) return raw;
	return handle === 'org' ? `user:${handle}/${p.name}` : `${handle}/${p.name}`;
}

/** True when a stored binding points outside `home` and the org vault — on a
 *  user-level service such a binding is never used. */
export function isForeignBinding(raw: string, home: string | null | undefined): boolean {
	const p = parseSecretPath(raw);
	return p.scope === 'user' && !!home && p.ownerId !== home.toLowerCase();
}

/** What to send for one binding field: the stored canonical value when the
 *  field still shows its seeded label (so an untouched binding is kept
 *  verbatim, whatever vault it points at), else what the user typed. */
export function bindingToWire(shown: string, seededLabel: string, stored: string): string {
	return shown === seededLabel ? stored : shown;
}
