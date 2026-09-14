// How a resource's owner is labelled when a list spans several users.
//
// Service instance names are unique per owner, not per org, so an org admin
// who flips "Show all users' services" sees three identical `gcal` rows. The
// disambiguator is the owner, and — per `$lib/identityDisplay` — the owner's
// real handle is their email, not the IdP `name` claim. This module turns an
// `owner_identity_id` into that label once, so the services list, the service
// detail header, the API Explorer picker and the connections list all agree.

import { formatIdentity, type IdentityLike } from '$lib/identityDisplay';

/** Who owns a row, relative to the viewer.
 *  - `org`: no owner identity — an org-level resource everyone shares.
 *  - `self`: the viewer's own.
 *  - `other`: someone else's (another user, or an agent).
 *  - `unknown`: an owner id that the identity list didn't resolve. */
export type OwnerScope =
	| { kind: 'org' }
	| { kind: 'self'; label: string; title: string }
	| { kind: 'other'; label: string; title: string }
	| { kind: 'unknown'; label: string; title: string };

/** Resolve a row's owner into a display scope.
 *
 *  `identityById` is the map every calling page already builds from
 *  `/v1/identities`. Callers soft-fail that request, and it can come back
 *  empty or partial, so an unresolved owner is the normal case rather than an
 *  error: it lands in `unknown`, which leaves the name unqualified instead of
 *  breaking the page. */
export function resolveOwner(
	ownerId: string | null | undefined,
	identityById: Map<string, IdentityLike>,
	currentUserId: string | undefined,
	allowedDomains: string[]
): OwnerScope {
	if (!ownerId) return { kind: 'org' };
	const ident = identityById.get(ownerId);
	if (!ident) {
		// Keep the raw id in the tooltip — it is the only handle a reader has
		// left, and the cells already surfaced it there before this module.
		return { kind: 'unknown', label: 'unknown', title: ownerId };
	}
	// Users are labelled by (domain-stripped) email; agents keep their name —
	// `formatIdentity` already makes that split, since agents have no email.
	const d = formatIdentity(ident, allowedDomains);
	const kind = ownerId === currentUserId ? 'self' : 'other';
	return { kind, label: d.primary, title: d.title };
}

/** Text for an "Owner" column: `Org` / `You` / the owner's label. */
export function ownerLabel(o: OwnerScope): string {
	switch (o.kind) {
		case 'org':
			return 'Org';
		case 'self':
			return 'You';
		default:
			return o.label;
	}
}

/** Lossless hover text for an owner cell: the full email (plus display name),
 *  or the raw id when the identity didn't resolve. `undefined` for org-level
 *  rows, which have no owner to describe. */
export function ownerTitle(o: OwnerScope): string | undefined {
	return o.kind === 'org' ? undefined : o.title;
}

/** True when a row's name needs the owner spelled out beside it. Only another
 *  identity's rows qualify: org-level and your own are the baseline, and an
 *  unresolved id would only add a UUID nobody can read. */
export function needsOwnerPrefix(
	o: OwnerScope
): o is { kind: 'other'; label: string; title: string } {
	return o.kind === 'other';
}

/** `other1 / gcal` for someone else's row, plain `gcal` otherwise. */
export function qualifyName(name: string, o: OwnerScope): string {
	return needsOwnerPrefix(o) ? `${o.label} / ${name}` : name;
}
