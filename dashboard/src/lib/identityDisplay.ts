// How a user identity is labelled across the dashboard.
//
// `identity.name` is the IdP's `name` claim (see
// crates/overslash-api/src/routes/auth/provisioning.rs) — a Google profile
// name that is neither unique nor stable. The email is the real handle, so it
// is the primary label everywhere a user identity is listed; the display name
// demotes to a secondary line and to detail panes.
//
// Agents and sub-agents have no email (`POST /v1/identities` never sets one),
// so they keep rendering their name unchanged.

/** The subset of an identity this module needs. Structural on purpose: all
 *  three `Identity` declarations in the app (`$lib/types`, `routes/members`,
 *  `$lib/api/groups`) satisfy it without edits. */
export interface IdentityLike {
	name: string;
	email?: string | null;
	kind?: string;
}

export interface IdentityDisplay {
	/** The label to render. Email (possibly domain-stripped) for users with an
	 *  email; the raw name for agents and email-less users. */
	primary: string;
	/** The IdP display name, or null when it would only repeat `primary`. */
	secondary: string | null;
	/** Lossless hover text — the full email, plus the display name when there
	 *  is one. Domain stripping throws information away; this is how a reader
	 *  gets it back. */
	title: string;
}

function localPart(email: string): string {
	// `lastIndexOf`, not `split('@')[0]`: a quoted local part may itself
	// contain '@' (`"a@b"@example.com`).
	const at = email.lastIndexOf('@');
	return at > 0 ? email.slice(0, at) : email;
}

/** Drop `@domain` when the org has exactly one allowed sign-in domain and the
 *  address is on it — `ada@acme.com` renders as `ada`. With zero or several
 *  allowed domains the domain carries information, so it stays. */
export function shortEmail(email: string, allowedDomains: string[]): string {
	if (allowedDomains.length !== 1) return email;
	const at = email.lastIndexOf('@');
	if (at <= 0) return email;
	const domain = email.slice(at + 1).toLowerCase();
	// The API normalizes stored domains to lowercase and strips a leading '@'
	// (routes/orgs/settings.rs::normalize_domains), but rows predating that are
	// possible — normalize both sides before comparing. The local part is
	// rendered as stored: IdPs emit mixed case and `Ada` beats `ada`.
	const allowed = allowedDomains[0].trim().replace(/^@/, '').toLowerCase();
	return domain === allowed ? email.slice(0, at) : email;
}

/** True when the display name adds nothing over the email. Compared against
 *  the *local part* rather than the computed primary, so the answer does not
 *  depend on whether domain stripping is active. Covers all three shapes the
 *  backend produces: an IdP with no `name` claim and magic-link sign-in both
 *  leave `name === email`, and a pending invite leaves `name === localPart`. */
function nameIsRedundant(name: string, email: string): boolean {
	const n = name.trim().toLowerCase();
	if (n === '') return true;
	const e = email.trim().toLowerCase();
	return n === e || n === localPart(e);
}

export function formatIdentity(i: IdentityLike, allowedDomains: string[]): IdentityDisplay {
	const email = i.email?.trim() ?? '';
	if (!email || (i.kind && i.kind !== 'user')) {
		return { primary: i.name, secondary: null, title: i.name };
	}
	const redundant = nameIsRedundant(i.name, email);
	return {
		primary: shortEmail(email, allowedDomains),
		secondary: redundant ? null : i.name,
		title: redundant ? email : `${email} · ${i.name}`
	};
}

/** Avatar initials. Prefers a real display name (`Ada Lovelace` → `AL`) and
 *  falls back to the email local part (`ada@acme.com` → `AD`) when the name is
 *  just the address echoed back. */
export function identityInitials(i: IdentityLike): string {
	const email = i.email?.trim() ?? '';
	const src = (email && nameIsRedundant(i.name, email) ? localPart(email) : i.name).trim();
	if (!src) return '?';
	const words = src.split(/\s+/).filter(Boolean);
	if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
	return src.slice(0, 2).toUpperCase();
}

/** Display label for an identity's IdP. */
export function providerLabel(p: string | null | undefined): string {
	if (!p) return '—';
	const map: Record<string, string> = {
		google: 'Google',
		github: 'GitHub',
		oidc: 'OIDC'
	};
	return map[p.toLowerCase()] ?? p;
}

export interface IdentityFormatter {
	short(email: string): string;
	format(i: IdentityLike): IdentityDisplay;
	initials(i: IdentityLike): string;
}

/** Pre-bind the org's allowed domains so templates read `fmt.format(u)`
 *  instead of threading the list through every expression. Pages hold it as
 *  `const fmt = $derived(makeIdentityFormatter(data.allowedDomains))`. */
export function makeIdentityFormatter(allowedDomains: string[]): IdentityFormatter {
	return {
		short: (email) => shortEmail(email, allowedDomains),
		format: (i) => formatIdentity(i, allowedDomains),
		initials: identityInitials
	};
}
