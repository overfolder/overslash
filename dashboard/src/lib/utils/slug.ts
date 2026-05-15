import { session } from '$lib/session';

/**
 * Stable lowercase-hyphen slug derived from arbitrary user input.
 * Mirrors the backend's `validate_slug_format` shape so the live-check
 * is unlikely to reject what `slugify` produces.
 */
export function slugify(raw: string): string {
	return raw
		.toLowerCase()
		.replace(/[^a-z0-9-]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, 63);
}

/**
 * One-shot availability check for an org slug, hitting the unauthenticated
 * `/v1/orgs/check-slug` endpoint. Resolves to either `'available'` or an
 * error reason matching the backend's `SlugReject::code()` (e.g.
 * `slug_taken`, `slug_too_short`, `lookup_failed`).
 */
export async function checkSlugAvailable(slug: string): Promise<
	{ kind: 'available' } | { kind: 'invalid'; reason: string }
> {
	try {
		const res = await session.get<{ available: boolean; reason?: string }>(
			`/v1/orgs/check-slug?slug=${encodeURIComponent(slug)}`
		);
		return res.available
			? { kind: 'available' }
			: { kind: 'invalid', reason: res.reason ?? 'slug_invalid' };
	} catch {
		return { kind: 'invalid', reason: 'lookup_failed' };
	}
}

export type SlugCheck =
	| { kind: 'idle' }
	| { kind: 'checking' }
	| { kind: 'available' }
	| { kind: 'invalid'; reason: string };

/**
 * Debounced slug-availability checker. Returns a `(slug: string) => void`
 * scheduler that calls `setState` with the latest `SlugCheck` for the
 * given slug, deduping in-flight requests with a sequence counter so a
 * stale response can't overwrite a fresher one.
 *
 * Caller wires `setState` into a `$state` rune in the component.
 */
export function makeDebouncedSlugChecker(
	setState: (s: SlugCheck) => void,
	debounceMs = 300
): (slug: string) => void {
	let timer: ReturnType<typeof setTimeout> | null = null;
	let seq = 0;

	return (slug: string) => {
		if (timer) clearTimeout(timer);
		if (!slug) {
			setState({ kind: 'idle' });
			return;
		}
		setState({ kind: 'checking' });
		const mySeq = ++seq;
		timer = setTimeout(async () => {
			const result = await checkSlugAvailable(slug);
			if (mySeq !== seq) return;
			setState(result);
		}, debounceMs);
	};
}
