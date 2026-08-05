// The org's allowed sign-in domains, fetched once per session.
//
// `$lib/identityDisplay` strips `@domain` from displayed emails when the org
// has exactly one allowed domain, so nearly every page that lists identities
// needs this list. The root layout load is the one place that runs before all
// of them — but it re-runs on every navigation (it reads `url.pathname`), so
// the fetch is memoized here rather than repeated per page view.

import type { ManagedSigninSettings } from '$lib/types';

type Fetch = typeof globalThis.fetch;

let cache: { orgId: string; promise: Promise<string[]> } | null = null;

/** Resolve the org's `managed_signin_allowed_domains`. Readable by any org
 *  member (`GET /v1/orgs/{id}/managed-signin` takes a plain AuthContext), and
 *  degrades to `[]` — an unavailable setting just means no domain stripping,
 *  never a broken page. */
export function loadAllowedDomains(orgId: string, fetchFn: Fetch): Promise<string[]> {
	if (cache && cache.orgId === orgId) return cache.promise;
	const promise = fetchFn(`/v1/orgs/${encodeURIComponent(orgId)}/managed-signin`, {
		credentials: 'include'
	})
		.then(async (res) => {
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const body = (await res.json()) as ManagedSigninSettings;
			return body.managed_signin_allowed_domains ?? [];
		})
		.catch(() => {
			// Drop the memo on failure so the next navigation retries. Caching a
			// rejected lookup would disable stripping for the whole session on one
			// transient blip.
			if (cache?.promise === promise) cache = null;
			return [];
		});
	cache = { orgId, promise };
	return promise;
}

/** Forget the memo. Called after an admin edits the domain list so labels
 *  update on the next navigation instead of waiting for a reload. */
export function invalidateAllowedDomains(): void {
	cache = null;
}
