// Links into the public docs site (overfolder/overslash-docs). Only providers
// with a published page get a link — a guessed URL 404s.

const DOCS_BASE = 'https://www.overslash.com/docs';

/** Per-user "bring your own OAuth app" guides. */
const BYOC_GUIDES: Record<string, string> = {
	google: `${DOCS_BASE}/guide/how-to/link-google-services`
};

/** Org-admin guides for setting up one OAuth app for the whole org. */
const ORG_APP_GUIDES: Record<string, string> = {
	google: `${DOCS_BASE}/guide/how-to/org-google-oauth-app`
};

export function byocGuideUrl(provider: string): string | null {
	return BYOC_GUIDES[provider] ?? null;
}

export function orgAppGuideUrl(provider: string): string | null {
	return ORG_APP_GUIDES[provider] ?? null;
}
