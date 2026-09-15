// Which deployment environment the dashboard is talking to.
//
// The client never gets told its environment directly — the API base is
// resolved server-side by `vercel.json` rewrites keyed on the request Host
// header. So we derive it the same way `vercel.json` routes: from the
// hostname. Production is the only allowlisted "silent" environment; anything
// we don't positively recognise as prod is treated as non-prod so the
// environment ribbon / dev favicon fail loud rather than silent.

export type AppEnv = {
	/** Short label for display, e.g. "dev", "preview", "local", "production". */
	name: string;
	isProd: boolean;
};

/**
 * Map a hostname to an environment. Pure — safe to call anywhere.
 *
 * Mirrors the host patterns in `dashboard/vercel.json`:
 *   app.overslash.com / *.app.overslash.com  → prod
 *   *.app.dev.overslash.com / everything else → dev (the fallback backend)
 */
export function environmentFromHost(hostname: string): AppEnv {
	const h = hostname.toLowerCase();

	const isProd =
		(h === 'app.overslash.com' || h.endsWith('.app.overslash.com')) && !h.includes('.dev.');
	if (isProd) return { name: 'production', isProd: true };

	let name = 'dev';
	if (h === 'localhost' || h === '127.0.0.1' || h.endsWith('.local')) name = 'local';
	else if (h.endsWith('.vercel.app')) name = 'preview';
	else if (h.includes('dev.overslash.com')) name = 'dev';

	return { name, isProd: false };
}

/** Browser-only convenience — callers must guard with `browser` from `$app/environment`. */
export function currentEnvironment(): AppEnv {
	return environmentFromHost(window.location.hostname);
}

/**
 * The MCP endpoint an MCP client should be pointed at, for the org the caller
 * is currently looking at.
 *
 * Two cases, and the split matters:
 *
 * 1. **A managed-cloud host we recognise**, with a slug we know is usable →
 *    the org subdomain form, `https://<slug>.api[.dev].overslash.com/mcp`.
 *    This is the form worth going out of our way for: per D26 the subdomain is
 *    an *enforced* enrollment lock, so an agent enrolled through it is
 *    guaranteed to land in this org, under this org's IdP and ceiling.
 *
 *    Note this deliberately goes *further* than `dashboard/vercel.json`, which
 *    only produces the slug form when the dashboard host already carries one
 *    (its apex rows are slug-free). On the apex — the multi-org hub — we still
 *    hand out the org-locked URL, because the operator is looking at a
 *    specific org and that is the org the client should be pinned to.
 *
 * 2. **Anything else** → the dashboard's own origin plus `/mcp`. That is the
 *    correct answer for every deployment whose hostnames we have no business
 *    guessing: a self-hosted `overslash web` serves the dashboard and the API
 *    from one origin, and on Vercel previews and the bare apex `vercel.json`
 *    already rewrites `/mcp` onto the right backend. Guessing an
 *    `overslash.com` URL for a self-hoster would hand them a command pointing
 *    at somebody else's server, which is worse than no command at all.
 *
 * `slugUsable` is the caller's assertion that the slug actually resolves as a
 * subdomain — it must be false for a personal org, which `subdomain_middleware`
 * 404s (`personal_org_unreachable`), and false whenever the caller cannot tell.
 * It has no default: getting it wrong yields a dead command, so the caller is
 * made to say.
 */
export function ownMcpUrlFor(origin: string, slug: string | null, slugUsable: boolean): string {
	let hostname: string;
	try {
		hostname = new URL(origin).hostname;
	} catch {
		return '/mcp';
	}
	const h = hostname.toLowerCase();

	// Only the managed cloud's own app hosts earn the subdomain form — match
	// the same patterns `environmentFromHost` allowlists, and nothing wider.
	const isCloudApp =
		h === 'app.overslash.com' ||
		h.endsWith('.app.overslash.com') ||
		h === 'app.dev.overslash.com' ||
		h.endsWith('.app.dev.overslash.com');

	if (isCloudApp && slug && slugUsable) {
		const apex = environmentFromHost(h).isProd ? 'api.overslash.com' : 'api.dev.overslash.com';
		return `https://${slug}.${apex}/mcp`;
	}
	return `${origin.replace(/\/+$/, '')}/mcp`;
}
